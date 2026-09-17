#![cfg(all(feature = "native", not(miri)))]
//! The signing path: `Keystore::sign_spend` behind the receipt gate (I1).
//! Gated on `native` because the keystore and the
//! derivation are, and on `not(miri)` for interpreter time alone: every test
//! here runs WOTS+ generations and signatures, at some 300 s each under Miri,
//! and the glue they exercise is safe Rust over primitives
//! `tests/miri.rs` already walks. What Miri does not see because of this gate
//! is the copies into `SpendSignature` and the derive-then-sign composition;
//! said here rather than discovered.
//!
//! The signer is `backend::native` directly (the keystore's own precedent for
//! key material) and the recovery `wots::pk_from_sig` is `backend::selected`,
//! which resolves to the native port -- the only backend; each evidence line
//! says which. The downstream probe is gated on `not(miri)` alone, because it
//! spawns cargo.
//!
//! Every expected value is TypeScript-emitted: `F-address-widths` in
//! `fixtures/group_f_derivation.json` (one master seed, account 0, its tag,
//! its account seed, the shipped `wots_index 0` -- our position 1 -- and its
//! 40-byte address) and the 2208-byte sidecar holding position 0's public key,
//! public seed and address image. Nothing is read back from our own
//! derivation.

#[path = "support/keystore_harness.rs"]
mod keystore_harness;

use keystore_harness::{
    derived_account, imported_account, reopen, ScratchDir, DERIVED_MASTER, DERIVED_POSITION, DERIVED_TAG,
    DIGEST, FIGURES, IMPORTED_TAG,
};
use mochimo_crypto::account::{Account, AccountKind, WotsIndex};
use mochimo_crypto::addr;
use mochimo_crypto::consts::{PK_LEN, SEED_LEN, WOTS_ADDR_LEN};
use mochimo_crypto::keystore::{Disk, Instrumented, KeyAccess, Keystore, Pending, SpendSignature};
use mochimo_crypto::{derive, wots, Error, Secret};

/// A second digest, distinct from the harness's `DIGEST`.
const DIGEST_2: [u8; 32] = [0xD2; 32];

const FILE: &str = "group_f_derivation.json";
const ANCHOR_ID: &str = "F-address-widths";
const SIDECAR: &str = "F-widths_account_address.bin";

/// The backend `wots::pk_from_sig` resolves to, for the evidence lines.
const RECOVERY: &str = "native";

fn repo_root() -> std::path::PathBuf {
    let mut p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p
}

fn fixture_vector(id: &str) -> serde_json::Value {
    let p = repo_root().join("fixtures").join(FILE);
    let text = std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("cannot read {}: {e}", p.display()));
    let json: serde_json::Value = serde_json::from_str(&text).unwrap_or_else(|e| panic!("cannot parse {}: {e}", p.display()));
    json["vectors"]
        .as_array()
        .and_then(|vs| vs.iter().find(|v| v["id"].as_str() == Some(id)).cloned())
        .unwrap_or_else(|| panic!("{FILE} has no vector {id}"))
}

fn hex(v: &serde_json::Value, key: &str) -> Vec<u8> {
    let s = v[key].as_str().unwrap_or_else(|| panic!("{ANCHOR_ID}: no string field {key}"));
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap_or_else(|_| panic!("{ANCHOR_ID}: {key} is not hex")))
        .collect()
}

fn sidecar() -> Vec<u8> {
    let p = repo_root().join("fixtures").join(SIDECAR);
    std::fs::read(&p).unwrap_or_else(|e| panic!("cannot read {}: {e}", p.display()))
}

/// The anchor every proof in this file stands on: the fixture's master seed at
/// account 0 derives to the fixture's tag, and its account seed is the one the
/// fixture recorded. If either moves, every green below is over an account the
/// TypeScript never described -- so it is asserted once, first, by name.
#[test]
fn fixture_anchor_derives_to_the_recorded_account_tag() {
    let v = fixture_vector(ANCHOR_ID);
    let master = Secret::<SEED_LEN>::from_slice(&hex(&v, "master_seed")).unwrap_or_else(|e| panic!("{e}"));
    let tag: [u8; 20] = hex(&v, "account_tag").as_slice().try_into().unwrap_or_else(|_| panic!("tag width"));
    let acct = Account::derive(&master, 0);
    assert_eq!(acct.tag(), tag, "Account::derive(master, 0) does not reproduce {ANCHOR_ID}'s account_tag");
    let derived = mochimo_crypto::derive::derive_account(&master, 0);
    assert_eq!(
        derived.seed().expose()[..],
        hex(&v, "account_seed")[..],
        "derive_account(master, 0).seed() is not {ANCHOR_ID}'s account_seed"
    );
    assert_eq!(sidecar().len(), 2208, "{SIDECAR} is not a 2208-byte legacy address");
    println!("  signing anchor: {ANCHOR_ID} derives to its recorded tag and seed (recovery via {RECOVERY})");
}

/// The fixture's account, read once: master, tag, account seed, the recorded
/// position-1 address hash, and the sidecar with position 0's public parts.
struct Anchor {
    master: Secret<SEED_LEN>,
    tag: [u8; 20],
    seed: Secret<SEED_LEN>,
    /// `wots_address[20..40]`: the hash half of the shipped `wotsIndex 0`
    /// address, our position 1.
    hash_at_1: [u8; 20],
    sidecar: Vec<u8>,
}

fn anchor() -> Anchor {
    let v = fixture_vector(ANCHOR_ID);
    let wots_address = hex(&v, "wots_address");
    assert_eq!(wots_address.len(), 40, "{ANCHOR_ID}: wots_address is not 40 bytes");
    let mut hash_at_1 = [0u8; 20];
    hash_at_1.copy_from_slice(&wots_address[20..40]);
    Anchor {
        master: Secret::<SEED_LEN>::from_slice(&hex(&v, "master_seed")).unwrap_or_else(|e| panic!("{e}")),
        tag: hex(&v, "account_tag").as_slice().try_into().unwrap_or_else(|_| panic!("tag width")),
        seed: Secret::<SEED_LEN>::from_slice(&hex(&v, "account_seed")).unwrap_or_else(|e| panic!("{e}")),
        hash_at_1,
        sidecar: sidecar(),
    }
}

/// Recover the public key a signature is valid under -- `wots::pk_from_sig`,
/// `backend::selected`, so the C in the default build.
fn recover(sig: &SpendSignature, digest: &[u8; 32]) -> wots::PublicKey {
    let mut adrs = sig.adrs;
    wots::pk_from_sig(&sig.signature, digest, &sig.pub_seed, &mut adrs)
}

fn hash_of_pk(pk: &[u8; PK_LEN]) -> [u8; 20] {
    let address = addr::from_wots(pk);
    let mut out = [0u8; 20];
    out.copy_from_slice(addr::hash_of(&address));
    out
}

/// A store over an instrumented medium, so a refusal's "no medium call" half
/// can be asserted; the seed accounts come from the harness.
fn instrumented(dir: &ScratchDir) -> Keystore<Instrumented<Disk>> {
    Keystore::create_with(dir.path(), Instrumented::new(Disk), &keystore_harness::init()).unwrap_or_else(|e| panic!("create: {e}"))
}

/// Every refusal has no side effect: no medium call, the snapshot unchanged.
fn assert_no_side_effect(ks: &Keystore<Instrumented<Disk>>, dir: &ScratchDir, before: &[u8], what: &str) {
    assert!(ks.medium().calls().is_empty(), "{what}: a refusal touched the medium: {:?}", ks.medium().calls());
    assert_eq!(dir.snapshot_bytes(), before, "{what}: a refusal changed the snapshot");
}

// ---------------------------------------------------------------------------
// The proof -- the census target of
// `key_signs_once_per_keystore_with_the_raw_signer_crate_private_not_absent`.
// ---------------------------------------------------------------------------

/// I1 through the receipt gate, executed over the fixture's account: each
/// position signs once, under the address the TypeScript recorded for it,
/// and every second receipt at a spent position is refused. The imported
/// twin signs position 1 from the root alone under the same recorded
/// address, and -- signing being deterministic -- produces the identical
/// bytes the derived path did for the same key and digest.
///
/// The recovery (`pk_from_sig`) is `backend::selected`; the signer is native.
/// Both resolve to the native port, the only backend, on every run. Nothing
/// here is read back from our own derivation: position 0's
/// public key, seed and address image come from the 2208-byte sidecar, and
/// position 1's address hash from `wots_address`.
#[test]
fn each_wots_key_signs_once_through_the_receipt_gate() {
    let a = anchor();
    let mut refusals = 0usize;

    // -- the derived account, position 0 --------------------------------
    let dir = ScratchDir::new("i1-proof");
    let mut ks = instrumented(&dir);
    let acct = Account::derive(&a.master, 0);
    assert_eq!(acct.tag(), a.tag, "the account is not the fixture's");
    ks.add(acct).unwrap_or_else(|e| panic!("{e}"));

    let r1 = ks.persist_advance(&a.tag, &DIGEST, FIGURES).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(r1.index(), WotsIndex::ZERO.advanced().unwrap_or_else(|e| panic!("{e}")));
    let before = dir.snapshot_bytes();
    ks.medium_mut().reset_calls();
    let s0 = ks
        .sign_spend(&DIGEST, r1, KeyAccess::Master(&a.master))
        .unwrap_or_else(|e| panic!("position 0: {e}"));
    assert_eq!(s0.spent_index, WotsIndex::ZERO);
    // Nothing persisted by signing: the advance already was.
    assert!(ks.medium().calls().is_empty(), "sign_spend touched the medium: {:?}", ks.medium().calls());
    assert_eq!(dir.snapshot_bytes(), before, "sign_spend changed the snapshot");
    // The signature is valid under position 0's RECORDED public key, and the
    // public parts released beside it are the recorded ones.
    let pk0 = recover(&s0, &DIGEST);
    assert_eq!(&pk0[..], &a.sidecar[..PK_LEN], "position 0's signature does not recover the recorded first public key");
    assert_eq!(&s0.pub_seed[..], &a.sidecar[PK_LEN..PK_LEN + SEED_LEN], "position 0's public seed is not the recorded one");
    assert_eq!(
        &s0.adrs.le_image()[..20],
        &a.sidecar[PK_LEN + SEED_LEN..WOTS_ADDR_LEN - 12],
        "position 0's address words 0-4 are not the recorded image (5-7 are the tag overlay)"
    );
    assert_eq!(&s0.public_key[..], &pk0[..], "public_key released beside the signature (one degree of freedom -- a smoke line, not the anchor)");
    assert_eq!(hash_of_pk(&pk0), a.tag, "position 0's address is not implicit under the account tag");

    // -- a second signature at position 0 is unobtainable ---------------
    assert!(
        matches!(ks.persist_advance(&a.tag, &DIGEST_2, FIGURES), Err(Error::PendingUnresolved { spent_index: 0 })),
        "a second reservation while position 0 is reserved"
    );
    refusals += 1;
    let one = WotsIndex::ZERO.advanced().unwrap_or_else(|e| panic!("{e}"));
    assert!(matches!(ks.persist_advance_to(&a.tag, one), Err(Error::PendingUnresolved { .. })));
    refusals += 1;
    ks.persist_settled(&a.tag).unwrap_or_else(|e| panic!("{e}"));
    assert!(
        matches!(ks.persist_advance_to(&a.tag, WotsIndex::ZERO), Err(Error::Range { min: 2, got: 0, .. })),
        "position 0 reachable again after settle"
    );
    refusals += 1;
    assert!(matches!(ks.persist_advance_to(&a.tag, one), Err(Error::Range { min: 2, got: 1, .. })));
    refusals += 1;

    // -- position 1: the shipped wotsIndex 0 ------------------------------
    let r2 = ks.persist_advance(&a.tag, &DIGEST_2, FIGURES).unwrap_or_else(|e| panic!("{e}"));
    let s1 = ks
        .sign_spend(&DIGEST_2, r2, KeyAccess::Master(&a.master))
        .unwrap_or_else(|e| panic!("position 1: {e}"));
    assert_eq!(s1.spent_index, one);
    let pk1 = recover(&s1, &DIGEST_2);
    assert_eq!(hash_of_pk(&pk1), a.hash_at_1, "position 1's signature does not recover the recorded wotsIndex-0 address");
    assert_ne!(&pk1[..], &pk0[..], "positions 0 and 1 are one key");

    // -- the imported twin: the same account reached from the other side --
    //
    // The `.mcm` pair this account would have been exported as: its account
    // seed, and the RECORDED 2208-byte first address the sidecar carries.
    // Nothing is constructed -- both halves are group F's -- and importing
    // them reproduces the SAME tag, because the tag is the first key's hash
    // and the first key is what the pair names. So a derived account and its
    // import are one account, reached from two sides, in a second store.
    let dir2 = ScratchDir::new("i1-proof-imported");
    let mut ks2 = instrumented(&dir2);
    let faddress: [u8; WOTS_ADDR_LEN] = a
        .sidecar
        .as_slice()
        .try_into()
        .unwrap_or_else(|_| panic!("the sidecar is not {WOTS_ADDR_LEN} bytes"));
    let twin = Account::import(a.seed.duplicate(), &faddress).unwrap_or_else(|e| panic!("import: {e}"));
    assert_eq!(twin.tag(), a.tag, "the import of an account's own recorded pair is that account");
    ks2.add(twin).unwrap_or_else(|e| panic!("{e}"));
    // Position 0 signs from the STORED components since format v2. Without
    // them this arm can only refuse, and the funds an imported account was
    // imported holding -- which sit at exactly this address -- are then
    // unspendable.
    let r = ks2.persist_advance(&a.tag, &DIGEST, FIGURES).unwrap_or_else(|e| panic!("{e}"));
    let si0 = ks2
        .sign_spend(&DIGEST, r, KeyAccess::StoredRoot)
        .unwrap_or_else(|e| panic!("imported position 0: {e}"));
    assert_eq!(si0.spent_index, WotsIndex::ZERO);
    assert_eq!(
        &recover(&si0, &DIGEST)[..],
        &a.sidecar[..PK_LEN],
        "the imported first key is not the recorded first public key"
    );
    assert_eq!(
        &si0.signature[..],
        &s0.signature[..],
        "one key, one digest, two kinds: the derived and imported paths must sign identically"
    );
    ks2.persist_settled(&a.tag).unwrap_or_else(|e| panic!("{e}"));
    let r = ks2.persist_advance(&a.tag, &DIGEST_2, FIGURES).unwrap_or_else(|e| panic!("{e}"));
    let si = ks2
        .sign_spend(&DIGEST_2, r, KeyAccess::StoredRoot)
        .unwrap_or_else(|e| panic!("imported position 1: {e}"));
    assert_eq!(si.spent_index, one);
    assert_eq!(hash_of_pk(&recover(&si, &DIGEST_2)), a.hash_at_1, "the imported root's position 1 is not the recorded address");
    assert_eq!(
        &si.signature[..],
        &s1.signature[..],
        "one key, one digest, two paths: the signatures must be identical bytes (signing is deterministic)"
    );

    assert_eq!(refusals, 4);
    // Every integer here is a small count.
    println!(
        "  I1 one signature: 2 position(s) signed once each under a TypeScript-recorded address \
         (signer native, recovery via {RECOVERY}), {refusals} refusal(s) of a second receipt at a \
         spent position, 1 imported root at position 1 under the same recorded address, 0 medium \
         call(s) by sign_spend"
    );
}

/// A receipt minted and lost before signing -- the process died between
/// `persist_advance` and `sign_spend`. Modelled by type: a receipt is one
/// process's memory value, not `Clone`, not constructible after a restart
/// (`ui/fail/account_advance_receipt_is_not_constructible.rs`). After the
/// reopen the reservation is on disk, no receipt names it, none can be
/// minted for it, and the key at the reserved position is never signed:
/// settling skips it, and the next receipt signs position 1.
#[test]
fn a_receipt_lost_before_signing_leaves_its_key_unsignable_after_reopen() {
    let a = anchor();
    let dir = ScratchDir::new("i1-lost-receipt");
    let mut ks = Keystore::create(dir.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
    ks.add(Account::derive(&a.master, 0)).unwrap_or_else(|e| panic!("{e}"));
    let r = ks.persist_advance(&a.tag, &DIGEST, FIGURES).unwrap_or_else(|e| panic!("{e}"));
    drop(r);
    drop(ks);

    let mut ks = reopen("I1 lost receipt", dir.path())
        .result
        .unwrap_or_else(|e| panic!("reopen: {e}"));
    let view = ks.view(&a.tag).unwrap_or_else(|e| panic!("{e}")).unwrap_or_else(|| panic!("vanished"));
    let one = WotsIndex::ZERO.advanced().unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(view.wots_index, one, "the advance was durable");
    assert_eq!(
        view.pending,
        Some(Pending {
            spent_index: WotsIndex::ZERO,
            digest: DIGEST,
            figures: Some(FIGURES),
        }),
        "the reservation survived the restart"
    );
    assert!(matches!(ks.persist_advance(&a.tag, &DIGEST, FIGURES), Err(Error::PendingUnresolved { spent_index: 0 })));
    assert!(matches!(ks.persist_advance_to(&a.tag, one), Err(Error::PendingUnresolved { .. })));
    assert!(matches!(ks.persist_advance_to(&a.tag, WotsIndex::ZERO), Err(Error::PendingUnresolved { .. })));
    ks.persist_settled(&a.tag).unwrap_or_else(|e| panic!("{e}"));
    assert!(matches!(ks.persist_advance_to(&a.tag, one), Err(Error::Range { min: 2, .. })));
    let r2 = ks.persist_advance(&a.tag, &DIGEST, FIGURES).unwrap_or_else(|e| panic!("{e}"));
    let s = ks
        .sign_spend(&DIGEST, r2, KeyAccess::Master(&a.master))
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(s.spent_index, one, "the next signature is not at position 1");
    let pk = recover(&s, &DIGEST);
    assert_ne!(&pk[..], &a.sidecar[..PK_LEN], "position 0's recorded key was signed with after all");
    assert_eq!(hash_of_pk(&pk), a.hash_at_1);
}

// ---------------------------------------------------------------------------
// Refusals, one per check, each on an input where only that check can fail.
// (g) shadows (c)-(f) on an imported account at position 0, so
// those use a derived account or an imported one at position 1.
// ---------------------------------------------------------------------------

#[test]
fn refuses_a_receipt_minted_by_another_keystore() {
    let dir_a = ScratchDir::new("refuse-a-store-a");
    let dir_b = ScratchDir::new("refuse-a-store-b");
    let mut ks_a = instrumented(&dir_a);
    ks_a.add(imported_account()).unwrap_or_else(|e| panic!("{e}"));
    let mut ks_b = instrumented(&dir_b);
    ks_b.add(derived_account()).unwrap_or_else(|e| panic!("{e}"));
    let r = ks_a.persist_advance(&IMPORTED_TAG, &DIGEST, FIGURES).unwrap_or_else(|e| panic!("{e}"));
    let before = dir_b.snapshot_bytes();
    ks_b.medium_mut().reset_calls();
    assert!(matches!(ks_b.sign_spend(&DIGEST, r, KeyAccess::StoredRoot), Err(Error::NoSuchAccount)));
    assert_no_side_effect(&ks_b, &dir_b, &before, "(a)");
}

#[test]
fn refuses_a_receipt_the_store_has_moved_past() {
    let dir = ScratchDir::new("refuse-b");
    let mut ks = instrumented(&dir);
    ks.add(imported_account()).unwrap_or_else(|e| panic!("{e}"));
    let r1 = ks.persist_advance(&IMPORTED_TAG, &DIGEST, FIGURES).unwrap_or_else(|e| panic!("{e}"));
    ks.persist_settled(&IMPORTED_TAG).unwrap_or_else(|e| panic!("{e}"));
    let r2 = ks.persist_advance(&IMPORTED_TAG, &DIGEST, FIGURES).unwrap_or_else(|e| panic!("{e}"));
    let before = dir.snapshot_bytes();
    ks.medium_mut().reset_calls();
    assert!(matches!(
        ks.sign_spend(&DIGEST, r1, KeyAccess::StoredRoot),
        Err(Error::StaleReceipt { attested: 1, stored: 2 })
    ));
    assert_no_side_effect(&ks, &dir, &before, "(b)");
    // Control: the live receipt signs position 1.
    let s = ks.sign_spend(&DIGEST, r2, KeyAccess::StoredRoot).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(s.spent_index.get(), 1);
}

#[test]
fn refuses_a_reconciliation_receipt() {
    let dir = ScratchDir::new("refuse-c");
    let mut ks = instrumented(&dir);
    ks.add(derived_account()).unwrap_or_else(|e| panic!("{e}"));
    let one = WotsIndex::ZERO.advanced().unwrap_or_else(|e| panic!("{e}"));
    let r = ks.persist_advance_to(&DERIVED_TAG, one).unwrap_or_else(|e| panic!("{e}"));
    let master = Secret::new(DERIVED_MASTER);
    let before = dir.snapshot_bytes();
    ks.medium_mut().reset_calls();
    assert!(matches!(ks.sign_spend(&DIGEST, r, KeyAccess::Master(&master)), Err(Error::NoReservation)));
    assert_no_side_effect(&ks, &dir, &before, "(c)");
}

#[test]
fn refuses_a_digest_other_than_the_reserved_one() {
    let dir = ScratchDir::new("refuse-d");
    let mut ks = instrumented(&dir);
    ks.add(derived_account()).unwrap_or_else(|e| panic!("{e}"));
    let master = Secret::new(DERIVED_MASTER);
    let r = ks.persist_advance(&DERIVED_TAG, &DIGEST, FIGURES).unwrap_or_else(|e| panic!("{e}"));
    let before = dir.snapshot_bytes();
    ks.medium_mut().reset_calls();
    assert!(matches!(ks.sign_spend(&DIGEST_2, r, KeyAccess::Master(&master)), Err(Error::DigestMismatch)));
    assert_no_side_effect(&ks, &dir, &before, "(d)");
    // Second observable: the reserved key is skipped, not reused -- the next
    // receipt names position 2.
    ks.persist_settled(&DERIVED_TAG).unwrap_or_else(|e| panic!("{e}"));
    let r = ks.persist_advance(&DERIVED_TAG, &DIGEST_2, FIGURES).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(r.index().get(), 2);
}

#[test]
fn refuses_stored_root_access_on_a_derived_account() {
    let dir = ScratchDir::new("refuse-e");
    let mut ks = instrumented(&dir);
    ks.add(derived_account()).unwrap_or_else(|e| panic!("{e}"));
    let r = ks.persist_advance(&DERIVED_TAG, &DIGEST, FIGURES).unwrap_or_else(|e| panic!("{e}"));
    let before = dir.snapshot_bytes();
    ks.medium_mut().reset_calls();
    assert!(matches!(
        ks.sign_spend(&DIGEST, r, KeyAccess::StoredRoot),
        Err(Error::KeyAccessMismatch {
            kind: AccountKind::Derived
        })
    ));
    assert_no_side_effect(&ks, &dir, &before, "(e)");
}

#[test]
fn refuses_master_access_on_an_imported_account() {
    let dir = ScratchDir::new("refuse-e2");
    let mut ks = instrumented(&dir);
    ks.add(imported_account()).unwrap_or_else(|e| panic!("{e}"));
    // Position 1, so (g) cannot shadow this check.
    let _ = ks.persist_advance(&IMPORTED_TAG, &DIGEST, FIGURES).unwrap_or_else(|e| panic!("{e}"));
    ks.persist_settled(&IMPORTED_TAG).unwrap_or_else(|e| panic!("{e}"));
    let r = ks.persist_advance(&IMPORTED_TAG, &DIGEST, FIGURES).unwrap_or_else(|e| panic!("{e}"));
    let any = Secret::new([0x11u8; SEED_LEN]);
    let before = dir.snapshot_bytes();
    ks.medium_mut().reset_calls();
    assert!(matches!(
        ks.sign_spend(&DIGEST, r, KeyAccess::Master(&any)),
        Err(Error::KeyAccessMismatch {
            kind: AccountKind::Imported
        })
    ));
    assert_no_side_effect(&ks, &dir, &before, "(e')");
}

#[test]
fn refuses_a_master_that_does_not_derive_the_stored_tag() {
    let dir = ScratchDir::new("refuse-f");
    let mut ks = instrumented(&dir);
    ks.add(derived_account()).unwrap_or_else(|e| panic!("{e}"));
    let r = ks.persist_advance(&DERIVED_TAG, &DIGEST, FIGURES).unwrap_or_else(|e| panic!("{e}"));
    let wrong = Secret::new([0x5Au8; SEED_LEN]);
    let before = dir.snapshot_bytes();
    ks.medium_mut().reset_calls();
    assert!(matches!(
        ks.sign_spend(&DIGEST, r, KeyAccess::Master(&wrong)),
        Err(Error::DerivedTagNotReproduced {
            account_index: DERIVED_POSITION
        })
    ));
    assert_no_side_effect(&ks, &dir, &before, "(f)");
}

/// One key stream under two tags is refused at `add`, **in either order and
/// across kinds** — which is what the record's stream identity bought.
///
/// The signing path could only refuse the halves it could see without a format change,
/// and this pair was not one of them: `add` has no master seed, so it cannot
/// compare a derived account's key material to a stored imported root, and a
/// drop-and-reopen threw away the in-memory knowledge that would have. The
/// identity is the comparable public value; `duplicate_key_streams_are_refused_across_kinds_after_reopen`
/// is the same property through a real reopen, and this is the in-process
/// half with the refusal's side effects measured.
///
/// (f') in `sign_spend` — the derived seed found among the stored imported
/// roots — is **defensive** since this landed: no public-API sequence builds
/// a store holding both, so the arm is unreachable except from a hand-edited
/// snapshot. Said here because a test that appears to demonstrate it would be
/// claiming more than it can.
#[test]
fn add_refuses_one_key_stream_under_two_tags_in_either_order() {
    let master = Secret::new(DERIVED_MASTER);
    let seed = derive::derive_account(&master, DERIVED_POSITION).seed().duplicate();

    // imported first, then the derived account over the same seed
    let dir = ScratchDir::new("refuse-stream-a");
    let mut ks = instrumented(&dir);
    ks.add(keystore_harness::synthetic_imported_account(seed.duplicate(), 0x77))
        .unwrap_or_else(|e| panic!("{e}"));
    let before = dir.snapshot_bytes();
    ks.medium_mut().reset_calls();
    assert!(matches!(
        ks.add(derived_account()),
        Err(Error::Exists { what: "key stream" })
    ));
    assert_no_side_effect(&ks, &dir, &before, "add (derived over an imported stream)");

    // derived first, then the import of its seed under another tag
    let dir = ScratchDir::new("refuse-stream-b");
    let mut ks = instrumented(&dir);
    ks.add(derived_account()).unwrap_or_else(|e| panic!("{e}"));
    let before = dir.snapshot_bytes();
    ks.medium_mut().reset_calls();
    assert!(matches!(
        ks.add(keystore_harness::synthetic_imported_account(seed, 0x77)),
        Err(Error::Exists { what: "key stream" })
    ));
    assert_no_side_effect(&ks, &dir, &before, "add (imported over a derived stream)");

    // Control: an unrelated seed under the same shape is accepted, so the
    // two reds above are the identity comparison and not `add` refusing
    // everything that looks like this.
    ks.add(keystore_harness::synthetic_imported_account(
        Secret::new([0x2Cu8; SEED_LEN]),
        0x77,
    ))
    .unwrap_or_else(|e| panic!("an unrelated stream must be accepted: {e}"));
}

#[test]
fn add_refuses_a_second_account_over_one_imported_root() {
    let dir = ScratchDir::new("refuse-add");
    let mut ks = instrumented(&dir);
    ks.add(imported_account()).unwrap_or_else(|e| panic!("{e}"));
    let before = dir.snapshot_bytes();
    ks.medium_mut().reset_calls();
    // The same root under a first address built from other components: a
    // valid pair, another tag, one key stream. The root dedupe runs first and
    // names the key material rather than the value derived from it.
    assert!(matches!(
        ks.add(keystore_harness::aliased_imported_account()),
        Err(Error::Exists { what: "imported root" })
    ));
    assert_no_side_effect(&ks, &dir, &before, "add");
    // Control: a different root is accepted, so the red above is the dedupe.
    ks.add(keystore_harness::synthetic_imported_account(
        Secret::new([0x2Cu8; SEED_LEN]),
        0x2B,
    ))
    .unwrap_or_else(|e| panic!("{e}"));
}

/// (g), inverted by format v2. An imported account at position 0 signs from
/// the components the record carries, and the key it signs with is the one
/// the stored first address names.
///
/// A refusal here is correct only while the components are not stored, since
/// a substitute would sign under an address nobody funded. The record carries
/// them, so refusing is not a property to preserve.
#[test]
fn an_imported_account_signs_position_zero_from_the_stored_components() {
    let dir = ScratchDir::new("import-position-zero");
    let mut ks = instrumented(&dir);
    ks.add(imported_account()).unwrap_or_else(|e| panic!("{e}"));
    let r = ks.persist_advance(&IMPORTED_TAG, &DIGEST, FIGURES).unwrap_or_else(|e| panic!("{e}"));
    let before = dir.snapshot_bytes();
    ks.medium_mut().reset_calls();
    let sig = ks
        .sign_spend(&DIGEST, r, KeyAccess::StoredRoot)
        .unwrap_or_else(|e| panic!("position 0 of an imported account: {e}"));
    assert_eq!(sig.spent_index, WotsIndex::ZERO);
    // The recovered key is the recorded first address's, byte for byte, and
    // its address hash is the account tag -- the first key's address is
    // implicit, which is what makes the tag checkable at all.
    assert_eq!(
        &recover(&sig, &DIGEST)[..],
        &keystore_harness::IMPORTED_FIRST_ADDRESS[..PK_LEN],
        "position 0 did not sign with the stored first key"
    );
    assert_eq!(hash_of_pk(&recover(&sig, &DIGEST)), IMPORTED_TAG);
    // Signing still persists nothing.
    assert!(ks.medium().calls().is_empty(), "sign_spend touched the medium");
    assert_eq!(dir.snapshot_bytes(), before, "sign_spend changed the snapshot");
}

/// The reopen case the key-stream marker names: a derived account spends,
/// its seed is imported under **another tag**, the store is dropped and
/// reopened, and both kinds refuse the duplicate stream.
///
/// # What makes this the half the signing path could not close
///
/// `Keystore::add` has no master seed. Before the record carried a stream
/// identity, the only comparable thing a reopened store held for a derived
/// account was its `account_index` — meaningless without the master — so an
/// import of that account's seed under a different tag walked in, took an
/// independent index, and signed rotations the derived slot had already
/// signed. Nothing computed a wrong answer and nothing went red. The identity
/// is the value both kinds can produce and a record can carry.
///
/// # What it still cannot see
///
/// The same stream in two *stores* — a copied directory, a seed re-derived
/// into a fresh keystore. That is I4's and I5's, and the identity this landed
/// is what a divergence report will compare.
#[test]
fn duplicate_key_streams_are_refused_across_kinds_after_reopen() {
    let mut kinds = 0usize;

    // (1) derived first: spend from it, drop, reopen, then import its seed.
    let dir = ScratchDir::new("stream-derived-then-imported");
    let master = Secret::new(DERIVED_MASTER);
    let seed = derive::derive_account(&master, DERIVED_POSITION).seed().duplicate();
    {
        let mut ks = Keystore::create(dir.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
        ks.add(derived_account()).unwrap_or_else(|e| panic!("{e}"));
        let r = ks.persist_advance(&DERIVED_TAG, &DIGEST, FIGURES).unwrap_or_else(|e| panic!("{e}"));
        let sig = ks
            .sign_spend(&DIGEST, r, KeyAccess::Master(&master))
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(sig.spent_index, WotsIndex::ZERO);
        ks.persist_settled(&DERIVED_TAG).unwrap_or_else(|e| panic!("{e}"));
    }
    let mut ks = keystore_harness::reopen("I1 stream identity (derived first)", dir.path())
        .result
        .unwrap_or_else(|e| panic!("reopen: {e}"));
    let alias = keystore_harness::synthetic_imported_account(seed.duplicate(), 0xA1);
    assert_ne!(alias.tag(), DERIVED_TAG, "the alias must arrive under another tag");
    assert!(
        matches!(ks.add(alias), Err(Error::Exists { what: "key stream" })),
        "an import of a spent derived account's seed was accepted after a reopen"
    );
    kinds += 1;

    // (2) imported first: the mirror, so neither ordering is the one that
    // happens to work.
    let dir = ScratchDir::new("stream-imported-then-derived");
    {
        let mut ks = Keystore::create(dir.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
        ks.add(keystore_harness::synthetic_imported_account(seed, 0xA2))
            .unwrap_or_else(|e| panic!("{e}"));
    }
    let mut ks = keystore_harness::reopen("I1 stream identity (imported first)", dir.path())
        .result
        .unwrap_or_else(|e| panic!("reopen: {e}"));
    assert!(
        matches!(ks.add(derived_account()), Err(Error::Exists { what: "key stream" })),
        "a derived account over a stored imported stream was accepted after a reopen"
    );
    kinds += 1;

    // Control: after a reopen an UNRELATED stream is still accepted, so the
    // two refusals above are the identity comparison rather than a store
    // that refuses every `add` it did not make itself.
    ks.add(imported_account())
        .unwrap_or_else(|e| panic!("an unrelated stream must be accepted after a reopen: {e}"));

    assert_eq!(kinds, 2, "both kinds must be driven");
    // Every integer on this line is a count of kinds.
    println!(
        "  I1 stream identity: {kinds} kind(s) refused across a reopen, 1 unrelated stream \
         still accepted"
    );
}

/// `check_spend` runs the same checks on a borrowed receipt: a wrong
/// passphrase costs nothing, and a passing check means the same `sign_spend`
/// on this handle will sign.
#[test]
fn check_spend_passes_exactly_when_sign_spend_would_and_keeps_the_receipt() {
    let dir = ScratchDir::new("check-spend");
    let mut ks = Keystore::create(dir.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
    ks.add(derived_account()).unwrap_or_else(|e| panic!("{e}"));
    let master = Secret::new(DERIVED_MASTER);
    let wrong = Secret::new([0x5Au8; SEED_LEN]);
    let r = ks.persist_advance(&DERIVED_TAG, &DIGEST, FIGURES).unwrap_or_else(|e| panic!("{e}"));
    assert!(matches!(
        ks.check_spend(&DIGEST, &r, &KeyAccess::Master(&wrong)),
        Err(Error::DerivedTagNotReproduced { .. })
    ));
    assert!(matches!(ks.check_spend(&DIGEST_2, &r, &KeyAccess::Master(&master)), Err(Error::DigestMismatch)));
    ks.check_spend(&DIGEST, &r, &KeyAccess::Master(&master)).unwrap_or_else(|e| panic!("{e}"));
    // The receipt is still ours: the checked call signs.
    let s = ks.sign_spend(&DIGEST, r, KeyAccess::Master(&master)).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(s.spent_index, WotsIndex::ZERO);
}

/// `KeyAccess` holds a reference to a `Secret`, so its `Debug` is hand-written
/// and redacts (`no_holder_of_key_material_derives_debug` finds the holder;
/// this pins the rendering). `SpendSignature` prints a position and an
/// address hash, not 4,320 bytes.
#[test]
fn key_access_debug_redacts_the_master_and_spend_signature_prints_the_address() {
    let master = Secret::new([0xAB; SEED_LEN]);
    let rendered = format!("{:?}", KeyAccess::Master(&master));
    assert_eq!(rendered, "Master(<redacted>)");
    assert!(!rendered.contains("ab"), "{rendered}");
    assert_eq!(format!("{:?}", KeyAccess::StoredRoot), "StoredRoot");

    let a = anchor();
    let dir = ScratchDir::new("debug-spend");
    let mut ks = Keystore::create(dir.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
    ks.add(Account::derive(&a.master, 0)).unwrap_or_else(|e| panic!("{e}"));
    let r = ks.persist_advance(&a.tag, &DIGEST, FIGURES).unwrap_or_else(|e| panic!("{e}"));
    let s = ks.sign_spend(&DIGEST, r, KeyAccess::Master(&a.master)).unwrap_or_else(|e| panic!("{e}"));
    let rendered = format!("{s:?}");
    let tag_hex: String = a.tag.iter().map(|b| format!("{b:02x}")).collect();
    assert!(rendered.starts_with("SpendSignature { spent_index: WotsIndex(0), address_hash: \""), "{rendered}");
    assert!(rendered.contains(&tag_hex), "position 0's address hash is the account tag: {rendered}");
    assert!(rendered.len() < 200, "SpendSignature's Debug is not a summary: {} chars", rendered.len());
}

// ---------------------------------------------------------------------------
// The downstream probe: the wallet build, checked for real.
// ---------------------------------------------------------------------------

/// The raw signer is unreachable from a dependent built WITHOUT `raw-backend`
/// -- the wallet's build. trybuild cannot see this: it reads the test build's
/// features out of cargo's fingerprint and enables them in its project, so a
/// `ui/fail` case naming `backend::native::wots_sign` would compile there.
/// This test `cargo check`s a real dependent, `ui/downstream`, with the
/// crate's default features: `pass` (a legitimate `sign_spend`) must compile,
/// and `fail` (both spellings of the raw signer, and the test tree's
/// `SpendAddresses::unverified`, which is under `raw-backend` too)
/// must be refused with exactly three errors: two E0603 for the signer and
/// one E0599 naming `unverified` -- exactly three, so a typo turning one of
/// them into another error is red rather than an accepted failure. The
/// constructor's case lives here and not under `ui/fail` for the reason
/// the raw signer's does: trybuild inherits `raw-backend`, and a `ui/fail`
/// case naming `unverified` compiles there.
///
/// Gated on `not(miri)` because it spawns cargo, which Miri cannot.
///
/// Cost, stated: the first run builds the crate with its default features
/// into `target/tests/downstream`, cached afterwards; the census child
/// re-runs it under cargo's lock. Its `Cargo.lock` is the workspace's, copied
/// in (cargo appends the probe's own entry, which is why it is not committed).
#[cfg(not(miri))]
#[test]
fn raw_signer_is_unreachable_from_a_default_features_dependent() {
    use std::process::Command;
    let root = repo_root();
    let probe = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("ui/downstream");
    let manifest = probe.join("Cargo.toml");
    assert!(manifest.is_file(), "the probe crate is missing at {}", manifest.display());
    std::fs::copy(root.join("Cargo.lock"), probe.join("Cargo.lock")).unwrap_or_else(|e| panic!("copy Cargo.lock: {e}"));
    let target = root.join("target/tests/downstream");
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());

    let check = |bin: &str| {
        let out = Command::new(&cargo)
            .args(["check", "--offline", "--manifest-path"])
            .arg(&manifest)
            .arg("--target-dir")
            .arg(&target)
            .args(["--bin", bin])
            .output()
            .unwrap_or_else(|e| panic!("could not run cargo check on the probe: {e}"));
        (out.status.success(), String::from_utf8_lossy(&out.stderr).into_owned())
    };

    let (pass_ok, pass_err) = check("pass");
    assert!(pass_ok, "the probe's legitimate signing path did not compile:\n{pass_err}");

    let (fail_ok, fail_err) = check("fail");
    assert!(!fail_ok, "the probe's raw-signer spellings COMPILED in a default-features dependent:\n{fail_err}");
    let errors: Vec<&str> = fail_err.lines().filter(|l| l.starts_with("error[")).collect();
    assert_eq!(
        errors.len(),
        3,
        "expected exactly three compiler errors (one per raw-signer spelling, one for the \
         unverified constructor), got {}:\n{fail_err}",
        errors.len()
    );
    assert_eq!(
        errors.iter().filter(|l| l.starts_with("error[E0603]")).count(),
        2,
        "expected two E0603 (privacy) errors for the raw signer:\n{fail_err}"
    );
    assert!(
        errors.iter().any(|l| l.starts_with("error[E0599]") && l.contains("unverified")),
        "no E0599 names `SpendAddresses::unverified`, so a default-features dependent can build \
         spend addresses that came out of no keystore:\n{fail_err}"
    );
    // Needles copied from the compiler's own output on the first run, never
    // typed from memory.
    assert!(
        errors.iter().any(|l| l.contains("module `backend` is private")),
        "no E0603 names the backend module:\n{fail_err}"
    );
    assert!(
        errors.iter().any(|l| l.contains("function `sign` is private")),
        "no E0603 names wots::sign:\n{fail_err}"
    );
    println!(
        "  downstream probe: 2 raw-signer spellings refused by E0603 and the unverified \
         spend-addresses constructor by E0599 in a default-features dependent ({} errors), 1 \
         pass target compiled",
        errors.len()
    );
}
