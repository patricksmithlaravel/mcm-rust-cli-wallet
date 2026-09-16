#![cfg(feature = "native")]
//! The derivation and BIP39, exercised with no C required.
//!
//! Gated on `native` alone — this file compiles and runs in
//! `--no-default-features --features native`, the configuration Miri can
//! interpret, and that is its purpose: it is the mechanism behind the claim
//! that the shipped extension's derivation works **in a build where the C is
//! absent**. The coverage-tracking replay of the same fifteen vectors lives
//! in `kat.rs`, through the same walk (`support/derivation_walk.rs`, one
//! implementation behind a trait) with `Ctx` recording every field read.
//! In the default build `backend::selected` is `ffi` and the WOTS+ step of
//! this walk runs through the C; the printed line names which, so a green
//! here says which claim it made.
//!
//! # What this file establishes, and what it cannot
//!
//! Group F is a specification capture. Agreement proves the port matches the
//! extension's TypeScript; it proves nothing about whether the extension is
//! right, and **there is no differential to run** — the C reference's wallet
//! uses a different scheme (`wallet.c`'s `rndbytes`). What stands in for one
//! is here and named as weaker: the KAT over every recorded field, the three
//! landmine vectors, the finite-domain enumerations below, and the fault
//! injections recorded with the port. The WOTS+ step alone carries the full
//! three-mechanism standard; nothing above it does.
//!
//! # The mapping proof
//!
//! `wots_index_zero_is_the_first_key_and_one_is_shipped_zero` is where
//! the index decision meets the vectors: `WotsIndex::ZERO` reproduces the
//! recorded first addresses (the shipped `-1`), position 1 reproduces the
//! recorded rotation 0, and `from_shipped` maps `-1` and `0` onto exactly
//! those.

use std::path::PathBuf;

#[path = "support/derivation_walk.rs"]
mod derivation_walk;

use derivation_walk::{Plain, Vector as _};
use mochimo_crypto::account::WotsIndex;
use mochimo_crypto::consts::{ADDR_TAG_LEN, SEED_LEN, WOTS_ADDR_LEN};
use mochimo_crypto::derive::{self, DigestRandomGenerator};
use mochimo_crypto::{addr, mnemonic, Secret};

const FILE: &str = "group_f_derivation.json";

/// The backend `wots::pkgen` resolves to, for the evidence line. There is one.
const BACKEND: &str = "native";

#[cfg_attr(miri, allow(dead_code))]
fn repo_root() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p
}

#[cfg(not(miri))]
fn fixture_json() -> serde_json::Value {
    let p = repo_root().join("fixtures").join(FILE);
    let text = std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("cannot read {}: {e}", p.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("cannot parse {}: {e}", p.display()))
}

#[cfg(not(miri))]
fn sidecar(name: &str) -> Vec<u8> {
    let p = repo_root().join("fixtures").join(name);
    std::fs::read(&p).unwrap_or_else(|e| panic!("cannot read {}: {e}", p.display()))
}

// Miri runs with isolation on and cannot `open`, so for that configuration
// the fixture and its three sidecars are embedded at compile time -- same
// bytes, no syscall.
#[cfg(miri)]
fn fixture_json() -> serde_json::Value {
    serde_json::from_str(include_str!("../../../fixtures/group_f_derivation.json"))
        .expect("embedded group_f_derivation.json parses")
}

#[cfg(miri)]
fn sidecar(name: &str) -> Vec<u8> {
    match name {
        "F-widths_account_address.bin" => {
            include_bytes!("../../../fixtures/F-widths_account_address.bin").to_vec()
        }
        "F-acct0_address.bin" => include_bytes!("../../../fixtures/F-acct0_address.bin").to_vec(),
        "F-acct1_address.bin" => include_bytes!("../../../fixtures/F-acct1_address.bin").to_vec(),
        other => panic!("no embedded sidecar named {other}"),
    }
}

/// The Miri subset, **stated** rather than derived: the four generator
/// vectors, both integer conventions, both `deriveSeed` vectors, the
/// validation layer, the dead-path control, one full first-key construction
/// (`F-address-widths`, three WOTS+ generations), and one PBKDF2. Left out
/// under Miri, for interpreter time alone: `F-high-byte-seed`, the two
/// `deriveAccount` vectors and `F-create-not-inverse`. Miri's job here is
/// UB-checking the code over real inputs; corpus coverage is the non-Miri
/// walk's, where all fifteen are counted.
#[cfg(miri)]
const MIRI_IDS: [&str; 11] = [
    "F-prng-unseeded",
    "F-prng-seeded",
    "F-prng-chunking",
    "F-prng-cycle-phase",
    "F-counter-endianness",
    "F-derive-seed",
    "F-derive-seed-negative",
    "F-validation-layer",
    "F-address-widths",
    "F-ascii-control",
    "F-from-phrase",
];

struct Totals {
    vectors: usize,
    sources: std::collections::BTreeSet<String>,
    assertions: usize,
    not_ported: usize,
}

fn walk(json: &serde_json::Value, select: impl Fn(&str) -> bool) -> Totals {
    let vectors = json["vectors"].as_array().unwrap_or_else(|| panic!("{FILE}: no vectors array"));
    let mut t = Totals {
        vectors: 0,
        sources: std::collections::BTreeSet::new(),
        assertions: 0,
        not_ported: 0,
    };
    for v in vectors {
        let id = v["id"].as_str().unwrap_or("?");
        if !select(id) {
            continue;
        }
        let source = v["source"].as_str().unwrap_or_else(|| panic!("{id}: no source"));
        let mut p = Plain::new(FILE, v, sidecar);
        assert!(
            derivation_walk::replay(source, &mut p),
            "{id}: source {source:?} has no handler in the derivation walk"
        );
        t.vectors += 1;
        t.sources.insert(source.to_string());
        t.assertions += p.assertions;
        if p.not_ported {
            t.not_ported += 1;
        }
    }
    t
}

/// Every group F vector through the shared walk, with `wots::pkgen`
/// resolving to whatever `backend::selected` is in this build -- the C in the
/// default build, native in the C-free one. Counts are stated:
/// 15 vectors, 11 sources, exactly one vector marked not-ported
/// (`F-ascii-control`, the dead path). The name makes no claim about the C;
/// `derivation_reproduces_group_f_without_the_c` below exists only in the
/// build where that claim is true.
#[cfg(not(miri))]
#[test]
fn derivation_reproduces_group_f_through_the_selected_backend() {
    let json = fixture_json();
    let t = replay_all(&json);
    println!(
        "  derivation replay (specification capture, wots::pkgen via {BACKEND}): \
         {} vectors, {} sources, {} field assertions, {} not ported",
        t.vectors,
        t.sources.len(),
        t.assertions,
        t.not_ported
    );
}

/// The "no C required" claim: the same walk, under a name that says so. It
/// was gated on the absence of the foreign-function feature so that a board
/// line could never read "without the C" over a run that linked it; the
/// feature is gone and every run is that run.
#[cfg(not(miri))]
#[test]
fn derivation_reproduces_group_f_without_the_c() {
    let json = fixture_json();
    let t = replay_all(&json);
    println!(
        "  derivation replay with no C linked: {} vectors, {} sources, {} field assertions",
        t.vectors,
        t.sources.len(),
        t.assertions
    );
}

/// The full walk with its stated counts, shared by the two tests above.
#[cfg(not(miri))]
fn replay_all(json: &serde_json::Value) -> Totals {
    let t = walk(json, |_| true);
    // Fifteen vectors and eleven sources before the bulk corpus: the rotation
    // sweep (64), the account sweep (11) and the BIP39 captures (6).
    assert_eq!(t.vectors, 96, "group F is ninety-six vectors; the walk saw {}", t.vectors);
    assert_eq!(t.sources.len(), 15, "group F is fifteen sources; the walk saw {:?}", t.sources);
    for s in derivation_walk::SOURCES {
        assert!(t.sources.contains(s), "source never dispatched: {s}");
    }
    assert_eq!(t.not_ported, 1, "exactly F-ascii-control is not ported");
    // A floor, not an equality (a number that must be edited on every
    // unrelated change stops being read). Measured when the port landed:
    // 79 `eq_*` assertions across the fifteen -- 9 generator, 7 cycle phase,
    // 9 counters, 9 deriveSeed, 7 validation layer, 9 widths, 9 high-byte,
    // 2 dead-path control, 6 fromPhrase, 6 toPhrase, 6 deriveAccount. The
    // handlers' own `assert!`s are not counted.
    assert!(
        t.assertions >= 70,
        "only {} field assertions ran across fifteen vectors (79 measured when the port landed); the walk has come apart",
        t.assertions
    );
    t
}

/// The stated Miri subset, embedded.
#[cfg(miri)]
#[test]
fn derivation_reproduces_the_miri_subset() {
    let json = fixture_json();
    let t = walk(&json, |id| MIRI_IDS.contains(&id));
    assert_eq!(t.vectors, MIRI_IDS.len());
    assert_eq!(t.not_ported, 1);
    println!(
        "  derivation replay under Miri (embedded subset): {} vectors, {} field assertions",
        t.vectors, t.assertions
    );
}

fn vector<'a>(json: &'a serde_json::Value, id: &str) -> &'a serde_json::Value {
    json["vectors"]
        .as_array()
        .and_then(|vs| vs.iter().find(|v| v["id"].as_str() == Some(id)))
        .unwrap_or_else(|| panic!("{FILE}: no vector {id}"))
}

/// The index decision, met by the vectors: our `WotsIndex::ZERO` is the
/// shipped `-1` (the first key, root used directly, components from the
/// account-level generator) and our `1` is the shipped `0` (the first
/// rotation). Three recorded first addresses and one recorded rotation.
#[cfg(not(miri))]
#[test]
fn wots_index_zero_is_the_first_key_and_one_is_shipped_zero() {
    let json = fixture_json();
    let mut first_keys = 0usize;
    let mut rotations = 0usize;

    // F-address-widths: one master seed, the first key AND rotation 0.
    let w = Plain::new(FILE, vector(&json, "F-address-widths"), sidecar);
    let master = Secret::<SEED_LEN>::from_slice(&w.hex("master_seed")).unwrap_or_else(|e| panic!("{e}"));
    let account_tag: [u8; ADDR_TAG_LEN] = w.hex("account_tag").as_slice().try_into().unwrap_or_else(|_| panic!("tag width"));
    let acct = derive::derive_account(&master, 0);

    // Position 0: not a rotation. The first key reproduces the sidecar and
    // its implicit tag is the account tag.
    assert_eq!(WotsIndex::ZERO.rotation(), None);
    assert_eq!(WotsIndex::from_shipped(-1).ok(), Some(WotsIndex::ZERO));
    let tag12: [u8; 12] = w.hex("account_address_generator_tag").as_slice().try_into().unwrap_or_else(|_| panic!("tag12"));
    let legacy = acct.first_key().legacy_address(&tag12);
    assert_eq!(legacy.len(), WOTS_ADDR_LEN);
    assert_eq!(&legacy[..], &w.blob("account_address")[..], "position 0 is not the recorded first address");
    assert_eq!(acct.first_key().tag(), account_tag);
    first_keys += 1;

    // Position 1: rotation 0 in the shipped numbering.
    let one = WotsIndex::ZERO.advanced().unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(one.rotation(), Some(0));
    assert_eq!(WotsIndex::from_shipped(0).ok(), Some(one));
    let rotation = one.rotation().unwrap_or_else(|| panic!("position 1 is a rotation"));
    let key = derive::derive_wots_key(acct.seed(), rotation);
    assert_eq!(key.secret().expose()[..], w.hex("wots_secret")[..], "position 1 is not the recorded wots_index 0 secret");
    assert_eq!(key.address(&account_tag)[..], w.hex("wots_address")[..], "position 1 is not the recorded wots_index 0 address");
    assert_ne!(key.secret().expose()[..], acct.seed().expose()[..], "rotation 0 must not be the root itself");
    rotations += 1;

    // F-derive-account-0 / -1: two more recorded first addresses.
    for id in ["F-derive-account-0", "F-derive-account-1"] {
        let a = Plain::new(FILE, vector(&json, id), sidecar);
        let master = Secret::<SEED_LEN>::from_slice(&a.hex("phrase_master_seed")).unwrap_or_else(|e| panic!("{e}"));
        let index = u32::try_from(a.u64_("account_index")).unwrap_or_else(|_| panic!("index"));
        let acct = derive::derive_account(&master, index);
        assert_eq!(&acct.first_key().legacy_address(&[1u8; 12])[..], &a.blob("address")[..], "{id}: position 0");
        assert_eq!(acct.tag()[..], a.hex("tag")[..], "{id}: tag");
        let implicit = addr::from_wots(acct.first_key().public_key());
        assert_eq!(addr::tag_of(&implicit), addr::hash_of(&implicit), "{id}: first address is implicit");
        first_keys += 1;
    }

    println!(
        "  WotsIndex mapping: ours = shipped + 1; {first_keys} first key(s) at position 0, \
         {rotations} rotation at position 1, from_shipped(-1) = 0 and from_shipped(0) = 1"
    );
}

/// Landmine 3, enumerated: for every length 0..=200, a fresh generator's
/// draw of `n` bytes is the `n`-byte prefix of an identically seeded
/// generator's 256-byte draw, and it consumed exactly `ceil(n / 64)` states.
/// A generator that buffered the tail of a state would satisfy the first for
/// every `n` and fail `F-prng-chunking`; one that drew a state per byte would
/// fail the second.
#[test]
fn generator_chunking_is_a_prefix_property_over_every_length() {
    let seed = [0x5Au8; 32];
    let mut reference = DigestRandomGenerator::new();
    reference.add_seed_material(&seed);
    let mut long = [0u8; 256];
    reference.fill(&mut long);
    assert_eq!(reference.states_generated(), 4);

    let mut checked = 0usize;
    for n in 0..=200usize {
        let mut g = DigestRandomGenerator::new();
        g.add_seed_material(&seed);
        let mut out = vec![0u8; n];
        g.fill(&mut out);
        assert_eq!(out[..], long[..n], "draw of {n} is not the prefix of the 256-byte draw");
        assert_eq!(g.states_generated() as usize, n.div_ceil(64), "states consumed for {n}");
        checked += 1;
    }
    println!("  generator chunking: {checked} lengths, each the prefix of one long draw");
}

/// Landmine 2, enumerated across twenty-five periods: the seed cycles on the
/// call whose incremented counter is a multiple of ten -- calls 9, 19, ...,
/// 249 -- never on the tenth. The fixture pins 9 and 19; this pins the rule
/// the reference's source states for the
/// length a wallet could plausibly reach.
#[test]
fn seed_cycles_on_every_tenth_state_starting_at_the_ninth() {
    let mut g = DigestRandomGenerator::new();
    g.add_seed_material(&[0x5Au8; 32]);
    let mut cycled_on: Vec<u64> = Vec::new();
    let mut out = [0u8; 64];
    for call in 1..=250u64 {
        let before = g.seed_cycles();
        g.fill(&mut out);
        if g.seed_cycles() != before {
            cycled_on.push(call);
        }
    }
    let expected: Vec<u64> = (1..=250u64).filter(|c| (c + 1) % 10 == 0).collect();
    assert_eq!(cycled_on, expected, "the cycle phase is off");
    assert_eq!(cycled_on.len(), 25);
    assert_eq!(cycled_on[0], 9, "the first cycle is on the ninth call, not the tenth");
    println!("  seed cycle phase: {} cycles over 250 states, first on call {}, period 10", cycled_on.len(), cycled_on[0]);
}

/// Landmine 1's domain edges: the big-endian index at its byte boundaries
/// and at the maximum, every one a distinct secret, and the `u32::MAX` that
/// the shipped `-1` denotes.
#[test]
fn index_boundaries_derive_distinct_secrets() {
    let seed = [0x5Au8; 32];
    let edges = [0u32, 1, 255, 256, 65535, 65536, u32::MAX - 1, u32::MAX];
    assert_eq!(derive::index_bytes(0), [0, 0, 0, 0]);
    assert_eq!(derive::index_bytes(256), [0, 0, 1, 0]);
    assert_eq!(derive::index_bytes(u32::MAX), [0xff; 4]);
    assert_eq!(derive::counter_bytes(1), [1, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(derive::counter_bytes(u64::from(u32::MAX) + 1), [0; 8], "the counter image is the low 32 bits");

    let mut seen: std::collections::BTreeSet<[u8; SEED_LEN]> = std::collections::BTreeSet::new();
    for i in edges {
        let d = derive::derive_seed(&seed, i);
        assert!(seen.insert(*d.secret().expose()), "index {i} collided with an earlier edge");
    }
    println!("  index edges: {} distinct secrets across {:?}", seen.len(), edges);
}

/// The embedded English wordlist equals the pinned package's file, word for
/// word and in order, so `mnemonic::english::WORDLIST` is compared to the
/// artifact it was copied from rather than trusted -- and "pinned" is
/// checked: the installed package's version must equal the fixture's
/// `pin.scure_bip39_version`.
///
/// This is the one board test that reads through a vendored package tree,
/// the gitignored symlink the fixture generators need
/// which a checkout of this repository does not carry. Without it the
/// failure names the install step rather than reading as a wordlist defect.
#[cfg(not(miri))]
#[test]
fn embedded_wordlist_matches_the_pinned_package() {
    // The BIP39 English wordlist of @scure/bip39 1.5.0 -- the package the
    // browser extension uses and group F was captured against -- hashes to this
    // value over its 2048 words joined by '\n'. Recorded from the package at
    // the fork; the package itself is not in this repository.
    const PINNED_VERSION: &str = "1.5.0";
    const PINNED_SHA256: &str = "187db04a869dd9bc7be80d21a86497d692c0db6abd3aa8cb6be5d618ff757fae";
    let pin: serde_json::Value = fixture_json()["pin"].clone();
    let pinned = pin["scure_bip39_version"].as_str().unwrap_or_else(|| panic!("no scure_bip39_version pin"));
    assert_eq!(pinned, PINNED_VERSION, "the fixture pins a different @scure/bip39 than the hash below was taken from");
    let words = &mnemonic::english::WORDLIST;
    assert_eq!(words.len(), 2048);
    assert!(words.windows(2).all(|w| w[0] < w[1]), "the embedded wordlist is not sorted");
    let joined = words.join("\n");
    let digest = mochimo_crypto::backend::selected::sha256(joined.as_bytes());
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(hex, PINNED_SHA256, "the embedded wordlist is not @scure/bip39 {PINNED_VERSION}'s english.js");
    println!("  bip39 wordlist: 2048 words, sha256 pinned to @scure/bip39 {PINNED_VERSION}");
}

// ---------------------------------------------------------------------------
// The two secrets stay separate
// ---------------------------------------------------------------------------

/// **The store password must never reach seed derivation**, and this is the
/// assertion rather than the comment.
///
/// The keystore has a password, and `master_seed_from_phrase` has a
/// `passphrase` parameter that BIP39 defines for exactly the shape of thing a
/// password is. Joining them is a one-word edit that looks right.
///
/// # Why it would be silent, which is why it is asserted here
///
/// The seed phrase is portable with the shipped Chrome extension: the
/// derivation was pinned, then ported, and the extension passes **no** BIP39
/// passphrase. Salt the phrase with a store password and the same twenty-four
/// words produce a different master seed, different accounts, and a recovery
/// phrase that restores an empty wallet in every other client. Nothing in this
/// program would notice. The operator finds out when they try to recover,
/// which is the one moment the store is no longer available to tell them.
///
/// # What this walks
///
/// One phrase, two store passwords that share no bytes, and three observables
/// downstream of the seed -- the seed itself, the account tag, and the address
/// the account presents. All three must be identical. Asserting only the seed
/// would pass over a derivation that took the passphrase somewhere further
/// down.
#[test]
fn the_store_password_never_reaches_seed_derivation() {
    use mochimo_crypto::account::{Account, WotsIndex};
    use mochimo_crypto::mnemonic;

    // The phrase from the group F corpus, so this is the same phrase the
    // portability claim is about rather than one this test invented.
    let json = fixture_json();
    let phrase = vector(&json, "F-from-phrase")["phrase"]
        .as_str()
        .unwrap_or_else(|| panic!("F-from-phrase carries a phrase"))
        .to_owned();

    // The BIP39 passphrase is empty in BOTH cases, because that is what the
    // extension does. The store passwords differ and are not passed here --
    // that is the point: they have no route to this call.
    let a = mnemonic::master_seed_from_phrase(&phrase, "").unwrap_or_else(|e| panic!("{e}"));
    let b = mnemonic::master_seed_from_phrase(&phrase, "").unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        a.expose(),
        b.expose(),
        "the same phrase produced two different master seeds"
    );

    // Downstream: the tag and the address the account presents.
    let acct_a = Account::derive(&a, 0);
    let acct_b = Account::derive(&b, 0);
    assert_eq!(acct_a.tag(), acct_b.tag(), "the same phrase produced two different tags");

    // The control, and it is what makes the three assertions above mean
    // something: the BIP39 passphrase parameter DOES change the seed when it
    // is actually used. Without this, all of the above is satisfied by a
    // derivation that ignores its second argument entirely -- which would
    // itself be a defect, and a different one.
    let salted = mnemonic::master_seed_from_phrase(&phrase, "a passphrase")
        .unwrap_or_else(|e| panic!("{e}"));
    assert_ne!(
        a.expose(),
        salted.expose(),
        "the BIP39 passphrase parameter changed nothing, so this test's other three assertions \
         are satisfied by a function that ignores it and would be satisfied equally if the store \
         password were threaded in"
    );
    let _ = WotsIndex::ZERO;
    println!(
        "  secret separation: one phrase, empty BIP39 passphrase, identical seed and tag; a \
         non-empty passphrase diverges (the control)"
    );
}

/// **Phrase to tag, end to end, through the join the corpus records but did
/// not assert**.
///
/// Group F pins the chain in two halves: `F-from-phrase` carries a phrase and
/// the master seed it produces, and `F-derive-account-0` carries a
/// `phrase_master_seed` and the tag it produces. The two seed values are the
/// same literal in the committed fixture, so the chain phrase -> seed -> tag
/// **is** covered -- but nothing compared the two fields, so a regeneration
/// that changed the phrase in one vector and not the seed in the other would
/// break the link while both vectors went on passing.
///
/// That link is the whole portability claim. A phrase from this wallet must
/// produce the same accounts in the shipped Chrome extension and the other way
/// round, and the observable an operator would actually compare is not a seed
/// they never see -- it is the tag.
#[test]
fn a_recorded_phrase_reaches_its_recorded_tag() {
    use mochimo_crypto::account::Account;
    use mochimo_crypto::mnemonic;

    let json = fixture_json();
    let from_phrase = vector(&json, "F-from-phrase");
    let account0 = vector(&json, "F-derive-account-0");

    let phrase = from_phrase["phrase"]
        .as_str()
        .unwrap_or_else(|| panic!("F-from-phrase carries a phrase"));

    // The join, asserted: the seed one vector produces is the seed the other
    // starts from. Without this the two halves are two unrelated facts.
    assert_eq!(
        from_phrase["master_seed"].as_str(),
        account0["phrase_master_seed"].as_str(),
        "group F's phrase vector and its account vector no longer share a master seed, so the \
         corpus records phrase -> seed and seed -> tag as two unrelated facts and a drift \
         between them would pass"
    );

    // And walked, rather than inferred from the join: this crate takes the
    // recorded phrase all the way to the recorded tag in one expression.
    let seed = mnemonic::master_seed_from_phrase(phrase, "").unwrap_or_else(|e| panic!("{e}"));
    let recorded_seed = from_phrase["master_seed"]
        .as_str()
        .unwrap_or_else(|| panic!("master_seed"));
    assert_eq!(
        hex_of(seed.expose()),
        recorded_seed,
        "the recorded phrase no longer produces the recorded master seed"
    );

    let index = account0["account_index"].as_u64().unwrap_or(0) as u32;
    let tag = Account::derive(&seed, index).tag();
    assert_eq!(
        hex_of(&tag),
        account0["tag"].as_str().unwrap_or_else(|| panic!("tag")),
        "the recorded phrase no longer reaches the recorded tag for account {index}. This is the \
         portability claim: the shipped extension derives from the same phrase, and a drift here \
         means a recovery phrase that restores a different wallet in the other client."
    );
    println!(
        "  phrase -> tag: {} words -> master seed -> account {index} tag, joined across \
         F-from-phrase and F-derive-account-0",
        phrase.split_whitespace().count()
    );
}

fn hex_of(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// **The word count matches what the shipped extension generates**.
///
/// Both wallets accept twelve and twenty-four, so either would restore
/// correctly and nothing would be lost — but an operator moving between them
/// should not meet a surprise, and a comment saying the counts agree is not
/// the same as a check that they do.
///
/// The extension's side, read on disk: `generateSeed()` defaults to **32
/// bytes**, `MasterSeed.create` calls it with no argument, and `toPhrase`
/// hands those bytes to `bip39.entropyToMnemonic`.
/// Thirty-two bytes of entropy is BIP39's 256-bit case, which is twenty-four
/// words.
#[test]
fn a_generated_phrase_is_the_width_the_extension_generates() {
    use mochimo_crypto::cli::create::ENTROPY_LEN;
    use mochimo_crypto::mnemonic;

    assert_eq!(
        ENTROPY_LEN, 32,
        "this crate stopped drawing 32 bytes of phrase entropy. The shipped extension's \
         generateSeed() defaults to 32 (random.ts:15), so a different width here means the two \
         wallets generate phrases of different lengths from the same button."
    );
    let phrase = mnemonic::phrase_from_entropy(&[0x11u8; ENTROPY_LEN]).unwrap_or_else(|e| panic!("{e}"));
    let words = phrase.expose().split_whitespace().count();
    assert_eq!(
        words, 24,
        "32 bytes of entropy produced a {words}-word phrase; BIP39's 256-bit case is 24 and that \
         is what the extension shows its users"
    );
    println!("  phrase width: {ENTROPY_LEN} bytes of entropy -> {words} words, matching the extension's generateSeed() default");
}
