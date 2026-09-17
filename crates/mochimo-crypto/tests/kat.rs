// Not under Miri: every test here reads the corpus from `fixtures/` through
// `std::fs`, which Miri's isolation refuses at the first `open` -- the whole
// binary aborts -- and a replay of 5,364 vectors -- a
// thousand WOTS+ key generations among them, at about three minutes each
// under the interpreter on this machine -- would take days if it could run.
#![cfg(all(feature = "native", not(miri)))]
//! The corpus replay. In this repository the fixtures are the specification:
//! every vector was produced by an implementation that is not this crate, and
//! this file dispatches each one on its `source` string to a handler that
//! recomputes the answer natively and compares.
//!
//! The handlers that called the vendored C directly (the transaction-validator
//! verdicts of group D, the bindings crosschecks) are gone with the C. Their
//! vectors are still read in full: `reference_verdicts_native` round-trips
//! every group D wire image through the native serializer, asserts the layout
//! the vector records, and marks the validator verdicts as *not called* --
//! this crate has no transaction validator; acceptance is the node's.

//! Known-answer tests against `fixtures/`.
//!
//! `fixtures/` was produced by a C program linked against the same reference
//! this crate binds. Both sides are therefore the same C, and **every vector
//! must match**. A failure here can only mean the binding is wrong or this
//! harness is wrong; it can never mean an algorithm is wrong.
//!
//! # How a vector is dispatched
//!
//! Not on its `id` — on its `source` field, which names the reference function
//! and `file:line` that produced it. An unregistered `source` is a hard
//! failure, not a skip: that is what makes "every vector runs" a structural
//! property rather than a convention, so a vector added upstream cannot slip
//! through unexecuted.

mod support;

/// Group F's replay, shared with `tests/derive.rs`'s C-free proof.
/// Gated on `native` because the derivation is; see the arms in `replay`.
#[cfg(feature = "native")]
#[path = "support/derivation_walk.rs"]
mod derivation_walk;
#[path = "support/mesh_walk.rs"]
mod mesh_walk;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use mochimo_crypto::consts::{PK_LEN, SEED_LEN, SIG_LEN};
// The raw WOTS+ surface -- `wots_sign`, `prf`, `thash_f`, `expand_seed`,
// `chain_lengths` -- is reached through `backend::selected` under the
// `raw-backend` feature the test tree turns on, and not through
// `wots::sign` or `wots::internals`, which are crate-private: I1's
// enforcement is that no dependent can name a raw signer.
use mochimo_crypto::backend::selected as raw;
use mochimo_crypto::wots::Adrs;
use mochimo_crypto::{addr, base58, bytes, crc16, tx, wots, Secret};

use support::{Ctx, Disposition, Fixture};

// =======================================================================
// Vectors whose inputs the fixture states in prose rather than in a field
// =======================================================================
//
/// Vectors whose replay reconstructs at least one input rather than reading
/// it from a field. Session 2b emptied this: every input is now recorded.
/// `no_input_is_reconstructed_from_prose` keeps it that way.
const DERIVED_INPUT_IDS: &[&str] = &[];

/// Vectors where the reference is deliberately not invoked for the operation
/// the vector is about. In every case the fixture itself records why.
/// Both pairs are the same two inputs seen from the two files. An all-'1'
/// Base58 string makes `base58_decode` compute a negative copy length and reach
/// `memcpy` with `SIZE_MAX`, so the reference cannot be called on it from
/// either side. The `CX-` entries are the crosscheck widening's: the crosscheck group is now where
/// a second implementation's answer to those inputs lives, and that answer is
/// the reason `C-base58-degenerate`'s expected output stopped being English
/// prose.
///
/// This list is four ids and not five: `C12b-1..3` reject too, but the C *was*
/// called for them and returned rc -1, so they carry a real comparison rather
/// than a refusal.
///
/// `F-ascii-control` is the fifth, for a different reason than the
/// four: nothing is refused, the port simply has no code for the operation.
/// It is the control for `F-high-byte-seed`'s zero call counts --
/// `WOTSWallet.componentsGenerator`'s ASCII round-trip, reachable only on
/// the branch `WOTSWallet.create` takes when handed no random generator,
/// which nothing live does (`derivation.ts` lines 8 and 40 both pass one).
/// The handler reads every field, asserts the dead path stays dead, and
/// marks the vector rather than porting a function nobody calls.
const NOT_CALLED_IDS: &[&str] = &[
    "C11-C7",
    "C-base58-degenerate",
    "CX-C11-C7",
    "CX-C-base58-degenerate",
    "F-ascii-control",
];

/// Vectors whose assertions cannot distinguish a correct replay from an
/// incorrect one, because every value they pin is independent of the input the
/// harness had to guess. Reported so the number is visible rather than assumed
/// to be zero.
const WEAKLY_CHECKED_IDS: &[&str] = &[];

/// Rust definitions that are checked against the reference less strictly than
/// everything else, with the reason each one is.
///
/// Every other value in this crate is *bound*: the C is compiled and Rust calls
/// it, so agreement is structural. An entry here is not. Listing them makes the
/// weaker standard appear in the output of every run instead of being assumed
/// equal to the rest — the same purpose `WEAKLY_CHECKED_IDS` serves for
/// vectors. Adding to this list is a decision, not a convenience.
const WEAKLY_ANCHORED: &[(&str, &str)] = &[(
    "mochimo_crypto::net::valid_op",
    "restated in Rust rather than read from an oracle: valid_op is a \
     function-like macro inside the reference's network.c, so no header \
     declares it and no fixture group carries its answers. Admissible only \
     because it is a predicate over constants — FIRST_OP and LAST_OP are \
     declared in lib.rs as literals read from the reference and compared \
     against group E's recorded constants by \
     group_e_constants_match_the_reference, and tests/net.rs enumerates the \
     whole input domain against those bounds rather than against literals. A \
     deliberate single exception, not precedent; net.rs's module doc carries the \
     argument and the specification's Open items records the transcription.",
)];

// =======================================================================
// Dispatch
// =======================================================================

/// The corpus total, hand-typed as the second, independently written figure
/// `manifest_counts_match_the_files` compares its sum against.
/// 217 -> 5364 with the bulk corpus: B +14, D +22, F +81, AK 1512, BK 1128,
/// HS 390, AKX 1000, CK 1000.
const TOTAL_P14: usize = 5364;

/// The bulk corpus's source strings, verbatim from the
/// fixtures. Named so the census below counts over the same constants the
/// dispatch matches on -- a source added to one and not the other is a
/// compile error or an `UNREGISTERED SOURCE`, never a silent skip.
const AK_PKGEN: &str = "wots_pkgen -> sha256 + addr_from_wots() @ \
reference/mochimo-core/src/wots.c:229, include/crypto-c/src/sha256.c, src/ledger.c:109";
const AK_EXPAND_SEED: &str =
    "expand_seed -> sha256() @ reference/mochimo-core/src/wots.c:125, include/crypto-c/src/sha256.c";
const AK_PRF: &str = "prf() @ reference/mochimo-core/src/wots.c:78";
const AK_THASH_F: &str = "thash_f() @ reference/mochimo-core/src/wots.c:93";
const AK_GEN_CHAIN: &str = "gen_chain() @ reference/mochimo-core/src/wots.c:144";
const BK_SIGN: &str = "wots_sign + wots_pk_from_sig -> sha256() @ \
reference/mochimo-core/src/wots.c:255,284, include/crypto-c/src/sha256.c";
const BK_CHAIN_LENGTHS: &str = "chain_lengths() @ reference/mochimo-core/src/wots.c:212";
const HS_SHA256: &str = "sha256() @ reference/mochimo-core/include/crypto-c/src/sha256.c";
const HS_SHA3: &str = "sha3() @ reference/mochimo-core/include/crypto-c/src/sha3.c";
const HS_RIPEMD160: &str = "ripemd160() @ reference/mochimo-core/include/crypto-c/src/ripemd160.c";
const AKX_PKGEN: &str = "WOTS.wots_pkgen() @ reference/mochimo-wots/src/protocol/wots.ts:120 -> \
WotsAddress.addrFromWots() @ reference/mochimo-wots/src/protocol/wots-addr.ts:116 + \
MochimoHasher.hashWith(\"sha256\") @ reference/mochimo-wots/src/hasher/mochimo-hasher.ts:75";
const CK_TAG: &str =
    "TagUtils.addrTagToBase58() @ reference/mochimo-wots/src/utils/tag-utils.ts:4 over crc16_base58_corpus";

fn replay(ctx: &mut Ctx) {
    match ctx.source.as_str() {
        "wots_pkgen() @ reference/mochimo-core/src/wots.c:229" => pkgen(ctx),
        // --- groups AK, BK, HS, AKX, CK: the bulk corpus -----------
        AK_PKGEN => pkgen_digest(ctx),
        AK_EXPAND_SEED => expand_seed_digest(ctx),
        AK_GEN_CHAIN => gen_chain(ctx),
        BK_SIGN => sign_digest(ctx),
        HS_SHA256 => sha256_vector(ctx),
        AKX_PKGEN => akx_pkgen(ctx),
        CK_TAG => ck_tag(ctx),
        "prf() @ reference/mochimo-core/src/wots.c:78" => prf(ctx),
        "thash_f() @ reference/mochimo-core/src/wots.c:93" => thash_f(ctx),
        "expand_seed() @ reference/mochimo-core/src/wots.c:125" => expand_seed(ctx),
        "wots_sign() @ reference/mochimo-core/src/wots.c:255" => sign(ctx),
        "wots_pk_from_sig() @ reference/mochimo-core/src/wots.c:284" => pk_from_sig(ctx),
        "chain_lengths() @ reference/mochimo-core/src/wots.c:212" => chain_lengths(ctx),
        "addr_hash_generate() @ reference/mochimo-core/src/ledger.c:95" => addr_hash(ctx),
        "sha3() @ reference/mochimo-core/include/crypto-c/src/sha3.c" => sha3(ctx),
        "ripemd160() @ reference/mochimo-core/include/crypto-c/src/ripemd160.c" => ripemd160(ctx),
        "addr_from_wots() @ reference/mochimo-core/src/ledger.c:109" => addr_from_wots(ctx),
        "addr_from_implicit() @ reference/mochimo-core/src/ledger.c:83" => addr_from_implicit(ctx),
        "addr_hash_generate + addr_from_implicit() @ reference/mochimo-core/src/ledger.c:95,83" => {
            addr_len_control(ctx)
        }
        "crc16 + put16 + base58_encode() @ reference/mochimo-core/src/tx.c:268-270" => tag_encode(ctx),
        "base58_decode() @ reference/mochimo-core/include/crypto-c/src/base58.c:101" => {
            base58_decode(ctx)
        }
        "base58_decode() @ reference/mochimo-core/include/crypto-c/src/base58.c:114-144" => {
            base58_degenerate(ctx)
        }
        "base58_encode / base58_decode() @ reference/mochimo-core/include/crypto-c/src/base58.c:44,101" => {
            base58_lengths(ctx)
        }
        "put16() @ reference/mochimo-core/include/extended-c/src/extlib.h:71" => put16_framing(ctx),
        "put16/get16() @ reference/mochimo-core/include/extended-c/src/extlib.h:71" => {
            put16_roundtrip(ctx)
        }
        "crc16() @ reference/mochimo-core/include/crypto-c/src/crc16.c" => crc16_vector(ctx),
        "TagUtils.addrTagToBase58() @ reference/mochimo-wots/src/utils/tag-utils.ts:4" => {
            ts_tag_to_base58(ctx)
        }
        "WotsAddress.addrFromWots() @ reference/mochimo-wots/src/protocol/wots-addr.ts:116" => {
            ts_addr_from_wots(ctx)
        }
        "WOTS.wots_pkgen() @ reference/mochimo-wots/src/protocol/wots.ts:120 -> \
WotsAddress.addrFromWots() @ reference/mochimo-wots/src/protocol/wots-addr.ts:116" => {
            ts_pkgen_to_addr(ctx)
        }
        "WotsAddress.addrFromImplicit() @ reference/mochimo-wots/src/protocol/wots-addr.ts:99" => {
            ts_addr_from_implicit(ctx)
        }
        "WotsAddress.addrHashGenerate() @ reference/mochimo-wots/src/protocol/wots-addr.ts:106" => {
            ts_addr_hash_generate(ctx)
        }
        "MochimoHasher.hashWith() @ reference/mochimo-wots/src/hasher/mochimo-hasher.ts:75" => {
            ts_standalone_digest(ctx)
        }
        "bs58.encode() @ bs58 6.0.0, resolved from mochimo-wots" => ts_base58_encode(ctx),
        "bs58.decode() @ bs58 6.0.0, and TagUtils.validateBase58Tag / \
base58ToAddrTag @ reference/mochimo-wots/src/utils/tag-utils.ts:20,39" => ts_base58_decode(ctx),
        "MochimoHasher.hashWith(\"ripemd160\") -> @noble/hashes/ripemd160" => rx_ripemd160(ctx),
        "TXDAT_TYPE / TXDSA_TYPE / MDST_COUNT() @ reference/mochimo-core/src/types.h:166,171,176" => {
            options_accessors(ctx)
        }
        // The group D sources whose handlers called the reference validators
        // (`tx__init`, `mdst_val__reference`, `tx_read`, `tx_hash`,
        // `tx_val__wots` and the transaction-core replay) route to one native
        // handler: there is no C in this repository to ask.
        s if is_reference_only_source(s) => reference_verdicts_native(ctx),
        // --- group F: the extension's derivation -------------------
        //
        // Eleven sources, one arm each, every handler in
        // `support/derivation_walk.rs` and shared with `tests/derive.rs`'s
        // C-free proof, so both binaries assert the same fields. `Ctx`
        // implements the walk's `Vector` trait below, which is what keeps
        // coverage fail-closed through the shared code. Gated on `native`
        // because the derivation is: an ffi-only build reports these sources
        // as unregistered, which is the right answer for a build with no
        // derivation to replay. Group F is a SPECIFICATION CAPTURE and these
        // arms do not change that (`group_f_is_specification_not_crosscheck`).
        #[cfg(feature = "native")]
        derivation_walk::PRNG => derivation_walk::prng(ctx),
        #[cfg(feature = "native")]
        derivation_walk::GENERATE_STATE => derivation_walk::generate_state(ctx),
        #[cfg(feature = "native")]
        derivation_walk::COUNTERS => derivation_walk::counters(ctx),
        #[cfg(feature = "native")]
        derivation_walk::DERIVE_SEED => derivation_walk::derive_seed(ctx),
        #[cfg(feature = "native")]
        derivation_walk::DERIVE_WOTS => derivation_walk::derive_wots(ctx),
        #[cfg(feature = "native")]
        derivation_walk::WIDTHS => derivation_walk::widths(ctx),
        #[cfg(feature = "native")]
        derivation_walk::DERIVE_TAG => derivation_walk::derive_tag(ctx),
        #[cfg(feature = "native")]
        derivation_walk::COMPONENTS => derivation_walk::components(ctx),
        #[cfg(feature = "native")]
        derivation_walk::FROM_PHRASE => derivation_walk::from_phrase(ctx),
        #[cfg(feature = "native")]
        derivation_walk::TO_PHRASE => derivation_walk::to_phrase(ctx),
        #[cfg(feature = "native")]
        derivation_walk::DERIVE_ACCOUNT => derivation_walk::derive_account(ctx),
        // The rotation sweep and the three BIP39 library captures.
        #[cfg(feature = "native")]
        derivation_walk::ROTATION => derivation_walk::rotation(ctx),
        #[cfg(feature = "native")]
        derivation_walk::BIP39_SEED => derivation_walk::bip39_seed(ctx),
        #[cfg(feature = "native")]
        derivation_walk::BIP39_ENTROPY => derivation_walk::bip39_entropy(ctx),
        #[cfg(feature = "native")]
        derivation_walk::BIP39_REJECT => derivation_walk::bip39_reject(ctx),
        // --- groups M and N: the mesh client and the mesh capture --
        //
        // Fifteen sources, one handler each, every handler in
        // `support/mesh_walk.rs` and shared with `tests/mesh.rs`'s C-free
        // run. Both groups are SPECIFICATION CAPTURES (group_f_is_specification_not_crosscheck
        // routes them): N is one server at one block, M is the shipped client
        // under a double. Gated on `native` because the codec is.
        #[cfg(feature = "native")]
        s if mesh_walk::SOURCES.contains(&s) => {
            // Owned, so the scrutinee's borrow of `ctx.source` ends before
            // the walk takes `ctx` mutably.
            let source = s.to_owned();
            mesh_walk::replay(ctx, &source)
        }
        unknown => panic!(
            "UNREGISTERED SOURCE\n  fixture : {}\n  vector  : {}\n  source  : {unknown}\n  \
             No replay is registered for this reference function, so the vector would run \
             nothing. Register it in tests/kat.rs rather than skipping it.",
            ctx.file, ctx.id
        ),
    }
    crosscheck_verdicts(ctx);
}

/// `Ctx` as the mesh walk's vector: the same arrangement as the
/// derivation walk below -- every accessor is `Ctx`'s own, so coverage stays
/// fail-closed through the shared handlers.
#[cfg(feature = "native")]
impl mesh_walk::Vector for Ctx<'_> {
    fn id(&self) -> String {
        self.id.clone()
    }
    fn has(&self, key: &str) -> bool {
        Ctx::has(self, key)
    }
    fn str_(&self, key: &str) -> String {
        Ctx::str_(self, key).to_string()
    }
    fn hex(&self, key: &str) -> Vec<u8> {
        Ctx::hex(self, key)
    }
    fn u64_(&self, key: &str) -> u64 {
        Ctx::u64_(self, key)
    }
    fn bool_(&self, key: &str) -> bool {
        Ctx::bool_(self, key)
    }
    fn blob(&self, key: &str) -> Vec<u8> {
        Ctx::blob(self, key)
    }
    fn eq_u64(&mut self, key: &str, actual: u64) {
        Ctx::eq_u64(self, key, actual);
    }
    fn eq_bool(&mut self, key: &str, actual: bool) {
        Ctx::eq_bool(self, key, actual);
    }
    fn eq_str(&mut self, key: &str, actual: &str) {
        Ctx::eq_str(self, key, actual);
    }
    fn eq_bytes(&mut self, key: &str, actual: &[u8]) {
        Ctx::eq_bytes(self, key, actual);
    }
    fn eq_blob(&mut self, key: &str, actual: &[u8]) {
        Ctx::eq_blob(self, key, actual);
    }
}

/// `Ctx` as the derivation walk's vector: every accessor is `Ctx`'s own, so
/// every field the shared handlers read is recorded and coverage stays
/// fail-closed through code this file does not own. `not_ported` marks the
/// disposition the way the base58 refusals do.
#[cfg(feature = "native")]
impl derivation_walk::Vector for Ctx<'_> {
    fn id(&self) -> String {
        self.id.clone()
    }
    fn has(&self, key: &str) -> bool {
        Ctx::has(self, key)
    }
    fn hex(&self, key: &str) -> Vec<u8> {
        Ctx::hex(self, key)
    }
    fn str_(&self, key: &str) -> String {
        Ctx::str_(self, key).to_string()
    }
    fn u64_(&self, key: &str) -> u64 {
        Ctx::u64_(self, key)
    }
    fn ints(&self, key: &str) -> Vec<i64> {
        Ctx::ints(self, key).into_iter().map(i64::from).collect()
    }
    fn blob(&self, key: &str) -> Vec<u8> {
        Ctx::blob(self, key)
    }
    fn eq_bytes(&mut self, key: &str, actual: &[u8]) {
        Ctx::eq_bytes(self, key, actual);
    }
    fn eq_blob(&mut self, key: &str, actual: &[u8]) {
        Ctx::eq_blob(self, key, actual);
    }
    fn eq_u64(&mut self, key: &str, actual: u64) {
        Ctx::eq_u64(self, key, actual);
    }
    fn eq_i64(&mut self, key: &str, actual: i64) {
        Ctx::eq_i64(self, key, actual);
    }
    fn eq_bool(&mut self, key: &str, actual: bool) {
        Ctx::eq_bool(self, key, actual);
    }
    fn eq_str(&mut self, key: &str, actual: &str) {
        Ctx::eq_str(self, key, actual);
    }
    fn eq_ints(&mut self, key: &str, actual: &[i64]) {
        // `Ctx::ints` is i32; every group F integer array fits.
        let narrowed: Vec<i32> = actual
            .iter()
            .map(|x| i32::try_from(*x).unwrap_or_else(|_| panic!("{}: {key} holds {x}, outside i32", self.id)))
            .collect();
        Ctx::eq_ints(self, key, &narrowed);
    }
    fn not_ported(&mut self) {
        self.mark(Disposition::NotCalled);
    }
}

/// A second implementation's verdict on the same input, recorded by the
/// generator.
///
/// Where the fixture carries the other implementation's actual output we
/// recompute and compare against it, which is what `tag_encode` does with
/// `crosscheck_typescript_expected`. Where it carries only a boolean verdict,
/// the most that can honestly be said is that the verdict is still agreement --
/// a regenerated fixture recording `false` turns this red, and that trigger is
/// what makes the field worth asserting rather than allow-listing.
///
/// Naming each field rather than matching a prefix is deliberate. The names are
/// not uniform across groups -- `matches_reference_expect_sig` in B,
/// `crosscheck_matches` in C -- a uniformity assumption that fails. Coverage is
/// what makes the `has()` gating safe here: a crosscheck field this function
/// fails to name is reported as uncovered rather than silently skipped.
fn crosscheck_verdicts(ctx: &mut Ctx) {
    for key in [
        "matches_reference_expect_pub_key",
        "matches_reference_expect_tag",
        "matches_reference_expect_sig",
        "crosscheck_matches",
        "crosscheck_executed_matches_literal",
    ] {
        if ctx.has(key) {
            ctx.eq_bool(key, true);
        }
    }
}

// --- group A ------------------------------------------------------------

fn pkgen(ctx: &mut Ctx) {
    let secret = Secret::<SEED_LEN>::new(ctx.arr("secret"));
    let pub_seed: [u8; SEED_LEN] = ctx.arr("pub_seed");
    let mut adrs = Adrs(ctx.words("adrs_in_words"));

    let pk = wots::pkgen(&secret, &pub_seed, &mut adrs);

    ctx.eq_blob("pk", pk.as_slice());
    ctx.eq_words("adrs_out_words", adrs.words());
    ctx.eq_bytes("adrs_out_bytes_addr_to_bytes_be", &adrs.to_bytes());
}

fn prf(ctx: &mut Ctx) {
    let input: [u8; 32] = ctx.arr("in");
    let key: [u8; SEED_LEN] = ctx.arr("key");
    let out = raw::prf(&input, &key);
    ctx.eq_bytes("out", &out);
}

fn thash_f(ctx: &mut Ctx) {
    let input: [u8; 32] = ctx.arr("in");
    let pub_seed: [u8; SEED_LEN] = ctx.arr("pub_seed");
    let mut adrs = Adrs(ctx.words("adrs_in_words"));

    let out = raw::thash_f(&input, &pub_seed, &mut adrs.0);

    ctx.eq_bytes("out", &out);
    ctx.eq_words("adrs_out_words", adrs.words());
    ctx.eq_bytes("adrs_out_bytes_addr_to_bytes_be", &adrs.to_bytes());
}

fn expand_seed(ctx: &mut Ctx) {
    let inseed = Secret::<SEED_LEN>::new(ctx.arr("inseed"));
    let out = raw::expand_seed(inseed.expose());
    ctx.eq_blob("outseeds", out.as_slice());
}

// --- group B ------------------------------------------------------------

fn sign(ctx: &mut Ctx) {
    // B-adrs-invariance shares wots_sign()'s source but pins a different
    // question: whether the starting value of adrs words 5-7 changes the
    // signature. It carries no key material of its own.
    if ctx.has("adrs_a_in_words") {
        return adrs_invariance(ctx);
    }

    let msg: [u8; SEED_LEN] = ctx.arr("msg");
    let secret = Secret::<SEED_LEN>::new(ctx.arr("secret"));
    let pub_seed: [u8; SEED_LEN] = ctx.arr("pub_seed");
    let mut adrs = Adrs(ctx.words("adrs_in_words"));

    let sig = raw::wots_sign(&msg, secret.expose(), &pub_seed, &mut adrs.0);

    ctx.eq_blob("sig", sig.as_slice());
    ctx.eq_words("adrs_out_words", adrs.words());
}

/// The two signatures differ only in the adrs words 5-7 they start from. Since
/// session 2b the vector also records the msg/secret/pub_seed it signs under
/// and the signature itself, so a wrong reading fails on the bytes rather than
/// passing on a self-comparison that holds for every input.
fn adrs_invariance(ctx: &mut Ctx) {
    let msg: [u8; SEED_LEN] = ctx.arr("msg");
    let secret = Secret::<SEED_LEN>::new(ctx.arr("secret"));
    let pub_seed: [u8; SEED_LEN] = ctx.arr("pub_seed");

    let mut a = Adrs(ctx.words("adrs_a_in_words"));
    let mut b = Adrs(ctx.words("adrs_b_in_words"));
    let sig_a = raw::wots_sign(&msg, secret.expose(), &pub_seed, &mut a.0);
    let sig_b = raw::wots_sign(&msg, secret.expose(), &pub_seed, &mut b.0);

    ctx.eq_words("adrs_a_out_words", a.words());
    ctx.eq_words("adrs_b_out_words", b.words());
    ctx.eq_bool("signatures_equal", sig_a == sig_b);
    ctx.eq_blob("sig", sig_a.as_slice());
}

fn pk_from_sig(ctx: &mut Ctx) {
    let sig_bytes = ctx.blob("sig");
    let sig: [u8; SIG_LEN] = sig_bytes
        .try_into()
        .unwrap_or_else(|v: Vec<u8>| panic!("{}: recorded signature is {} bytes", ctx.id, v.len()));
    let msg: [u8; SEED_LEN] = ctx.arr("msg");
    let pub_seed: [u8; SEED_LEN] = ctx.arr("pub_seed");
    let mut adrs = Adrs(ctx.words("adrs_in_words"));

    let pk = wots::pk_from_sig(&sig, &msg, &pub_seed, &mut adrs);

    ctx.eq_blob("recovered_pk", pk.as_slice());
    ctx.eq_words("adrs_out_words", adrs.words());

    // `equals_keygen_pk` is the vector's actual claim: recovery reproduces the
    // keygen public key for a good signature and does not for a tampered one.
    // The key is regenerated with wots_pkgen from the vector's own recorded
    // seeds, so the comparison is a replay and not a stored answer.
    let secret = Secret::<SEED_LEN>::new(ctx.arr("keygen_secret"));
    let key_pub_seed: [u8; SEED_LEN] = ctx.arr("keygen_pub_seed");
    let mut keygen_adrs = Adrs::ZERO;
    let keygen = wots::pkgen(&secret, &key_pub_seed, &mut keygen_adrs);
    ctx.eq_bool("equals_keygen_pk", pk == keygen);
}

fn chain_lengths(ctx: &mut Ctx) {
    let msg: [u8; SEED_LEN] = ctx.arr("msg");
    let lengths = raw::chain_lengths(&msg);
    ctx.eq_ints("lengths", &lengths);
    ctx.eq_ints("checksum_digits", &lengths[lengths.len() - 3..]);
}

// --- groups AK and BK: the bulk corpus, recorded as digests --------
//
// A WOTS+ public key or signature is 2144 bytes, and the bulk
// files hold a thousand of each, so they record sha256 of the artifact --
// computed by the reference's own sha256() over the reference's own output --
// rather than a sidecar. The replay is the same shape as groups A and B up to
// the last step: the native (or, on the default board, the C) value is
// computed from the recorded inputs, and then it is digested here and the
// digest compared. `raw::sha256` is `backend::selected`, so the default board
// digests through the C and the C-free build through RustCrypto; the digest
// is recomputed on every replay, never read back and trusted.
// `artifact_policy_is_declared_by_the_generator_and_enforced_here` is what
// keeps a digest from standing in for bytes anywhere the bytes are owed.

/// The digest that stands in for an artifact: `<key>_len` and `<key>_sha256`.
fn digest_leg(ctx: &mut Ctx, key: &str, artifact: &[u8]) {
    ctx.eq_u64(&format!("{key}_len"), artifact.len() as u64);
    ctx.eq_bytes(&format!("{key}_sha256"), &raw::sha256(artifact));
}

fn pkgen_digest(ctx: &mut Ctx) {
    let secret = Secret::<SEED_LEN>::new(ctx.arr("secret"));
    let pub_seed: [u8; SEED_LEN] = ctx.arr("pub_seed");
    let mut adrs = Adrs(ctx.words("adrs_in_words"));

    let pk = wots::pkgen(&secret, &pub_seed, &mut adrs);

    ctx.eq_words("adrs_out_words", adrs.words());
    ctx.eq_bytes("adrs_out_bytes_addr_to_bytes_be", &adrs.to_bytes());
    digest_leg(ctx, "pk", pk.as_slice());
    // The v3 address the wallet actually shows for this key: the whole
    // secret -> pk -> address path, at a thousand points.
    ctx.eq_bytes("addr", &addr::from_wots(&pk));
}

fn expand_seed_digest(ctx: &mut Ctx) {
    let inseed = Secret::<SEED_LEN>::new(ctx.arr("inseed"));
    let out = raw::expand_seed(inseed.expose());
    digest_leg(ctx, "outseeds", out.as_slice());
}

fn gen_chain(ctx: &mut Ctx) {
    let input: [u8; 32] = ctx.arr("in");
    let start = u32::try_from(ctx.u64_("start"))
        .unwrap_or_else(|_| panic!("{}: `start` is not a u32", ctx.id));
    let steps = u32::try_from(ctx.u64_("steps"))
        .unwrap_or_else(|_| panic!("{}: `steps` is not a u32", ctx.id));
    let pub_seed: [u8; SEED_LEN] = ctx.arr("pub_seed");
    let mut adrs = Adrs(ctx.words("adrs_in_words"));

    let out = raw::gen_chain(&input, start, steps, &pub_seed, &mut adrs.0);

    ctx.eq_bytes("out", &out);
    ctx.eq_words("adrs_out_words", adrs.words());
    ctx.eq_bytes("adrs_out_bytes_addr_to_bytes_be", &adrs.to_bytes());
}

/// Sign, recover, and recover from a one-bit mutation -- the three legs group
/// B carries as B1..B5, B6-* and B7/B8, here on one key per vector at a
/// thousand points. `recovered_equals_keygen_pk` and its mutated twin were
/// computed by the reference; both are recomputed here, and the mutation's
/// position is read from the vector rather than chosen, so the positive and
/// the negative replay the same bytes the C compared.
fn sign_digest(ctx: &mut Ctx) {
    let msg: [u8; SEED_LEN] = ctx.arr("msg");
    let secret = Secret::<SEED_LEN>::new(ctx.arr("secret"));
    let pub_seed: [u8; SEED_LEN] = ctx.arr("pub_seed");
    let adrs_in = ctx.words("adrs_in_words");

    let mut keygen_adrs = Adrs(adrs_in);
    let pk = wots::pkgen(&secret, &pub_seed, &mut keygen_adrs);
    digest_leg(ctx, "pk", pk.as_slice());

    let mut adrs = Adrs(adrs_in);
    let sig = raw::wots_sign(&msg, secret.expose(), &pub_seed, &mut adrs.0);
    ctx.eq_words("adrs_out_words", adrs.words());
    digest_leg(ctx, "sig", sig.as_slice());

    let mut recovery_adrs = Adrs(adrs_in);
    let recovered = wots::pk_from_sig(&sig, &msg, &pub_seed, &mut recovery_adrs);
    ctx.eq_words("recovery_adrs_out_words", recovery_adrs.words());
    ctx.eq_bool("recovered_equals_keygen_pk", recovered == pk);

    let flip_byte = ctx.u64_("flip_byte") as usize;
    let flip_bit = ctx.u64_("flip_bit");
    assert!(
        flip_byte < SIG_LEN && flip_bit < 8,
        "{}: flip_byte {flip_byte} / flip_bit {flip_bit} is outside the signature",
        ctx.id
    );
    let mut mutated: [u8; SIG_LEN] = *sig;
    mutated[flip_byte] ^= 1u8 << flip_bit;
    let mut mutated_adrs = Adrs(adrs_in);
    let recovered_mut = wots::pk_from_sig(&mutated, &msg, &pub_seed, &mut mutated_adrs);
    ctx.eq_bool("mutated_recovered_equals_keygen_pk", recovered_mut == pk);
}

// --- group HS: the hash primitives at every length -----------------

fn sha256_vector(ctx: &mut Ctx) {
    let input = ctx.hex("in");
    assert_eq!(input.len(), ctx.u64_("inlen") as usize);
    ctx.eq_bytes("out", &raw::sha256(&input));
}

// --- group C ------------------------------------------------------------

fn addr_hash(ctx: &mut Ctx) {
    let inlen = ctx.u64_("inlen") as usize;

    // Inputs over jsonw.h's JW_INLINE_MAX are sidecared, so C1's 2144 bytes
    // arrive as in_file/in_len and C2/C3's as inline hex. Which one is present
    // is the only thing branched on -- neither branch reads prose.
    let input: Vec<u8> = if ctx.has("in_file") {
        ctx.blob("in")
    } else {
        ctx.hex("in")
    };
    assert_eq!(
        input.len(),
        inlen,
        "{}: vector {} `in` is {} bytes but `inlen` says {inlen}",
        ctx.file,
        ctx.id,
        input.len()
    );

    ctx.eq_bytes("hash", &addr::hash_generate(&input));
}

/// The vector's `outlen` selects the function, and an unknown width fails.
///
/// `addr::sha3` once took `&mut [u8]` and this handler passed the
/// fixture's `outlen` straight through. The seam now carries four fixed-width
/// functions, so the dispatch is here and it is **fail-closed** — same idiom as
/// `ts_standalone_digest`'s `algorithm` match. A vector at a width nobody
/// implements fails loudly rather than being hashed with the wrong function or
/// silently skipped.
///
/// Only `outlen: 64` appears in the corpus today. The other three arms are not
/// speculative: the reference names all four as compatible, and the reason 28 and
/// 48 exist natively at all is that the oracle covers them.
fn sha3(ctx: &mut Ctx) {
    let input = ctx.hex("in");
    assert_eq!(input.len(), ctx.u64_("inlen") as usize);
    let outlen = ctx.u64_("outlen") as usize;
    let out: Vec<u8> = match outlen {
        28 => addr::sha3_224(&input).to_vec(),
        32 => addr::sha3_256(&input).to_vec(),
        48 => addr::sha3_384(&input).to_vec(),
        64 => addr::sha3_512(&input).to_vec(),
        n => panic!(
            "sha3 vector {} has outlen {n}, which is not one of the four widths \
             sha3.h:44 declares compatible (28, 32, 48, 64). The reference \
             would accept it and produce a non-standard sponge -- and from \
             outlen 100 its own rsiz underflows and sha3_final writes out of \
             bounds, which is why the width here is a type and not a \
             parameter (addr.rs's sha3 doc). \
             Either the vector is wrong or a fifth width needs porting.",
            ctx.id
        ),
    };
    ctx.eq_bytes("out", &out);
}

fn ripemd160(ctx: &mut Ctx) {
    let input = ctx.hex("in");
    assert_eq!(input.len(), ctx.u64_("inlen") as usize);
    ctx.eq_bytes("out", &addr::ripemd160(&input));
}

/// `addr_from_wots` over two vector shapes.
///
/// The seven `C4-A*` vectors carry a seed triple and replay the whole
/// seed -> pk -> address path. `C-addr-from-wots-fill42` carries a bare
/// 2144-byte public key with no seed behind it — it exists to be the same input
/// the TypeScript's own test file uses, and that test starts from
/// `new Uint8Array(2144).fill(0x42)`, which no seed produces.
///
/// Gating on `secret` rather than on the id: dispatch is on `source`, and a
/// second bare-PK vector added later should take this arm without being named
/// here. Coverage is what makes the `has()` safe — a field either shape carries
/// and this function fails to read is reported, not skipped.
fn addr_from_wots(ctx: &mut Ctx) {
    let pk: Box<[u8; PK_LEN]> = if ctx.has("secret") {
        // The pk is regenerated from the vector's own seeds rather than read
        // from a group A sidecar, so C4 replays the whole seed -> pk -> address
        // path.
        let secret = Secret::<SEED_LEN>::new(ctx.arr("secret"));
        let pub_seed: [u8; SEED_LEN] = ctx.arr("pub_seed");
        let mut adrs = Adrs(ctx.words("adrs_in_words"));
        wots::pkgen(&secret, &pub_seed, &mut adrs)
    } else {
        let fill = ctx.u64_("input_fill_byte");
        assert!(fill <= 0xff, "{}: input_fill_byte {fill} is not a byte", ctx.id);
        let bytes = ctx.blob("in");
        ctx.eq_u64("input_len", bytes.len() as u64);
        // The sidecar is opaque otherwise: asserting it really is the constant
        // fill the vector claims is what stops this from being a blob compared
        // against a blob.
        assert!(
            bytes.iter().all(|&b| b as u64 == fill),
            "{}: {} is not uniformly 0x{fill:02x}",
            ctx.file,
            ctx.id
        );
        let n = bytes.len();
        bytes.into_boxed_slice().try_into().unwrap_or_else(|_| {
            panic!(
                "{}: {} sidecar is {n} bytes, expected WOTS_PK_LEN = {PK_LEN}",
                ctx.file, ctx.id
            )
        })
    };

    let address = addr::from_wots(&pk);
    ctx.eq_bytes("addr", &address);
    ctx.eq_bytes("tag_half", addr::tag_of(&address));
    ctx.eq_bytes("hash_half", addr::hash_of(&address));
    ctx.eq_bool(
        "halves_equal",
        addr::tag_of(&address) == addr::hash_of(&address),
    );

    // The literal the TypeScript package's own test file states for this input.
    // Asserting it here is the weak leg of the crosscheck — it pins a
    // transcription — and `group_c_crosscheck.json` carries the strong one,
    // where the same function is executed. Both are kept: the literal is the
    // only thing that checks the transcription, and dropping it would remove a
    // check rather than remove a duplicate.
    if ctx.has("crosscheck_typescript_expected") {
        ctx.eq_str("crosscheck_typescript_expected", &hex(&address));
    }
}

fn addr_from_implicit(ctx: &mut Ctx) {
    let tag: [u8; 20] = ctx.arr("tag_in");
    let address = addr::from_implicit(&tag);
    ctx.eq_bytes("addr", &address);
    ctx.eq_bool(
        "halves_equal",
        addr::tag_of(&address) == addr::hash_of(&address),
    );
}

/// C6, the 2144-vs-2208 negative control.
///
/// Both halves are now replayed. `addr_correct_2144` comes from A4's key
/// regenerated here; `addr_wrong_2208` comes from hashing the recorded
/// 2208-byte buffer, which session 2b emitted. The vector's point is that a
/// port confusing the two lengths fails loudly, and that is only testable if
/// the wrong value is actually computed rather than read back.
fn addr_len_control(ctx: &mut Ctx) {
    assert!(ctx.bool_("is_negative_control"));
    assert_eq!(ctx.u64_("inlen"), 2208);

    let secret = Secret::<SEED_LEN>::new(ctx.arr("in_secret"));
    let pub_seed: [u8; SEED_LEN] = ctx.arr("in_pub_seed");
    let mut adrs = Adrs::ZERO;
    let pk = wots::pkgen(&secret, &pub_seed, &mut adrs);
    let correct = addr::from_wots(&pk);
    ctx.eq_bytes("addr_correct_2144", &correct);

    // The recorded buffer is pk || pub_seed || terminal adrs. Asserting that
    // its first PK_LEN bytes are the key we just generated is what stops this
    // from being an opaque blob comparison.
    let buf = ctx.blob("in");
    assert_eq!(buf.len(), 2208, "C6: `in` is {} bytes", buf.len());
    assert_eq!(&buf[..PK_LEN], pk.as_slice(), "C6: `in` does not start with A4's pk");

    let wrong = addr::from_implicit(&addr::hash_generate(&buf));
    ctx.eq_bytes("addr_wrong_2208", &wrong);
    ctx.eq_bool("differs_from_correct", wrong != correct);
}

fn tag_encode(ctx: &mut Ctx) {
    let tag: [u8; 20] = ctx.arr("tag");

    let sum = crc16::crc16(&tag);
    ctx.eq_u64("crc16", sum as u64);

    let sum_bytes = bytes::put16(sum);
    ctx.eq_bytes("crc16_bytes_put16", &sum_bytes);

    let mut tag22 = [0u8; 22];
    tag22[..20].copy_from_slice(&tag);
    tag22[20..].copy_from_slice(&sum_bytes);
    ctx.eq_bytes("tag_with_crc16", &tag22);

    let probe20 = base58::encode_probe_len(&tag).expect("base58_encode probe failed on tag20");
    ctx.eq_u64("base58_of_tag20_probe_len", reference_encode_probe(&tag, probe20) as u64);
    ctx.eq_str(
        "base58_of_tag20",
        &base58::encode(&tag).expect("base58_encode failed on tag20"),
    );

    let probe22 = base58::encode_probe_len(&tag22).expect("base58_encode probe failed on tag22");
    ctx.eq_u64("base58_of_tag22_probe_len", reference_encode_probe(&tag22, probe22) as u64);
    let encoded22 = base58::encode(&tag22).expect("base58_encode failed on tag22");
    ctx.eq_str("base58_of_tag22", &encoded22);

    // An independent oracle: the TypeScript tag utilities in
    // produce this same string from the same tag, so a
    // match is a genuinely separate implementation agreeing rather than the
    // reference agreeing with itself. It sat in the fixture unread until
    // coverage reported it.
    //
    // This is the *weak* leg of that oracle and no longer the only one. The
    // string here was read out of the upstream test file and typed into the C
    // generator, so it pins a transcription. `group_c_crosscheck.json` carries
    // the strong leg, where `addrTagToBase58` is executed and its return value
    // recorded. Both are asserted: the literal is the only check on the
    // transcription itself.
    if ctx.has("crosscheck_typescript_expected") {
        ctx.eq_str("crosscheck_typescript_expected", &encoded22);
    }
}

// --- group CX: the executed TypeScript crosscheck -----------------------
//
// `fixtures/group_c_crosscheck.json` holds a second implementation's *return
// values* for questions group C already answered in C. Each vector closes a
// three-way agreement, and each leg can fail on its own:
//
//   1. `crosscheck_typescript_expected` == group C's copy of the same literal
//      -- the two files still cite the same string.
//   2. `crosscheck_typescript_executed` == what the C computes here, live
//      -- the two implementations agree.
//   3. `crosscheck_executed_matches_literal` is true, via `crosscheck_verdicts`
//      -- the literal that was transcribed is what the TypeScript returns.
//
// Leg 2 is the executed second implementation -- the suite's standard of
// independence -- and it is the only one of the three that
// could not be written before this group existed: the literal C7 and C9 carried
// was read out of an upstream test file, so asserting against it pinned a
// transcription rather than an implementation.

/// The transcription leg, which is now conditional and fail-closed in both
/// directions.
///
/// Before the crosscheck widening every crosscheck vector had a transcribed literal, because
/// carrying one was how the generator selected it. Widening the domain to all
/// of group C means most vectors have none -- nobody ever typed one for them --
/// and the leg has to become optional without becoming skippable.
///
/// So there is no third state. Group C either carries a literal for this
/// subject, in which case it is asserted here, or it does not, in which case
/// the crosscheck vector must say so with `literal_absent`. A vector that
/// claims `literal_absent` while group C has a literal fails, and so does one
/// that carries neither. That is what stops "the literal stopped being
/// compared" from looking identical to "there was never a literal".
///
/// The cross-reference is itself the assertion. Fetching the literal from the
/// other file rather than trusting this one means a vector id that no longer
/// exists is a hard failure inside `vector_by_id`, and a literal that diverges
/// between the two files is a diff.
fn literal_leg(ctx: &mut Ctx) {
    let file = ctx.str_("crosschecks_file").to_string();
    let id = ctx.str_("crosschecks_vector").to_string();
    let fx = Fixture::load(&file);
    let v = fx.vector_by_id(&id);
    literal_leg_against(ctx, &file, &id, v);
}

/// The transcription leg over an upstream vector the caller has already
/// located -- split out so the bulk crosschecks can run it over a
/// fixture loaded once rather than once per vector.
fn literal_leg_against(ctx: &mut Ctx, file: &str, id: &str, v: &serde_json::Value) {
    let upstream = v
        .get("crosscheck_typescript_expected")
        .and_then(|x| x.as_str())
        .map(str::to_string);

    match upstream {
        Some(lit) => {
            assert!(
                !ctx.has("literal_absent"),
                "{}: {} claims `literal_absent`, but {file}::{id} carries a \
                 transcribed literal. The literal is the only thing in the \
                 suite that checks the transcription itself, so declaring it \
                 absent is how that check would be lost silently.",
                ctx.file,
                ctx.id
            );
            ctx.eq_str("crosscheck_typescript_expected", &lit);
        }
        None => {
            assert!(
                ctx.has("literal_absent"),
                "{}: {} crosschecks {file}::{id}, which carries no \
                 `crosscheck_typescript_expected`, and this vector does not \
                 declare `literal_absent` either. One of the two must be true: \
                 either there is a literal to compare or the vector says there \
                 is not. Silence here is indistinguishable from a literal that \
                 quietly stopped being asserted.",
                ctx.file,
                ctx.id
            );
            ctx.eq_bool("literal_absent", true);
            assert!(
                !ctx.has("crosscheck_typescript_expected"),
                "{}: {} declares `literal_absent` but carries a \
                 `crosscheck_typescript_expected` of its own. A literal that \
                 group C does not also carry is a literal nothing cross-checks.",
                ctx.file,
                ctx.id
            );
        }
    }
}

// --- groups AKX and CK: the bulk crosschecks ------------------------
//
// The same three-way agreement CX closes, over the bulk corpus: the C's
// recorded answer (in the file each vector names), the TypeScript's executed
// answer (recorded here), and this crate's answer (computed now). Each leg
// can fail on its own. The upstream file is loaded once per process -- AK is
// 1.4 MB and a thousand vectors would otherwise parse it a thousand times --
// and its name is asserted against the constant the cache holds, so a vector
// pointing somewhere else fails rather than being compared against the
// wrong file.

fn cached_upstream(file: &str, expect: &'static str, slot: &'static OnceLock<Fixture>) -> &'static Fixture {
    assert_eq!(
        file, expect,
        "a bulk crosscheck vector names {file:?} as its upstream; this group's \
         upstream is {expect:?} and the cache holds only that"
    );
    slot.get_or_init(|| Fixture::load(expect))
}

fn akx_pkgen(ctx: &mut Ctx) {
    static AK: OnceLock<Fixture> = OnceLock::new();

    let secret = Secret::<SEED_LEN>::new(ctx.arr("input_secret"));
    let pub_seed: [u8; SEED_LEN] = ctx.arr("input_pub_seed");
    let words = ctx.words("input_adrs_in_words");

    let all_zero = words.iter().all(|&w| w == 0);
    ctx.eq_bool("adrs_all_zero", all_zero);
    // Little-endian, as `ts_pkgen_to_addr` argues; half the AK
    // vectors carry a non-zero adrs, so this leg is exercised five hundred
    // times rather than once.
    let mut image = [0u8; 32];
    for (i, w) in words.iter().enumerate() {
        image[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
    }
    ctx.eq_bytes("adrs_byte_image", &image);
    let representation = ctx.str_("adrs_representation");
    assert_eq!(
        representation.starts_with("all-zero"),
        all_zero,
        "{}: {} has adrs_all_zero = {all_zero} but adrs_representation says {representation:?}",
        ctx.file,
        ctx.id
    );

    let mut adrs = Adrs(words);
    let pk = wots::pkgen(&secret, &pub_seed, &mut adrs);
    ctx.eq_u64("input_pk_len", pk.len() as u64);
    let address = addr::from_wots(&pk);
    let pk_digest = raw::sha256(pk.as_slice());

    // Leg 2: the TypeScript's executed values against this crate's.
    ctx.eq_str("crosscheck_typescript_executed", &hex(&address));
    ctx.eq_bytes("pk_sha256_typescript_executed", &pk_digest);

    // Leg 1: the C's recorded values, read from the AK vector this one names.
    let file = ctx.str_("crosschecks_file").to_string();
    let id = ctx.str_("crosschecks_vector").to_string();
    let upstream = cached_upstream(&file, "group_ak_keygen_bulk.json", &AK).vector_by_id(&id);
    assert_eq!(
        upstream.get("addr").and_then(|x| x.as_str()),
        Some(hex(&address).as_str()),
        "{}: {} -- the C's recorded address for {id} is not what the \
         TypeScript and this crate both computed",
        ctx.file,
        ctx.id
    );
    assert_eq!(
        upstream.get("pk_sha256").and_then(|x| x.as_str()),
        Some(hex(&pk_digest).as_str()),
        "{}: {} -- the C's recorded pk digest for {id} is not what the \
         TypeScript and this crate both computed",
        ctx.file,
        ctx.id
    );
    literal_leg_against(ctx, &file, &id, upstream);
}

fn ck_tag(ctx: &mut Ctx) {
    static C: OnceLock<Fixture> = OnceLock::new();

    let tag: [u8; 20] = ctx.arr("input_tag");
    ctx.eq_u64("input_len", tag.len() as u64);

    let sum = crc16::crc16(&tag);
    let mut tag22 = [0u8; 22];
    tag22[..20].copy_from_slice(&tag);
    tag22[20..].copy_from_slice(&bytes::put16(sum));
    let from_c = base58::encode(&tag22).expect("base58_encode failed on tag22");

    ctx.eq_str("crosscheck_typescript_executed", &from_c);
    ctx.eq_u64("crc16_typescript_executed", u64::from(sum));

    // The corpus entry this vector crosschecks, located by the index in
    // `crosschecks_vector` ("crc16_base58_corpus[i]") and checked to be the
    // entry it claims -- the tag must match before its answers are compared.
    let file = ctx.str_("crosschecks_file").to_string();
    let which = ctx.str_("crosschecks_vector").to_string();
    let index: usize = which
        .strip_prefix("crc16_base58_corpus[")
        .and_then(|s| s.strip_suffix(']'))
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("{}: {} crosschecks {which:?}, not a corpus index", ctx.file, ctx.id));
    let corpus = &cached_upstream(&file, "group_c_addr.json", &C).root["crc16_base58_corpus"];
    let entry = corpus["entries"]
        .get(index)
        .unwrap_or_else(|| panic!("{}: {} names corpus entry {index}, which does not exist", ctx.file, ctx.id));
    assert_eq!(entry["i"].as_u64(), Some(index as u64), "{}: entry {index} carries a different `i`", ctx.id);
    assert_eq!(entry["tag"].as_str(), Some(hex(&tag).as_str()), "{}: entry {index} is a different tag", ctx.id);
    assert_eq!(
        entry["base58"].as_str(),
        Some(from_c.as_str()),
        "{}: the C's recorded Base58 for corpus entry {index} is not what the \
         TypeScript and this crate both computed",
        ctx.id
    );
    assert_eq!(
        entry["crc16"].as_u64(),
        Some(u64::from(sum)),
        "{}: the C's recorded crc16 for corpus entry {index} is not what the \
         TypeScript and this crate both computed",
        ctx.id
    );
    // The corpus entries carry no transcribed literal, so the vector must say so.
    literal_leg_against(ctx, &file, &which, entry);
}

/// `TagUtils.addrTagToBase58` against `crc16 + put16 + base58_encode`.
///
/// The C composes three separate reference functions; the TypeScript composes
/// its own `crc` and `bs58` inside one function. That the two compositions
/// agree is what settled survey open question 3, and it is now established by
/// running both rather than by reading one.
fn ts_tag_to_base58(ctx: &mut Ctx) {
    let tag: [u8; 20] = ctx.arr("input_hex");
    ctx.eq_u64("input_len", tag.len() as u64);

    let mut tag22 = [0u8; 22];
    tag22[..20].copy_from_slice(&tag);
    tag22[20..].copy_from_slice(&bytes::put16(crc16::crc16(&tag)));
    let from_c = base58::encode(&tag22).expect("base58_encode failed on tag22");

    ctx.eq_str("crosscheck_typescript_executed", &from_c);

    // The CRC16 the TypeScript embedded, against the one the C computed.
    //
    // `crc()` is not exported from the mochimo-wots package -- the built bundle
    // exports eleven names and it is not one of them -- so the generator
    // recovers it by decoding addrTagToBase58's own output and reading back the
    // two checksum bytes it appended. That makes this leg weaker than a direct
    // call: it cannot separate a wrong CRC from a compensating bug in the
    // encoder, because both sides of that pair live inside the one function.
    // It is still the only place the CRC *parameters* are crosschecked rather
    // than inferred from a matching Base58 string, and the limitation is
    // written down here rather than left to be discovered.
    ctx.eq_u64("crc16_typescript_executed", u64::from(crc16::crc16(&tag)));

    literal_leg(ctx);
}

/// `WotsAddress.addrFromWots` against `addr_from_wots`.
///
/// Both read the same 2144-byte sidecar. `ctx.blob` checks its length against
/// the vector's own `input_len` before handing the bytes over, so a truncated
/// or swapped sidecar fails as a sidecar rather than as a mismatched address.
fn ts_addr_from_wots(ctx: &mut Ctx) {
    let pk_bytes = ctx.blob("input");

    // The two implementations disagree about what a non-WOTS_PK_LEN input
    // MEANS, and that is a difference in kind rather than a failure.
    // `addrFromWots` guards the length and returns null;
    // `addr_from_wots` hashes whatever it is handed, which is the whole reason
    // C6 exists as a negative control. Recorded as its own shape and
    // deliberately not routed through the value comparison below -- folding a
    // known difference in behaviour into the same assertion as the value
    // agreements would make a real disagreement harder to see, not easier.
    if pk_bytes.len() != PK_LEN {
        ctx.eq_bool("returned_null", true);
        ctx.eq_opt_str("crosscheck_typescript_executed", None);
        ctx.eq_u64("input_len", pk_bytes.len() as u64);
        literal_leg(ctx);
        return;
    }

    let pk: [u8; PK_LEN] = pk_bytes.as_slice().try_into().unwrap_or_else(|_| {
        panic!(
            "{}: {} sidecar is {} bytes, expected WOTS_PK_LEN = {PK_LEN}",
            ctx.file,
            ctx.id,
            pk_bytes.len()
        )
    });

    let from_c = hex(&addr::from_wots(&pk));
    ctx.eq_str("crosscheck_typescript_executed", &from_c);
    ctx.eq_u64("input_len", pk_bytes.len() as u64);
    literal_leg(ctx);
}

/// `WOTS.wots_pkgen` + `WotsAddress.addrFromWots` against the C's whole
/// seed → pk → address path.
///
/// The longest path in the corpus, and the one the funds depend on. Seven
/// vectors, `C4-A1..A7`, each carrying a secret, a public seed and an `adrs`,
/// replayed end to end by two implementations sharing no code.
///
/// # These were deferred for six years' worth of the wrong reason
///
/// Once all seven were on `NOT_CROSSCHECKED`, under a single blanket
/// string assigned in a loop: that the byte-vs-word `adrs` ambiguity
/// "would surface as an ADDRESS disagreement -- a check going red
/// about a subject it does not name". **Six of the seven carry an all-zero
/// `adrs`**, whose byte image is identical under every endianness, so there was
/// no representation decision to contaminate. One reason over
/// seven ids read as seven decisions and was one.
///
/// # What each half of the comparison is
///
/// `adrs_byte_image` is the *memory* image of the eight words — the
/// byte-versus-word conversion the crate normalizes to little-endian by
/// decision, the form the TypeScript's `addr: ByteArray` parameter takes
/// (the TypeScript wraps it `LITTLE_ENDIAN`). It is **not**
/// `Adrs::to_bytes`, which is the big-endian serialization `addr_to_bytes`
/// feeds to `prf`. Two different byte images of one value, and conflating them
/// is precisely the confusion the deferral was afraid of.
///
/// Asserting it here is what makes `CX-C4-A5` corroborate the little-endian decision rather than
/// merely assume it: the generator built that buffer with the reference's own
/// little-endian `ByteBuffer`, this side builds it from `u32::to_le_bytes`, and
/// the address agreement then rests on both sides having read the
/// representation the same way. Measured: the big-endian image yields a
/// completely different address, so this vector discriminates.
fn ts_pkgen_to_addr(ctx: &mut Ctx) {
    let secret = Secret::<SEED_LEN>::new(ctx.arr("input_secret"));
    let pub_seed: [u8; SEED_LEN] = ctx.arr("input_pub_seed");
    let words = ctx.words("input_adrs_in_words");

    let all_zero = words.iter().all(|&w| w == 0);
    ctx.eq_bool("adrs_all_zero", all_zero);

    // The little-endian memory image, composed here so the two sides can
    // disagree about it. `no_native_endian_conversions_anywhere_in_the_crate`
    // scans `crates/*/src` and not `tests/`, so this spelling is deliberate
    // and in scope: the little-endian decision is `to_le_bytes`, and this is the
    // assertion that a second implementation agrees with it.
    let mut image = [0u8; 32];
    for (i, w) in words.iter().enumerate() {
        image[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
    }
    ctx.eq_bytes("adrs_byte_image", &image);

    // The prose field is tied to the branch rather than merely read. A
    // description that stops matching which case ran is a field that has gone
    // decorative, and coverage alone would not notice.
    let representation = ctx.str_("adrs_representation");
    let claims_zero = representation.starts_with("all-zero");
    assert_eq!(
        claims_zero, all_zero,
        "{}: {} has adrs_all_zero = {all_zero} but adrs_representation says \
         {representation:?}. The two describe the same branch of the generator \
         and must agree; a representation string that outlives its case is how \
         a reader learns the wrong thing about which endianness ran.",
        ctx.file, ctx.id
    );

    let mut adrs = Adrs(words);
    let pk = wots::pkgen(&secret, &pub_seed, &mut adrs);
    ctx.eq_u64("input_pk_len", pk.len() as u64);

    ctx.eq_str(
        "crosscheck_typescript_executed",
        &hex(&addr::from_wots(&pk)),
    );
    literal_leg(ctx);
}

/// `WotsAddress.addrFromImplicit` against `addr_from_implicit`.
///
/// The behaviour worth crosschecking is the duplication: both halves of the
/// 40-byte address receive the 20-byte tag. An implementation that filled
/// the tag half and left
/// the hash half zero would produce an address of the right length with the
/// right prefix, so this is agreement about the part most likely to be wrong
/// quietly.
fn ts_addr_from_implicit(ctx: &mut Ctx) {
    let tag: [u8; 20] = ctx.arr("input_hex");
    ctx.eq_u64("input_len", tag.len() as u64);
    ctx.eq_str(
        "crosscheck_typescript_executed",
        &hex(&addr::from_implicit(&tag)),
    );
    literal_leg(ctx);
}

/// `WotsAddress.addrHashGenerate` against `addr_hash_generate`.
///
/// Both sides compose two published algorithms, so a disagreement here is
/// about the composition -- which hash, in which order, over how many bytes --
/// rather than about either hash. The primitives are crosschecked apart from
/// each other by `ts_standalone_digest`, so a broken composition and a broken
/// hash report separately instead of both arriving as one wrong address.
fn ts_addr_hash_generate(ctx: &mut Ctx) {
    let input = if ctx.has("input_file") {
        ctx.blob("input")
    } else {
        ctx.hex("input_hex")
    };
    ctx.eq_u64("input_len", input.len() as u64);
    ctx.eq_str(
        "crosscheck_typescript_executed",
        &hex(&addr::hash_generate(&input)),
    );
    literal_leg(ctx);
}

/// `MochimoHasher.hashWith` against crypto-c's `sha3` and `ripemd160`.
///
/// The algorithm comes out of the fixture rather than out of the vector id, so
/// a third standalone vector reaches the right primitive without this handler
/// being edited, and one nobody has taught it fails loudly instead of being
/// hashed with the wrong function.
fn ts_standalone_digest(ctx: &mut Ctx) {
    let input = ctx.hex("input_hex");
    ctx.eq_u64("input_len", input.len() as u64);

    let from_c = match ctx.str_("algorithm") {
        "sha3-512" => hex(&addr::sha3_512(&input)),
        "ripemd160" => {
            // Guarded rather than trusted, and the reason MOVED with the hardening
            // pass. Until then, a vector drifting into the faulting class took the
            // whole binary down -- addr::ripemd160 forwarded every
            // length to the C. Since then the wrapper answers that class
            // with NATIVE, so the failure mode is quieter and worse: this
            // handler's claim is "the C agrees with the TypeScript", and a
            // faulting-class vector would silently substitute native for the C
            // -- a crosscheck green about a subject it does not name. The
            // class's native-vs-TS comparison lives in group RX, on purpose.
            assert!(
                input.len() % 64 < 56,
                "{}: {} carries {} bytes, which is in the reference-faulting \
                 class (len % 64 >= 56). addr::ripemd160 answers that class \
                 with native, so replaying it here would \
                 crosscheck native against the TypeScript while claiming the C \
                 was compared. The class belongs to \
                 fixtures/group_rx_ripemd.json, which says whose answer it is.",
                ctx.file,
                ctx.id,
                input.len()
            );
            hex(&addr::ripemd160(&input))
        }
        other => panic!(
            "{}: {} names algorithm {other:?}, which this handler cannot reach \
             in the reference. Add it rather than letting the vector replay \
             nothing.",
            ctx.file, ctx.id
        ),
    };
    ctx.eq_str("crosscheck_typescript_executed", &from_c);
    literal_leg(ctx);
}

/// `bs58.encode` against `base58_encode`, at the two lengths that are not a
/// 20-byte tag.
///
/// `addrTagToBase58` throws on any length but 20, so the encoder is reached
/// directly. Every other Base58 vector in the corpus sits at the tag length;
/// these two are the only evidence the codecs agree away from it, which is
/// where a length-handling difference would live.
fn ts_base58_encode(ctx: &mut Ctx) {
    for (input_key, executed_key) in [
        ("input_hex_21", "crosscheck_typescript_executed"),
        ("input_hex_23", "crosscheck_typescript_executed_23"),
    ] {
        let input = ctx.hex(input_key);
        let from_c = base58::encode(&input)
            .unwrap_or_else(|e| panic!("{}: {} base58_encode failed: {e:?}", ctx.file, ctx.id));
        ctx.eq_str(executed_key, &from_c);
    }
    literal_leg(ctx);
}

/// `bs58.decode` and the two `TagUtils` entry points, against `base58_decode`.
///
/// This arm answers questions the reference cannot be asked. For an all-'1'
/// string `base58_decode` computes a negative copy length and reaches `memcpy`
/// with `SIZE_MAX` (`C-base58-degenerate`), so the reference is **not called**
/// on that class here. Group C records the refusal; this vector records what a
/// second implementation returns instead, which is how a value that was English
/// prose became a value.
///
/// Where the reference can be called, it is, and the two are compared.
fn ts_base58_decode(ctx: &mut Ctx) {
    let input = ctx.str_("input_base58").to_string();
    ctx.eq_u64("input_len", input.len() as u64);

    let ts_decoded = ctx.opt_str("crosscheck_typescript_executed").map(str::to_string);
    let ts_ok = ctx.bool_("decode_ok");
    assert_eq!(
        ts_ok,
        ts_decoded.is_some(),
        "{}: {} says decode_ok = {ts_ok} but the executed value is {}",
        ctx.file,
        ctx.id,
        if ts_decoded.is_some() { "present" } else { "null" }
    );
    if ts_ok {
        ctx.eq_u64(
            "decoded_len",
            (ts_decoded.as_ref().map_or(0, String::len) / 2) as u64,
        );
    } else {
        // The exception type is recorded but not asserted against the
        // reference: the C signals failure through a return code and an errno,
        // not through a class name, so there is nothing to compare it to.
        assert!(
            !ctx.str_("decode_threw").is_empty(),
            "{}: {} failed to decode but names no exception",
            ctx.file,
            ctx.id
        );
    }

    // `validateBase58Tag` and `base58ToAddrTag` over the same string. Both are
    // recorded even where they reject, because which inputs a codec REFUSES is
    // as much a part of its behaviour as what it returns for the rest -- and it
    // is the half a crosscheck that only records successes cannot see.
    let validates = ctx.bool_("validate_base58_tag");
    let tag_out = ctx.opt_str("base58_to_addr_tag").map(str::to_string);
    if ctx.has("base58_to_addr_tag_threw") {
        assert!(
            tag_out.is_none(),
            "{}: {} records both a base58ToAddrTag result and a throw",
            ctx.file,
            ctx.id
        );
        assert!(!ctx.str_("base58_to_addr_tag_threw").is_empty());
    }
    if validates {
        assert!(
            tag_out.is_some(),
            "{}: {} says validateBase58Tag accepted {input:?} while \
             base58ToAddrTag produced nothing. Both go through the same \
             22-byte decode, so one accepting and the other not is a \
             contradiction inside the TypeScript rather than a disagreement \
             with the C.",
            ctx.file,
            ctx.id
        );
    }

    // The reference leg. Group C carries the decoded bytes where it could be
    // asked; where it could not, it records why, and this is the only side with
    // an answer at all.
    let src = Fixture::load(ctx.str_("crosschecks_file"));
    let subject = src.vector_by_id(ctx.str_("crosschecks_vector"));

    if let Some(from_c) = subject.get("out").and_then(|x| x.as_str()) {
        // The C decoded it. Compare the bytes.
        let ts = ts_decoded.as_deref().unwrap_or_else(|| {
            panic!(
                "{}: {} -- the C decoded this string but the TypeScript \
                 rejected it. That is a genuine disagreement about the codec's \
                 domain and must be reported, not reconciled here.",
                ctx.file, ctx.id
            )
        });
        assert_eq!(
            ts, from_c,
            "{}: {} -- base58_decode and bs58.decode returned different bytes \
             for {input:?}. This is the disagreement group CX exists to \
             produce. Report it; do not decide which side is right.",
            ctx.file, ctx.id
        );
    } else if let Some(rc) = subject.get("rc").and_then(serde_json::Value::as_i64) {
        // The C was called and REJECTED the string. That is an answer, and
        // agreement about it is worth asserting: which inputs a codec refuses
        // is half its behaviour, and it is the half a crosscheck comparing only
        // successful outputs cannot see.
        //
        // The comparison is deliberately at the level of "is this a valid
        // 22-byte tag", not "did decode throw". bs58.decode("") returns an
        // empty array where the C returns an error, so asserting the throws
        // line up would report a difference in convention as a disagreement
        // about Base58. `validateBase58Tag` is the question both sides actually
        // answer the same way.
        assert_ne!(
            rc, 0,
            "{}: {} has no `out` and rc == 0, so the C neither failed nor \
             produced output. The vector's shape changed and this handler is \
             reading it wrong.",
            ctx.file, ctx.id
        );
        assert!(
            !validates,
            "{}: {} -- the C rejected {input:?} with rc {rc}, but \
             validateBase58Tag accepted it. The two implementations disagree \
             about which strings are valid tags, which is exactly the kind of \
             disagreement this group exists to surface. Report it.",
            ctx.file, ctx.id
        );
    } else {
        // Neither an output nor a return code: the reference was never called,
        // because calling it is what faults. Group C says so in its own
        // `decode_not_called` / `correct_out_expected` fields; this is the only
        // side of the pair with an answer at all.
        ctx.mark(Disposition::NotCalled);
    }

    literal_leg(ctx);
}

/// Group RX: `@noble/hashes` RIPEMD-160 against the port's own.
///
/// There is no reference leg and there cannot be one -- calling the vendored
/// `ripemd160` on this input class ends the process. The assertion is against
/// `mochimo_crypto::addr::ripemd160`, which computes every length with one
/// implementation, so the recorded `@noble/hashes` digest is compared to what
/// this crate answers as well as to the fixture's own internal consistency.
fn rx_ripemd160(ctx: &mut Ctx) {
    let input = ctx.hex("in");
    ctx.eq_u64("in_len", input.len() as u64);
    ctx.eq_u64("block_residue", (input.len() % 64) as u64);
    ctx.eq_bool("reference_can_compute", false);

    assert!(
        input.len() % 64 >= 56,
        "{}: {} is {} bytes, residue {} -- OUTSIDE the faulting class. This \
         group's entire premise is that the reference cannot answer here; a \
         vector the reference *can* answer belongs in group C, where it would \
         be crosschecked against the C instead of standing on one \
         implementation.",
        ctx.file,
        ctx.id,
        input.len(),
        input.len() % 64
    );

    let digest = ctx.str_("ripemd160").to_string();
    // The native RIPEMD-160 is defined on this class (the reference is not), so
    // the recorded @noble/hashes digest is compared against it here.
    ctx.eq_str("ripemd160", &hex(&addr::ripemd160(&input)));
    assert_eq!(
        digest.len(),
        40,
        "{}: {} digest is {} hex chars, not the 40 RIPEMD-160 produces",
        ctx.file,
        ctx.id,
        digest.len()
    );

    // The one vector carrying a published expected value. The generator aborts
    // if the executed value disagrees with it, so this is the second place that
    // agreement is checked rather than the first -- deliberately, because the
    // generator's check runs at generation time and this one runs on whatever
    // is committed.
    if ctx.has("published_digest") {
        ctx.eq_str("published_digest", &digest);
        ctx.eq_bool("published_digest_matches_executed", true);
        let ascii = ctx.str_("in_ascii").to_string();
        assert_eq!(
            ascii.as_bytes(),
            input.as_slice(),
            "{}: {} in_ascii and in disagree about the input bytes",
            ctx.file,
            ctx.id
        );
    }
}

/// Lowercase hex, matching what the generators emit.
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn base58_decode(ctx: &mut Ctx) {
    let input = ctx.str_("in").to_string();

    // The fixture itself records when the reference was not called: an all-'1'
    // string faults inside base58_decode (see C-base58-degenerate). The probe
    // on the same input is safe and is still replayed.
    if ctx.has("decode_not_called") && ctx.bool_("decode_not_called") {
        ctx.mark(Disposition::NotCalled);
        assert!(
            ctx.has("decode_not_called_reason"),
            "{}: {} claims decode_not_called without a reason",
            ctx.file,
            ctx.id
        );
        let probe = base58::decode_probe_len(&input).expect("base58_decode probe failed");
        ctx.eq_u64("probe_len", reference_decode_probe(&input, probe) as u64);
        return;
    }

    match base58::decode(&input) {
        Ok(out) => {
            ctx.eq_i64("rc", 0);
            let probe = base58::decode_probe_len(&input).expect("base58_decode probe failed");
            ctx.eq_u64("probe_len", reference_decode_probe(&input, probe) as u64);
            ctx.eq_bytes("out", &out);
            // C12 additionally recomputes the CRC over the decoded tag to show
            // that the codec carries no checksum of its own.
            if ctx.has("recomputed_crc16") {
                assert!(out.len() >= 20);
                let recomputed = crc16::crc16(&out[..20]);
                ctx.eq_u64("recomputed_crc16", recomputed as u64);
                // The codec carries no checksum of its own, so a corrupted final
                // character decodes cleanly and only a separate CRC check would
                // catch it. Recomputed here rather than taken on trust: the last
                // two decoded bytes are the embedded CRC, and they disagree.
                if ctx.has("checksum_would_reject") {
                    assert!(out.len() >= 22);
                    let embedded = bytes::get16(&[out[20], out[21]]);
                    ctx.eq_bool("checksum_would_reject", embedded != recomputed);
                }
            }
        }
        Err(mochimo_crypto::Error::ReferenceErrno { rc, errno, .. }) => {
            ctx.eq_i64("rc", rc as i64);
            ctx.eq_i64("errno", errno as i64);
        }
        // The native decoder refuses with the same return code and no errno;
        // the recorded errno is the reference's and is read, not recomputed.
        Err(mochimo_crypto::Error::Reference { rc, .. }) => {
            ctx.eq_i64("rc", rc as i64);
            let _ = ctx.touch("errno");
        }
        Err(e) => panic!("{}: {} unexpected error {e}", ctx.file, ctx.id),
    }
}

/// C-base58-degenerate. `base58_decode` with a non-NULL `out` reaches a
/// `memcpy` length of `(size_t)(-1)` and faults, so it
/// would crash the test process rather than fail it. The probe on the same
/// input is safe, and the probe value is the defect the vector is about: it
/// returns 21 for a 22-byte payload.
fn base58_degenerate(ctx: &mut Ctx) {
    ctx.mark(Disposition::NotCalled);
    let input = ctx.str_("in").to_string();
    let probe = base58::decode_probe_len(&input).expect("base58_decode probe failed");
    ctx.eq_u64("reference_probe_len", reference_decode_probe(&input, probe) as u64);

    let correct = ctx.u64_("correct_len");
    // This crate's probe reports the true length; the recorded value is the
    // reference's, which under-reports by one on this class. The relation the
    // vector documents is between the reference's probe and the true length.
    assert!(
        reference_decode_probe(&input, probe) as u64 != correct,
        "{}: the recorded probe no longer under-reports against the true length; the \
         reference defect this vector documents would have been fixed upstream, which \
         is a fixture change, not a harness change",
        ctx.id
    );
}

/// The reference implementation's Base58 length probe, reconstructed from this
/// crate's. The reference under-reports by one for a non-empty all-zero encode
/// input and for an all-'1' decode input -- the two classes the corpus records
/// the defect on -- and agrees everywhere else. This crate's probes report the
/// true length, and the recorded values are the reference's, so the comparison
/// is made at the reference's value by the rule the specification states.
fn reference_encode_probe(input: &[u8], ours: usize) -> usize {
    if !input.is_empty() && input.iter().all(|&b| b == 0) {
        ours - 1
    } else {
        ours
    }
}

fn reference_decode_probe(input: &str, ours: usize) -> usize {
    if !input.is_empty() && input.bytes().all(|b| b == b'1') {
        ours - 1
    } else {
        ours
    }
}

fn base58_lengths(ctx: &mut Ctx) {
    for (input_key, b58_key, probe_key) in [
        ("in21", "base58_21", "decode_probe_len_21"),
        ("in23", "base58_23", "decode_probe_len_23"),
    ] {
        let input = ctx.hex(input_key);
        let encoded = base58::encode(&input).expect("base58_encode failed");
        ctx.eq_str(b58_key, &encoded);
        let probe = base58::decode_probe_len(&encoded).expect("base58_decode probe failed");
        ctx.eq_u64(probe_key, reference_decode_probe(&encoded, probe) as u64);
    }
}

// --- group D, the part that needs no TXENTRY ----------------------------

/// The three `D-acc-` vectors. Three reads of a bare four-byte options array through the
/// `types.h` accessor macros. No transaction, no `TXENTRY`, nothing allocated.
fn options_accessors(ctx: &mut Ctx) {
    let opts: [u8; 4] = ctx.arr("opts");
    ctx.eq_u64("txdat_type", tx::dat_type(&opts) as u64);
    ctx.eq_u64("txdsa_type", tx::dsa_type(&opts) as u64);
    ctx.eq_u64("mdst_count", tx::mdst_count(&opts) as u64);
}

// --- group D, the transaction core --------------------------------------
//
// The handlers that rebuilt each entry through the reference's own `tx_read`
// and asked its validators for a verdict went with the C; every one of these
// sources is replayed by `reference_verdicts_native` below, which round-trips
// the wire image natively, asserts the recorded layout, and marks the verdicts
// not called.

/// The `source` strings the transaction-core replay serves.
///
/// Three, not two: `D8`'s call site overwrites the source `tx_emit` wrote with
/// `put64`, and `D6`/`D7` are emitted by hand with `MDST_COUNT`. They are
/// all the same replay — a
/// transaction whose layout the reference computed — and the `source` records
/// which property the vector was written to pin, not which handler it needs.
///
/// `replay()` routes this list to `reference_verdicts_native` and
/// `group_d_core_census` counts over it, so the set of vectors that reach the
/// handler and the set the census describes cannot come apart.
const TX_CORE_SOURCES: [&str; 3] = [
    "tx__init() @ reference/mochimo-core/src/tx.c:119",
    "MDST_COUNT() @ reference/mochimo-core/src/types.h:176",
    "put64() @ reference/mochimo-core/include/extended-c/src/extmath.c",
];

// --- group E ------------------------------------------------------------

fn put16_framing(ctx: &mut Ctx) {
    let network = ctx.u64_("TXNETWORK") as u16;
    ctx.eq_bytes("network_bytes", &bytes::put16(network));
    let eot = ctx.u64_("TXEOT") as u16;
    ctx.eq_bytes("trailer_bytes", &bytes::put16(eot));
}

fn put16_roundtrip(ctx: &mut Ctx) {
    let pversion = ctx.constant(&["PVERSION"]) as u16;
    let encoded = bytes::put16(pversion);
    ctx.eq_bytes("pversion_bytes", &encoded);
    ctx.eq_u64("pversion_roundtrip", bytes::get16(&encoded) as u64);

    ctx.eq_bytes(
        "port1_bytes",
        &bytes::put16(ctx.constant(&["PORT1"]) as u16),
    );
    ctx.eq_bytes(
        "port2_bytes",
        &bytes::put16(ctx.constant(&["PORT2"]) as u16),
    );
    ctx.eq_bytes(
        "op_tx_bytes",
        &bytes::put16(ctx.constant(&["opcodes", "OP_TX"]) as u16),
    );
}

fn crc16_vector(ctx: &mut Ctx) {
    let input = ctx.hex("in");
    assert_eq!(
        input.len(),
        ctx.u64_("in_len") as usize,
        "{}: {} `in` length disagrees with `in_len`",
        ctx.file,
        ctx.id
    );
    ctx.eq_u64("crc16", crc16::crc16(&input) as u64);
}

// =======================================================================
// Tests
// =======================================================================

#[test]
fn manifest_and_disk_agree() {
    let manifest = support::load_manifest();
    let on_disk: BTreeSet<String> = support::json_files_on_disk().into_iter().collect();
    let listed: BTreeSet<String> = manifest.iter().map(|g| g.file.clone()).collect();

    let unlisted: Vec<&String> = on_disk.difference(&listed).collect();
    let missing: Vec<&String> = listed.difference(&on_disk).collect();

    assert!(
        unlisted.is_empty(),
        "fixture files on disk but absent from manifest.toml: {unlisted:?}\n\
         Every fixture must be listed, active or deferred, so nothing goes unverified in silence."
    );
    assert!(
        missing.is_empty(),
        "manifest.toml lists files that do not exist: {missing:?}"
    );
    assert!(
        !listed.is_empty(),
        "manifest.toml lists no fixture files at all"
    );
}

#[test]
fn manifest_counts_match_the_files() {
    let mut total = 0usize;
    for g in support::load_manifest() {
        let fx = Fixture::load(&g.file);
        let vectors = fx.vectors().len();
        let sources = fx.sources().len();
        assert_eq!(
            vectors, g.vectors,
            "{}: manifest says {} vectors, file has {vectors}",
            g.file, g.vectors
        );
        assert_eq!(
            sources, g.sources,
            "{}: manifest says {} distinct sources, file has {sources}",
            g.file, g.sources
        );
        total += vectors;
    }
    // Stated here as well as in the manifest, and the duplication is the
    // mechanism rather than an oversight: the loop above sums the manifest's
    // own per-group figures, so without a second independently-written total
    // the comparison would have one degree of freedom and could not fail
    // (two degrees of freedom). 176 -> 183 with the seven C4-A crosschecks;
    // 183 -> 189 with group D's six shape-space vectors; 189 -> 213 with
    // group M (6) and group N (18). 217 -> TOTAL_P14 with the bulk
    // corpus -- AK, BK, HS, AKX, CK, plus B's digit sweep, D's
    // count sweep and F's rotation, account and BIP39 captures.
    assert_eq!(total, TOTAL_P14, "corpus vector count changed");
}

#[test]
fn constants_match_the_reference() {
    use mochimo_crypto::consts as k;
    let fx = Fixture::load("group_a_keygen.json");
    let c = fx
        .root
        .get("constants")
        .expect("group_a_keygen.json has no constants block");
    let want = |name: &str| -> usize {
        c.get(name)
            .and_then(|v| v.as_u64())
            .unwrap_or_else(|| panic!("constants block has no `{name}`")) as usize
    };

    // Each of these is the value the C compiler saw when the fixtures were
    // generated, printf'd from the real macro. A Rust constant that disagrees
    // fails here rather than inside a 2144-byte diff. With the bindings gone
    // this is the one comparison the WOTS+ and address widths have.
    assert_eq!(k::PARAMSN, want("PARAMSN"));
    assert_eq!(k::WOTSW, want("WOTSW"));
    assert_eq!(k::WOTSLOGW, want("WOTSLOGW"));
    assert_eq!(k::WOTSLEN1, want("WOTSLEN1"));
    assert_eq!(k::WOTSLEN2, want("WOTSLEN2"));
    assert_eq!(k::WOTSLEN, want("WOTSLEN"));
    assert_eq!(k::WOTSSIGBYTES, want("WOTSSIGBYTES"));
    assert_eq!(k::WOTS_ADDR_LEN, want("WOTS_ADDR_LEN"));
    assert_eq!(k::ADDR_LEN, want("ADDR_LEN"));
    assert_eq!(k::ADDR_TAG_LEN, want("ADDR_TAG_LEN"));
    assert_eq!(k::ADDR_HASH_LEN, want("ADDR_HASH_LEN"));
    assert_eq!(k::SHA256LEN, want("SHA256LEN"));
    assert_eq!(k::SHA3LEN512, want("SHA3LEN512"));
    assert_eq!(k::RIPEMDLEN160, want("RIPEMDLEN160"));
    assert_eq!(k::CRC16LEN, want("CRC16LEN"));
    assert_eq!(k::PK_LEN, want("WOTS_PK_LEN"));
    assert_eq!(k::SIG_LEN, want("WOTS_SIG_LEN"));
}

#[test]
fn active_groups_replay() {
    let manifest = support::load_manifest();
    let mut failures: Vec<String> = Vec::new();
    let mut tally: BTreeMap<Disposition, usize> = BTreeMap::new();
    let mut replayed_total = 0usize;
    let mut fields_total = 0usize;

    for g in manifest.iter().filter(|g| g.is_active()) {
        let fx = Fixture::load(&g.file);
        let vectors = fx.vectors();
        let mut in_group = 0usize;

        for v in &vectors {
            let mut ctx = Ctx::new(&fx.file, &fx.root, v);
            replay(&mut ctx);
            *tally.entry(ctx.disposition).or_default() += 1;
            in_group += 1;
            fields_total += ctx.fields_read();
            failures.extend(ctx.into_failures());
        }

        assert_eq!(
            in_group, g.vectors,
            "{}: replayed {in_group} vectors, manifest says {}",
            g.file, g.vectors
        );
        replayed_total += in_group;
        println!("  group {} ({}): {in_group} vectors replayed", g.id, g.name);
    }

    for g in manifest.iter().filter(|g| !g.is_active()) {
        if g.activated.is_empty() {
            println!(
                "  group {} ({}): SKIPPED — {} vectors deferred, {} distinct sources unbound",
                g.id, g.name, g.vectors, g.sources
            );
            continue;
        }

        let fx = Fixture::load(&g.file);
        let mut ran = 0usize;
        for id in &g.activated {
            let v = fx.vector_by_id(id);
            let mut ctx = Ctx::new(&fx.file, &fx.root, v);
            replay(&mut ctx);
            *tally.entry(ctx.disposition).or_default() += 1;
            ran += 1;
            fields_total += ctx.fields_read();
            failures.extend(ctx.into_failures());
        }

        // The partition, checked against the file rather than against the
        // manifest's own arithmetic. `still_deferred` is recomputed here from
        // the ids actually present, so a vector cannot go missing between the
        // two halves: an activated id that no longer exists already failed in
        // vector_by_id, and a vector the manifest forgot lands in `deferred`
        // and blows the count.
        let activated: BTreeSet<&str> = g.activated.iter().map(String::as_str).collect();
        let all = fx.vector_ids();
        let deferred = all.iter().filter(|i| !activated.contains(i.as_str())).count();
        assert_eq!(
            ran, g.activated.len(),
            "{}: ran {ran} activated vectors, manifest lists {}",
            g.file,
            g.activated.len()
        );
        assert_eq!(
            deferred, g.still_deferred,
            "{}: the file leaves {deferred} vectors unactivated but the manifest \
             says {}. The manifest states that number rather than deriving it, \
             so this is the check that an id dropped from `activated` cannot \
             quietly stop being replayed.",
            g.file, g.still_deferred
        );

        replayed_total += ran;
        println!(
            "  group {} ({}): DEFERRED — {ran} activated, {deferred} still deferred, \
             {} distinct sources",
            g.id, g.name, g.sources
        );
    }

    assert!(
        replayed_total > 0,
        "no active vectors were replayed; a KAT run must never pass by iterating nothing"
    );
    println!("\n  {replayed_total} vectors replayed in total");
    println!("  {fields_total} fixture fields read and covered");
    for (d, n) in &tally {
        println!("    {d:?}: {n}");
    }

    print_pending(&manifest);

    if !failures.is_empty() {
        panic!(
            "\n\n{} KAT failure(s):\n\n{}\n",
            failures.len(),
            failures.join("\n\n")
        );
    }

    // Vacuity floor for the coverage check, asserted after the failure report
    // above so that a real coverage failure is what the reader sees first. An
    // empty `failures` already proves the walk is non-vacuous; this catches the
    // other order, where nothing is uncovered because nothing was recorded.
    //
    // A floor rather than an equality: the exact number moves whenever a vector
    // is added, and an assertion that must be edited on every unrelated change
    // stops being read.
    //
    // The input that makes this red is `Ctx::check_coverage` going vacuous while
    // `Ctx::get` stops recording -- both at once, which is exactly the state in
    // which every other signal here is silent. Bypassing `get` alone does not
    // reach it: nothing is recorded, so every field reads as uncovered and the
    // panic above fires first with a far more useful message.
    assert!(
        fields_total >= 400,
        "coverage recorded only {fields_total} field reads across {replayed_total} \
         vectors. The accessors are meant to funnel through Ctx::get, so a tally \
         this low means fields are being read without being recorded and the \
         coverage check is passing because it sees nothing."
    );
}

#[test]
fn base58_corpus_replays() {
    let fx = Fixture::load("group_c_addr.json");
    let corpus = fx
        .root
        .get("crc16_base58_corpus")
        .expect("group_c_addr.json has no crc16_base58_corpus");
    let entries = corpus
        .get("entries")
        .and_then(|e| e.as_array())
        .expect("corpus has no entries array");
    let count = corpus
        .get("count")
        .and_then(|c| c.as_u64())
        .expect("corpus has no count") as usize;
    assert_eq!(entries.len(), count, "corpus count disagrees with entries");
    assert!(count > 0, "corpus is empty");

    let mut failures = Vec::new();
    for e in entries {
        // The corpus entries carry `i` rather than `id`/`source`; label them so
        // a failure still points at the right place.
        let i = e.get("i").and_then(|x| x.as_u64()).expect("entry has no `i`");
        let source = corpus
            .get("crc16_source")
            .and_then(|s| s.as_str())
            .unwrap_or("crc16_base58_corpus")
            .to_string();
        let mut ctx = Ctx::labelled(
            &fx.file,
            &fx.root,
            e,
            format!("crc16_base58_corpus[{i}]"),
            source,
        );

        let tag: [u8; 20] = ctx.arr("tag");
        let sum = crc16::crc16(&tag);
        ctx.eq_u64("crc16", sum as u64);

        let mut tag22 = [0u8; 22];
        tag22[..20].copy_from_slice(&tag);
        tag22[20..].copy_from_slice(&bytes::put16(sum));
        ctx.eq_str(
            "base58",
            &base58::encode(&tag22).expect("base58_encode failed"),
        );

        failures.extend(ctx.into_failures());
    }

    println!("  {count} crc16/base58 corpus entries replayed");
    if !failures.is_empty() {
        panic!(
            "\n\n{} corpus failure(s):\n\n{}\n",
            failures.len(),
            failures.join("\n\n")
        );
    }
}

#[test]
fn derived_inputs_are_exactly_as_expected() {
    let expected: BTreeSet<&str> = DERIVED_INPUT_IDS.iter().copied().collect();
    let mut not_called: BTreeSet<String> = NOT_CALLED_IDS.iter().map(|s| s.to_string()).collect();
    // Every group D vector whose handler called the reference is replayed by
    // `reference_verdicts_native` and marked not called. The set is derived
    // from the fixture by SOURCE, the same predicate the dispatch uses.
    {
        let d = Fixture::load("group_d_tx.json");
        for v in d.vectors() {
            let src = v.get("source").and_then(|s| s.as_str()).unwrap_or("");
            if is_reference_only_source(src) {
                not_called.insert(v["id"].as_str().expect("id").to_string());
            }
        }
    }
    let not_called: BTreeSet<&str> = not_called.iter().map(String::as_str).collect();

    let mut derived_found: BTreeSet<String> = BTreeSet::new();
    let mut not_called_found: BTreeSet<String> = BTreeSet::new();

    // Everything the suite replays, which since group D split is not the same
    // as "every vector of every active group".
    for g in support::load_manifest() {
        let fx = Fixture::load(&g.file);
        let ids = if g.is_active() {
            fx.vector_ids()
        } else {
            g.activated.clone()
        };
        for id in &ids {
            let v = fx.vector_by_id(id);
            let mut ctx = Ctx::new(&fx.file, &fx.root, v);
            replay(&mut ctx);
            match ctx.disposition {
                Disposition::DerivedInput => {
                    derived_found.insert(ctx.id.clone());
                }
                Disposition::NotCalled => {
                    not_called_found.insert(ctx.id.clone());
                }
                Disposition::Replayed => {}
            }
        }
    }

    let derived_found: BTreeSet<&str> = derived_found.iter().map(String::as_str).collect();
    let not_called_found: BTreeSet<&str> = not_called_found.iter().map(String::as_str).collect();

    assert_eq!(
        derived_found, expected,
        "the set of vectors whose inputs are reconstructed from prose changed.\n\
         A new one appearing means a fixture grew a prose input; one disappearing \
         means session two fixed it and this list should shrink."
    );
    assert_eq!(
        not_called_found, not_called,
        "the set of vectors that do not invoke the reference changed.\n\
         The crosscheck widening added the two crosscheck vectors for the same two inputs: the \
         reference cannot be called on an all-'1' string in either file, and \
         the CX side is where a second implementation's answer now lives. \
         The derivation port added F-ascii-control, the dead-path control the port has no \
         code for. A SIXTH id appearing means some vector stopped calling \
         the reference without anybody deciding that it should; one \
         disappearing means a handler started computing something it used \
         to declare it could not."
    );

    for id in WEAKLY_CHECKED_IDS {
        assert!(
            expected.contains(id),
            "{id} is listed as weakly checked but not as derived-input"
        );
    }
}

// =======================================================================
// Deferred debt
// =======================================================================

/// Known fixture debt, filed on the group whose data it concerns and printed
/// as one block so the whole of session 2b's scope reads in one place.
///
/// These vectors all still run — this is not a skip list. It prints in every
/// run for the same reason the deferred-group marker (now
/// `no_group_is_deferred_by_manifest_status_not_by_replay`) failed in every
/// run while a group was deferred: debt kept in a commit message or a design
/// doc reaches only whoever already suspects it exists.
fn print_pending(manifest: &[support::Group]) {
    let total: usize = manifest.iter().map(|g| g.pending.len()).sum();
    if total == 0 {
        return;
    }
    println!("\n  PENDING — {total} fixture-generator item(s) owed:");
    for g in manifest {
        for item in &g.pending {
            println!("    [group {}] {}", g.id, wrap(item, 72, 14));
        }
    }
}

/// Soft-wraps at `width`, indenting continuation lines by `indent`, so a long
/// debt entry stays readable in test output.
fn wrap(text: &str, width: usize, indent: usize) -> String {
    let pad = " ".repeat(indent);
    let mut out = String::new();
    let mut col = 0usize;
    for word in text.split_whitespace() {
        if col > 0 && col + 1 + word.len() > width {
            out.push('\n');
            out.push_str(&pad);
            col = 0;
        } else if col > 0 {
            out.push(' ');
            col += 1;
        }
        out.push_str(word);
        col += word.len();
    }
    out
}

/// Session 2b converted the last of session two's prose inputs into recorded
/// fields, and deleted the module that reconstructed them. Nothing enforces
/// that state except this test.
///
/// It reads the harness's own source, because the property is about the
/// harness rather than about any one vector: an assertion phrased over fixture
/// data could not see a handler that starts parsing English again. The needle
/// is assembled at runtime so that this test does not match itself.
#[test]
fn no_input_is_reconstructed_from_prose() {
    let src = include_str!("kat.rs");
    let key = "note";
    let forbidden = [format!("(\"{key}\")"), format!("[\"{key}\"]")];

    let hits: Vec<(usize, &str)> = src
        .lines()
        .enumerate()
        .filter(|(_, l)| forbidden.iter().any(|f| l.contains(f.as_str())))
        .map(|(i, l)| (i + 1, l.trim()))
        .collect();

    assert!(
        hits.is_empty(),
        "the harness reads the `{key}` field at {hits:#?}.\n\
         `{key}` is prose. An input taken from it is a guess dressed as a \
         replay, and the one vector where that guess could not be detected \
         (B-adrs-invariance) sat green in the suite from session two until \
         session 2b. If a vector's input is not recorded as a field, fix the \
         generator -- do not parse the sentence."
    );
}

// =======================================================================
// The transaction-core census
// =======================================================================

/// How many of the 21 transaction-core vectors carry each field that is not
/// universal among them.
///
/// # What this is for, and why coverage is not enough
///
/// `Ctx::check_coverage` is fail-closed over the keys a vector *has*: a field
/// present and unread is a failure. It is therefore structurally unable to see
/// a field that is *absent*. `tx_core` gates every non-universal field on
/// `has()`, so if `group_d_tx.c` lost one of its `verdict()` call sites, the
/// regenerated vector would simply not carry `mdst_val_rc`, the gate would
/// find it missing, the vector would replay green, and the validator would
/// stop being checked with nothing anywhere reporting it. That is the Ds5 trap
/// with the fixture, rather than the harness, as the thing that changed.
///
/// So the shape is stated: a number per field, checked against the number
/// derived from the corpus. It is the same mechanism `manifest.toml` uses for
/// `vectors` and `sources`, applied to field presence.
///
/// Together with coverage the warrant is two-sided: **coverage catches a field
/// the handler did not handle; this catches a field the handler was never
/// offered.**
///
/// The counts are not arbitrary. Reading down `group_d_tx.c`'s call sites:
/// 25 vectors go through `tx_emit` and so carry a wire sidecar (`D6`/`D7` do
/// not); 22 call `mdst_val` and 17 call `tx_val__wots`; 8 of the `mdst_val`
/// calls fail with an `errno` set; `blk_to_live_bytes` is written by `D8`,
/// `D18` and the three `D9`s, `blk_to_live_value` by `D18` and the `D9`s,
/// `rule_not_evaluated` by the `D9`s and `D17`.
///
/// # What the shape-space fill moved, and why every number here rose
///
/// Six vectors were appended to close the shape-space gap that was measured:
/// `D16`/`D16-badref` (a non-zero `MDST::ref` inside a transaction, positive
/// and negative), `D17` (a `chg_addr` whose halves differ), `D18` (four
/// mutually distinct asymmetric 64-bit header values) and
/// `D19-totals`/`D19-fees` (`EMCM_XTXTOTALS` and `EMCM_XTXFEES`, the two
/// uncovered `mdst_val` arms whose subject is a total computed from the
/// destination list).
///
/// All six are signed and all six have `tx_val__wots` run over them, which is
/// why `tx_val__wots_rc` counts six more than the signed-image count would
/// otherwise imply. The three `mdst_val` errnos they add are `EMCM_XTXREF`,
/// `EMCM_XTXTOTALS` and `EMCM_XTXFEES`.
///
/// `D5` is signed exactly as `D4` and carries `D4`'s `tx_val__wots` verdict
/// (VEOK), so no signed vector in the group is missing one.
const TX_CORE_CENSUS: &[(&str, usize)] = &[
    // The Ds12 destination-count sweep added 22 signed, validated images:
    // 25 -> 47, 22 -> 44, 18 -> 40.
    ("wire_file", 47),
    ("wire_len", 47),
    ("mdst_val_rc", 44),
    ("mdst_val_rc_name", 44),
    ("tx_val__wots_rc", 40),
    ("tx_val__wots_rc_name", 40),
    ("mdst_val_errno", 8),
    ("mdst_val_errno_name", 8),
    ("mdst_val_errno_text", 8),
    ("blk_to_live_bytes", 5),
    ("blk_to_live_value", 4),
    ("rule_not_evaluated", 4),
    ("amount0_bytes", 1),
    ("amount0_value", 1),
    ("amount1_bytes", 1),
    ("amount1_value", 1),
    // `D8` records the bytes; `D18` records the bytes and the value. The value
    // keys are the half that actually tests byte order.
    ("send_total_bytes", 2),
    ("send_total_value", 1),
    ("change_total_bytes", 2),
    ("change_total_value", 1),
    ("fee_total_bytes", 2),
    ("fee_total_value", 1),
    ("sizeof_txentry_buffer", 1),
    ("tx_sz_equals_buffer_size", 1),
    // The shape-space fill. `ref0`/`ref1` are on both `D16` (four destinations) and
    // `D16-badref` (two); `ref2`/`ref3` on `D16` alone.
    ("ref0_bytes", 2),
    ("ref1_bytes", 2),
    ("ref2_bytes", 1),
    ("ref3_bytes", 1),
    ("chg_addr_bytes", 1),
    ("src_chg_tag_equal", 1),
    ("src_chg_hash_equal", 1),
    ("chg_tag_half_equals_hash_half", 1),
    ("fee_minimum_destinations", 1),
];

/// The number of fields every transaction-core vector carries: the 35-field
/// layout core plus the four metadata keys `id`, `note`, `falsifies`,
/// `source`.
///
/// Stated so that a core field appearing or disappearing is reported here as
/// well as wherever else it lands. The `tx_core` handler reads all 35 by name,
/// so a core field that vanished already fails in the handler and one that
/// appeared already fails coverage; this makes the number itself auditable
/// rather than leaving the reader to count the handler.
const TX_CORE_UNIVERSAL_KEYS: usize = 39;

#[test]
fn group_d_core_census() {
    let fx = Fixture::load("group_d_tx.json");

    let core: Vec<&serde_json::Value> = fx
        .vectors()
        .into_iter()
        .filter(|v| {
            v.get("source")
                .and_then(|s| s.as_str())
                .is_some_and(|s| TX_CORE_SOURCES.contains(&s))
        })
        .collect();

    // The domain is derived from the artifact, not typed: it is exactly the
    // vectors `replay()` sends to `tx_core`, selected by the same constant.
    assert_eq!(
        core.len(),
        49,
        "the transaction-core sources {TX_CORE_SOURCES:?} now select {} vectors, not 49. \
         Either a vector was added or removed upstream, or a source string moved; \
         both change what the census below describes. It was 21 until the six \
         that close the shape-space gap were appended, and 27 until the \
         22-count Ds12 sweep was.",
        core.len()
    );

    let keys = |v: &serde_json::Value| -> BTreeSet<String> {
        v.as_object()
            .expect("a vector is not a JSON object")
            .keys()
            .cloned()
            .collect()
    };

    let mut universal = keys(core[0]);
    for v in &core {
        universal = universal.intersection(&keys(v)).cloned().collect();
    }
    assert_eq!(
        universal.len(),
        TX_CORE_UNIVERSAL_KEYS,
        "the {} transaction-core vectors now share {} keys, not {TX_CORE_UNIVERSAL_KEYS}. \
         The `tx_core` handler mirrors a 35-field core plus four metadata keys; a change here \
         means the core itself moved.\n  shared: {universal:?}",
        core.len(),
        universal.len()
    );

    let mut found: BTreeMap<&str, usize> = BTreeMap::new();
    for v in &core {
        for k in keys(v) {
            if !universal.contains(&k) {
                // The key is borrowed from the census where it is listed, so an
                // unlisted key is reported by its own name below rather than
                // needing an owned copy here.
                let name = TX_CORE_CENSUS
                    .iter()
                    .map(|(n, _)| *n)
                    .find(|n| *n == k)
                    .unwrap_or("");
                if name.is_empty() {
                    panic!(
                        "group_d_tx.json: `{k}` is carried by some but not all of the 21 \
                         transaction-core vectors and is not listed in TX_CORE_CENSUS. \
                         A non-universal field has to be counted there, or tx_core's \
                         has()-gate for it could go missing without anything failing."
                    );
                }
                *found.entry(name).or_default() += 1;
            }
        }
    }

    // Reported per field rather than as two whole maps: the point of the
    // census is to name which count moved, and a diff of twenty-one pairs
    // makes the reader do that work.
    let mut moved: Vec<String> = Vec::new();
    for (key, stated) in TX_CORE_CENSUS {
        let actual = found.get(key).copied().unwrap_or(0);
        if actual != *stated {
            moved.push(format!(
                "  {key}: census says {stated} vector(s) carry it, the corpus has {actual}"
            ));
        }
    }
    assert!(
        moved.is_empty(),
        "the transaction-core field census disagrees with group_d_tx.json:\n{}\n\n\
         A count that dropped means a call site disappeared from \
         reference/gen-fixtures/src/group_d_tx.c and a validator or value silently \
         stopped being checked -- tx_core gates on has(), so nothing else in the \
         suite can see it. A count that rose means a vector gained a field the \
         handler may not read. Fix the harness or update the census deliberately; \
         do not adjust the number to match.",
        moved.join("\n")
    );
}

// =======================================================================
// The censuses over the remaining eighteen
// =======================================================================

/// The shared half of every group D field census.
///
/// `group_d_core_census` predates this and keeps its own body: it carries an
/// extra check nothing else needs — that an unlisted non-universal key is a
/// panic naming that key — and folding the two would have meant either losing
/// that or giving three callers a parameter only one uses. Written out once
/// here for the three census arms instead, so the three cannot drift from each
/// other.
///
/// Every argument is a stated number rather than a derived one, which is the
/// entire point: deriving `expect_vectors` from the selection, or
/// `expect_universal` from the intersection, would make each comparison a
/// tautology and the census would agree with whatever the corpus happened to
/// be.
fn field_census(
    label: &str,
    sources: &[&str],
    expect_vectors: usize,
    expect_universal: usize,
    census: &[(&str, usize)],
) {
    let fx = Fixture::load("group_d_tx.json");
    let selected: Vec<&serde_json::Value> = fx
        .vectors()
        .into_iter()
        .filter(|v| {
            v.get("source")
                .and_then(|s| s.as_str())
                .is_some_and(|s| sources.contains(&s))
        })
        .collect();

    assert_eq!(
        selected.len(),
        expect_vectors,
        "{label}: the source(s) {sources:?} now select {} vectors, not \
         {expect_vectors}. Either a vector moved between sources or one was \
         added or removed; both change what this census describes.",
        selected.len()
    );

    let keys = |v: &serde_json::Value| -> BTreeSet<String> {
        v.as_object()
            .expect("a vector is not a JSON object")
            .keys()
            .cloned()
            .collect()
    };

    let mut universal = keys(selected[0]);
    for v in &selected {
        universal = universal.intersection(&keys(v)).cloned().collect();
    }
    assert_eq!(
        universal.len(),
        expect_universal,
        "{label}: the {expect_vectors} vectors now share {} keys, not \
         {expect_universal}.\n  shared: {universal:?}",
        universal.len()
    );

    let mut found: BTreeMap<String, usize> = BTreeMap::new();
    for v in &selected {
        for k in keys(v) {
            if !universal.contains(&k) {
                *found.entry(k).or_default() += 1;
            }
        }
    }

    let mut moved: Vec<String> = Vec::new();
    for (key, stated) in census {
        let actual = found.get(*key).copied().unwrap_or(0);
        if actual != *stated {
            moved.push(format!(
                "  {key}: census says {stated} vector(s) carry it, the corpus \
                 has {actual}"
            ));
        }
    }
    for key in found.keys() {
        if !census.iter().any(|(n, _)| n == key) {
            moved.push(format!(
                "  {key}: carried by some but not all of the {expect_vectors} \
                 vectors and absent from the census. A non-universal field has \
                 to be counted, or the handler's has()-gate for it could go \
                 missing without anything failing"
            ));
        }
    }

    assert!(
        moved.is_empty(),
        "{label} disagrees with group_d_tx.json:\n{}\n\n\
         A count that dropped means a call site disappeared from \
         reference/gen-fixtures/src/group_d_tx.c and a value or a verdict \
         silently stopped being checked -- the handler gates on has(), so \
         nothing else in the suite can see it. A count that rose means a \
         vector gained a field the handler may not read. Fix the harness or \
         move the census deliberately; do not adjust the number to match.",
        moved.join("\n")
    );

    println!("  {label}: {expect_vectors} vectors, {expect_universal} universal keys, {} counted fields", census.len());
}

/// `Ds7`..`Ds11`, the six signature negatives.
///
/// Universal: the four metadata keys, the two `validated_wire` keys, and the
/// verdict's `rc` pair — eight. Everything else is per-vector and counted:
///
/// * `adrs` — `Ds7` alone, the only one that corrupts the address scheme.
/// * `src_addr` — `Ds8`, `Ds8b`, `Ds9`, the three that touch the source
///   address.
/// * `tag_half_equals_hash_half` — `Ds8b` alone.
/// * `baseline_wire_*` and the three `message_hash_*` — `Ds8` alone, the only
///   negative that records a value taken before its own mutation.
/// * the `errno` triple — five of six. `Ds8b` is the exception because it
///   *passes*: `tx_val__wots` checks `ADDR_HASH_PTR` alone, so a tag half that
///   is not the address hash is accepted and no `errno` is set.
const SIGNATURE_NEGATIVE_CENSUS: &[(&str, usize)] = &[
    ("adrs", 1),
    ("src_addr", 3),
    ("tag_half_equals_hash_half", 1),
    ("baseline_wire_file", 1),
    ("baseline_wire_len", 1),
    ("message_hash_before", 1),
    ("message_hash_after", 1),
    ("message_hash_changed", 1),
    ("tx_val__wots_errno", 5),
    ("tx_val__wots_errno_name", 5),
    ("tx_val__wots_errno_text", 5),
];

#[test]
fn group_d_signature_negative_census() {
    field_census(
        "the signature-negative census",
        &["tx_val__wots() @ reference/mochimo-core/src/tx.c:653"],
        6,
        8,
        SIGNATURE_NEGATIVE_CENSUS,
    );
}

/// The eight `tx_hash` vectors, and the measurement that justifies splitting
/// them.
///
/// **`expect_universal` is 4 — the metadata keys and nothing else.** That is
/// the whole argument for `tx_hash_vector`'s shape dispatch, asserted rather
/// than asserted-in-prose: `Ds1-N*` and `Ds3`/`Ds4`/`Ds5` share no data field
/// at all. If a later change gave them one, this number moves and whoever
/// reads the failure is looking at the premise the split rests on.
///
/// `hash_unchanged` 2 against `hash_changed` 1 is the Ds5 trap stated as a
/// number. A generator change that made all three carry `hash_unchanged` would
/// destroy the control, and `tx_hash_mutation`'s exhaustive match would still
/// pass — every vector would take a valid arm. This is the only thing that
/// notices.
const TX_HASH_CENSUS: &[(&str, usize)] = &[
    // The Ds1-N* shape: both hashes of one entry, with the range each covers.
    ("ndst", 5),
    ("message_hash", 5),
    ("message_hash_len", 5),
    ("id_hash", 5),
    ("id_hash_len", 5),
    ("message_hash_input_file", 5),
    ("message_hash_input_len", 5),
    ("hashed_wire_file", 5),
    ("hashed_wire_len", 5),
    ("hashes_differ", 5),
    // The Ds3/Ds4/Ds5 shape: one hash of each of two entries.
    ("baseline_wire_file", 3),
    ("baseline_wire_len", 3),
    ("mutated_wire_file", 3),
    ("mutated_wire_len", 3),
    ("baseline_hash", 3),
    ("mutated_hash", 3),
    ("hash_unchanged", 2),
    ("hash_changed", 1),
];

#[test]
fn group_d_tx_hash_census() {
    field_census(
        "the tx_hash census",
        &["tx_hash() @ reference/mochimo-core/src/tx.c:447"],
        8,
        4,
        TX_HASH_CENSUS,
    );
}

/// The three vectors carrying a `cases` array: how many cases, and how many
/// keys each case has.
///
/// # Why this is not `field_census`
///
/// The other censuses count fields across vectors. Here the population is
/// *inside* a vector, and the property that matters is different: within one
/// `cases` array every element must have the **same** keys. `D11`'s five cases
/// all carry `result_errno_set`; `D10`'s four all do not; `D15`'s three all
/// carry the full `tx_read` verdict. A case that gained or lost a key relative
/// to its siblings is exactly what the recursion's per-case coverage cannot
/// see — coverage is fail-closed over what a case *has* — so it is asserted
/// here as "no non-universal key, anywhere".
///
/// The case counts are stated because an array that shrank would descend over
/// fewer cases, and every one of them would pass.
const CASES_CENSUS: &[(&str, usize, usize)] = &[
    // id, cases, keys per case
    //
    // D10: ref, ref_bytes, result_rc, result_rc_name. Four accepted
    // references, so no errno half at all.
    ("D10", 4, 4),
    // D11: the same four plus result_errno_set. mdst_val__reference rejects
    // without touching errno, and these five are the corpus's only exercise of
    // that arm of the verdict mirror outside D-badtype-*.
    ("D11", 5, 5),
    // D15: case, options, case_wire_file, case_wire_len, and the full five-key
    // tx_read verdict -- rc, rc_name and the errno triple.
    ("D15", 3, 9),
];

#[test]
fn group_d_cases_census() {
    let fx = Fixture::load("group_d_tx.json");

    let mut nested = 0usize;
    for v in fx.vectors() {
        if v.get("cases").is_some() {
            nested += 1;
        }
    }
    assert_eq!(
        nested,
        CASES_CENSUS.len(),
        "group_d_tx.json has {nested} vector(s) carrying a `cases` array, not \
         {}. Every one needs an entry here and a handler that descends with \
         Ctx::cases; a vector that gained one would otherwise fail coverage \
         with no census saying which.",
        CASES_CENSUS.len()
    );

    for (id, want_cases, want_keys) in CASES_CENSUS {
        let v = fx.vector_by_id(id);
        let cases = v
            .get("cases")
            .and_then(|c| c.as_array())
            .unwrap_or_else(|| panic!("group_d_tx.json: vector {id} has no `cases` array"));

        assert_eq!(
            cases.len(),
            *want_cases,
            "group_d_tx.json: vector {id} now has {} cases, not {want_cases}. \
             An array that shrank descends over fewer inputs and every one of \
             them passes.",
            cases.len()
        );

        let keys = |c: &serde_json::Value| -> BTreeSet<String> {
            c.as_object()
                .unwrap_or_else(|| panic!("group_d_tx.json: {id}'s cases hold a non-object"))
                .keys()
                .cloned()
                .collect()
        };

        let mut universal = keys(&cases[0]);
        let mut all: BTreeSet<String> = BTreeSet::new();
        for c in cases {
            universal = universal.intersection(&keys(c)).cloned().collect();
            all.extend(keys(c));
        }

        let ragged: Vec<&String> = all.difference(&universal).collect();
        assert!(
            ragged.is_empty(),
            "group_d_tx.json: vector {id}'s cases do not all carry the same \
             keys -- {ragged:?} is on some and not others. Per-case coverage \
             is fail-closed over the keys a case HAS, so a case that lost one \
             replays green with that value unchecked. Either the generator \
             changed or this vector needs splitting into two."
        );
        assert_eq!(
            universal.len(),
            *want_keys,
            "group_d_tx.json: vector {id}'s cases carry {} keys each, not \
             {want_keys}.\n  keys: {universal:?}",
            universal.len()
        );
    }

    println!(
        "  cases census: {} vectors, {} cases total",
        CASES_CENSUS.len(),
        CASES_CENSUS.iter().map(|(_, n, _)| n).sum::<usize>()
    );
}

/// The machine-readable half of `rule_not_evaluated`.
///
/// Four vectors carry a sentence saying a *rule* lives in `tx_val`, which
/// needs an open ledger and so is not called — only the
/// encoding is pinned. Three are the `D9`s, whose rule is the block-to-live
/// range; the fourth is `D17`, whose rule is the src/chg address
/// relationship. That sentence is a `jw_str` literal identical in all four, so
/// comparing it to a Rust copy would assert that two copies of one sentence
/// agree. Its real content is an absence, and this is that absence stated as
/// an assertion: if the generator ever does reach `tx_val`, a vector will cite
/// it as a source, and all four disclaimers become false.
///
/// The needle is assembled rather than written, and terminated with `()` so it
/// cannot match `tx_val__wots()` — a different function that six vectors
/// legitimately do cite, and which `contains` would otherwise swallow, since
/// substring matching has no notion of where an identifier ends.
///
/// # The needle is in the corpus, and that is deliberate
///
/// `tx_val() @` appears verbatim four times in `group_d_tx.json` — inside
/// `rule_not_evaluated` itself, the field this test is the counterpart to.
/// A scan over the file *text* would match the prose describing the absence it
/// asserts and this test could never fail. That is a check reading its own prose, in JSON
/// rather than in Rust, and it is avoided here only because the walk reads the
/// `source` key rather than the bytes of the file.
///
/// So both halves are asserted below. The raw text **must** contain the
/// needle, which proves the needle is matchable at all — a misspelled one
/// would match nothing anywhere and this test would stay green for ever — and
/// the walk over `source` **must not**. Widening the walk to the file text
/// turns the second assertion red instead of quietly satisfying the first.
#[test]
fn tx_val_is_absent_from_the_corpus() {
    let function = "tx_val";
    let needle = format!("{function}() @");

    let mut citations: Vec<String> = Vec::new();
    let mut scanned = 0usize;
    let mut in_prose = 0usize;
    for file in support::json_files_on_disk() {
        let fx = Fixture::load(&file);
        for source in fx.sources() {
            scanned += 1;
            if source.contains(&needle) {
                citations.push(format!("  {file}: {source}"));
            }
        }
        let raw = std::fs::read_to_string(support::fixtures_dir().join(&file))
            .unwrap_or_else(|e| panic!("cannot read {file}: {e}"));
        in_prose += raw.matches(&needle).count();
    }

    // Without this the check passes on an empty walk, which is the one state
    // in which it proves nothing at all.
    assert!(
        scanned >= 20,
        "only {scanned} source strings were scanned across the corpus; that is a \
         walk that failed, not a corpus in which {function} is absent"
    );
    // And without this a needle that matches nothing anywhere -- a typo, a
    // renamed function -- reads as an absence rather than as a broken check.
    assert!(
        in_prose > 0,
        "the needle `{needle}` does not occur anywhere in the corpus text, not \
         even in the four `rule_not_evaluated` sentences where it is known to \
         be. A needle that cannot match is not evidence of an absence."
    );
    assert!(
        citations.is_empty(),
        "{} vector source(s) now cite {function}:\n{}\n\n\
         Four vectors carry `rule_not_evaluated` saying {function} cannot be \
         called because it needs an open ledger -- the three D9s for the \
         block-to-live range, D17 for the src/chg address relationship. If it \
         can be called, that sentence is stale and both rules are owed a real \
         verdict rather than a disclaimer.",
        citations.len(),
        citations.join("\n")
    );
}

/// No group in the manifest is `deferred` — **a statement about
/// `manifest.toml`'s status field, and only that.** Whether every vector of
/// an active group actually replays is `active_groups_replay`'s claim,
/// asserted there against the files; this test never opens a fixture.
///
/// # What this was, and why it is renamed rather than deleted
///
/// The bound is in the name — "by manifest status, not by replay" — because
/// a green "no group is deferred" would otherwise read as replay having been
/// verified *here*. It is not; it is measured by the test named above.
///
/// # Why this is not `group_d_is_deferred`
///
/// It was, and the id was hardcoded. That was correct for exactly as long as D
/// was the only deferred group, and group F arrived and was not covered: the
/// manifest listed it `deferred`, `active_groups_replay` printed
/// `SKIPPED — 15 vectors deferred`, every test passed, and nothing failed. Debt
/// that prints while the suite reports success is debt in a commit message
/// wearing a costume.
///
/// So the domain is read out of the manifest instead of typed here:
/// *every* group whose status is `deferred`. A group deferred in a later
/// session — or one sent back to `deferred` — is reported on the day it is
/// written, by nobody remembering anything; that is the regression this now
/// guards against, and the message below is written for it.
#[test]
fn no_group_is_deferred_by_manifest_status_not_by_replay() {
    let manifest = support::load_manifest();

    // A manifest that failed to parse into groups would report nothing
    // deferred, which reads exactly like a clean manifest.
    assert!(
        manifest.len() >= 5,
        "the manifest loaded only {} group(s); with a corpus this size that is \
         a parse failure, and an empty manifest defers nothing by vacuity",
        manifest.len()
    );

    let deferred: Vec<_> = manifest.iter().filter(|g| g.status == "deferred").collect();
    if deferred.is_empty() {
        println!(
            "  no group is deferred in manifest.toml: {} groups, every one `active`. \
             That is the status field only; whether each active group's vectors \
             replay is active_groups_replay's claim, asserted there.",
            manifest.len()
        );
        return;
    }

    for g in &deferred {
        println!("  group {} ({}):", g.id, g.name);
        if let Some(reason) = &g.reason {
            println!("    reason: {}", reason.trim());
        }
        if g.activated.is_empty() {
            println!("    no vector replays yet");
        } else {
            println!(
                "    {} of {} vectors now replay: {}",
                g.activated.len(),
                g.vectors,
                g.activated.join(", ")
            );
        }
    }

    let summary: Vec<String> = deferred
        .iter()
        .map(|g| format!("{} ({} of {})", g.id, g.still_deferred, g.vectors))
        .collect();
    let total: usize = deferred.iter().map(|g| g.still_deferred).sum();
    panic!(
        "{} group(s) deferred, {total} vectors replayed nowhere: {}\n\
         Every group has been `active` since group F, the last, was activated when \
         the derivation landed). A group listed `deferred` again is either new \
         corpus with no consumer yet or a group sent back; either way its \
         vectors run in no test until it activates, and this red is where that \
         debt is visible. Replay of the active groups is active_groups_replay's \
         claim, not this test's.",
        deferred.len(),
        summary.join(", ")
    );
}

/// The 33 group E constants, compared against the fixture the C `printf`'d.
///
/// This is the check that anchors them. Every value below is the crate's own
/// literal on one side and the fixture's on the other; a transcription error
/// in either fails here by name, and
/// `invariants.rs::group_e_constants_stay_anchored` demands that it runs.
#[test]
fn group_e_constants_match_the_reference() {
    use mochimo_crypto::consts::net as k;

    let fx = Fixture::load("group_e_net.json");
    let c = fx
        .root
        .get("constants")
        .expect("group_e_net.json has no constants block");

    let at = |node: &serde_json::Value, name: &str| -> u64 {
        node.get(name)
            .and_then(|v| v.as_u64())
            .unwrap_or_else(|| panic!("group_e_net.json constants has no `{name}`"))
    };
    let ops = c
        .get("opcodes")
        .expect("group_e_net.json constants has no `opcodes` block");

    let mut checked = 0usize;
    let mut check = |name: &str, rust: u64, fixture: u64| {
        assert_eq!(
            rust, fixture,
            "group E constant {name}: the crate's literal says {rust}, the \
             fixture the reference printf'd says {fixture}"
        );
        checked += 1;
    };

    check("PVERSION", k::PVERSION as u64, at(c, "PVERSION"));
    check("CBITS", k::CBITS as u64, at(c, "CBITS"));
    check("TXNETWORK", k::TXNETWORK as u64, at(c, "TXNETWORK"));
    check("TXEOT", k::TXEOT as u64, at(c, "TXEOT"));
    check("PORT1", k::PORT1 as u64, at(c, "PORT1"));
    check("PORT2", k::PORT2 as u64, at(c, "PORT2"));
    check("WORD16_MAX", k::word16_max() as u64, at(c, "WORD16_MAX"));

    // Three of the four the constants block carries that are not `net`
    // values. The two lengths are sums of sizeof expressions the crate
    // carries as `consts::wire`; `sizeof_TX`, the network packet container's
    // size, was read off the bound C struct and this crate has no literal for
    // it, so it is compared to nothing, by decision: the census in
    // tests/invariants.rs excludes it by name with the reason. CRC16LEN is
    // also pinned by group A, and
    // asserting it in both places is what would catch the two fixtures
    // disagreeing with each other.
    check(
        "TXLEN_MIN",
        mochimo_crypto::tx::len_min() as u64,
        at(c, "TXLEN_MIN"),
    );
    check(
        "TXLEN_DSK_MIN",
        mochimo_crypto::tx::len_dsk_min() as u64,
        at(c, "TXLEN_DSK_MIN"),
    );
    check(
        "CRC16LEN",
        mochimo_crypto::consts::CRC16LEN as u64,
        at(c, "CRC16LEN"),
    );

    check("FIRST_OP", k::FIRST_OP as u64, at(ops, "FIRST_OP"));
    check("LAST_OP", k::LAST_OP as u64, at(ops, "LAST_OP"));
    check("OP_NULL", k::OP_NULL as u64, at(ops, "OP_NULL"));
    check("OP_HELLO", k::OP_HELLO as u64, at(ops, "OP_HELLO"));
    check("OP_HELLO_ACK", k::OP_HELLO_ACK as u64, at(ops, "OP_HELLO_ACK"));
    check("OP_TX", k::OP_TX as u64, at(ops, "OP_TX"));
    check("OP_FOUND", k::OP_FOUND as u64, at(ops, "OP_FOUND"));
    check("OP_GET_BLOCK", k::OP_GET_BLOCK as u64, at(ops, "OP_GET_BLOCK"));
    check("OP_GET_IPL", k::OP_GET_IPL as u64, at(ops, "OP_GET_IPL"));
    check("OP_SEND_FILE", k::OP_SEND_FILE as u64, at(ops, "OP_SEND_FILE"));
    check("OP_SEND_IPL", k::OP_SEND_IPL as u64, at(ops, "OP_SEND_IPL"));
    check("OP_BUSY", k::OP_BUSY as u64, at(ops, "OP_BUSY"));
    check("OP_NACK", k::OP_NACK as u64, at(ops, "OP_NACK"));
    check("OP_GET_TFILE", k::OP_GET_TFILE as u64, at(ops, "OP_GET_TFILE"));
    check("OP_BALANCE", k::OP_BALANCE as u64, at(ops, "OP_BALANCE"));
    check("OP_SEND_BAL", k::OP_SEND_BAL as u64, at(ops, "OP_SEND_BAL"));
    check("OP_RESOLVE", k::OP_RESOLVE as u64, at(ops, "OP_RESOLVE"));
    check("OP_GET_CBLOCK", k::OP_GET_CBLOCK as u64, at(ops, "OP_GET_CBLOCK"));
    check("OP_MBLOCK", k::OP_MBLOCK as u64, at(ops, "OP_MBLOCK"));
    check("OP_HASH", k::OP_HASH as u64, at(ops, "OP_HASH"));
    check("OP_TF", k::OP_TF as u64, at(ops, "OP_TF"));
    check("OP_IDENTIFY", k::OP_IDENTIFY as u64, at(ops, "OP_IDENTIFY"));

    // Every integer the block carries but `sizeof_TX` (above). The two
    // non-integers -- `note` and `opcodes.valid_op_rule` -- are prose and are
    // asserted against nothing here by design; valid_op is handled in
    // tests/net.rs.
    assert_eq!(
        checked, 32,
        "group E anchors {checked} constants, expected 32. A constant dropped \
         from this test is a constant back to agreeing only with itself, which \
         is the exact state this test was written to end."
    );
    println!("  {checked} group E constants anchored to the fixture the reference printf'd");
}

/// Prints the weakly-anchored list. It is not a failure — it is the visibility
/// condition attached to granting the exception in the first place.
#[test]
fn weakly_anchored_definitions_are_named() {
    assert_eq!(
        WEAKLY_ANCHORED.len(),
        1,
        "the weakly-anchored set changed. Each entry is a definition checked \
         against the reference less strictly than everything else, and adding \
         one is a decision that belongs in the specification's Open items before it \
         belongs here."
    );
    println!("\n  WEAKLY ANCHORED — {} definition(s):", WEAKLY_ANCHORED.len());
    for (what, why) in WEAKLY_ANCHORED {
        println!("    {what}\n      {}", wrap(why, 70, 6));
    }
}

// =======================================================================
// Group D without the C: the native round trip, and the verdicts as knowledge
// =======================================================================

/// The group D sources whose handlers called the reference validators or the
/// reference's own transaction struct. In this repository they route to
/// [`reference_verdicts_native`]. Kept as one list so the dispatch and the
/// not-called census below agree by construction.
const REFERENCE_ONLY_SOURCES: [&str; 6] = [
    "tx__init() @ reference/mochimo-core/src/tx.c:146",
    "tx__init() @ reference/mochimo-core/src/tx.c:156",
    "mdst_val__reference() @ reference/mochimo-core/src/tx.c:510",
    "tx_read() @ reference/mochimo-core/src/tx.c:474",
    "tx__init / tx_read() @ reference/mochimo-core/src/tx.c:119,474",
    "tx_hash() @ reference/mochimo-core/src/tx.c:447",
];

/// Whether a group D vector's verdicts are the reference's and not this
/// crate's: true for every source in [`REFERENCE_ONLY_SOURCES`], for
/// `tx_val__wots`, and for the transaction-core sources.
fn is_reference_only_source(s: &str) -> bool {
    REFERENCE_ONLY_SOURCES.contains(&s)
        || s == "tx_val__wots() @ reference/mochimo-core/src/tx.c:653"
        || TX_CORE_SOURCES.contains(&s)
}

/// Reads every field of a case object so coverage sees it; the values are the
/// reference's and are not recomputed here.
fn touch_all(ctx: &mut Ctx) {
    let Some(obj) = ctx.v.as_object() else { return };
    let keys: Vec<(String, serde_json::Value)> = obj.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    let has_file = |k: &str| keys.iter().any(|(kk, _)| kk == &format!("{k}_file"));
    for (k, val) in &keys {
        if ["id", "note", "falsifies", "source"].contains(&k.as_str()) {
            continue;
        }
        if let Some(stem) = k.strip_suffix("_file") {
            // `blob` reads `<stem>_file` and `<stem>_len` and checks the sidecar.
            let _ = ctx.blob(stem);
            continue;
        }
        if let Some(stem) = k.strip_suffix("_len") {
            if has_file(stem) {
                continue;
            }
        }
        if val.as_array().is_some_and(|a| a.iter().any(serde_json::Value::is_object)) {
            ctx.cases(k, touch_all);
            continue;
        }
        let _ = ctx.touch(k);
    }
}

/// The group D replay for a build with no C: the wire image round-trips
/// through `tx::wire::Transaction` byte for byte and the layout the vector
/// records is asserted against the native serializer; the validator verdicts
/// (`mdst_val`, `tx_val__wots`, `tx_read`, `tx__init`'s rejections) are read
/// and marked NOT CALLED, because this crate has no validator to call. They are
/// the specification of what a node does, carried as knowledge.
fn reference_verdicts_native(ctx: &mut Ctx) {
    use mochimo_crypto::tx::wire::Transaction;

    if ctx.has("wire_file") {
        let wire = ctx.blob("wire");
        let id = ctx.id.clone();
        let parsed = Transaction::from_wire(&wire)
            .unwrap_or_else(|e| panic!("{id}: the native serializer rejects a recorded wire image: {e}"));
        let again = parsed.to_wire();
        assert!(
            again == wire,
            "{id}: the native serializer does not reproduce the recorded wire image (first difference at byte {})",
            again.iter().zip(wire.iter()).position(|(a, b)| a != b).unwrap_or(again.len().min(wire.len()))
        );
        let n = u64::from(parsed.dst_count());
        let dsa = parsed.dsa_off() as u64;
        let tlr = parsed.tlr_off() as u64;
        ctx.eq_u64("tx_sz", parsed.tx_sz() as u64);
        ctx.eq_u64("ndst", n);
        ctx.eq_u64("mdst_count_from_reference", n);
        ctx.eq_u64("dsaoff", dsa);
        ctx.eq_u64("tlroff", tlr);
        ctx.eq_u64("signed_len", dsa);
        ctx.eq_u64("off_mdst_first", 116);
        ctx.eq_u64("off_mdst_last", 116 + 44 * (n - 1));
        ctx.eq_u64("off_wots_signature", dsa);
        ctx.eq_u64("off_wots_pub_seed", dsa + 2144);
        ctx.eq_u64("off_wots_adrs", dsa + 2176);
        ctx.eq_u64("off_nonce", tlr);
        ctx.eq_u64("off_id", tlr + 8);
        for (key, off) in [
            ("off_src_addr", 4u64), ("off_chg_addr", 44), ("off_send_total", 84), ("off_change_total", 92),
            ("off_fee_total", 100), ("off_blk_to_live", 108),
            ("entry_off_hdr", 0), ("entry_off_dat", 116), ("entry_off_options", 0), ("entry_off_src_addr", 4),
            ("entry_off_chg_addr", 44), ("entry_off_send_total", 84), ("entry_off_change_total", 92),
            ("entry_off_tx_fee", 100), ("entry_off_tx_btl", 108), ("entry_off_mdst", 116),
        ] {
            ctx.eq_u64(key, off);
        }
        ctx.eq_u64("entry_off_dsa", dsa);
        ctx.eq_u64("entry_off_wots", dsa);
        ctx.eq_u64("entry_off_tlr", tlr);
        ctx.eq_u64("entry_off_tx_nonce", tlr);
        ctx.eq_u64("entry_off_tx_id", tlr + 8);
        ctx.eq_u64("options_byte_2", n - 1);
    }
    // The WOTS+ half of the reference's verdict IS reproducible here:
    // `mesh::spend::verify_wots` recovers the public key from the signature and
    // compares its hash with the source address, which is what `tx_val__wots`
    // decides. Every image carrying that verdict is checked against it, so a
    // byte changed anywhere under the signature is caught in this file and not
    // only by `tests/spend.rs`. The `mdst_val` half stays the reference's.
    for image_key in ["wire", "validated_wire"] {
        if ctx.has(&format!("{image_key}_file")) && ctx.has("tx_val__wots_rc_name") {
            let bytes = ctx.blob(image_key);
            let id = ctx.id.clone();
            let parsed = Transaction::from_wire(&bytes)
                .unwrap_or_else(|e| panic!("{id}: the native serializer rejects a recorded {image_key} image: {e}"));
            let want_ok = ctx.str_("tx_val__wots_rc_name") == "VEOK";
            let got = mochimo_crypto::mesh::spend::verify_wots(&parsed);
            assert_eq!(
                got.is_ok(),
                want_ok,
                "{id}: the reference's tx_val__wots verdict on {image_key} is {} and verify_wots says {got:?}",
                if want_ok { "VEOK" } else { "a refusal" }
            );
        }
    }
    if ctx.has("hashed_wire_file") {
        let hashed = ctx.blob("hashed_wire");
        let id = ctx.id.clone();
        let parsed = Transaction::from_wire(&hashed)
            .unwrap_or_else(|e| panic!("{id}: the native serializer rejects a recorded hashed image: {e}"));
        ctx.eq_bytes("message_hash", &parsed.message_digest());
        ctx.eq_bytes("id_hash", &parsed.id_digest());
    }
    touch_all(ctx);
    ctx.mark(Disposition::NotCalled);
}

// =======================================================================
// The bulk corpus: the artifact policy and its censuses
// =======================================================================

/// Every group states, in its own header, whether an artifact wider than
/// `JW_INLINE_MAX` is carried whole (a `.bin` sidecar) or as its sha256, and
/// this holds the statement to the file in both directions. A digest group
/// that carried a sidecar would be a group whose size argument
/// stopped applying; a whole-artifact group that carried a digest in place of
/// bytes would be a byte-level diff quietly downgraded to a yes/no. A file
/// with no `artifacts` key is a whole-artifact group, because that is what
/// every group was before the bulk corpus.
///
/// The input that makes this red: a `_file` key in AK, BK, AKX or CK, or a
/// `_sha256` key anywhere else. Both directions were injected.
#[test]
fn artifact_policy_is_declared_by_the_generator_and_enforced_here() {
    let mut digest_groups: Vec<String> = Vec::new();
    let mut whole_groups: Vec<String> = Vec::new();
    let mut offences: Vec<String> = Vec::new();

    for g in support::load_manifest() {
        let fx = Fixture::load(&g.file);
        let policy = fx
            .root
            .get("artifacts")
            .map(|a| {
                a.as_str().unwrap_or_else(|| panic!("{}: `artifacts` is not a string", g.file))
                    .to_string()
            })
            .unwrap_or_else(|| "whole".to_string());
        let (forbidden, list): (&str, &mut Vec<String>) = match policy.as_str() {
            "digest" => ("_file", &mut digest_groups),
            "whole" => ("_sha256", &mut whole_groups),
            other => panic!(
                "{}: `artifacts` is {other:?}; the policy is \"digest\" or \"whole\" and \
                 nothing else, so a third word would be a group nobody's check applies to",
                g.file
            ),
        };
        list.push(g.id.clone());
        for v in fx.vectors() {
            let Some(obj) = v.as_object() else { continue };
            for k in obj.keys().filter(|k| k.ends_with(forbidden)) {
                offences.push(format!(
                    "  {} ({policy}): vector {} carries `{k}`",
                    g.file,
                    obj.get("id").and_then(|x| x.as_str()).unwrap_or("?")
                ));
            }
        }
    }

    assert!(
        digest_groups.len() >= 2 && whole_groups.len() >= 8,
        "the walk classified {} digest and {} whole-artifact groups; with the \
         corpus this size that is a parse failure rather than a corpus",
        digest_groups.len(),
        whole_groups.len()
    );
    assert!(
        offences.is_empty(),
        "ARTIFACT POLICY VIOLATED\n{}\n  A digest group carries no sidecar and a \
         whole-artifact group carries no digest in place of bytes.",
        offences.join("\n")
    );
    println!("  artifact policy: digest {digest_groups:?}, whole {whole_groups:?}");
}

/// The bulk files state their own populations per source in the header
/// (`count_*`, `*_max_len`) and this holds the `vectors` array to them. Every
/// bulk handler is unconditional in what it reads, so unlike group D no
/// `has()` gate can hide a dropped field; what CAN go unnoticed is a loop
/// bound moving in the generator, and a count the file states about itself is
/// the cheapest check on that. A count is the only thing
/// that notices a vector that stopped being emitted.
#[test]
fn bulk_populations_match_the_headers() {
    fn population(fx: &Fixture, source: &str) -> u64 {
        fx.vectors()
            .iter()
            .filter(|v| v.get("source").and_then(|s| s.as_str()) == Some(source))
            .count() as u64
    }
    fn header(fx: &Fixture, key: &str) -> u64 {
        fx.root
            .get(key)
            .and_then(|x| x.as_u64())
            .unwrap_or_else(|| panic!("{}: header has no integer `{key}`", fx.file))
    }

    let ak = Fixture::load("group_ak_keygen_bulk.json");
    let bk = Fixture::load("group_bk_sign_bulk.json");
    let hs = Fixture::load("group_hs_hash_sweep.json");

    let mut checked = 0usize;
    for (fx, key, source) in [
        (&ak, "count_wots_pkgen", AK_PKGEN),
        (&ak, "count_expand_seed", AK_EXPAND_SEED),
        (&ak, "count_prf", AK_PRF),
        (&ak, "count_thash_f", AK_THASH_F),
        (&ak, "count_gen_chain", AK_GEN_CHAIN),
        (&bk, "count_wots_sign", BK_SIGN),
        (&bk, "count_chain_lengths", BK_CHAIN_LENGTHS),
    ] {
        let want = header(fx, key);
        let got = population(fx, source);
        assert_eq!(got, want, "{}: header says {key} = {want}, the file holds {got}", fx.file);
        assert!(want > 0, "{}: {key} is zero, so the source below it replays nothing", fx.file);
        checked += 1;
    }
    // The header counts must account for the whole file: a source nobody
    // counted is a source the census cannot see shrink.
    assert_eq!(
        ak.vectors().len() as u64,
        ["count_wots_pkgen", "count_expand_seed", "count_prf", "count_thash_f", "count_gen_chain"]
            .iter()
            .map(|k| header(&ak, k))
            .sum::<u64>(),
        "group AK holds vectors its header counts do not account for"
    );
    assert_eq!(
        bk.vectors().len() as u64,
        header(&bk, "count_wots_sign") + header(&bk, "count_chain_lengths"),
        "group BK holds vectors its header counts do not account for"
    );

    // HS: every length in 0..=max for the two hashes the C can always compute.
    for (key, source) in [("sha256_max_len", HS_SHA256), ("sha3_512_max_len", HS_SHA3)] {
        let max = header(&hs, key);
        let lengths: BTreeSet<u64> = hs
            .vectors()
            .iter()
            .filter(|v| v.get("source").and_then(|s| s.as_str()) == Some(source))
            .map(|v| v["inlen"].as_u64().expect("inlen"))
            .collect();
        let want: BTreeSet<u64> = (0..=max).collect();
        assert_eq!(lengths, want, "group HS: {source} does not cover every length in 0..={max}");
        checked += 1;
    }
    assert_eq!(checked, 9);
    println!("  bulk populations: {checked} header counts match the files");
}

/// The lengths the C cannot answer for RIPEMD-160 are exactly the
/// ones group HS omits and exactly the ones group RX carries, so between the
/// two files every length in `0..=ripemd160_max_len` has one recorded digest
/// and no length has two oracles that could be confused for each other.
///
/// Reds when: the generator's omission predicate drifts from `len % 64 >= 56`;
/// group RX stops covering a residue; or a length appears in both.
#[test]
fn hash_sweep_and_rx_partition_the_ripemd160_lengths() {
    let hs = Fixture::load("group_hs_hash_sweep.json");
    let rx = Fixture::load("group_rx_ripemd.json");

    let max = hs.root["ripemd160_max_len"].as_u64().expect("ripemd160_max_len");
    let omitted: BTreeSet<u64> = hs.root["ripemd160_omitted"]
        .as_array()
        .expect("ripemd160_omitted")
        .iter()
        .map(|x| x.as_u64().expect("an omitted length"))
        .collect();
    let present: BTreeSet<u64> = hs
        .vectors()
        .iter()
        .filter(|v| v.get("source").and_then(|s| s.as_str()) == Some(HS_RIPEMD160))
        .map(|v| v["inlen"].as_u64().expect("inlen"))
        .collect();
    let faulting: BTreeSet<u64> = (0..=max).filter(|l| l % 64 >= 56).collect();
    let rx_lengths: BTreeSet<u64> = rx
        .vectors()
        .iter()
        .map(|v| v["in_len"].as_u64().expect("in_len"))
        .filter(|l| *l <= max)
        .collect();

    assert_eq!(omitted, faulting, "group HS omits a set other than the faulting class");
    assert!(present.is_disjoint(&omitted), "group HS carries a length it also declares omitted");
    assert_eq!(
        present.union(&omitted).copied().collect::<BTreeSet<u64>>(),
        (0..=max).collect::<BTreeSet<u64>>(),
        "group HS's present and omitted RIPEMD-160 lengths do not cover 0..={max}"
    );
    assert_eq!(
        rx_lengths, omitted,
        "group RX's lengths at or below {max} are not exactly the ones group HS omits"
    );
    println!(
        "  ripemd160 lengths 0..={max}: {} from the C (HS), {} from @noble/hashes (RX)",
        present.len(),
        omitted.len()
    );
}
