//! The `native` backend: WOTS+ in Rust, with no C anywhere in it.
//!
//! **No `unsafe`.** Nothing here has anything to call that would need it, and
//! that is what memory safety in this crate rests on: it cannot be
//! established by comparing one implementation against another, so it is
//! established by running this module under Miri.
//! `invariants.rs::memory_safety_is_established_only_for_the_native_paths_miri_walks`
//! is the marker, and its name is the size of the claim.
//!
//! # What this is checked against
//!
//! `tests/kat.rs`, which replays the group A and B fixtures against *this*
//! module through `backend::selected` rather than inheriting `wots::*`'s
//! greens; and `tests/wots_internals.rs`, four oracle-free property tests
//! over the shapes the corpus cannot see -- the two chain loops held to each
//! other, the checksum's totality and its formula, the signing counts
//! against the digits, and the digit bound.
//!
//! # Hash primitive
//!
//! `sha2::Sha256`, not a hand-rolled one. The reference defines
//! `core_hash(out, in, inlen)` as `sha256(in, inlen, out)`, and the
//! parameterization is its own. A hand-rolled hash would put a second
//! unproven thing inside every disagreement with the corpus, so the first
//! question on any mismatch would be the one question the fixtures cannot
//! answer.
//!
//! # Zeroization, and what it does not cover
//!
//! Every scratch buffer that holds secret material is [`Zeroizing`]. That
//! includes `prf`'s 96-byte `buf`, which contains the *key* argument verbatim —
//! and at `expand_seed`'s call site that key is the WOTS+ private
//! seed. It includes `thash_f`'s `buf` and `bitmask`, and `gen_chain`'s working
//! value, which is a private chain element until the last step turns it into a
//! public one.
//!
//! What is **not** covered, said out loud rather than left for a reader to
//! assume from the sentence above: `sha2::Sha256`'s internal block buffer and
//! state words. `Digest` exposes no way to scrub them, and the crate is trusted
//! here by the same decision that chose it over a hand-rolled hash. So "every
//! intermediate is `Zeroizing`" is true of this module's own stack and false of
//! the hash's, and no test in this tree can tell the difference — see
//! `zeroization_has_no_reference_counterpart`, red because a drop-witness is
//! unwritable without UB.

use ripemd::Ripemd160;
use sha2::{Digest, Sha256};
use sha3::Sha3_512;
use zeroize::Zeroizing;

use crate::consts::{
    wire, ADDR_HASH_LEN, ADDR_HASH_OFF, ADDR_LEN, ADDR_TAG_LEN, ADDR_TAG_OFF, PARAMSN, PK_LEN,
    SEED_LEN, SHA3LEN224, SHA3LEN256, SHA3LEN384, SHA3LEN512, SIG_LEN, WOTSLEN as WOTSLEN_TOTAL,
    WOTSLEN1, WOTSLEN2, WOTSLOGW, WOTSW,
};
use crate::error::Result;

/// The WOTS+ `core_hash`.
///
/// `#define core_hash(out, in, inlen) sha256(in, inlen, out)` — the argument
/// order is transposed by the macro, which is worth noticing once here rather
/// than at each of the four call sites.
///
/// The reference's own `sha256` is a one-shot over
/// `sha256_init`/`_update`/`_final`. `Sha256::digest` is the same shape, and the
/// two are compared in `tests/kat.rs` through group HS, which records the
/// reference's digest at every input length across two blocks.
#[must_use]
pub fn sha256(input: &[u8]) -> [u8; 32] {
    Sha256::digest(input).into()
}

// -------------------------------------------------------------------------
// Step 1 --- the chain function
// -------------------------------------------------------------------------

/// The XMSS hash padding domain separators.
const XMSS_HASH_PADDING_F: u64 = 0;
const XMSS_HASH_PADDING_PRF: u64 = 3;

/// Writes `out.len()` bytes of `value` in **big-endian** order, truncating
/// from the top when `out` is narrower than the value.
///
/// The truncation is not incidental. `wots_checksum` calls this
/// with a 2-byte buffer and a `csum` that has already been shifted left by 4, so
/// the top bits of a 32-bit `int` are dropped by design; a Rust version that
/// used `to_be_bytes()` and copied a fixed width would be a different function
/// at that call site.
///
/// **An empty `out` panics rather than being defined as a no-op.** No call
/// site in this module passes one, and the reference's behaviour at zero
/// length is implementation-defined, so there is nothing to agree with: the
/// assertion refuses the case instead of inventing an answer for it.
pub fn ull_to_bytes(out: &mut [u8], value: u64) {
    assert!(
        !out.is_empty(),
        "ull_to_bytes with an empty output; see this function's doc comment for why \
         zero is refused rather than defined."
    );
    let mut v = value;
    // Decreasing, for big-endianness.
    for byte in out.iter_mut().rev() {
        *byte = (v & 0xff) as u8;
        v >>= 8;
    }
}

/// Each of the 8 address words, big-endian, in order.
///
/// This is the function that makes the `adrs` byte order a *serialization*
/// rather than a memory layout: the caller holds words, and the bytes that reach
/// `prf` are big-endian regardless of host endianness. The transaction path
/// stores those same words host-endian (`put32`), so the two
/// differ by a per-word reversal on a little-endian host — recorded here because
/// this function is where the two conventions meet, and settled against
/// `fixtures/group_d_tx.json` and group A rather than by reasoning.
#[must_use]
pub fn addr_to_bytes(adrs: &[u32; 8]) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for (i, &word) in adrs.iter().enumerate() {
        ull_to_bytes(&mut bytes[i * 4..(i + 1) * 4], u64::from(word));
    }
    bytes
}

// The address setters. Named rather than inlined so
// that a wrong index reads as a wrong index: an injection that writes word 4
// instead of word 5 is only legible as a fault if the words have names here.
//
// Words 5, 6 and 7 are the *scratch* words -- chain index, hash index, and
// key/mask selector. Words 0-4 are the caller's and are never written. That
// split is what `B-adrs-invariance` pins from the other side.
fn set_chain_addr(adrs: &mut [u32; 8], chain: u32) {
    adrs[5] = chain;
}
fn set_hash_addr(adrs: &mut [u32; 8], hash: u32) {
    adrs[6] = hash;
}
fn set_key_and_mask(adrs: &mut [u32; 8], key_and_mask: u32) {
    adrs[7] = key_and_mask;
}

/// `PRF(key, in)` = `sha256(pad(3) ‖ key ‖ in)` over 96 bytes.
///
/// **Total.** The buffer is fixed-width, the writes are infallible and
/// `sha256` is total, so there is no input for which this has no answer. The
/// return type says so: a fallible one would put a failure arm in front of
/// every caller on the signing path, and the only values a caller could
/// invent for it are wrong keys.
#[must_use]
pub fn prf(input: &[u8; 32], key: &[u8; SEED_LEN]) -> [u8; 32] {
    // Secret: `key` is the private seed at expand_seed's call site.
    let mut buf = Zeroizing::new([0u8; 2 * PARAMSN + 32]);
    ull_to_bytes(&mut buf[..PARAMSN], XMSS_HASH_PADDING_PRF);
    buf[PARAMSN..2 * PARAMSN].copy_from_slice(key);
    buf[2 * PARAMSN..].copy_from_slice(input);
    sha256(&buf[..])
}

/// The keyed, masked compression step.
///
/// `sha256(pad(0) ‖ PRF(pub_seed, adrs@key=0) ‖ (in ⊕ PRF(pub_seed, adrs@key=1)))`.
///
/// **`adrs` is mutated and the mutation is observable.** Word 7 is set to 0 for
/// the key derivation and then to 1 for the mask, and it is left at 1 on return.
/// `gen_chain` calls this in a loop and never resets word 7, so every iteration
/// after the first enters with word 7 already 1 — which is harmless only because
/// this function's first act is to overwrite it. Reproduced rather than tidied:
/// the reference's callers can observe `adrs` afterwards, and one of them
/// (`wots_pkgen` via `tx_bot_get_wots`) writes it into a transaction.
///
/// The key and the mask are *different* derivations of the same address.
/// Transposing the two `prf` calls is undetectable by the corpus — the one
/// `A-thash` vector has an all-defaults address — which is precisely the gap
/// the corpus leaves here.
#[must_use]
pub fn thash_f(input: &[u8; 32], pub_seed: &[u8; SEED_LEN], adrs: &mut [u32; 8]) -> [u8; 32] {
    // Secret: `input` is a private chain element until the final chain step.
    let mut buf = Zeroizing::new([0u8; 3 * PARAMSN]);
    ull_to_bytes(&mut buf[..PARAMSN], XMSS_HASH_PADDING_F);

    set_key_and_mask(adrs, 0);
    let key_addr = addr_to_bytes(adrs);
    let key = prf(&key_addr, pub_seed);
    buf[PARAMSN..2 * PARAMSN].copy_from_slice(&key);

    set_key_and_mask(adrs, 1);
    let mask_addr = addr_to_bytes(adrs);
    let bitmask = Zeroizing::new(prf(&mask_addr, pub_seed));

    for i in 0..PARAMSN {
        buf[2 * PARAMSN + i] = input[i] ^ bitmask[i];
    }
    sha256(&buf[..])
}

/// `steps` applications of [`thash_f`] from chain position
/// `start`.
///
/// The loop is `for (i = start; i < (start+steps) && i < WOTSW; i++)`, and all
/// three parts of that condition are reproduced literally:
///
///   * `start + steps` is computed with wrapping arithmetic, because the C
///     computes it in `unsigned int`. A `start` near `u32::MAX` makes the sum
///     wrap below `start` and the loop runs zero times — reachable only by
///     calling this directly, which the boundary walk does.
///   * The `&& i < WOTSW` guard is **dead at every real call site**: `wots_pkgen`
///     passes `(0, WOTSW-1)`, `wots_sign` passes `(0, lengths[i])` with
///     `lengths[i] ≤ 15`, and `wots_pk_from_sig` passes
///     `(lengths[i], WOTSW-1-lengths[i])`, all summing to at most 15. It is
///     reproduced because a port that dropped it would be indistinguishable from
///     this one over the entire corpus, and the only way to observe it is to call
///     `gen_chain` with `start + steps > WOTSW` directly.
///   * `steps == 0` copies the input and returns it unchanged, touching neither
///     the hash nor `adrs`. That arm is what makes a WOTS+ signature publish a
///     raw chain seed for a zero message digit — the property that makes the key
///     one-time, not a defect.
#[must_use]
pub fn gen_chain(
    input: &[u8; SEED_LEN],
    start: u32,
    steps: u32,
    pub_seed: &[u8; SEED_LEN],
    adrs: &mut [u32; 8],
) -> [u8; 32] {
    // Secret until the chain reaches its public end.
    let mut out = Zeroizing::new(*input);

    let end = start.wrapping_add(steps);
    let mut i = start;
    while i < end && (i as usize) < WOTSW {
        set_hash_addr(adrs, i);
        *out = thash_f(&out, pub_seed, adrs);
        i += 1;
    }
    *out
}

/// Instrumented [`gen_chain`]: returns the chain value and the number of
/// `thash_f` applications it performed.
///
/// This exists because output equality is insufficient — two implementations
/// can agree on output and disagree on how much work each chain did, and
/// asserting only that `recovery(sign(m)) == pkgen()` would pass with both
/// sides off by the same amount. The count is that quantity, and it is not
/// recoverable from the bytes.
///
/// It is `cfg(test)`-free and public rather than hidden behind a test flag: the
/// proof tests live in `tests/`, which links this crate as a dependency, so a
/// `#[cfg(test)]` item would not be visible to them.
///
/// **The count is derived, not asserted.** `gen_chain` above is not written in
/// terms of this function, and this function is not written in terms of it —
/// they are two copies of the same loop. That is deliberate: if the counter were
/// bolted onto the real loop, a fault in the loop bound would move the count and
/// the output together, and the count would stop being independent evidence.
/// `tests/wots_internals.rs::gen_chain_counted_walks_the_chain_gen_chain_walks`
/// pins the two loops to each other -- the bytes, the `adrs` left behind and
/// the count -- over every `(start, steps)` in `0..18` squared, at the edges
/// where the sum wraps, and on pairs drawn from the whole `u32` range, with
/// no oracle behind it.
#[must_use]
pub fn gen_chain_counted(
    input: &[u8; SEED_LEN],
    start: u32,
    steps: u32,
    pub_seed: &[u8; SEED_LEN],
    adrs: &mut [u32; 8],
) -> ([u8; 32], u32) {
    let mut out = Zeroizing::new(*input);
    let mut count = 0u32;

    let end = start.wrapping_add(steps);
    let mut i = start;
    while i < end && (i as usize) < WOTSW {
        set_hash_addr(adrs, i);
        *out = thash_f(&out, pub_seed, adrs);
        i += 1;
        count += 1;
    }
    (*out, count)
}

// -------------------------------------------------------------------------
// Step 2 --- the Winternitz ladder and checksum
// -------------------------------------------------------------------------

/// Reinterprets `input`'s nibbles as base-`WOTSW` digits, high
/// nibble first, writing `output.len()` of them.
///
/// The loop is transcribed rather than simplified. For `WOTSW = 16` this is just
/// `(b >> 4, b & 15)` per byte, and writing it that way would be shorter and
/// would be a different function the moment `WOTSLOGW` changed — the reference
/// carries a general `bits` accumulator and the port carries it too.
///
/// `if (bits == 0)` is the fourth data-dependent branch in the port, and the
/// only one deliberately **not** marked. `bits` is
/// loop-carried and `WOTSLOGW` divides 8, so the branch alternates on a fixed
/// period determined by the loop index alone — it is not selected by the input.
/// That is the argument, and reproducing the loop as written is what keeps it
/// true of this code rather than only of the C.
///
/// The `& (WOTSW - 1)` mask is what confines every digit to
/// `0..=15`. That is not cosmetic: `wots_pk_from_sig` computes
/// `WOTSW - 1 - lengths[i]`, which underflows if a digit ever
/// exceeded 15.
pub fn base_w(output: &mut [i32], input: &[u8]) {
    let needed = output.len().div_ceil(2);
    assert!(
        input.len() >= needed,
        "base_w with out_len={} needs at least {needed} input bytes, got {}",
        output.len(),
        input.len()
    );

    let mut in_idx = 0usize;
    let mut total = 0u8;
    let mut bits = 0i32;

    for slot in output.iter_mut() {
        if bits == 0 {
            total = input[in_idx];
            in_idx += 1;
            bits += 8;
        }
        bits -= WOTSLOGW as i32;
        *slot = i32::from((total >> bits) & (WOTSW as u8 - 1));
    }
}

/// The WOTS+ checksum over a base-w message, itself in base w.
///
/// `csum = Σ (WOTSW - 1 - msg[i])` over `WOTSLEN1` digits, then shifted left by
/// `8 - ((WOTSLEN2 * WOTSLOGW) % 8)` = `8 - (12 % 8)` = **4**, then serialized
/// big-endian into `(WOTSLEN2 * WOTSLOGW + 7) / 8` = **2** bytes and read back as
/// `WOTSLEN2` = 3 base-w digits.
///
/// The shift is the subtle part and it is why the third checksum digit is always
/// a multiple of nothing in particular rather than always zero: 3 digits need 12
/// bits, 2 bytes hold 16, and the shift pushes the 12 significant bits to the
/// **top** so that `base_w` — which reads high nibble first — finds them in the
/// first three nibbles. Drop the shift and the digits come out of the wrong
/// nibbles entirely.
///
/// `csum` is `i32`, and **the width is not load-bearing.** Over the reachable
/// domain the value is `0..=960` before the shift and `0..=15360` after, so
/// the sign never enters; and the three digits read the low twelve bits of
/// the sum and no more -- the shift moves them into the top three nibbles of
/// the two bytes, and the two bytes are the low sixteen bits of the
/// accumulator -- so any accumulator wider than twelve bits, signed or
/// unsigned, wrapping or not, produces the same three digits. The test named
/// below computes the formula with a `u32` accumulator as well and holds it
/// equal.
///
/// The arithmetic is **explicitly wrapping**. This function is
/// `pub`, so its domain is any `[i32; 64]` a caller can name, not only the
/// masked digits `chain_lengths` produces — and on out-of-domain digits the
/// unadorned `+` was two functions selected by profile: an overflow panic in
/// debug, a silent two's-complement wrap in release (measured, both). The C's
/// `int` overflow there is undefined behaviour in theory and the same wrap in
/// every artifact this project builds, so the wrap is pinned, on the
/// [`gen_chain`] precedent (`start.wrapping_add(steps)`). What the wrapping
/// buys is that the function is total; what it does not change is the
/// output. **The formula, on any `[i32; 64]`:** the three digits are the
/// base-16 digits of `Σ (15 − d[i]) mod 4096`, the sum taken over the
/// integers. The wrap is modulo 2^32 and the output reads the sum modulo
/// 2^12, which divides it, so the wrap never shows in the digits; a digit
/// below `i32::MIN + 16`, or a running sum past `i32::MAX`, is where a
/// checked `+` would panic in a debug build and this wraps instead. On the
/// reachable domain no operation wraps and nothing changes.
/// `tests/wots_internals.rs::wots_checksum_is_total_and_reads_the_low_twelve_bits_of_the_sum`
/// holds the formula on inputs drawn from the whole `i32` range, computed
/// there with explicit wrapping arithmetic and again over the integers.
#[must_use]
pub fn wots_checksum(msg_base_w: &[i32; WOTSLEN1]) -> [i32; WOTSLEN2] {
    let mut csum: i32 = 0;
    for &digit in msg_base_w.iter() {
        csum = csum.wrapping_add((WOTSW as i32 - 1).wrapping_sub(digit));
    }

    csum <<= 8 - ((WOTSLEN2 * WOTSLOGW) % 8);

    // spells this `(WOTSLEN2 * WOTSLOGW + 7) / 8`; `div_ceil` is
    // the same value and is what clippy::manual_div_ceil requires. Both are 2.
    let mut csum_bytes = [0u8; (WOTSLEN2 * WOTSLOGW).div_ceil(8)];
    ull_to_bytes(&mut csum_bytes, csum as u32 as u64);

    let mut out = [0i32; WOTSLEN2];
    base_w(&mut out, &csum_bytes);
    out
}

/// The `WOTSLEN1` message digits followed by the `WOTSLEN2`
/// checksum digits.
///
/// Note that the reference computes the checksum from `lengths` **in place** —
/// `wots_checksum(lengths + WOTSLEN1, lengths)` reads the first 64 entries of
/// the same array it is about to append to. The two halves are separate arrays
/// here, so the read range and the write range cannot overlap by construction
/// rather than by an argument about indices, and `wots_checksum` receives a
/// `[i32; WOTSLEN1]` the compiler supplied. `WOTSLEN1 + WOTSLEN2 == WOTSLEN`
/// exactly, which is what makes the two spellings the same computation.
#[must_use]
pub fn chain_lengths(msg: &[u8; SEED_LEN]) -> [i32; WOTSLEN_TOTAL] {
    let mut msg_digits = [0i32; WOTSLEN1];
    base_w(&mut msg_digits, msg);
    let csum = wots_checksum(&msg_digits);

    let mut lengths = [0i32; WOTSLEN_TOTAL];
    lengths[..WOTSLEN1].copy_from_slice(&msg_digits);
    lengths[WOTSLEN1..].copy_from_slice(&csum);
    lengths
}

// -------------------------------------------------------------------------
// Step 3 --- key generation
// -------------------------------------------------------------------------

/// Expands an `n`-byte seed into the `WOTSLEN * PARAMSN` byte private key.
///
/// **The return value is the WOTS+ private key, and it is not
/// [`Zeroizing`].** Ownership passes to the caller, who is the only one who
/// knows when it stops being secret. [`wots_pkgen`] below, the only caller in
/// this module, does zeroize it. A caller outside this module that keeps the
/// raw expansion around is holding key material, and nothing in this tree
/// detects that.
///
/// The counter is the whole content of the function: `ull_to_bytes(ctr, 32, i)`
/// is 31 zero bytes and `i`, big-endian, and `prf` keys on the *seed*. Omit the
/// counter and all 67 chain seeds are identical, which the corpus's `A-expand`
/// vector catches and `A-prf-ctr1` localises.
#[must_use]
pub fn expand_seed(inseed: &[u8; SEED_LEN]) -> Box<[u8; PK_LEN]> {
    let mut out = Box::new([0u8; PK_LEN]);
    expand_seed_into(&mut out[..], inseed);
    out
}

/// The expansion itself, writing into a caller-owned buffer.
///
/// This exists so that [`wots_pkgen`] can expand into a [`Zeroizing`] buffer
/// **without** first materializing the private key in a `Box` that would then be
/// dropped unscrubbed. Calling `expand_seed` and copying out of it would leave a
/// 2144-byte plaintext private key on the heap with nothing to clear it — the
/// exact leak the module header claims not to have. The two entry points share
/// this body rather than duplicating the loop, so the corpus's `A-expand` vector
/// covers both.
fn expand_seed_into(out: &mut [u8], inseed: &[u8; SEED_LEN]) {
    assert_eq!(
        out.len(),
        PK_LEN,
        "expand_seed writes WOTSLEN * PARAMSN = {PK_LEN} bytes (wots.c:130)"
    );
    let mut ctr = Zeroizing::new([0u8; 32]);
    for i in 0..WOTSLEN_TOTAL {
        ull_to_bytes(&mut ctr[..], i as u64);
        let seed = Zeroizing::new(prf(&ctr, inseed));
        out[i * PARAMSN..(i + 1) * PARAMSN].copy_from_slice(&seed[..]);
    }
}

/// Seed → private key → public key.
///
/// `expand_seed` fills the buffer with the private key and then each of the 67
/// chains is run `WOTSW - 1` times **in place**, so the same 2144 bytes are
/// secret on entry to the loop and public on exit. That is why the working
/// buffer here is [`Zeroizing`] and the public result is copied out of it: the
/// alternative is returning the very allocation that held the private key and
/// trusting that every byte of it was overwritten.
///
/// **Nothing here is data-dependent.** passes the literals `0` and
/// `WOTSW - 1`, and `expand_seed` loops `WOTSLEN` times unconditionally. The
/// secret selects no branch and no count, which is why key generation carries
/// no timing note while signing and verification do.
///
/// `adrs` is mutated: word 5 walks `0..WOTSLEN`, and `gen_chain`/`thash_f` leave
/// words 6 and 7 at their last values. Group A records the result —
/// `adrs_out_words` is `[.., 66, 14, 1]` for every vector, which is
/// `WOTSLEN - 1`, `WOTSW - 2` and the mask selector.
#[must_use]
pub fn wots_pkgen(
    secret: &[u8; SEED_LEN],
    pub_seed: &[u8; SEED_LEN],
    adrs: &mut [u32; 8],
) -> Box<[u8; PK_LEN]> {
    // Secret from here until the chain loop finishes. A `Vec` rather than a
    // `Box<[u8; PK_LEN]>` because `Zeroizing` needs its contents to be
    // `Zeroize`, which `Vec<u8>` is and a boxed array is not.
    let mut buf = Zeroizing::new(vec![0u8; PK_LEN]);
    expand_seed_into(&mut buf, secret);

    // `PK_LEN` is `WOTSLEN * PARAMSN`, so this splits into exactly `WOTSLEN`
    // chains with nothing over: the remainder is empty as arithmetic on the
    // constants and the chunk count is the loop bound. Each chain is run where
    // it lies, inside the buffer that zeroizes, so no copy of a private chain
    // element is made to run it.
    let (chains, _nothing_over) = buf.as_chunks_mut::<PARAMSN>();
    for (i, chain) in chains.iter_mut().enumerate() {
        set_chain_addr(adrs, i as u32);
        *chain = gen_chain(chain, 0, WOTSW as u32 - 1, pub_seed, adrs);
    }

    let mut pk = Box::new([0u8; PK_LEN]);
    pk.copy_from_slice(&buf[..]);
    pk
}

// -------------------------------------------------------------------------
// Step 4 --- signing
// Step 5 --- verification
// -------------------------------------------------------------------------

/// Signs a 32-byte message digest.
///
/// Each of the 67 chains is advanced `lengths[i]` times from position 0, where
/// `lengths = chain_lengths(msg)`. **The per-chain iteration count is derived
/// from the message**, which is the port's second data-dependent site.
///
/// # The timing argument, owed with the port
///
/// The counts derive from `msg`. At every call site in this tree `msg` is
/// `tx_hash(TX_HASH_MESSAGE)` — a public value present in the transaction on the
/// wire. The secret is expanded unconditionally by `expand_seed` and selects no
/// branch and no count anywhere in `wots.c`. So the timing variation here is a
/// function of public data, and reproducing it is not a leak.
///
/// **And nothing enforces that.** No check in this tree verifies that a future
/// call site does not sign a secret-derived message. That is a judgement about
/// call sites, not a property any test observes; `docs/specification.md`
/// records it under the WOTS+ present-tense limits. The argument is stated
/// where the property lives, and what would enforce it is named rather than
/// implied.
///
/// # `lengths[i] == 0` publishes a raw chain seed
///
/// `gen_chain` with `steps == 0` copies its input through, so a zero message
/// digit puts the *expanded private seed* for that chain directly into the
/// signature. That is WOTS, not a defect — it is exactly why the key is
/// one-time — but it means the `steps == 0` arm is the arm that emits secret
/// material, and it is the arm no fixture reaches on its own.
#[must_use]
pub fn wots_sign(
    msg: &[u8; SEED_LEN],
    secret: &[u8; SEED_LEN],
    pub_seed: &[u8; SEED_LEN],
    adrs: &mut [u32; 8],
) -> Box<[u8; SIG_LEN]> {
    let (sig, _) = wots_sign_counted(msg, secret, pub_seed, adrs);
    sig
}

/// [`wots_sign`] with the per-chain iteration counts.
///
/// Two implementations can agree on output and disagree on how much work
/// each chain did, so signature equality does not establish the counts. This
/// returns the 67 counts alongside the signature;
/// `tests/wots_internals.rs::wots_sign_counted_runs_each_chain_exactly_its_digit`
/// compares them against `chain_lengths(msg)` chain by chain over hundreds of
/// messages, with no oracle behind it.
///
/// Unlike [`gen_chain_counted`], this is not a second copy of the loop —
/// [`wots_sign`] is a thin wrapper around it. Duplicating a 67-iteration loop
/// buys nothing: the count here comes from `gen_chain_counted`.
#[must_use]
pub fn wots_sign_counted(
    msg: &[u8; SEED_LEN],
    secret: &[u8; SEED_LEN],
    pub_seed: &[u8; SEED_LEN],
    adrs: &mut [u32; 8],
) -> (Box<[u8; SIG_LEN]>, [u32; WOTSLEN_TOTAL]) {
    let lengths = chain_lengths(msg);

    let mut buf = Zeroizing::new(vec![0u8; SIG_LEN]);
    expand_seed_into(&mut buf, secret);

    let mut counts = [0u32; WOTSLEN_TOTAL];
    // `SIG_LEN` is `WOTSLEN * PARAMSN`, so the split is exact and the chunk
    // count is `WOTSLEN`. Signing runs each chain where it lies, inside the
    // buffer that zeroizes.
    let (chains, _nothing_over) = buf.as_chunks_mut::<PARAMSN>();
    for (i, chain) in chains.iter_mut().enumerate() {
        set_chain_addr(adrs, i as u32);
        // `lengths[i]` is in 0..=15 -- base_w masks with WOTSW - 1 -- so this
        // cast cannot wrap. `tests/kat.rs::chain_lengths` reads every recorded
        // digit vector back through this function; the bound itself is held by
        // the mask alone, and
        // `tests/wots_internals.rs::chain_lengths_never_yields_a_digit_outside_the_base`
        // holds the mask's effect over every single-byte fill, every one-bit
        // message and two hundred thousand drawn ones.
        let (out, n) = gen_chain_counted(chain, 0, lengths[i] as u32, pub_seed, adrs);
        *chain = out;
        counts[i] = n;
    }

    let mut sig = Box::new([0u8; SIG_LEN]);
    sig.copy_from_slice(&buf[..]);
    (sig, counts)
}

/// Recovers the public key from a signature and its message.
///
/// Chain `i` resumes at position `lengths[i]` — where signing stopped — and runs
/// the remaining `WOTSW - 1 - lengths[i]` steps. That identity,
/// `start + count == WOTSW - 1` for every chain, is what makes signing and
/// recovery inverse; asserting only that `recovery(sign(m)) == pkgen()` would
/// pass with both sides off by the same amount, which is why the bounds are
/// returned by [`wots_pk_from_sig_counted`] as a value of their own.
///
/// The subtraction `WOTSW - 1 - lengths[i]` is where a digit above 15 would
/// underflow into an enormous `unsigned int` `steps`. `base_w`'s
/// `& (WOTSW - 1)` is the only thing preventing it, which is why that mask has
/// its own fault injection and its own bound test.
///
/// No [`Zeroizing`] here and that is deliberate: every input is public — a
/// signature, a message, a public seed — and there is no secret to scrub. Adding
/// it would suggest the opposite.
#[must_use]
pub fn wots_pk_from_sig(
    sig: &[u8; SIG_LEN],
    msg: &[u8; SEED_LEN],
    pub_seed: &[u8; SEED_LEN],
    adrs: &mut [u32; 8],
) -> Box<[u8; PK_LEN]> {
    let (pk, _) = wots_pk_from_sig_counted(sig, msg, pub_seed, adrs);
    pk
}

/// [`wots_pk_from_sig`] with the per-chain `(start, count)` pairs.
///
/// Both halves are returned because the marker's condition is about both: the
/// start must equal `chain_lengths(msg)[i]` and `start + count` must equal
/// `WOTSW - 1`. Transposing the two — the compensating-error pair a round-trip
/// test cannot see — moves one and not the other.
#[must_use]
pub fn wots_pk_from_sig_counted(
    sig: &[u8; SIG_LEN],
    msg: &[u8; SEED_LEN],
    pub_seed: &[u8; SEED_LEN],
    adrs: &mut [u32; 8],
) -> (Box<[u8; PK_LEN]>, [(u32, u32); WOTSLEN_TOTAL]) {
    let lengths = chain_lengths(msg);

    let mut pk = Box::new([0u8; PK_LEN]);
    let mut bounds = [(0u32, 0u32); WOTSLEN_TOTAL];

    // Both widths are `WOTSLEN * PARAMSN`, so both splits are exact and the two
    // chunk sequences are the same length: signature chain `i` resumes into
    // public-key chain `i` with no index arithmetic to get wrong.
    let (sig_chains, _nothing_over) = sig.as_chunks::<PARAMSN>();
    let (pk_chains, _nothing_over) = pk.as_chunks_mut::<PARAMSN>();
    for (i, (sig_chain, pk_chain)) in sig_chains.iter().zip(pk_chains).enumerate() {
        set_chain_addr(adrs, i as u32);
        let start = lengths[i] as u32;
        let steps = WOTSW as u32 - 1 - start;
        let (out, n) = gen_chain_counted(sig_chain, start, steps, pub_seed, adrs);
        *pk_chain = out;
        bounds[i] = (start, n);
    }

    (pk, bounds)
}

// -------------------------------------------------------------------------
// The address path
//
//. Everything below is outside WOTS+: `wots.rs` deals in
// `Adrs([u32; 8])` and never in address bytes, so the two paths meet only at
// `addr_from_wots`, which takes a finished public key.
// -------------------------------------------------------------------------

/// SHA3-512 (`outlen = SHA3LEN512`).
///
/// # Why this is `Sha3_512` and not `Keccak512`
///
/// The two Keccak variants differ in one byte and both compile. The reference
/// picks FIPS-202: is `ctx->st.b[ctx->pt] ^= 0x06`, where the same
/// file's `keccak_final` uses `0x07`. The rate agrees
/// independently — is `rsiz = 200 - (outlen << 1)`, giving 72 for
/// `outlen = 64`, which is SHA3-512's rate. Two reads, one conclusion.
///
/// # The host dependence this silently removes
///
/// is `memcpy(out, ctx->st.q, ctx->outlen)`, reading the state
/// through its `uint64_t[25]` view. The reference's SHA3 is therefore FIPS-202
/// **only on a little-endian host**; its equivalence to FIPS-202 was
/// established against Python's `hashlib` running on exactly such a host, and
/// nothing in the C says so. RustCrypto is endian-defined, so this function
/// normalizes. That is a decision, matched by the same decision for `adrs`
/// and for [`put16`] — that function's doc carries the reason.
#[must_use]
pub fn sha3_512(input: &[u8]) -> [u8; SHA3LEN512] {
    Sha3_512::digest(input).into()
}

/// SHA3-256 (`outlen = SHA3LEN256`, rate 136), for.
#[must_use]
pub fn sha3_256(input: &[u8]) -> [u8; SHA3LEN256] {
    sha3::Sha3_256::digest(input).into()
}

/// SHA3-224 (`outlen = SHA3LEN224`, rate 144).
///
/// # Why a width with no caller is here
///
/// The seam carries no runtime `outlen`: each width is a separate name with a
/// separate return type, so a width nobody implements is a compile error at
/// the call site rather than a value reaching a dispatcher. That makes "no
/// caller today" a weak reason to omit one that costs a line, and the corpus
/// covers all four.
#[must_use]
pub fn sha3_224(input: &[u8]) -> [u8; SHA3LEN224] {
    sha3::Sha3_224::digest(input).into()
}

/// SHA3-384 (`outlen = SHA3LEN384`, rate 104). See [`sha3_224`] for why this
/// exists with no caller in front of it.
#[must_use]
pub fn sha3_384(input: &[u8]) -> [u8; SHA3LEN384] {
    sha3::Sha3_384::digest(input).into()
}

/// RIPEMD-160, as the ledger uses it.
#[must_use]
pub fn ripemd160(input: &[u8]) -> [u8; 20] {
    Ripemd160::digest(input).into()
}

/// `ripemd160(sha3_512(in))`.
///
/// The intermediate is 64 bytes and is not secret — it is a hash of a public
/// key — so it is not `Zeroizing`, unlike everything in the WOTS+ half of this
/// module. Said explicitly because the asymmetry with `prf`'s buffer above is
/// otherwise the kind of thing a reader assumes is an oversight.
#[must_use]
pub fn addr_hash_generate(input: &[u8]) -> [u8; ADDR_HASH_LEN] {
    ripemd160(&sha3_512(input))
}

/// Writes the 20-byte tag into **both** halves of the 40-byte
/// address.
///
/// Not a typo in the reference and not a typo here: `ADDR_TAG_PTR(addr)` and
/// `ADDR_HASH_PTR(addr)` both receive `tag`, `ADDR_TAG_LEN` bytes each. An
/// implicit address is one whose hash half *is* its tag, which is what makes
/// `addr_from_wots` below produce an address whose two halves are equal.
#[must_use]
pub fn addr_from_implicit(tag: &[u8; ADDR_TAG_LEN]) -> [u8; ADDR_LEN] {
    let mut addr = [0u8; ADDR_LEN];
    addr[..ADDR_TAG_LEN].copy_from_slice(tag);
    addr[ADDR_TAG_LEN..].copy_from_slice(tag);
    addr
}

/// The legacy WOTS+ public key to a v3 hash-based address.
///
/// Hashes exactly `WOTS_PK_LEN` = 2144 bytes. **Not 2208.** The pre-v3 wire
/// form of a WOTS+ address carried the public key followed by the 32-byte
/// public seed and the 32-byte address scheme, and 2208 is the number a reader
/// who knows the old format will reach for. passes
/// `WOTS_PK_LEN`, and the type here makes the other length unrepresentable.
#[must_use]
pub fn addr_from_wots(wots: &[u8; PK_LEN]) -> [u8; ADDR_LEN] {
    addr_from_implicit(&addr_hash_generate(wots))
}

// -------------------------------------------------------------------------
// CRC16
// -------------------------------------------------------------------------

/// The `crc16.c` table, **computed** rather than transcribed.
///
/// The reference ships 256 literals. Copying them would be a transcription with
/// 256 chances to slip and no mechanism to catch one — and the project's rule
/// is that oracles call the reference rather than restating it. Generating from
/// the polynomial instead means the Rust side is a *claim about the parameters*
/// that the tests can falsify, rather than a copy that agrees with itself.
///
/// The claim is `poly = 0x1021`, MSB-first, no reflection. It is established,
/// not asserted: `tests/kat.rs::crc16_vector` and `base58_corpus_replays`
/// hold it to the reference's recorded values over group E's vectors and the
/// 1,000-entry tag corpus. The exhaustive one- and two-byte walks against
/// the linked C went with the differential suite.
///
/// Nothing here says "CRC16/XMODEM". The name would add no information and
/// would invite the next reader to check a table against a web page instead of
/// against `crc16.c`.
const CRC16_TABLE: [u16; 256] = {
    let mut table = [0u16; 256];
    let mut i = 0usize;
    while i < 256 {
        let mut crc = (i as u16) << 8;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
            bit += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
};

/// `crc16.c`. Init `0x0000`, no final xor, no reflection.
#[must_use]
pub fn crc16(input: &[u8]) -> u16 {
    let mut crc: u16 = 0x0000;
    for &byte in input {
        crc = (crc << 8) ^ CRC16_TABLE[usize::from((crc >> 8) as u8 ^ byte)];
    }
    crc
}

// -------------------------------------------------------------------------
// The 16-bit wire accessors, and the third host dependence
// -------------------------------------------------------------------------

/// **Little-endian, by decision, not by transcription.**
///
/// The reference is `*((word16 *) buff) = value` — a bare store through a
/// reinterpreted pointer, so its byte order is whatever the host's is and
/// nothing in the C says so. That is the same class of host dependence as
/// the node's `memcpy` into `word32 adrs[8]` and as `sha3_final`'s `memcpy`
/// out of a `uint64_t[25]`; this is the third one, and the three are settled
/// the same way, for the reason given below.
///
/// The corpus is not silent on it. `fixtures/group_c_addr.json`'s C8 records
/// `crc16` = 45906 = `0xb352` beside `crc16_bytes_put16` = `52b3`, so the
/// generating host wrote the low byte first. C7 cannot distinguish the two
/// readings — its value is zero — which is exactly why the maximal vector is
/// the one cited here.
///
/// `to_le_bytes`, never `to_ne_bytes`. A native-endian version would make the
/// *Rust* output host-dependent while every fixture that checks it was
/// generated on one host, which is an untestable branch.
#[must_use]
pub fn put16(value: u16) -> [u8; 2] {
    value.to_le_bytes()
}

/// The inverse of [`put16`], and little-endian for the same
/// reason and by the same decision.
#[must_use]
pub fn get16(bytes: &[u8; 2]) -> u16 {
    u16::from_le_bytes(*bytes)
}

/// **Little-endian, by decision, and with no measurement behind
/// the decision — read this before trusting it.**
///
/// The reference is `*((word32 *) buff) = value`, the same bare host-endian
/// store as [`put16`], and the whole class is settled the same way: normalize,
/// never `to_ne_bytes`.
///
/// # What checks this, and what cannot
///
/// A differential against the C's `put32` **could not decide the question
/// this function exists to get right.** On a little-endian host `to_le_bytes`
/// and `to_ne_bytes` are the same function, so the comparison passed under
/// either — a check that cannot fail for the property it appears to cover. It
/// caught a wrong *byte*, which was worth having, and it was not evidence
/// about byte *order*.
///
/// `put16` has two second anchors and **`put32` now has one of them.**
/// `group_c_addr.json`'s C8 records `crc16_bytes_put16: "52b3"` against
/// `crc16: 45906`, and `CX-C9` catches a `to_be_bytes` injection against
/// the TypeScript, an implementation sharing no code with the C.
///
/// `put32`'s anchor is group D: `fixtures/group_d_tx.json` records the image
/// as `identity.adrs_tail12 = "420000000e00000001000000"`, and
/// `tests/kat.rs::reference_verdicts_native` reads every recorded field of
/// group D, that one included.
///
/// The second anchor is still absent: no implementation independent of the C
/// exposes a 32-bit store, so there is no `put32` analogue of `CX-C9`.
///
/// So the standing answer to "what input makes this red?" is now: *a
/// `to_be_bytes` port, on any host* — measured, the fixture assertion reddens.
/// For `to_ne_bytes` the answer is still *a host*, and there is not one here.
/// `invariants.rs::no_native_endian_conversions_anywhere_in_the_crate` therefore
/// remains the only thing standing behind that case, and behind `get32`, which
/// no fixture records at all. **Narrowed, not retired.** Said plainly because
/// the alternative is a reader inferring from four green tests that the byte
/// order was measured in full. Half of it was.
#[must_use]
pub fn put32(value: u32) -> [u8; 4] {
    value.to_le_bytes()
}

/// The inverse of [`put32`], and carrying the same caveat: read
/// that function's note on why a differential against the C was blind to the
/// byte order.
#[must_use]
pub fn get32(bytes: &[u8; 4]) -> u32 {
    u32::from_le_bytes(*bytes)
}

/// The 22-byte tag payload: the tag, then its CRC16 through
/// [`put16`].
///
/// Named rather than left as two lines at the call site because the *order* of
/// the two is the thing a port gets wrong — appending `crc16(tag_with_crc)` or
/// prepending the checksum both produce a well-formed 22-byte payload that
/// Base58 encodes without complaint, and the codec carries no checksum logic to
/// object (fixture C12: an altered string decodes with `rc == 0`).
#[must_use]
pub fn tag_with_crc16(tag: &[u8; ADDR_TAG_LEN]) -> [u8; ADDR_TAG_LEN + 2] {
    let mut out = [0u8; ADDR_TAG_LEN + 2];
    out[..ADDR_TAG_LEN].copy_from_slice(tag);
    out[ADDR_TAG_LEN..].copy_from_slice(&put16(crc16(tag)));
    out
}

// -------------------------------------------------------------------------
// Base58
// -------------------------------------------------------------------------

///, verbatim, because it is the wire alphabet and not a
/// parameter anyone gets to choose.
const BASE58_ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// The inverse of [`BASE58_ALPHABET`], **derived** rather than transcribed.
///
/// ships the map as 128 literals. Computing it from the
/// alphabet instead means the two can never disagree with each other, and the
/// only remaining question — whether this alphabet is the reference's — is one
/// the corpus settles: the group C Base58 vectors decode through it
/// (`tests/kat.rs::base58_decode`).
///
/// `0`, `O`, `I` and `l` are absent from the alphabet and therefore land here
/// as `NONE`. That exclusion is the alphabet's, not ours.
const BASE58_MAP: [u8; 256] = {
    const NONE: u8 = 0xff;
    let mut map = [NONE; 256];
    let mut i = 0usize;
    while i < 58 {
        map[BASE58_ALPHABET[i] as usize] = i as u8;
        i += 1;
    }
    map
};

///, **corrected**. Encodes `input`; never returns a short length.
///
/// # This deliberately differs from the reference, on a named finite class
///
/// The C's length probe (`out == NULL`) is one short whenever the input is
/// **entirely zero bytes**, and that is the whole class — not an approximation
/// of one. The mechanism: `low` is initialised to
/// `size`, the conversion loop runs `inlen - zeros` times, and for an
/// all-zero input that is zero times, so `low` is never assigned. `low++` at
/// `:72` then leaves it at `size + 1`, and the probe returns
/// `zeros + size - low` = `zeros - 1`. Writing is unaffected — `:84` memsets
/// `zeros` `'1'` characters regardless — so the reference *encodes* correctly
/// and *reports* one byte less than it wrote.
///
/// `inlen == 0` is rejected by the C and is rejected here, so the
/// class is "all-zero and non-empty" exactly.
///
/// An all-zero tag is a reachable value — `fixtures/group_c_addr.json`'s C7 is
/// one — so reproducing the defect is not an option. This returns the true
/// length, which for a 20-byte zero tag is 20 and not 19.
///
/// # Why this is not a transcription
///
/// The C computes in a `calloc`'d scratch buffer sized by a fixed-point ratio
/// (`* 138 / 100 + 1`) and walks it with three cursors. Reproducing that
/// arithmetic in Rust would reproduce its off-by-one along with it, since the
/// off-by-one *is* the cursor arithmetic. This is written as the base
/// conversion the format specifies, so its correctness does not depend on
/// having read the C's index handling correctly.
pub fn base58_encode(input: &[u8]) -> Result<String> {
    if input.is_empty() {
        return Err(crate::error::Error::Reference {
            function: "base58_encode",
            rc: -1,
        });
    }

    let zeros = input.iter().take_while(|&&b| b == 0).count();

    // Base58 digits, least-significant first.
    let mut digits: Vec<u8> = Vec::with_capacity(input.len() * 138 / 100 + 1);
    for &byte in &input[zeros..] {
        let mut carry = u32::from(byte);
        for d in &mut digits {
            carry += u32::from(*d) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }

    let mut out = String::with_capacity(zeros + digits.len());
    for _ in 0..zeros {
        out.push('1');
    }
    for &d in digits.iter().rev() {
        out.push(BASE58_ALPHABET[usize::from(d)] as char);
    }
    Ok(out)
}

///, **corrected**. Decodes `s`; never faults, never short.
///
/// # The reference faults here, and this is where it does it
///
/// For a string of **entirely `'1'` characters** the same stale-cursor
/// mechanism as in [`base58_encode`] leaves `low == size + 1`, so
/// `:144`'s `memcpy(out + zeros, buffer + low, size - low)` is called with
/// `size - low == -1`, converted to `(size_t)(-1)`. `fixtures/group_c_addr.json`'s
/// `C-base58-degenerate` records the crash under `lldb` and notes that the
/// probe on the same input returns 21 for a 22-byte payload, so a caller that
/// sized its buffer from the probe is already wrong before the `memcpy`.
///
/// The correct answer for an all-`'1'` string of length *n* is *n* zero bytes.
/// The C cannot be asked for it, so the fixture states it as a requirement
/// rather than recording it as an output. That is the one value in this path
/// with no oracle behind it, and `tests/kat.rs::ts_base58_decode` checks it
/// against the `bs58`-executed crosscheck value.
///
/// Rejection matches the reference exactly, and only there: the empty string,
/// a byte with the high bit set (`:122`), and any byte the alphabet
/// does not contain. Notably **not** a checksum — `base58.c` has no
/// checksum logic, which fixture C12 pins from the other side.
pub fn base58_decode(s: &[u8]) -> Result<Vec<u8>> {
    let reject = || {
        Err(crate::error::Error::Reference {
            function: "base58_decode",
            rc: -1,
        })
    };

    if s.is_empty() {
        return reject();
    }

    let zeros = s.iter().take_while(|&&c| c == b'1').count();

    // Bytes, least-significant first.
    let mut bytes: Vec<u8> = Vec::with_capacity((s.len() - zeros) * 733 / 1000 + 1);
    for &c in &s[zeros..] {
        let v = BASE58_MAP[usize::from(c)];
        if v == 0xff {
            return reject();
        }
        let mut carry = u32::from(v);
        for b in &mut bytes {
            carry += u32::from(*b) * 58;
            *b = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            bytes.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }

    let mut out = Vec::with_capacity(zeros + bytes.len());
    out.resize(zeros, 0);
    out.extend(bytes.iter().rev());
    Ok(out)
}

/// The length [`base58_encode`] would produce, without producing it.
///
/// Kept as a separate function because the reference has one and a port that
/// silently dropped it would leave callers reaching for the C's. It agrees with
/// `base58_encode(..)?.len()` by construction and is checked to.
pub fn base58_encoded_len(input: &[u8]) -> Result<usize> {
    base58_encode(input).map(|s| s.len())
}

/// The length [`base58_decode`] would produce, without producing it.
pub fn base58_decoded_len(s: &[u8]) -> Result<usize> {
    base58_decode(s).map(|v| v.len())
}

// --- the transaction accessor surface ------------------------------------
//
// The seven accessors, ported from the `types.h` macros. Every one is a byte read or a
// slice; there is no arithmetic here beyond one widening add.
//
// # The endian scan's blind spot is not entered
//
// `invariants.rs::no_native_endian_conversions_anywhere_in_the_crate` is sole
// enforcement for 32-bit byte order everywhere except `put32`, and the class it
// cannot see is a multi-byte integer assembled from bytes by hand. **None of
// the seven assembles one.** `mdst_count` widens a single `u8` to `u16`, which
// has no byte order to get wrong; the rest return bytes or slices of bytes.
// Stated here rather than left to be inferred from the scan staying green.
//
// # No `adrs` conversion appears, and if one ever does, stop
//
// The little-endian decision (`put16`'s doc) settled `from_le_bytes` /
// `to_le_bytes` for a byte-versus-word
// `adrs` call site that still does not exist. Nothing below touches `adrs`. A
// future edit that needs one here has pulled in work belonging elsewhere.

/// `TXDAT_TYPE(options)`: the first options byte.
pub fn dat_type(options: &[u8; 4]) -> u8 {
    options[0]
}

/// `TXDSA_TYPE(options)`: the second options byte.
pub fn dsa_type(options: &[u8; 4]) -> u8 {
    options[1]
}

/// `MDST_COUNT(options)`: the third options byte, plus one.
///
/// **The widening is the whole function.** `((word8 *) options)[2] + 1` is C
/// integer promotion: the byte is promoted to `int` and the sum is an `int`, so
/// `0xFF` yields **256**. Writing this as `options[2] + 1` in Rust would be
/// `u8 + u8`, which panics on overflow in debug and wraps to 0 in release --
/// two different wrong answers, neither of them the reference's. `u16::from`
/// before the add is what reproduces the promotion.
pub fn mdst_count(options: &[u8; 4]) -> u16 {
    u16::from(options[2]) + 1
}

/// `ADDR_TAG_PTR(ptr)`: the tag half of an address.
///
/// # Why this reads `ADDR_TAG_OFF` rather than starting at zero
///
/// Because the reference states an offset and this is a port of what it states.
/// `ADDR_TAG_OFF` is 0 today, so the expression folds to `&addr[..20]` and the
/// generated code is identical -- what differs is that the offset moving
/// upstream is a value this function reads rather than a fact it assumes.
pub fn tag_ptr(addr: &[u8; ADDR_LEN]) -> &[u8] {
    &addr[ADDR_TAG_OFF..ADDR_TAG_OFF + ADDR_TAG_LEN]
}

/// `ADDR_HASH_PTR(ptr)`: the hash half of an address.
///
/// # This is where the bound offset earns its place
///
/// `ADDR_HASH_OFF` is 20 and `ADDR_TAG_LEN` is 20, so `&addr[ADDR_TAG_LEN..]`
/// returns the same bytes and was the obvious way to write it. It is an
/// **inference** -- that the hash half begins where the tag half ends, with no
/// gap -- rather than a reading of the offset states. That is the
/// shape corrected at [`put32`], where `put16` being verified little-endian was
/// standing in for a measurement of `put32`. `crate::addr::hash_of` still makes
/// the inference; with `ADDR_HASH_OFF` bound, the two agreeing is now a checked
/// fact rather than one assumption twice.
pub fn hash_ptr(addr: &[u8; ADDR_LEN]) -> &[u8] {
    &addr[ADDR_HASH_OFF..ADDR_HASH_OFF + ADDR_HASH_LEN]
}

/// `TXLEN_MIN`: `sizeof(TXHDR) + sizeof(MDST) + sizeof(WOTSVAL)`.
///
/// The three sizes come from `crate::consts::wire`, which carries the
/// reference's own `STATIC_ASSERT` expressions rather than three numbers. See
/// that module for why, and `tests/layout.rs` for the two independent things
/// each is checked against.
pub fn len_min() -> usize {
    wire::SIZEOF_TXHDR + wire::SIZEOF_MDST + wire::SIZEOF_WOTSVAL
}

/// `TXLEN_DSK_MIN`: [`len_min`] plus a trailer.
pub fn len_dsk_min() -> usize {
    len_min() + wire::SIZEOF_TXTLR
}
