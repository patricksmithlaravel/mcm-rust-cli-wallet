#![cfg(feature = "native")]
//! The native backend, run under Miri.
//!
//! # What this file is for
//!
//! Memory safety is a property no fixture reaches: an over-read past a
//! fixed-size buffer is not a value, so a corpus of values cannot see it.
//! Miri does. It is an interpreter and could not execute a linked foreign
//! function, which is why the port had to compile with no C before it could
//! run at all; the C is gone from this repository and the default
//! configuration is the one it interprets:
//!
//! ```sh
//! cargo +nightly miri test -p mochimo-crypto
//! ```
//!
//! # Two walks
//!
//! **Nothing in [`walk_native`] is backend-dependent**: every call names
//! `backend::native::*` explicitly. [`walk_selected_routing`] drives the
//! public wrappers, which route through `backend::selected`; that is a plain
//! alias of `native` now, and the second walk is kept because it is the one
//! that would notice a second backend being selected under the wrappers.
//!
//! # The domain, and why it is declared rather than implied
//!
//! A green Miri run reads as "this crate is memory-safe". What it can mean is
//! "the paths Miri walked are memory-safe", and with a third of the crate's
//! surface panicking on entry those are different claims (state what makes the
//! domain complete, or state that it isn't).
//!
//! [`MIRI_DOMAIN`] is that statement: every `pub fn` in
//! `src/backend/native.rs`, each either covered or excluded **with its reason**.
//! Two independent checks keep it honest, and they are in different files on
//! purpose:
//!
//!   * here, [`native_backend_is_clean_under_miri`] asserts that the set of
//!     functions it actually exercised equals the set the table calls covered;
//!   * in `invariants.rs`,
//!     `memory_safety_is_established_only_for_the_native_paths_miri_walks`
//!     asserts that the table's key set equals the `pub fn` set *parsed out of
//!     `native.rs` itself*, so a function added to the backend is undeclared
//!     until someone decides its Miri status.
//!
//! Only the second is derived from the artifact. The first would be a
//! self-comparison on its own — the table and the calls are in one file — which
//! is why it is not on its own.

use std::collections::BTreeSet;

#[path = "support/drop_witness.rs"]
mod drop_witness;

use mochimo_crypto::backend::native;
use mochimo_crypto::consts::{ADDR_LEN, PK_LEN, SEED_LEN, SIG_LEN, WOTSLEN1};

/// Every `pub fn` in `src/backend/native.rs`: `None` covered, `Some(reason)` not.
///
/// The key set is asserted equal to what `invariants.rs` parses out of
/// `native.rs`, so this cannot silently fall behind the backend.
///
/// # On the four that are not covered
///
/// The `_counted` variants are covered; their plain wrappers are one-line
/// delegations to them (`wots_sign` is `wots_sign_counted(..).0`), so the bytes
/// Miri would interpret are the same bytes it already interpreted. That is an
/// argument about *this* pair specifically and not a general licence — a
/// wrapper that did any work of its own would need its own entry.
///
/// The stubs that once sat beside the backend panicked by construction, and
/// exercising an `unimplemented!()` under Miri would have measured the panic
/// path, not the port; the backend carries none today.
const MIRI_DOMAIN: &[(&str, Option<&str>)] = &[
    ("sha256", None),
    ("ull_to_bytes", None),
    ("addr_to_bytes", None),
    ("prf", None),
    ("thash_f", None),
    ("gen_chain", None),
    ("gen_chain_counted", None),
    ("base_w", None),
    ("wots_checksum", None),
    ("chain_lengths", None),
    ("expand_seed", None),
    ("wots_pkgen", None),
    (
        "wots_sign",
        Some("a one-line delegation to wots_sign_counted, which is covered"),
    ),
    ("wots_sign_counted", None),
    (
        "wots_pk_from_sig",
        Some("a one-line delegation to wots_pk_from_sig_counted, which is covered"),
    ),
    ("wots_pk_from_sig_counted", None),
    ("sha3_224", None),
    ("sha3_256", None),
    ("sha3_384", None),
    ("sha3_512", None),
    ("ripemd160", None),
    ("addr_hash_generate", None),
    ("addr_from_implicit", None),
    ("addr_from_wots", None),
    ("crc16", None),
    ("put16", None),
    ("get16", None),
    ("tag_with_crc16", None),
    ("base58_encode", None),
    ("base58_decode", None),
    ("base58_encoded_len", None),
    ("base58_decoded_len", None),
    ("get32", None),
    ("put32", None),
    // The transaction accessor surface, ported from the `types.h` macros. Every one is covered:
    // they are byte reads and slices, so the interpreter walks them in
    // microseconds and there is no reason to exclude any. `len_min` and
    // `len_dsk_min` take no arguments and index nothing -- they are walked
    // anyway, because "this one cannot possibly be wrong" is the judgement this
    // table exists to stop anyone making silently.
    ("dat_type", None),
    ("dsa_type", None),
    ("mdst_count", None),
    ("tag_ptr", None),
    ("hash_ptr", None),
    ("len_min", None),
    ("len_dsk_min", None),
];

/// Calls `native::$name(..)` and records `"$name"`, from the same token.
///
/// The name and the call cannot diverge, which a `log.push("sha256")` beside a
/// `native::sha3_512(..)` very much can. Same reason `lib.rs::declare_consts!`
/// emits both sides of a constant from one list: a correspondence that has to be
/// maintained by hand is a correspondence that eventually is not.
///
/// The result goes through [`core::hint::black_box`], which does two jobs. It
/// satisfies `#[must_use]` at the call sites that do not need the value — but
/// more to the point, it stops the optimiser deleting a call whose result is
/// unread. A walk that exists to be *executed* is precisely the walk that dead
/// code elimination is entitled to remove, and Miri cannot report undefined
/// behaviour in code that was not run.
macro_rules! exercise {
    ($log:expr, $name:ident ( $($arg:expr),* $(,)? )) => {{
        $log.insert(stringify!($name));
        core::hint::black_box(native::$name($($arg),*))
    }};
}

/// Every covered function in [`MIRI_DOMAIN`], once, with real inputs.
///
/// Returns the names it exercised. Inputs are small but not degenerate: a
/// zero-length or all-zero input can miss the bounds arithmetic that is the
/// whole point of running this under an interpreter.
fn walk_native() -> BTreeSet<&'static str> {
    let mut log = BTreeSet::new();

    let seed: [u8; SEED_LEN] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
    let pub_seed: [u8; SEED_LEN] = core::array::from_fn(|i| (i as u8) ^ 0x5a);
    let msg: [u8; SEED_LEN] = core::array::from_fn(|i| (i as u8).wrapping_add(0x11));

    // --- hashes -----------------------------------------------------------
    exercise!(log, sha256(b"the quick brown fox"));
    exercise!(log, sha3_224(b"the quick brown fox"));
    exercise!(log, sha3_256(b"the quick brown fox"));
    exercise!(log, sha3_384(b"the quick brown fox"));
    exercise!(log, sha3_512(b"the quick brown fox"));
    // 62 bytes: `len % 64 >= 56`, the class the reference overflows on and the
    // native path is defined over. It is the interesting length for a bounds
    // interpreter, so it is the one used here.
    exercise!(log, ripemd160(&[0xa5u8; 62]));

    // --- WOTS+ internals --------------------------------------------------
    let mut out8 = [0u8; 8];
    exercise!(log, ull_to_bytes(&mut out8, 0x0123_4567_89ab_cdef));

    let mut adrs = [1u32, 2, 3, 4, 5, 6, 7, 8];
    exercise!(log, addr_to_bytes(&adrs));
    let hashed = exercise!(log, prf(&[0x33u8; 32], &seed)).expect("prf over 32 bytes");
    exercise!(log, thash_f(&hashed, &pub_seed, &mut adrs));
    exercise!(log, gen_chain(&seed, 3, 4, &pub_seed, &mut adrs));
    exercise!(log, gen_chain_counted(&seed, 0, 15, &pub_seed, &mut adrs));

    let mut base_w_out = [0i32; WOTSLEN1];
    exercise!(log, base_w(&mut base_w_out, &msg));
    exercise!(log, wots_checksum(&base_w_out));
    exercise!(log, chain_lengths(&msg));
    exercise!(log, expand_seed(&seed));

    // --- WOTS+ proper -----------------------------------------------------
    let mut a = adrs;
    let pk: Box<[u8; PK_LEN]> = exercise!(log, wots_pkgen(&seed, &pub_seed, &mut a));
    let mut a = adrs;
    let (sig, counts): (Box<[u8; SIG_LEN]>, _) =
        exercise!(log, wots_sign_counted(&msg, &seed, &pub_seed, &mut a));
    let mut a = adrs;
    let (recovered, bounds) = exercise!(
        log,
        wots_pk_from_sig_counted(&sig, &msg, &pub_seed, &mut a)
    );
    // Not a KAT -- `tests/native.rs` owns correctness. This is here so the
    // recovered key is *read*, which is what makes an over-read past it
    // something Miri can see rather than something the optimiser deletes.
    assert_eq!(pk, recovered, "WOTS+ round trip disagreed under the walk");
    assert_eq!(counts.len(), bounds.len());

    // --- address path -----------------------------------------------------
    exercise!(log, addr_hash_generate(b"an address preimage"));
    let tag = [0x2bu8; 20];
    exercise!(log, addr_from_implicit(&tag));
    exercise!(log, addr_from_wots(&pk));
    exercise!(log, tag_with_crc16(&tag));

    // --- small integer and checksum accessors -----------------------------
    exercise!(log, crc16(b"123456789"));
    let two = exercise!(log, put16(0xabcd));
    exercise!(log, get16(&two));
    // Deliberately non-palindromic, so a byte-order slip is visible to the
    // interpreter's bounds checking as well as to the KAT.
    let four = exercise!(log, put32(0x0123_4567));
    exercise!(log, get32(&four));

    // --- base58 -----------------------------------------------------------
    // A leading zero byte and a non-zero body: the leading-zero run is the part
    // of the codec that indexes a separately computed prefix length.
    let payload = [0x00u8, 0x00, 0x9f, 0x41, 0x77, 0x02];
    let encoded = exercise!(log, base58_encode(&payload)).expect("base58 encode");
    exercise!(log, base58_decode(encoded.as_bytes())).expect("base58 decode");
    exercise!(log, base58_encoded_len(&payload)).expect("base58 encoded len");
    exercise!(log, base58_decoded_len(encoded.as_bytes())).expect("base58 decoded len");

    // --- the transaction accessor surface ---------------------------------
    //
    // Option bytes chosen mutually distinct and non-zero, so an accessor
    // reading the wrong index is visible here and not only in the KAT. The
    // third is 0xFF, which is the one input where MDST_COUNT's integer
    // promotion matters: it yields 256, and a u8 return would make it 0.
    let opts = [0x5au8, 0xa5, 0xff, 0x3c];
    exercise!(log, dat_type(&opts));
    exercise!(log, dsa_type(&opts));
    exercise!(log, mdst_count(&opts));

    // A full 40-byte address whose two halves differ, so a slice taken at the
    // wrong offset reads bytes the other half owns rather than the same bytes
    // twice.
    let addr: [u8; ADDR_LEN] = core::array::from_fn(|i| (i as u8).wrapping_mul(3).wrapping_add(9));
    exercise!(log, tag_ptr(&addr));
    exercise!(log, hash_ptr(&addr));

    exercise!(log, len_min());
    exercise!(log, len_dsk_min());

    log
}

/// The public wrappers, which route through `backend::selected`.
///
/// Separate from [`walk_native`] so that the two claims stay two: the backend
/// is clean, and the wrappers reach it. These names are deliberately absent
/// from [`MIRI_DOMAIN`], which is a domain over `backend/native.rs`, not over
/// the crate.
fn walk_selected_routing() -> usize {
    use mochimo_crypto::{addr, crc16, wots, Secret};

    let seed = Secret::<{ SEED_LEN }>::new([0x31u8; SEED_LEN]);
    let pub_seed = [0x77u8; SEED_LEN];
    let msg = [0x42u8; SEED_LEN];

    let mut adrs = wots::Adrs::ZERO;
    let _ = adrs.to_bytes();
    let _ = adrs.words();
    let pk = wots::pkgen(&seed, &pub_seed, &mut adrs);

    // `wots::sign` is crate-private (I1), so it is no
    // longer a public wrapper this walk can route through. The raw signer is
    // walked by `walk_native` as `wots_sign_counted`; what this walk loses is
    // one call through the demoted wrapper, and the count below fell by one
    // to say so. The signature `pk_from_sig` recovers below is produced by
    // the backend directly for exactly that reason.
    let mut adrs = wots::Adrs::ZERO;
    let sig = native::wots_sign(&msg, seed.expose(), &pub_seed, &mut adrs.0);
    let mut adrs = wots::Adrs::ZERO;
    let _ = wots::pk_from_sig(&sig, &msg, &pub_seed, &mut adrs);

    let a = addr::from_wots(&pk);
    let _ = addr::tag_of(&a);
    let _ = addr::hash_of(&a);
    let _ = addr::hash_generate(b"x");
    let _ = addr::ripemd160(b"x");
    let _ = addr::from_implicit(&[9u8; 20]);
    let _ = crc16::crc16(b"x");

    // `Secret`'s own path: a clone, a borrow, and a drop that must scrub.
    let clone = seed.clone();
    assert_eq!(clone.expose().len(), SEED_LEN);
    drop(clone);

    14
}

/// The native backend, walked end to end so an interpreter can watch it.
///
/// # What a pass means, exactly
///
/// Under `cargo miri test`: every function [`MIRI_DOMAIN`] marks covered
/// executed without Miri reporting undefined behaviour. **Not** that the crate
/// is memory-safe — see this file's header, and the name of the marker in
/// `invariants.rs`, which carries the same qualification so it cannot be quoted
/// without it.
///
/// Under plain `cargo test` it is a smoke test and nothing more. That is fine:
/// its job in that build is to keep compiling and keep the domain honest.
///
/// # The count
///
/// A run that executes nothing and passes is indistinguishable from a clean
/// result, and this is the one result the exercise exists to produce. So the
/// number is asserted non-zero, asserted *equal to the declared covered set*,
/// and printed — a floor of "at least one" would go green on a walk that
/// silently stopped after `sha256`.
#[test]
fn native_backend_is_clean_under_miri() {
    let exercised = walk_native();

    assert!(
        !exercised.is_empty(),
        "the Miri walk executed nothing. A run that interprets no code passes \
         exactly as a clean run does, which makes this assertion the only thing \
         standing between a vacuous pass and a result."
    );

    let covered: BTreeSet<&str> = MIRI_DOMAIN
        .iter()
        .filter(|(_, why)| why.is_none())
        .map(|(name, _)| *name)
        .collect();

    assert_eq!(
        exercised, covered,
        "the walk and MIRI_DOMAIN disagree about what is covered. Left is what \
         ran, right is what the table claims; a name on the right only is a \
         function declared covered that nothing calls, and a name on the left \
         only is a function exercised without an entry."
    );

    let excluded = MIRI_DOMAIN.len() - covered.len();
    eprintln!(
        "native_backend_is_clean_under_miri: executed {} of {} native functions \
         ({excluded} excluded with a reason). Running under miri: {}.",
        exercised.len(),
        MIRI_DOMAIN.len(),
        cfg!(miri)
    );

    {
        let routed = walk_selected_routing();
        assert!(routed > 0);
        eprintln!("  and {routed} public entry points, which route to native.");
    }
}

/// The zeroization witness, run under the interpreter.
///
/// # Why this test exists beside `native.rs`'s copy
///
/// `secret_bytes_are_gone_after_drop` lives in `tests/native.rs`, which is where
/// the execution census demands the proof be. That file is gated on **both**
/// backends, so Miri -- which runs `--no-default-features --features native`,
/// the only configuration an interpreter can execute -- never sees it.
///
/// The construction is the delicate part of that test, not the assertion: it
/// reads storage across an object's death, and the version the marker's own doc
/// comment proposes is undefined behaviour. **Miri is the only thing in this
/// tree that can tell a sound witness from one that merely appears to work**, so
/// the witness is shared from `support/drop_witness.rs` and executed here as
/// well. One implementation, two consumers; a second copy could drift into
/// unsoundness in exactly the binary the interpreter does not run.
///
/// Under a normal `cargo test` this is a cheap duplicate of the other test's
/// observation. Under `cargo +nightly miri test` it is the whole point.
#[test]
fn secret_drop_witness_is_sound_under_miri() {
    let obs = drop_witness::observe_secret_drop::<32>();

    assert!(
        obs.pattern_seen_before_drop,
        "the witness could not see the pattern in the Secret's storage before \
         the drop, so it is reading the wrong bytes and everything it says \
         after the drop is about the wrong memory"
    );
    assert!(
        obs.all_zero_after_drop,
        "{} of {} bytes still match the pattern after the drop",
        obs.surviving_pattern_bytes,
        obs.bytes
    );

    eprintln!(
        "secret_drop_witness_is_sound_under_miri: {} bytes, {} surviving. \
         Running under miri: {}.",
        obs.bytes,
        obs.surviving_pattern_bytes,
        cfg!(miri)
    );
}
