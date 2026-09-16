#![cfg(feature = "native")]
//! The transaction wire codec, exercised with no C required.
//!
//! Gated on `native` alone — this file compiles and runs in
//! `--no-default-features --features native`, the configuration Miri can
//! interpret, and that is its purpose: it is the mechanism behind the claim
//! that the native transaction path works **in a build where the C is
//! absent**. The walk itself is `support/wire_images.rs`, one implementation
//! shared with `spend.rs`'s loaders; the marker in `invariants.rs` names which
//! test carries which claim.
//!
//! # What this file alone cannot establish
//!
//! A parse/serialize error pair that compensates — both sides using the same
//! wrong offset — keeps every pure round trip here green. The recorded-field
//! assertions in the shared walk catch the corpus-visible cases; closing the
//! class off-corpus would need a second construction path to differ from, and
//! this repository has none. A green here is "the C-free build round-trips the
//! corpus", not "the codec agrees with the C everywhere".

#[path = "support/wire_images.rs"]
mod wire_images;

use mochimo_crypto::tx::wire::{Destination, Transaction};

/// Every group D wire image, parsed and re-serialized natively, with every
/// recorded field asserted — in a test binary that links no C.
///
/// The counts are stated, not derived: 49 named images — 45 the
/// reference accepted and round-trip byte-identically, 4 it rejected
/// (`D14`'s one-byte-long form, `D15`'s three unknown-type cases) whose
/// rejection the native parser reproduces.
#[test]
fn native_transaction_round_trip_needs_no_reference() {
    let file = wire_images::fixture_json("group_d_tx.json");
    let totals = wire_images::native_round_trip_walk(&file);

    // Stated both ways: the full corpus everywhere, and the ten-image
    // embedded subset under Miri, whose isolation forbids the `open` the
    // walk otherwise performs (see `wire_images::embedded` for the choice).
    let (want_accepted, want_rejected, field_floor) =
        if cfg!(miri) { (8, 2, 40) } else { (67, 4, 60) };
    assert_eq!(
        totals.accepted, want_accepted,
        "expected {want_accepted} accepted group D wire images to round-trip; \
         walked {}. If the corpus grew, restate this number deliberately; if \
         it shrank, an image key stopped being walked.",
        totals.accepted
    );
    assert_eq!(
        totals.rejected, want_rejected,
        "expected {want_rejected} reference-rejected group D wire images; saw {}",
        totals.rejected
    );
    assert!(
        totals.field_assertions >= field_floor,
        "only {} recorded-field assertions ran across the walk (floor \
         {field_floor}); the field gate has come apart from the corpus",
        totals.field_assertions
    );

    println!(
        "  C-free transaction round trip: {} images byte-identical, {} \
         rejections reproduced, {} recorded fields asserted",
        totals.accepted, totals.rejected, totals.field_assertions
    );
}

/// The bytes of a group D sidecar, in the C-free build and under Miri. Only
/// `Ds1_N1_hashed.bin` is embedded, so Miri walks one of the five hashed
/// images and the count below says so.
fn hashed_image(name: &str) -> Option<Vec<u8>> {
    #[cfg(miri)]
    {
        if name == "Ds1_N1_hashed.bin" {
            return Some(include_bytes!("../../../fixtures/Ds1_N1_hashed.bin").to_vec());
        }
        None
    }
    #[cfg(not(miri))]
    {
        Some(wire_images::fixture_bytes(name))
    }
}

/// The two digests the node takes (`tx_hash`), reproduced
/// natively against the values the reference itself recorded: every `Ds1-N*`
/// vector carries the image `tx_hash` was called on (`hashed_wire_file`) and
/// both outputs (`message_hash`, `id_hash`). Then `seal`: the same prefix and
/// validation data, a zero nonce, and an id that is the id digest of the
/// sealed image — the trailer `process_tx` writes.
///
/// In the default build `backend::selected::sha256` is the C's own, so this
/// is the reference hashing its own image; in the C-free build it is the
/// native `sha256`, and this test is the per-call-site evidence that the
/// digests survive with no C linked.
#[test]
fn native_digests_match_the_reference_recorded_hashes() {
    let file = wire_images::fixture_json("group_d_tx.json");
    let mut checked = 0usize;
    for v in file["vectors"].as_array().expect("vectors") {
        let (Some(hashed), Some(message_hash), Some(id_hash)) = (
            v.get("hashed_wire_file").and_then(|x| x.as_str()),
            v.get("message_hash").and_then(|x| x.as_str()),
            v.get("id_hash").and_then(|x| x.as_str()),
        ) else {
            continue;
        };
        let id = v["id"].as_str().unwrap_or("?");
        let Some(bytes) = hashed_image(hashed) else { continue };
        let tx = Transaction::from_wire(&bytes).unwrap_or_else(|e| panic!("{id}: {hashed} does not parse: {e:?}"));
        assert_eq!(
            mochimo_crypto::mesh::hex::encode(&tx.message_digest()),
            message_hash,
            "{id}: message_digest is not the recorded TX_HASH_MESSAGE"
        );
        assert_eq!(
            mochimo_crypto::mesh::hex::encode(&tx.id_digest()),
            id_hash,
            "{id}: id_digest is not the recorded TX_HASH_ID (nonce as held)"
        );

        let mut sealed = tx.clone();
        sealed.seal();
        let w = sealed.to_wire();
        assert_eq!(w.len(), bytes.len(), "{id}: sealing changed the image length");
        assert_eq!(&w[..tx.tlr_off()], &bytes[..tx.tlr_off()], "{id}: sealing touched the signed prefix or validation data");
        let t = sealed.trailer.as_ref().unwrap_or_else(|| panic!("{id}: sealed image has no trailer"));
        assert_eq!(t.nonce, 0, "{id}: sealed nonce is not zero");
        assert_eq!(t.id, sealed.id_digest(), "{id}: sealed id is not the id digest of the sealed image");
        checked += 1;
    }
    let want = if cfg!(miri) { 1 } else { 5 };
    assert_eq!(
        checked, want,
        "expected {want} Ds1 hashed images to replay; walked {checked}. If the corpus grew, restate \
         this number; if it shrank, a key stopped being read."
    );
    println!("  C-free digests: {checked} Ds1 image(s), message_hash and id_hash reproduced, seal checked");
}

/// The construction invariant: the one state the wire cannot express is
/// unrepresentable, and the bound is the constructor's, not a panic.
#[test]
fn native_transaction_construction_holds_the_count_bound() {
    let d = Destination {
        tag: [0; 20],
        reference: [0; 16],
        amount: 1,
    };

    assert!(
        Transaction::new(vec![]).is_err(),
        "a zero-destination transaction is unrepresentable on the wire \
         (MDST_COUNT = options[2] + 1, types.h:176) and must be rejected"
    );
    assert!(
        Transaction::new(vec![d.clone(); 257]).is_err(),
        "257 destinations cannot be encoded in options[2] and must be rejected"
    );

    for n in [1usize, 2, 256] {
        let tx = Transaction::new(vec![d.clone(); n])
            .unwrap_or_else(|e| panic!("{n} destinations must construct: {e:?}"));
        assert_eq!(tx.dst_count(), n as u16);
        let wire = tx.to_wire();
        assert_eq!(
            wire.len(),
            tx.wire_len(),
            "to_wire's length disagrees with wire_len at n = {n}"
        );
        let back = Transaction::from_wire(&wire)
            .unwrap_or_else(|e| panic!("self round trip failed at n = {n}: {e:?}"));
        assert_eq!(back, tx, "self round trip changed the value at n = {n}");
    }
    println!("  C-free construction bounds: 0 and 257 rejected; 1, 2, 256 built");
}
