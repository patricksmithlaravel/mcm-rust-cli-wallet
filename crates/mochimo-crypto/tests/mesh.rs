#![cfg(feature = "native")]
//! The Mesh codec and the two mesh fixture groups, exercised with no C
//! required and, for the parts that read no files, under Miri.
//!
//! Gated on `native` alone: this file compiles and runs in
//! `--no-default-features --features native`. The coverage-tracking replay of
//! the same vectors lives in `kat.rs`, through the same walk
//! (`support/mesh_walk.rs`, one implementation behind a trait) with `Ctx`
//! recording every field read; this binary is the "works with no C linked"
//! execution and the totality run.
//!
//! # What this file establishes, and what it cannot
//!
//! Group N is a **specification capture** of one server at one block and
//! group M is the shipped client executed under a double; neither is an
//! oracle for the codec being right. What the replays
//! establish is that the codec builds the bytes that server accepted, parses
//! the bytes it returned into independently derivable values, and refuses
//! every truncation and every single-byte corruption of every recorded body
//! without panicking. Whether a node accepts a transaction this crate
//! builds is not knowable here (the residue at `mesh::spend`).

use std::path::PathBuf;

#[path = "support/mesh_walk.rs"]
mod mesh_walk;

use mesh_walk::Plain;
use mochimo_crypto::mesh::{codec, hex, max_response_bytes, MAX_HISTORY_RESPONSE_BYTES, MAX_RECON_RESPONSE_BYTES, MAX_REQUEST_BYTES};
use mochimo_crypto::Error;

const N_FILE: &str = "group_n_mesh_live.json";
const M_FILE: &str = "group_m_mesh_client.json";

#[cfg_attr(miri, allow(dead_code))]
fn repo_root() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p
}

#[cfg(not(miri))]
fn fixture_json(name: &str) -> serde_json::Value {
    let p = repo_root().join("fixtures").join(name);
    let text = std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("cannot read {}: {e}", p.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("cannot parse {}: {e}", p.display()))
}

// Miri runs with isolation on and cannot `open`; the N fixture is embedded
// for the totality run, which reads no sidecar.
#[cfg(miri)]
fn fixture_json(name: &str) -> serde_json::Value {
    assert_eq!(name, N_FILE, "only group N is embedded for Miri");
    serde_json::from_str(include_str!("../../../fixtures/group_n_mesh_live.json")).expect("embedded group N parses")
}

#[cfg(not(miri))]
fn sidecar(name: &str) -> Vec<u8> {
    let p = repo_root().join("fixtures").join(name);
    std::fs::read(&p).unwrap_or_else(|e| panic!("cannot read {}: {e}", p.display()))
}

// --- hex ---------------------------------------------------------------------

#[test]
fn hex_round_trips_and_refuses_by_offset() {
    let bytes: Vec<u8> = (0..=255).collect();
    let s = hex::encode(&bytes);
    assert_eq!(s.len(), 512);
    assert_eq!(hex::decode(&s, "t").unwrap_or_else(|e| panic!("{e}")), bytes);
    assert_eq!(hex::decode(&s.to_ascii_uppercase(), "t").unwrap_or_else(|e| panic!("{e}")), bytes);
    assert_eq!(hex::decode("", "t").unwrap_or_else(|e| panic!("{e}")), Vec::<u8>::new());
    assert_eq!(hex::decode("abc", "t"), Err(Error::Hex { what: "t", offset: 2 }));
    assert_eq!(hex::decode("0g", "t"), Err(Error::Hex { what: "t", offset: 1 }));
    assert_eq!(hex::decode("g0", "t"), Err(Error::Hex { what: "t", offset: 0 }));
    assert_eq!(hex::decode("00zz", "t"), Err(Error::Hex { what: "t", offset: 2 }));
    assert_eq!(hex::decode_exact::<2>("0001", "t"), Ok([0, 1]));
    assert_eq!(
        hex::decode_exact::<2>("000102", "t"),
        Err(Error::Length {
            what: "t",
            expected: 2,
            got: 3
        })
    );
    assert_eq!(hex::decode_prefixed::<1>("0xff", "t"), Ok([0xff]));
    assert_eq!(hex::decode_prefixed::<1>("ff", "t"), Err(Error::Hex { what: "t", offset: 0 }));
    println!("  hex: 256 bytes round-tripped, 7 refusals by offset");
}

// --- requests ----------------------------------------------------------------

/// The request KATs against group N depend on `serde_json` emitting keys
/// sorted; if `preserve_order` were ever unified into the build the bodies
/// would come out in insertion order and every KAT would fail with a
/// misleading diff. This names the mechanism.
#[test]
fn request_bodies_serialise_with_sorted_keys() {
    let v = serde_json::json!({ "zeta": 1, "alpha": { "z": 2, "a": 3 }, "mid": true });
    assert_eq!(v.to_string(), r#"{"alpha":{"a":3,"z":2},"mid":true,"zeta":1}"#);
    let body = codec::request_tag_resolve(&[0x11; 20]);
    let text = String::from_utf8(body).unwrap_or_else(|e| panic!("{e}"));
    assert!(text.starts_with(r#"{"method":"tag_resolve","network_identifier":{"blockchain":"mochimo","network":"mainnet"},"parameters":{"tag":"0x"#), "{text}");
    assert!(!text.contains(' '), "compact, no spaces: {text}");
    println!("  request bodies: sorted keys, compact, 1 tag_resolve body inspected");
}

/// The Mesh middleware caps a request body at 30 KiB (`http.MaxBytesReader(w,
/// r.Body, 30*1024)` in its `maxRequestSizeMiddleware`); this crate's cap is
/// the same number. Stated here; the Go source is not in this repository.
#[cfg(not(miri))]
#[test]
fn request_cap_is_the_middlewares() {
    assert_eq!(MAX_REQUEST_BYTES, 30 * 1024);
    println!("  request cap: MAX_REQUEST_BYTES is the middleware's 30*1024");
}

// --- the two groups, replayed with no C -----------------------------------------

#[cfg(not(miri))]
fn replay_group(file: &'static str, want: usize) -> (usize, usize) {
    let json = fixture_json(file);
    let vectors = json["vectors"].as_array().unwrap_or_else(|| panic!("{file}: no vectors"));
    let mut assertions = 0usize;
    let mut replayed = 0usize;
    for v in vectors {
        let source = v["source"].as_str().unwrap_or_else(|| panic!("{file}: a vector has no source"));
        assert!(
            mesh_walk::SOURCES.contains(&source),
            "{file}: vector {} cites a source the walk does not register: {source}",
            v["id"]
        );
        let mut plain = Plain::new(file, v, sidecar);
        mesh_walk::replay(&mut plain, source);
        assertions += plain.assertions;
        replayed += 1;
    }
    assert_eq!(
        replayed, want,
        "{file}: expected {want} vectors, walked {replayed}. If the corpus grew, restate this number deliberately."
    );
    (replayed, assertions)
}

/// Every group N vector through the walk with no C linked. The count is
/// stated, not derived: 22 captured exchanges, of
/// which four read a SEALED block rather than the tip and are therefore the
/// only vectors in this group a re-capture must reproduce byte for byte.
#[cfg(not(miri))]
#[test]
fn group_n_replays_with_no_reference() {
    let (n, a) = replay_group(N_FILE, 22);
    println!("  group N specification capture: {n} exchanges replayed, {a} recorded-field assertions, no C linked");
}

/// Every group M vector through the walk with no C linked: 6 vectors, every
/// recorded boolean recomputed from the sidecars.
#[cfg(not(miri))]
#[test]
fn group_m_replays_with_no_reference() {
    let (n, a) = replay_group(M_FILE, 6);
    println!("  group M specification capture: {n} vectors replayed, {a} recorded-field assertions, no C linked");
}

/// The one figure two server code paths spell two ways -- `/call`'s JSON
/// number and `/account/balance`'s decimal string -- parsed by the two
/// parsers and required equal, at the block the pin says both were read.
#[cfg(not(miri))]
#[test]
fn call_amount_and_balance_value_agree_at_one_block() {
    let json = fixture_json(N_FILE);
    let pin = &json["pin"];
    assert_eq!(
        pin["captured_block_index_start"], pin["captured_block_index_end"],
        "the capture's found-tag triple straddled a block; the equality below is not at one height"
    );
    let vectors = json["vectors"].as_array().unwrap_or_else(|| panic!("no vectors"));
    let find = |id: &str| {
        vectors
            .iter()
            .find(|v| v["id"].as_str() == Some(id))
            .unwrap_or_else(|| panic!("no {id}"))
    };
    let found = find("N-call-tag-resolve-found");
    let tag = hex::decode_prefixed::<20>(found["tag"].as_str().unwrap_or(""), "tag").unwrap_or_else(|e| panic!("{e}"));
    let entry = codec::parse_tag_resolve(found["response_body"].as_str().unwrap_or("").as_bytes(), &tag)
        .unwrap_or_else(|e| panic!("{e}"));
    let by_tag = codec::parse_account_balance(find("N-account-balance-found-by-tag")["response_body"].as_str().unwrap_or("").as_bytes())
        .unwrap_or_else(|e| panic!("{e}"));
    let by_address =
        codec::parse_account_balance(find("N-account-balance-found-by-address")["response_body"].as_str().unwrap_or("").as_bytes())
            .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(entry.balance, by_tag.balance, "/call amount vs /account/balance value");
    assert_eq!(entry.balance, by_address.balance, "/call amount vs /account/balance by address");
    assert_eq!(by_tag.tip.index, pin["captured_block_index_start"].as_u64().unwrap_or(0));
    println!(
        "  cross-endpoint balance: 3 parses agree on {} nanoMCM at block {}",
        entry.balance, by_tag.tip.index
    );
}

// --- the documented shape, enforced --------------------------------------------

/// Bodies no capture holds -- a server that spells a field the wrong way --
/// each refused by the parser naming the field. The captured bodies show the
/// parsers accepting the documented shape; these show them refusing the
/// neighbours of it, which is the half a capture cannot demonstrate.
#[test]
fn parsers_refuse_the_documented_shapes_neighbours() {
    let tag = [0x9f; 20];
    let good_address = format!("0x{}{}", hex::encode(&tag), "ab".repeat(20));
    let resolve = |address: &str, amount: &str| format!(r#"{{"result":{{"address":"{address}","amount":{amount}}},"idempotent":true}}"#);
    let refused = std::cell::Cell::new(0usize);
    let refuse = |body: String, what: &'static str, parse: &dyn Fn(&[u8]) -> Result<(), Error>| {
        assert_eq!(parse(body.as_bytes()), Err(Error::MeshResponse { what }), "body: {body}");
        refused.set(refused.get() + 1);
    };
    let tr = |b: &[u8]| codec::parse_tag_resolve(b, &tag).map(|_| ());
    // The genuine shape parses.
    assert!(codec::parse_tag_resolve(resolve(&good_address, "42").as_bytes(), &tag).is_ok());
    // amount: a string, a float, a negative, absent.
    refuse(resolve(&good_address, "\"42\""), "result.amount: unsigned integer", &tr);
    refuse(resolve(&good_address, "42.0"), "result.amount: unsigned integer", &tr);
    refuse(resolve(&good_address, "-1"), "result.amount: unsigned integer", &tr);
    refuse(
        format!(r#"{{"result":{{"address":"{good_address}"}},"idempotent":true}}"#),
        "result.amount: unsigned integer",
        &tr,
    );
    // address: another tag's address, a 39-byte one, no 0x.
    let other = format!("0x{}{}", "11".repeat(20), "ab".repeat(20));
    refuse(resolve(&other, "42"), "result.address: does not begin with the tag resolved", &tr);
    assert!(matches!(
        codec::parse_tag_resolve(resolve(&good_address[..good_address.len() - 2], "42").as_bytes(), &tag),
        Err(Error::Length { what: "result.address", .. })
    ));
    assert!(matches!(
        codec::parse_tag_resolve(resolve(&good_address[2..], "42").as_bytes(), &tag),
        Err(Error::Hex { what: "result.address", offset: 0 })
    ));
    refused.set(refused.get() + 2);
    // balance: a signed value, a non-decimal, the wrong currency, the wrong
    // scale, an empty list.
    let balance = |value: &str, symbol: &str, decimals: &str| {
        format!(
            r#"{{"block_identifier":{{"index":7,"hash":"0x{}"}},"balances":[{{"value":{value},"currency":{{"symbol":"{symbol}","decimals":{decimals}}}}}]}}"#,
            "00".repeat(32)
        )
    };
    let ab = |b: &[u8]| codec::parse_account_balance(b).map(|_| ());
    assert!(codec::parse_account_balance(balance("\"42\"", "MCM", "9").as_bytes()).is_ok());
    refuse(balance("\"+42\"", "MCM", "9"), "balances[0].value: decimal", &ab);
    refuse(balance("\"4a\"", "MCM", "9"), "balances[0].value: decimal", &ab);
    refuse(balance("\"\"", "MCM", "9"), "balances[0].value: decimal", &ab);
    refuse(balance("\"123456789012345678901\"", "MCM", "9"), "balances[0].value: decimal", &ab);
    refuse(balance("42", "MCM", "9"), "balances[0].value", &ab);
    refuse(balance("\"42\"", "BTC", "9"), "balances[0].currency.symbol: not MCM", &ab);
    refuse(balance("\"42\"", "MCM", "8"), "balances[0].currency.decimals: not 9", &ab);
    refuse(
        format!(r#"{{"block_identifier":{{"index":7,"hash":"0x{}"}},"balances":[]}}"#, "00".repeat(32)),
        "balances[0]",
        &ab,
    );
    // the envelope: not JSON, not an object, an error object without a
    // message (not the middleware's shape, so not routed as its error).
    refuse("nope".to_owned(), "json", &ab);
    refuse("[1,2]".to_owned(), "object", &ab);
    refuse(r#"{"code":4}"#.to_owned(), "block_identifier.index", &ab);
    assert_eq!(
        codec::parse_account_balance(br#"{"code":4,"message":"x"}"#),
        Err(Error::Mesh { code: 4, retriable: false }),
        "retriable absent defaults to false"
    );
    // submit: a 0x-prefixed hash (the handler emits bare hex), a short one.
    let sub = |b: &[u8]| codec::parse_submit(b).map(|_| ());
    assert!(codec::parse_submit(format!(r#"{{"transaction_identifier":{{"hash":"{}"}},"metadata":{{}}}}"#, "ab".repeat(32)).as_bytes()).is_ok());
    assert!(matches!(
        sub(format!(r#"{{"transaction_identifier":{{"hash":"0x{}"}},"metadata":{{}}}}"#, "ab".repeat(32)).as_bytes()),
        Err(Error::Hex { what: "transaction_identifier.hash", .. })
    ));
    assert!(matches!(
        sub(format!(r#"{{"transaction_identifier":{{"hash":"{}"}},"metadata":{{}}}}"#, "ab".repeat(31)).as_bytes()),
        Err(Error::Length { what: "transaction_identifier.hash", .. })
    ));
    refused.set(refused.get() + 2);
    println!(
        "  documented-shape neighbours: {} bodies refused naming the field, 3 genuine shapes parsed",
        refused.get()
    );
}

// --- totality ------------------------------------------------------------------

/// Every parser over every truncation and every single-byte corruption of
/// every recorded body: an `Err` or an `Ok`, never a panic. Network input is
/// the DoS class the hardening pass named; this is the census's blind spot (indexing,
/// arithmetic) exercised on the bytes that matter. Under Miri the fixture is
/// embedded and the positions are sampled; the printed count is what ran.
/// The vector count `fixtures/manifest.toml` declares for one group file.
///
/// A second, independently maintained statement of a number this file also
/// counts, so a comparison between them has two degrees of freedom.
///
/// **Embedded rather than read**, as `fixture_json` is under Miri: this
/// function's one caller runs under the interpreter, where filesystem isolation
/// forbids `std::fs`. Reading it from disk compiled, passed the ordinary board,
/// and would have failed only under a Miri run — which a session that changes
/// nothing Miri interprets is entitled to skip.
fn manifest_vectors_for(file: &str) -> usize {
    let doc: toml::Value = include_str!("../../../fixtures/manifest.toml")
        .parse()
        .unwrap_or_else(|e| panic!("manifest.toml: {e}"));
    doc["group"]
        .as_array()
        .unwrap_or_else(|| panic!("manifest.toml has no [[group]] array"))
        .iter()
        .find(|g| g["file"].as_str() == Some(file))
        .and_then(|g| g["vectors"].as_integer())
        .unwrap_or_else(|| panic!("manifest.toml declares no vector count for {file}"))
        as usize
}

#[test]
fn parsers_are_total_over_mutated_bodies() {
    let json = fixture_json(N_FILE);
    let vectors = json["vectors"].as_array().unwrap_or_else(|| panic!("no vectors"));
    let tag = [0x9f; 20];
    let run = |bytes: &[u8]| {
        let _ = codec::parse_network_list(bytes);
        let _ = codec::parse_network_options(bytes);
        let _ = codec::parse_network_status(bytes);
        let _ = codec::parse_tag_resolve(bytes, &tag);
        let _ = codec::parse_account_balance(bytes);
        let _ = codec::parse_submit(bytes);
    };
    let step = if cfg!(miri) { 64 } else { 1 };
    let mut mutations = 0usize;
    let mut bodies = 0usize;
    for v in vectors {
        let body = v["response_body"].as_str().unwrap_or("").as_bytes().to_vec();
        bodies += 1;
        run(&body);
        for cut in (0..body.len()).step_by(step) {
            run(&body[..cut]);
            mutations += 1;
        }
        for i in (0..body.len()).step_by(step) {
            let mut m = body.clone();
            m[i] ^= 0xff;
            run(&m);
            mutations += 1;
            let mut m = body.clone();
            m[i] = b'"';
            run(&m);
            mutations += 1;
        }
    }
    // **The body count is asserted, not merely printed**. The
    // mutation floor is a floor over *bytes*, and the four block vectors took
    // the total from 12,333 to 34,719 -- so the margin over 12,000 went from
    // 333 to more than twenty thousand, and a floor with that much slack stops
    // distinguishing "the corpus shrank" from "the corpus is fine". A body
    // count derived from the same array the walk iterates closes it: losing
    // any vector is now red by name, whatever the byte total does. The
    // rule -- "at least N" does not catch a corpus silently shorter than the
    // files it was built from.
    // The count is compared against the MANIFEST's declaration, not against
    // `vectors.len()`. `bodies` is incremented once per element of `vectors`,
    // so comparing the two would be `x == x`, which is the defect this repair
    // exists to fix, one level up. `manifest.toml` is a separate artifact
    // maintained by hand and
    // asserted against the files by `kat.rs::manifest_counts_match_the_files`,
    // so the two sides can disagree.
    let declared = manifest_vectors_for(N_FILE);
    assert_eq!(
        bodies, declared,
        "the mutation walk saw {bodies} bodies where the manifest declares {declared} vectors \
         for {N_FILE}; a vector the loop skipped is a body no parser was driven over, and the \
         mutation floor has too much slack to notice"
    );
    let floor = if cfg!(miri) { 200 } else { 12_000 };
    assert!(
        mutations >= floor,
        "only {mutations} mutations ran over {bodies} bodies (floor {floor}); the corpus or the loop shrank"
    );
    println!("  parser totality: {mutations} mutations over {bodies} recorded bodies, 6 parsers, 0 panics");
}

// ---------------------------------------------------------------------------
// The three explorer endpoints, replayed against the capture
// ---------------------------------------------------------------------------

/// **The request bodies the explorer calls build are the bodies the server
/// accepted**, byte for byte, for the three shapes group N recorded:
/// `/block` by index, `/block/transaction`, and `/search/transactions` by
/// hash.
///
/// The two shapes group N does **not** record -- a search by account and a
/// block by hash -- have no vector to compare against and are not asserted
/// here; they are built from the Go at the pinned commit and driven against
/// a double in `tests/cli.rs`.
#[cfg(not(miri))]
#[test]
fn the_explorer_request_bodies_are_the_captured_ones() {
    let json = fixture_json(N_FILE);
    let vectors = json["vectors"].as_array().unwrap_or_else(|| panic!("no vectors"));
    let find = |id: &str| {
        vectors
            .iter()
            .find(|v| v["id"].as_str() == Some(id))
            .unwrap_or_else(|| panic!("no {id}"))
    };
    // `request_body` is recorded as the request's own TEXT, so the
    // comparison is against those bytes and not against a re-serialisation
    // of a parsed object, which would compare two serialisers instead.
    let recorded = |id: &str| -> Vec<u8> {
        find(id)["request_body"]
            .as_str()
            .unwrap_or_else(|| panic!("{id}: request_body is not a string"))
            .as_bytes()
            .to_vec()
    };
    let hash = hex::decode_prefixed::<32>(
        find("N-submit-block")["submitted_transaction_id"].as_str().unwrap_or(""),
        "submitted_transaction_id",
    )
    .unwrap_or_else(|e| panic!("{e}"));

    let index = find("N-submit-block")["submitted_block_index"].as_u64().unwrap_or(0);
    assert_eq!(
        codec::request_block_by_index(index),
        recorded("N-submit-block"),
        "/block by index: the body this codec builds is not the body the server was sent"
    );
    assert_eq!(
        codec::request_search_by_hash(&hash),
        recorded("N-submit-search"),
        "/search by hash: the body this codec builds is not the body the server was sent"
    );
    // `/block/transaction` carries the block identifier with BOTH index and
    // hash, which no call this crate makes builds; the vector is replayed for
    // its reply below, and its request is compared as the capture's own JSON
    // rather than against a builder that does not exist.
    let bt: serde_json::Value = serde_json::from_str(
        find("N-submit-block-transaction")["request_body"].as_str().unwrap_or(""),
    )
    .unwrap_or_else(|e| panic!("the captured /block/transaction request is not JSON: {e}"));
    assert!(
        bt["block_identifier"]["hash"].is_string() && bt["block_identifier"]["index"].is_u64(),
        "the captured /block/transaction request no longer carries both index and hash"
    );
    println!(
        "  explorer requests: /block by index and /search by hash are byte-equal to the capture; \
         /block/transaction's recorded body carries index AND hash and is not built here"
    );
}

/// **The captured replies parse into the fields the pages render**, and the
/// two endpoints' two computations are preserved rather than reconciled.
///
/// This is the net-versus-gross discrepancy `N-submit-search`'s note
/// records, asserted from the bodies rather than from the note: for one
/// transaction, `/block/transaction` gives three operations with the source
/// debited its NET `-10_000_500` and the change netted away, while
/// `/search/transactions` gives four with the source debited its GROSS
/// `-50_000_000` and the change back as its own destination. The metadata
/// values differ in JSON type by the same split -- decimal strings from
/// `/block`, numbers from `/search` -- and both are rendered as the endpoint
/// spelled them.
#[cfg(not(miri))]
#[test]
fn the_two_endpoints_disagree_and_both_renderings_are_kept() {
    let json = fixture_json(N_FILE);
    let vectors = json["vectors"].as_array().unwrap_or_else(|| panic!("no vectors"));
    let body = |id: &str| -> Vec<u8> {
        vectors
            .iter()
            .find(|v| v["id"].as_str() == Some(id))
            .unwrap_or_else(|| panic!("no {id}"))["response_body"]
            .as_str()
            .unwrap_or("")
            .as_bytes()
            .to_vec()
    };

    let one = codec::parse_block_transaction(&body("N-submit-block-transaction")).unwrap_or_else(|e| panic!("{e}"));
    let page = codec::parse_search(&body("N-submit-search")).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(page.total_count, 1);
    assert_eq!(page.next_offset, None, "a one-row page must carry no next_offset");
    let searched = page.transactions.first().unwrap_or_else(|| panic!("the search page is empty"));
    assert_eq!(one.hash, searched.hash, "the two endpoints rendered different transactions");

    // The operation counts and the source debit: net against gross.
    assert_eq!(one.operations.len(), 3, "/block/transaction no longer gives three operations");
    assert_eq!(searched.operations.len(), 4, "/search no longer gives four operations");
    let source = |t: &codec::MeshTransaction| -> i128 {
        t.operations
            .iter()
            .find(|o| o.kind == codec::OP_SOURCE)
            .unwrap_or_else(|| panic!("no source operation"))
            .amount
    };
    assert_eq!(source(&one), -10_000_500, "/block/transaction's source debit is not the NET");
    assert_eq!(source(searched), -50_000_000, "/search's source debit is not the GROSS");
    assert_eq!(
        source(searched) - source(&one),
        -39_999_500,
        "the difference between the two debits is not the change"
    );
    // The change is its own destination on /search and on neither on /block.
    let dests = |t: &codec::MeshTransaction| -> Vec<i128> {
        t.operations.iter().filter(|o| o.kind == codec::OP_DESTINATION).map(|o| o.amount).collect()
    };
    assert_eq!(dests(&one), vec![10_000_000], "/block/transaction carries a change destination");
    assert_eq!(dests(searched), vec![10_000_000, 39_999_500], "/search does not carry the change as a destination");

    // The metadata, in the spelling each endpoint used.
    let meta = |t: &codec::MeshTransaction, k: &str| -> String {
        t.metadata
            .iter()
            .find(|(key, _)| key == k)
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| panic!("no metadata key {k}"))
    };
    assert_eq!(meta(&one, "block_to_live"), "0");
    assert_eq!(meta(searched, "block_to_live"), "0");
    assert_eq!(meta(searched, "send_total"), "10000000");
    assert_eq!(meta(searched, "change_total"), "39999500");
    assert_eq!(meta(searched, "fee_total"), "500");
    // The block and timestamp are on the search row and not on the other.
    assert_eq!(one.block, None);
    assert_eq!(searched.block.map(|b| b.index), Some(1_078_535));
    assert_eq!(searched.timestamp_ms, Some(1_788_500_208_000));
    println!(
        "  net vs gross: /block/transaction 3 ops with source -10,000,500; /search 4 ops with \
         source -50,000,000 and the change 39,999,500 as its own destination; the difference is \
         the change, and both metadata spellings are kept"
    );
}

/// **`/block` parses into a whole block**: identifier, parent, timestamp and
/// every transaction, the mining reward among them as its own transaction
/// with one `REWARD` operation.
#[cfg(not(miri))]
#[test]
fn the_captured_block_parses_with_its_reward_and_its_transactions() {
    let json = fixture_json(N_FILE);
    let vectors = json["vectors"].as_array().unwrap_or_else(|| panic!("no vectors"));
    let v = vectors
        .iter()
        .find(|v| v["id"].as_str() == Some("N-submit-block"))
        .unwrap_or_else(|| panic!("no N-submit-block"));
    let block = codec::parse_block(v["response_body"].as_str().unwrap_or("").as_bytes()).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(block.block.index, 1_078_535);
    assert_eq!(block.parent.index, block.block.index - 1, "the parent is not one below");
    assert_eq!(block.timestamp_ms, 1_788_500_198_000);
    assert_eq!(block.transactions.len(), 5, "the captured block no longer carries five transactions");

    let rewards: Vec<&codec::MeshTransaction> = block
        .transactions
        .iter()
        .filter(|t| t.operations.iter().any(|o| o.kind == codec::OP_REWARD))
        .collect();
    assert_eq!(rewards.len(), 1, "a block has exactly one reward transaction");
    let reward = rewards[0].operations.first().unwrap_or_else(|| panic!("no reward operation"));
    assert_eq!(reward.amount, 12_065_840_589, "the captured reward moved");

    // What `block <n>` sums as "moved": destination transfers over the
    // transactions that are not the reward. On THIS endpoint there is no
    // change operation, so that is exactly value delivered to payees.
    let moved: i128 = block
        .transactions
        .iter()
        .filter(|t| !t.operations.iter().any(|o| o.kind == codec::OP_REWARD))
        .flat_map(|t| t.operations.iter())
        .filter(|o| o.kind == codec::OP_DESTINATION)
        .map(|o| o.amount)
        .sum();
    assert_eq!(moved, 1_111_416_500, "the total delivered to payees in the captured block moved");
    println!(
        "  captured block 1,078,535: parent 1,078,534, 5 transactions, reward 12,065,840,589 \
         excluded, {moved} nanoMCM delivered to payees"
    );
}

/// **The response cap and the field-by-field refusal hold for the three new
/// **The history cap fits what `--count` accepts, and the reconciliation cap
/// does not have to.**
///
/// `--count` is validated to `1..=100` in the parser, so a hundred
/// `/search/transactions` rows is a page the CLI can ask for. Measured against
/// the group N capture, the widest recorded row is 1,221 bytes; a cap that
/// cannot hold a hundred of them is a flag the parser accepts and the
/// transport refuses, which is the defect this pins shut from the transport's
/// side.
///
/// The reconciliation endpoints are the other half of the same assertion. Their
/// widest recorded reply is `/network/status` at 664 bytes, and their cap stays
/// small on purpose: it bounds an allocation a remote server chooses the size
/// of, and there is nothing for it to buy by being loose.
/// Measured from `fixtures/group_n_mesh_live.json`, the widest recorded body of
/// each shape. Restated here rather than read from the fixture, so the two can
/// disagree.
const WIDEST_SEARCH_ROW: usize = 1_221;
const WIDEST_BLOCK_TX: usize = 1_020;
const WIDEST_RECON_REPLY: usize = 664;
/// `--count`'s ceiling in `cli::args`. A history cap that cannot hold this many
/// rows makes `--count 100` a value the parser accepts and the transport
/// refuses, which is the defect the split cap exists to close.
const MAX_COUNT: usize = 100;

/// The caps against the endpoints they are for. Every operand is a constant, so
/// a width that stops holding fails the build rather than one test.
const _: () = assert!(
    MAX_HISTORY_RESPONSE_BYTES >= WIDEST_SEARCH_ROW * MAX_COUNT,
    "the history cap does not hold a full `--count 100` page of the widest recorded search row"
);
const _: () = assert!(
    MAX_HISTORY_RESPONSE_BYTES >= WIDEST_BLOCK_TX * 64,
    "the history cap does not hold a 64-transaction block at the widest recorded transaction"
);
const _: () = assert!(
    MAX_RECON_RESPONSE_BYTES >= WIDEST_RECON_REPLY * 4,
    "the reconciliation cap leaves no headroom over the widest recorded reply"
);
const _: () = assert!(
    MAX_RECON_RESPONSE_BYTES < MAX_HISTORY_RESPONSE_BYTES,
    "the reconciliation cap is not tighter than the history cap, so it bounds nothing"
);

/// **Every endpoint the client posts to resolves to the right one of the two.**
///
/// The sizes are held by the `const` assertions above; this is the other half,
/// which is a table lookup and has to run. A cap correct in magnitude and
/// applied to the wrong path is the same defect as a cap of the wrong size.
#[cfg(not(miri))]
#[test]
fn every_endpoint_resolves_to_the_cap_its_replies_need() {
    for path in ["/call", "/account/balance", "/network/status", "/construction/submit"] {
        assert_eq!(max_response_bytes(path), MAX_RECON_RESPONSE_BYTES, "{path}");
    }
    for path in ["/block", "/search/transactions"] {
        assert_eq!(max_response_bytes(path), MAX_HISTORY_RESPONSE_BYTES, "{path}");
    }
    // A path this table does not name is not a reason to widen an allocation.
    assert_eq!(max_response_bytes("/something/new"), MAX_RECON_RESPONSE_BYTES);
    println!(
        "  response caps: recon {MAX_RECON_RESPONSE_BYTES} B, history {MAX_HISTORY_RESPONSE_BYTES} B \
         (a --count {MAX_COUNT} page of {WIDEST_SEARCH_ROW}-byte rows is {} B)",
        WIDEST_SEARCH_ROW * MAX_COUNT
    );
}

/// parsers too**: an oversize body is refused by size before it is parsed,
/// and a body missing a documented field is refused naming that field and
/// nothing else. Neither ever dumps bytes.
#[cfg(not(miri))]
#[test]
fn the_explorer_parsers_refuse_by_size_and_by_field() {

    // One byte over the cap, valid JSON, refused before parsing.
    let mut oversize = br#"{"block":{"pad":""#.to_vec();
    oversize.resize(MAX_HISTORY_RESPONSE_BYTES + 1, b'x');
    /// One parser, erased to the shape these tables share.
    type Parse = fn(&[u8]) -> Result<(), Error>;

    let by_size: [(&str, Parse); 3] = [
        ("parse_block", |b| codec::parse_block(b).map(|_| ())),
        ("parse_block_transaction", |b| codec::parse_block_transaction(b).map(|_| ())),
        ("parse_search", |b| codec::parse_search(b).map(|_| ())),
    ];
    for (what, run) in by_size {
        let e = run(&oversize);
        match e {
            Err(Error::PayloadTooLarge { what: w, max, got }) => {
                assert_eq!(w, "response body", "{what}");
                assert_eq!(max, MAX_HISTORY_RESPONSE_BYTES, "{what}");
                assert_eq!(got, MAX_HISTORY_RESPONSE_BYTES + 1, "{what}");
            }
            other => panic!("{what} did not refuse an oversize body by size: {other:?}"),
        }
    }

    // A field removed from each documented shape, and the field it names.
    let cases: [(&str, &str, Parse); 6] = [
        (
            r#"{"block":{"parent_block_identifier":{"index":1,"hash":"0x00"},"timestamp":1,"transactions":[]}}"#,
            "block_identifier.index",
            |b| codec::parse_block(b).map(|_| ()),
        ),
        (
            r#"{"block":{"block_identifier":{"index":2,"hash":"0x0000000000000000000000000000000000000000000000000000000000000000"},"parent_block_identifier":{"index":1,"hash":"0x0000000000000000000000000000000000000000000000000000000000000000"},"transactions":[]}}"#,
            "timestamp",
            |b| codec::parse_block(b).map(|_| ()),
        ),
        (
            r#"{"transaction":{"operations":[]}}"#,
            "transaction_identifier",
            |b| codec::parse_block_transaction(b).map(|_| ()),
        ),
        (
            r#"{"transaction":{"transaction_identifier":{"hash":"0x0000000000000000000000000000000000000000000000000000000000000000"}}}"#,
            "operations",
            |b| codec::parse_block_transaction(b).map(|_| ()),
        ),
        (r#"{"total_count":0}"#, "transactions", |b| codec::parse_search(b).map(|_| ())),
        (r#"{"transactions":[]}"#, "total_count", |b| codec::parse_search(b).map(|_| ())),
    ];
    for (body, want, run) in cases {
        match run(body.as_bytes()) {
            Err(Error::MeshResponse { what }) => assert_eq!(what, want, "the refusal named {what}, not {want}"),
            other => panic!("{want} was not missed: {other:?}"),
        }
    }

    // An amount that is a JSON number rather than the decimal string both
    // endpoints send is refused, not coerced.
    let numeric = r#"{"transaction":{"transaction_identifier":{"hash":"0x0000000000000000000000000000000000000000000000000000000000000000"},"operations":[{"operation_identifier":{"index":0},"type":"FEE","account":{"address":"0x00"},"amount":{"value":500}}]}}"#;
    match codec::parse_block_transaction(numeric.as_bytes()) {
        Err(Error::MeshResponse { what }) => assert_eq!(what, "operations[].amount.value"),
        other => panic!("a numeric amount was accepted: {other:?}"),
    }
    println!(
        "  explorer refusals: 3 parsers refuse an oversize body by size, 6 missing fields are each \
         named, and an amount sent as a number rather than a decimal string is refused"
    );
}
