//! `valid_op` over its entire input domain.
//!
//! `mochimo_crypto::net::valid_op` is the one definition in this crate that is
//! restated in Rust rather than bound. `valid_op` is a function-like macro
//! defined inside `reference/mochimo-core/src/network.c` rather than a header,
//! so bindgen never sees it, and `network.c` cannot be compiled into the crate
//! to shim it — it leaves ~65 symbols unresolved across the peer subsystem,
//! block and tfile I/O, and `process_tx`.
//!
//! The exception was granted on the grounds that `valid_op` is a **predicate
//! over constants** rather than a protocol value, and it comes with the
//! obligation this file discharges: enumerate the whole input domain, with the
//! expectation written in terms of the bound constants rather than the literals
//! they currently equal. `FIRST_OP` and `LAST_OP` are read from the generated
//! bindings and compared against the C by
//! `kat.rs::group_e_constants_match_the_reference`, so if upstream widens the
//! opcode range this test follows it instead of pinning the old range.
//!
//! It is listed in `kat.rs::WEAKLY_ANCHORED` so the weaker standard is visible,
//! and `invariants.rs::valid_op_upstream_header_fix_owed` fails until the
//! durable fix lands upstream. It is not precedent; the specification's *Open
//! items* records the transcription.

use mochimo_crypto::consts::net::{FIRST_OP, LAST_OP};
use mochimo_crypto::net::valid_op;

/// A degenerate range would make the enumeration below pass while `valid_op`
/// rejected everything. Stated as a `const` assertion rather than a runtime one
/// because both operands are constants: an upstream inversion should fail the
/// build, not one test.
const _: () = assert!(
    FIRST_OP <= LAST_OP,
    "FIRST_OP exceeds LAST_OP: the opcode range is empty"
);

/// Every `u8`. The domain is 256 values wide, so "exhaustive" is literal here
/// rather than a sampling strategy.
#[test]
// The expectation deliberately repeats the predicate's own shape rather than
// using a range expression, for the reason given on `net::valid_op` itself:
// this pair is meant to be read against the C macro side by side.
#[allow(clippy::manual_range_contains)]
fn valid_op_agrees_with_its_bounds_over_the_entire_domain() {
    let mut accepted = 0usize;

    for op in u8::MIN..=u8::MAX {
        // Phrased over the bound constants, not over 3 and 19. The point of the
        // exception is that the *facts* are FIRST_OP and LAST_OP; restating
        // them as literals here would put a second copy of the range in the
        // test and let the two agree with each other while the C moved.
        let expected = op >= FIRST_OP && op <= LAST_OP;
        assert_eq!(
            valid_op(op),
            expected,
            "valid_op({op}) is {}, but FIRST_OP = {FIRST_OP} and LAST_OP = \
             {LAST_OP} make it {expected}",
            valid_op(op)
        );
        if expected {
            accepted += 1;
        }
    }

    // A predicate that accepted everything, or nothing, would satisfy the loop
    // above only if the bounds themselves were degenerate. Checking the size of
    // the accepted set against the bounds catches that without naming a range.
    assert_eq!(
        accepted,
        usize::from(LAST_OP - FIRST_OP) + 1,
        "the accepted set is not the closed interval [FIRST_OP, LAST_OP]"
    );
    assert!(
        accepted < 256,
        "valid_op accepts the entire u8 domain, so it distinguishes nothing"
    );

    println!("  valid_op: 256 inputs enumerated, {accepted} accepted ([{FIRST_OP}, {LAST_OP}])");
}

/// The boundary itself, stated separately so a failure says which edge moved.
///
/// An off-by-one at either end passes any test that only samples the interior,
/// and these four are the inputs where a `>` / `>=` slip shows up.
#[test]
fn valid_op_boundaries_are_closed() {
    assert!(valid_op(FIRST_OP), "FIRST_OP itself must be accepted");
    assert!(valid_op(LAST_OP), "LAST_OP itself must be accepted");

    if let Some(below) = FIRST_OP.checked_sub(1) {
        assert!(!valid_op(below), "the value below FIRST_OP must be rejected");
    }
    if let Some(above) = LAST_OP.checked_add(1) {
        assert!(!valid_op(above), "the value above LAST_OP must be rejected");
    }
}

/// Every named opcode the bindings carry lies inside the range, except the
/// three the reference places outside it on purpose.
///
/// `OP_NULL`, `OP_HELLO` and `OP_HELLO_ACK` are the pre-handshake codes:
/// `valid_op` answers "usable *after* a successful 3-way handshake", so their
/// exclusion is the predicate working, not a gap in it. Pinning that here stops
/// a future widening of `FIRST_OP` from quietly making the handshake codes
/// acceptable mid-session.
#[test]
fn handshake_opcodes_are_outside_the_valid_range() {
    use mochimo_crypto::consts::net as k;

    for (name, op) in [
        ("OP_NULL", k::OP_NULL),
        ("OP_HELLO", k::OP_HELLO),
        ("OP_HELLO_ACK", k::OP_HELLO_ACK),
    ] {
        assert!(
            !valid_op(op),
            "{name} ({op}) is inside [{FIRST_OP}, {LAST_OP}]. These three are \
             the pre-handshake codes; valid_op exists to exclude them."
        );
    }

    for (name, op) in [
        ("OP_TX", k::OP_TX),
        ("OP_FOUND", k::OP_FOUND),
        ("OP_GET_BLOCK", k::OP_GET_BLOCK),
        ("OP_GET_IPL", k::OP_GET_IPL),
        ("OP_SEND_FILE", k::OP_SEND_FILE),
        ("OP_SEND_IPL", k::OP_SEND_IPL),
        ("OP_BUSY", k::OP_BUSY),
        ("OP_NACK", k::OP_NACK),
        ("OP_GET_TFILE", k::OP_GET_TFILE),
        ("OP_BALANCE", k::OP_BALANCE),
        ("OP_SEND_BAL", k::OP_SEND_BAL),
        ("OP_RESOLVE", k::OP_RESOLVE),
        ("OP_GET_CBLOCK", k::OP_GET_CBLOCK),
        ("OP_MBLOCK", k::OP_MBLOCK),
        ("OP_HASH", k::OP_HASH),
        ("OP_TF", k::OP_TF),
        ("OP_IDENTIFY", k::OP_IDENTIFY),
    ] {
        assert!(
            valid_op(op),
            "{name} ({op}) is outside [{FIRST_OP}, {LAST_OP}] but is a \
             post-handshake operation code"
        );
    }
}
