//! Whether an opcode is usable after a successful handshake.
//!
//! # The crate's one restated predicate
//!
//! Everything else this crate knows about the protocol is a value held to a
//! fixture. [`valid_op`] is not a value: it is a predicate, and the only
//! facts under it are `FIRST_OP` and `LAST_OP`, two constants in
//! `consts::net` that `kat.rs::group_e_constants_match_the_reference` holds
//! to what group E records. Nothing here is a transcribed number -- the
//! bounds are those constants, so widening the opcode range moves this
//! predicate and its test together.
//!
//! That is the whole argument for restating it, and it is a single
//! exception rather than a precedent: a predicate over checked constants can
//! be written out, a protocol value cannot. `docs/specification.md` records
//! the restatement under *Open items*.

use crate::consts::net::{FIRST_OP, LAST_OP};

/// Whether `op` is an operation code usable after a successful 3-way handshake.
///
/// Mirrors the reference's own macro:
///
/// ```c
/// #define valid_op(op)  ((op) >= FIRST_OP && (op) <= LAST_OP)
/// ```
///
/// The bounds are `consts::net`'s constants, not literals of this file's own.
/// `tests/net.rs` enumerates
/// the entire input domain against this function with its expectations phrased
/// the same way, so if the reference widens the opcode range the test follows
/// it instead of pinning the old range.
#[must_use]
// clippy suggests `(FIRST_OP..=LAST_OP).contains(&op)`. Declined here, and only
// here: this is the crate's single restated definition, and the entire argument
// for allowing it is that a reader can hold it against the macro quoted above
// and see the same two comparisons in the same order. A range expression is
// equivalent to the compiler and no longer legible against the C.
#[allow(clippy::manual_range_contains)]
pub fn valid_op(op: u8) -> bool {
    op >= FIRST_OP && op <= LAST_OP
}
