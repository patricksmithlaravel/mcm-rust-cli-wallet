//! The network predicate the reference keeps out of reach of any binding.
//!
//! # Why this module contains logic when no other one does
//!
//! Every other value in this crate is a literal read from the reference and
//! held to a fixture the reference printed. `valid_op` cannot be pinned that
//! way. It is a function-like macro defined at
//! `reference/mochimo-core/src/network.c:34` — inside a `.c` file, not a
//! header — so no binding generator ever saw it, and `network.c` could not be
//! compiled into a crate to shim it: it leaves ~65 symbols unresolved,
//! spanning the peer subsystem, block and tfile I/O, and `process_tx`.
//!
//! The two alternatives were both worse.
//!
//! *Extracting the macro's text into a shim* is not what the port's other
//! shims did. Those worked because the preprocessor expanded the original
//! definition in place, so `types.h` stayed authoritative and an upstream
//! edit propagated on the next build. Copying `valid_op`'s text into a file of ours creates a
//! second definition that agrees with itself — upstream could change
//! `network.c` and nothing here would go red. Automating the extraction is
//! worse still: pulling a `#define` out of a `.c` file is regex-parsing C, and
//! that breaks silently on multi-line, conditional, or redefined macros.
//!
//! *Restating it in Rust* is what this file does, and it is admissible only
//! because of what `valid_op` is: a **predicate over constants**, not a
//! protocol value. The facts it depends on are `FIRST_OP` and `LAST_OP`, two
//! literals in `consts::net` that `kat.rs::group_e_constants_match_the_reference`
//! holds to the values the reference printed into group E. Nothing below is a
//! transcribed *value*; the bounds are those constants, so a change to either
//! one moves this predicate and its test together.
//!
//! This is a deliberate, single exception, granted on that reasoning. **It is
//! not precedent.** Any other symbol wanting this treatment comes back for a
//! decision.
//!
//! The durable fix is upstream and is one line: move the `#define` into a
//! header, and it becomes bindable for every implementation rather than only
//! this one. `docs/specification.md` records the transcription under *Open
//! items* (one validation predicate).

use crate::consts::net::{FIRST_OP, LAST_OP};

/// Whether `op` is an operation code usable after a successful 3-way handshake.
///
/// Mirrors `valid_op(op)` at `reference/mochimo-core/src/network.c:34`:
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
