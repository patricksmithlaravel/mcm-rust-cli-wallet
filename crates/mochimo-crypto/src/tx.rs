//! Transaction accessors and length bounds.
//!
//! The free functions at the bottom cover the parts of the transaction
//! surface that need no transaction value: the three options-byte accessors,
//! the two address-half accessors, and the two minimum-length constants. Each
//! is the native counterpart of a function-like macro in the reference's
//! `types.h`, delegated through [`crate::backend::selected`], and group D
//! gives every one of them a vector.
//!
//! The native construction path is [`wire`]: ordinary Rust types with a
//! serializer at the boundary, so the crate both reads and
//! builds transactions. This module once also carried a handle over the
//! reference's own `TXENTRY` -- a heap-pinned C struct with fifteen interior
//! pointers, which is where invariant I7 came from -- behind the
//! foreign-function feature. The binding is not in this repository and the
//! handle went with it; I7 is satisfied by construction, because nothing here
//! is a self-referential struct. See `docs/specification.md`.

use crate::consts::ADDR_LEN;

/// `TXDAT_MDST` (`types.h:168`) — the one transaction-data type `tx__init`
/// accepts. Every other value takes its `default:` arm at `tx.c:146`.
pub const DAT_MDST: u8 = crate::consts::TXDAT_MDST;

/// `TXDSA_WOTS` (`types.h:173`) — the one signature-algorithm type `tx__init`
/// accepts. `types.h:514-516` lists three more commented out; none is live, and
/// the `default:` arm at `tx.c:156` rejects them.
pub const DSA_WOTS: u8 = crate::consts::TXDSA_WOTS;

/// `ADDR_REF_LEN` (`types.h:116`) — the optional destination reference field.
pub const REF_LEN: usize = crate::consts::ADDR_REF_LEN;

/// `HASHLEN` (`types.h:84`) — the transaction id is a SHA-256 digest.
pub const ID_LEN: usize = crate::consts::HASHLEN;

/// The largest destination count an options byte can encode.
///
/// `MDST_COUNT(options)` is `options[2] + 1` (`types.h:176`), so a `word8` of
/// `0xFF` yields 256 — not zero, and not 255. `tx.c:130-140` leans on exactly
/// this bound to argue that no offset it computes can leave the buffer.
pub const MAX_DESTINATIONS: u16 = 256;

/// The native construction path: owned transaction types and the wire codec.
/// Requires only the `native` feature — this is the half of the module that
/// works with no C linked at all.
#[cfg(feature = "native")]
pub mod wire;

// --- the accessor surface, delegated to the backend seam ----------------
//
// Seven wrappers over `types.h` function-like macros, each delegating to
// [`crate::backend::selected`] so that one definition serves every build and
// there is no second body to drift. Each was once a foreign-function body
// paired with an `unimplemented!()` twin, which is why they are written as
// delegations rather than as bodies of their own.

use crate::backend::selected;

/// The transaction-data type code: the first options byte.
///
/// `TXDAT_TYPE(options)` at `types.h:166`.
#[must_use]
pub fn dat_type(options: &[u8; 4]) -> u8 {
    selected::dat_type(options)
}

/// The DSA type code: the second options byte.
///
/// `TXDSA_TYPE(options)` at `types.h:171`.
#[must_use]
pub fn dsa_type(options: &[u8; 4]) -> u8 {
    selected::dsa_type(options)
}

/// The multi-destination count: the third options byte, plus one.
///
/// `MDST_COUNT(options)` at `types.h:176`. Returns `u16` rather than `u8`
/// because the macro's `+ 1` integer-promotes: an options byte of `0xFF` yields
/// **256**, not 0. Truncating that would be a behaviour change rather than a
/// binding.
#[must_use]
pub fn mdst_count(options: &[u8; 4]) -> u16 {
    selected::mdst_count(options)
}

/// The tag half of an address: `ADDR_TAG_LEN` bytes from `ADDR_TAG_OFF`.
///
/// `ADDR_TAG_PTR(ptr)` at `types.h:126`. Returned as a slice rather than a raw
/// pointer, with both the offset and the length taken from bound constants.
///
/// # `crate::addr::tag_of` is not a substitute, and the agreement is not evidence
///
/// While the foreign-function backend was here this was the reference's own
/// pointer arithmetic and `addr::tag_of` was Rust slicing, so the two
/// agreeing was real evidence. **Now they are the same computation twice**
/// -- both slice the same array at the same bound -- so their agreement
/// establishes nothing. What carries the property is group D: the recorded
/// offsets `reference_verdicts_native` asserts on every replay.
#[must_use]
pub fn tag_ptr(addr: &[u8; ADDR_LEN]) -> &[u8] {
    selected::tag_ptr(addr)
}

/// The hash half of an address: `ADDR_HASH_LEN` bytes from `ADDR_HASH_OFF`.
///
/// `ADDR_HASH_PTR(ptr)` at `types.h:128`. See [`tag_ptr`] on why
/// `addr::hash_of` is not a substitute -- and note that `hash_of` slices at
/// `ADDR_TAG_LEN`, which infers that the halves abut, where the native backend
/// reads the offset `types.h:124` states.
#[must_use]
pub fn hash_ptr(addr: &[u8; ADDR_LEN]) -> &[u8] {
    selected::hash_ptr(addr)
}

/// Minimum length of a transaction received over the network.
///
/// `TXLEN_MIN` at `types.h:148`, a sum of three `sizeof`s. The C binding
/// reached it through a shim, because its generator could not evaluate a
/// `sizeof` expression; this crate sums `crate::consts::wire`, which carries
/// the reference's own `STATIC_ASSERT` expressions rather than three numbers.
#[must_use]
pub fn len_min() -> usize {
    selected::len_min()
}

/// Minimum length of a transaction on disk: `TXLEN_MIN` plus a trailer.
///
/// `TXLEN_DSK_MIN` at `types.h:151`.
#[must_use]
pub fn len_dsk_min() -> usize {
    selected::len_dsk_min()
}
