//! Backend selection.
//!
//! One backend: [`native`], pure safe Rust. [`selected`] is a plain alias of
//! it, under the name every caller uses.
//!
//! **[`native`] contains no `unsafe` at all.** That is load-bearing rather
//! than incidental: it is what Miri's guarantee over this crate rests on, and
//! `invariants.rs::unsafe_is_confined_to_declared_files` asserts it.
//!
//! # Why this module is public -- and only under `raw-backend`
//!
//! It is **not** the wallet API -- that is [`crate::wots`], which calls
//! exactly one backend and gives a caller no way to pick. `lib.rs` declares
//! this module `pub` under the `raw-backend` feature and `pub(crate)`
//! otherwise; the crate's dev-dependency on itself turns the feature on for
//! every test target and nothing else does. So the test tree names
//! `backend::{native, selected}` -- `tests/kat.rs` spells its raw-signer
//! replay through `selected` rather than through the demoted `wots::sign` --
//! while a wallet build cannot name this module at all, which is what makes
//! "the raw signer is unreachable from outside the crate" (I1) a property of
//! the build rather than a sentence. The I1 marker anchors on both
//! declarations and on the manifest; a downstream probe compiles a dependent
//! without the feature and pins the E0603 it gets.

#[cfg(feature = "native")]
pub mod native;

/// The backend every caller resolves to. A plain alias of [`native`]: the
/// name is what the callers, the tests and the specification use, and it
/// marks the one place a second backend would be selected if there were one.
#[cfg(feature = "native")]
pub use native as selected;
