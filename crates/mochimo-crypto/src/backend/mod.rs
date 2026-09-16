//! Backend selection.
//!
//! One backend: [`native`], the hand-written Rust port. This module was the
//! seam between it and a foreign-function binding of the vendored C
//! reference, which the differential tests compared side by side; the
//! binding and the tests are not in this repository, and [`selected`] is a
//! plain alias of [`native`] kept under the name every caller already uses.
//! [`native`] contains no `unsafe` at all -- that is load-bearing for what
//! Miri establishes and is asserted by
//! `invariants.rs::unsafe_is_confined_to_declared_files`.
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

/// The backend every caller resolves to. A plain alias of [`native`] since the
/// foreign-function backend left; the name stays because it is the name the
/// callers, the tests and the specification use, and because it marks the
/// one place a second backend would be selected if one ever returned.
#[cfg(feature = "native")]
pub use native as selected;
