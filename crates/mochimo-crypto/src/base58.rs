//! Base58.
//!
//! The reference codec carries **no checksum**. Mochimo's tag checksum is two
//! CRC-16 bytes the caller appends before encoding, so it is not
//! this module's business.
//!
//! # The probe, and why these functions still exist
//!
//! The C's protocol is probe-then-allocate-then-call: pass a null output
//! pointer to learn the length, allocate, call again. That protocol once
//! *was* the backend seam and this module implemented it — `to_c_string`, a
//! `Vec<c_char>`, two calls per operation. It is gone from here now; the seam is
//! four Rust-shaped functions, and the C-shaped pair went with the
//! foreign-function backend.
//!
//! [`encode_probe_len`] and [`decode_probe_len`] survive because the probe's
//! *answer* is a value the fixtures pin, not because callers need it to size
//! anything. `C-base58-degenerate` records the reference reporting 21 for a
//! 22-character encoding of an all-zero payload, and a corpus that could not ask
//! for that number could not record the defect.
//!
//! **They report what the backend reports, and on the all-zero class that
//! is the true length where the reference reports one less** — a decided
//! divergence, and `tests/kat.rs::base58_decode` and `base58_degenerate`
//! assert the recorded reference answer beside this crate's on every group C
//! vector that carries one.

use crate::backend::selected as backend;
use crate::error::Result;

/// The encode length the selected backend reports.
///
/// Equal to `encode(input)?.len()` under `native`. Under the foreign-function
/// backend it was the reference's `NULL`-out probe, which runs **one short**
/// when `input` is entirely zero bytes — see the module documentation.
pub fn encode_probe_len(input: &[u8]) -> Result<usize> {
    backend::base58_encoded_len(input)
}

/// Encodes `input`.
pub fn encode(input: &[u8]) -> Result<String> {
    backend::base58_encode(input)
}

/// The decode length the selected backend reports.
///
/// Safe on the all-`'1'` class: the native decoder answers it (see
/// [`decode`]), where the reference's probe returned before reaching the
/// `memcpy` its own decoder did not survive.
pub fn decode_probe_len(s: &str) -> Result<usize> {
    backend::base58_decoded_len(s.as_bytes())
}

/// Decodes `s`. Total over every input, including the class the reference
/// cannot survive.
///
/// # The all-`'1'` class is answered before the decoder runs
///
/// With the foreign-function backend selected this once called the
/// reference decoder directly, which **ends the process** on an all-`'1'`
/// string: it reaches the encoder with `size = 1` and `low = 2` and calls
/// `memcpy` with a length of `(size_t)(-1)`. No buffer size prevents it — and
/// the input is a string, the exact shape a wallet is handed from outside.
/// That decoder was given the class as an `unsafe` contract and this wrapper
/// made to short-circuit the class to the decided value: an all-`'1'` string of
/// length *n* decodes to *n* zero bytes.
///
/// That value has no C oracle behind it — the C cannot be asked; that is the
/// defect — so it is a requirement, not a measurement: fixture
/// `C-base58-degenerate` states it, the `CX-C-base58-degenerate` crosscheck
/// pins it from `bs58`, and `tests/kat.rs::ts_base58_decode` holds it
/// through **this** function. The reference's *probe* answer on the
/// class is untouched — [`decode_probe_len`] still reports the backend's own
/// number, divergence and all, because recording that defect is what the
/// probe functions exist for.
pub fn decode(s: &str) -> Result<Vec<u8>> {
    if !s.is_empty() && s.as_bytes().iter().all(|&c| c == b'1') {
        return decode_degenerate_class(s);
    }
    decode_via_backend(s)
}

/// The class arm: `native::base58_decode`, whose handling of exactly this
/// class is the decided divergence and carries its own tests.
#[cfg(feature = "native")]
fn decode_degenerate_class(s: &str) -> Result<Vec<u8>> {
    crate::backend::native::base58_decode(s.as_bytes())
}

/// The non-degenerate arm, through the selected backend.
fn decode_via_backend(s: &str) -> Result<Vec<u8>> {
    backend::base58_decode(s.as_bytes())
}
