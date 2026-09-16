//! The reference's little-endian integer accessors (`extlib.h:70-74`).
//!
//! These are real linkable C functions, not macros, so they bind directly. They
//! are here because every multi-byte field on the wire goes through them, and a
//! port that guesses big-endian produces packets that are dropped before any
//! signature is examined.

use crate::backend::selected as backend;

pub fn get16(bytes: &[u8; 2]) -> u16 {
    backend::get16(bytes)
}

pub fn put16(value: u16) -> [u8; 2] {
    backend::put16(value)
}

pub fn get32(bytes: &[u8; 4]) -> u32 {
    backend::get32(bytes)
}

pub fn put32(value: u32) -> [u8; 4] {
    backend::put32(value)
}
