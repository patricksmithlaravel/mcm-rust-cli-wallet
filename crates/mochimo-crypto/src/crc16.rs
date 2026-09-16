//! CRC-16, the reference's `crc16()`.
//!
//! `crc16.h` documents XMODEM parameters (poly `0x1021`, init `0x0000`, no
//! reflection, xorout `0x0000`). Group E pins that against measured values
//! rather than against the comment.

use crate::backend::selected as backend;

pub fn crc16(input: &[u8]) -> u16 {
    backend::crc16(input)
}
