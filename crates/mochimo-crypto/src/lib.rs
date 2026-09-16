//! Safe Rust API for the Mochimo cryptographic primitives.
//!
//! Every operation here delegates to [`backend::native`], the hand-written
//! Rust port, through the alias [`backend::selected`]. The port was written
//! against a vendored C reference under differential testing; the reference
//! is not in this repository and the fixture corpus under `fixtures/` is what
//! the port is checked against -- see `docs/specification.md`.

#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(not(feature = "native"))]
compile_error!(
    "no backend selected: mochimo-crypto requires the `native` feature. \
     Building with --no-default-features would silently produce a crate that \
     cannot compute anything."
);

/// The backend seam is public **only under `raw-backend`**, the test tree's
/// surface. In every other build it is crate-private, so no dependent can
/// name a raw primitive -- the raw WOTS+ signer above all (I1). The
/// KATs route through `selected` on purpose; a wallet needs nothing from it.
#[cfg(feature = "raw-backend")]
pub mod backend;
/// Without the feature the backend carries the whole primitive surface --
/// every function the corpus replays, most of which the wallet never calls
/// -- so the dead-code lint is off for it in that build on purpose: the
/// surface is sized by `tests/kat.rs`, not by the wallet's call graph.
#[cfg(not(feature = "raw-backend"))]
#[allow(dead_code)]
pub(crate) mod backend;
mod error;

pub mod account;
pub mod addr;
pub mod base58;
pub mod bytes;
pub mod crc16;
#[cfg(feature = "native")]
pub mod derive;
#[cfg(feature = "native")]
pub mod keystore;
#[cfg(feature = "native")]
pub mod mesh;
#[cfg(feature = "native")]
pub mod mnemonic;
#[cfg(feature = "native")]
pub mod cli;
#[cfg(feature = "native")]
pub mod recon;
#[cfg(feature = "native")]
pub mod wallet;
pub mod net;
pub mod secret;
pub mod tx;
pub mod wots;

pub use error::{errno_name, errno_text, ve2str, Error, Result, TransportKind, Verdict};
pub use secret::Secret;

/// Reference constants, as Rust literals read from the reference at the
/// `file:line` each doc comment cites.
///
/// They were once defined twice -- as these literals and as the generated
/// bindings of the vendored C -- and compared, so that a constant retyped in
/// Rust was a constant somebody checked. The bindings are not in
/// this repository. What anchors the literals now is the corpus:
/// `tests/kat.rs::constants_match_the_reference` compares the WOTS+ and
/// address widths against the `constants` block group A's fixture `printf`'d
/// from the real macros, and `tests/kat.rs::group_e_constants_match_the_reference`
/// does the same for every network constant against group E's. A literal
/// that disagrees with what the C compiler saw fails there rather than inside
/// a 2144-byte diff.
pub mod consts {
    /// Declares each constant once, as a Rust literal read from the reference.
    ///
    /// Emits `mod native` and the `pub use` of it. The macro once emitted a
    /// second module of generated bindings and a `CROSSCHECK` table pairing
    /// the two; the row grammar lost its `sys = NAME` half with them.
    macro_rules! declare_consts {
        ($(
            $(#[doc = $doc:literal])*
            $name:ident : $ty:ty = $native:expr;
        )*) => {
            /// The Rust literals, read off disk from the reference.
            pub mod native {
                $($(#[doc = $doc])* pub const $name: $ty = $native;)*
            }

            pub use native::*;
        };
    }

    declare_consts! {
        /// WOTS+ hash output and seed width. `wots.h:30`.
        PARAMSN: usize = 32;
        /// Winternitz parameter. `wots.h:31`.
        WOTSW: usize = 16;
        /// `log2(WOTSW)`. `wots.h:32`.
        WOTSLOGW: usize = 4;
        /// Message chains: `(8 * PARAMSN / WOTSLOGW)`. `wots.h:34`.
        ///
        /// The header's expression, not its value. A folded `64` would agree with
        /// itself if `PARAMSN` ever moved.
        WOTSLEN1: usize = 8 * PARAMSN / WOTSLOGW;
        /// Checksum chains. `wots.h:33`.
        WOTSLEN2: usize = 3;
        /// `(WOTSLEN1 + WOTSLEN2)`. `wots.h:35`.
        WOTSLEN: usize = WOTSLEN1 + WOTSLEN2;
        /// `(WOTSLEN * PARAMSN)`. `wots.h:36`.
        WOTSSIGBYTES: usize = WOTSLEN * PARAMSN;
        /// Legacy full WOTS+ address length. `types.h:133`.
        WOTS_ADDR_LEN: usize = 2208;
        /// Full v3 address: a tag then a hash. `types.h:114`.
        ADDR_LEN: usize = 40;
        /// Address tag. `types.h:118`.
        ADDR_TAG_LEN: usize = 20;
        /// Address hash. `types.h:120`.
        ADDR_HASH_LEN: usize = 20;
        /// A destination's optional reference field. `types.h:116`.
        ADDR_REF_LEN: usize = 16;
        /// Where an address's tag half starts. `types.h:122`.
        ADDR_TAG_OFF: usize = 0;
        /// Where an address's hash half starts. `types.h:124`.
        ///
        /// Not `ADDR_TAG_LEN`. The two are equal and that is a fact about this
        /// protocol rather than a rule about addresses -- deriving one from the
        /// other assumes the halves abut, which is the shape corrected once
        /// before, when `put16`'s byte order was standing in for `put32`'s
        /// (`backend::native::put32`'s doc).
        ADDR_HASH_OFF: usize = 20;
        /// Digest length of the core hashes. `types.h:84`.
        HASHLEN: usize = 32;
        /// `sha256.h:22`.
        SHA256LEN: usize = 32;
        /// `sha3.h:61`. SHA3-224.
        SHA3LEN224: usize = 28;
        /// `sha3.h:62`. SHA3-256.
        SHA3LEN256: usize = 32;
        /// `sha3.h:63`. SHA3-384.
        SHA3LEN384: usize = 48;
        /// `sha3.h:64`. SHA3-512.
        SHA3LEN512: usize = 64;
        /// `ripemd160.h:18`.
        RIPEMDLEN160: usize = 20;
        /// `crc16.h:25`.
        CRC16LEN: usize = 2;
        /// The success status code. `types.h:89`.
        ///
        /// `c_int` because that is what the reference's validators return, and
        /// comparing a return code against a `usize` would need a cast at every
        /// call site.
        VEOK: core::ffi::c_int = 0;
        /// The one transaction-data type `tx__init` accepts. `types.h:168`.
        TXDAT_MDST: u8 = 0x00;
        /// The one signature-algorithm type `tx__init` accepts. `types.h:173`.
        TXDSA_WOTS: u8 = 0x00;
        /// The minimum transaction fee, in nanoMochimo. `types.h:48`; the
        /// 64-bit little-endian form the validators take is `MFEE64` at
        /// `types.h:78`. `u64` because `tx_val` compares it against
        /// `tx_fee` and `mdst_val` accumulates one per
        /// destination into the floor `fee_total` must clear (`tx.c:621`,
        /// `:636`). Read by `mesh::spend`; the C binding's `mdst_val` shim,
        /// its only reader before that, took the eight-byte pointer form and
        /// is gone.
        MFEE: u64 = 500;
    }

    /// The four wire-struct sizes, as `types.h` asserts them.
    ///
    /// # Why these are expressions and not `size_of`
    ///
    /// `TXLEN_MIN` and `TXLEN_DSK_MIN` are sums of `sizeof`s, and the native
    /// backend has no C structs to take `sizeof` of. What it does have is the
    /// reference's own `STATIC_ASSERT`s, each of which states a struct's size as
    /// an arithmetic expression over constants already declared above:
    ///
    /// ```text
    /// types.h:429  sizeof(MDST)    == ADDR_REF_LEN + ADDR_TAG_LEN + 8
    /// types.h:451  sizeof(WOTSVAL) == WOTS_SIG_LEN + 32 + 32
    /// types.h:487  sizeof(TXHDR)   == 4 + (ADDR_LEN * 2) + (8 * 4)
    /// types.h:538  sizeof(TXTLR)   == 8 + HASHLEN
    /// ```
    ///
    /// Transcribing the *expression* rather than the value is the same choice
    /// [`WOTSLEN1`] makes — a folded literal would agree with itself if a
    /// constant underneath it moved.
    ///
    /// # What checks them
    ///
    /// `tests/kat.rs::reference_verdicts_native` and `tests/txwire.rs` hold
    /// each of these to the offsets `group_d_tx.json`'s layout table records,
    /// through the native serializer, on every replay. The bindgen struct they
    /// were once also compared against is not in this repository, which is
    /// exactly why these are written as the reference's expression rather
    /// than as numbers somebody checked once.
    pub mod wire {
        use super::{ADDR_LEN, ADDR_REF_LEN, ADDR_TAG_LEN, HASHLEN, SIG_LEN};
        /// `types.h:487`.
        pub const SIZEOF_TXHDR: usize = 4 + (ADDR_LEN * 2) + (8 * 4);
        /// `types.h:429`.
        pub const SIZEOF_MDST: usize = ADDR_REF_LEN + ADDR_TAG_LEN + 8;
        /// `types.h:451`. `WOTS_SIG_LEN` is this crate's [`SIG_LEN`].
        pub const SIZEOF_WOTSVAL: usize = SIG_LEN + 32 + 32;
        /// `types.h:538`.
        pub const SIZEOF_TXTLR: usize = 8 + HASHLEN;
    }

    /// WOTS+ seed, message digest, and public seed width.
    pub const SEED_LEN: usize = PARAMSN;
    /// A WOTS+ public key, and equally a WOTS+ signature.
    ///
    /// The reference calls these `WOTS_PK_LEN` / `WOTS_SIG_LEN` and files them
    /// under the "LEGACY" comment. They are not legacy: that
    /// comment spans both dead constants (the 12-byte legacy tag's, which this
    /// crate never bound) and load-bearing ones (the 2,208-byte `WOTSVAL`
    /// layout these two size, `STATIC_ASSERT`-pinned), so its scope is not
    /// evidence that a symbol is droppable — anything under it needs a
    /// call-site check before removal.
    pub const PK_LEN: usize = WOTSSIGBYTES;
    /// Ditto — the reference gives these separate names for the same value.
    pub const SIG_LEN: usize = WOTSSIGBYTES;

    /// The network surface: protocol version, framing marks, ports, and the
    /// operation codes.
    ///
    /// These are `u16`/`u8` rather than `usize` because every one of them is a
    /// wire value with a width the protocol fixes, not a length. `TXNETWORK`
    /// and `TXEOT` go onto the wire through `put16`; the opcodes occupy a
    /// single byte.
    ///
    /// Until this module existed, `fixtures/group_e_net.json` pinned all of
    /// these against nothing at all — the fixture and the survey agreed with
    /// each other and neither was compared to the C.
    /// `kat.rs::group_e_constants_match_the_reference` now checks every one
    /// against the `constants` block the reference printed into that fixture.
    pub mod net {
        declare_consts! {
            /// Protocol version number. `types.h:27`.
            PVERSION: u16 = 5;
            /// Capability bits for TX. `types.h:47`.
            CBITS: u16 = 0;
            /// Network TX protocol version. `types.h:105`.
            TXNETWORK: u16 = 1337;
            /// End-of-transmission id for packets. `types.h:104`.
            TXEOT: u16 = 0xabcd;
            /// Default TCP listening port. `types.h:102`.
            PORT1: u16 = 2095;
            /// Secondary port, primarily for testnet. `types.h:103`.
            PORT2: u16 = 2096;
            /// First valid operation code. `types.h:241`.
            FIRST_OP: u8 = 3;
            /// Last valid operation code. `types.h:355`.
            LAST_OP: u8 = 19;
            /// `types.h:223`.
            OP_NULL: u8 = 0;
            /// `types.h:229`.
            OP_HELLO: u8 = 1;
            /// `types.h:235`.
            OP_HELLO_ACK: u8 = 2;
            /// `types.h:247`.
            OP_TX: u8 = 3;
            /// `types.h:253`.
            OP_FOUND: u8 = 4;
            /// `types.h:259`.
            OP_GET_BLOCK: u8 = 5;
            /// `types.h:265`.
            OP_GET_IPL: u8 = 6;
            /// `types.h:271`.
            OP_SEND_FILE: u8 = 7;
            /// `types.h:277`.
            OP_SEND_IPL: u8 = 8;
            /// `types.h:282`.
            OP_BUSY: u8 = 9;
            /// `types.h:289`.
            OP_NACK: u8 = 10;
            /// `types.h:296`.
            OP_GET_TFILE: u8 = 11;
            /// `types.h:302`.
            OP_BALANCE: u8 = 12;
            /// `types.h:308`.
            OP_SEND_BAL: u8 = 13;
            /// `types.h:314`.
            OP_RESOLVE: u8 = 14;
            /// `types.h:320`.
            OP_GET_CBLOCK: u8 = 15;
            /// `types.h:327`.
            OP_MBLOCK: u8 = 16;
            /// `types.h:334`.
            OP_HASH: u8 = 17;
            /// `types.h:341`.
            OP_TF: u8 = 18;
            /// `types.h:348`.
            OP_IDENTIFY: u8 = 19;
        }

        /// `extint.h:299`. Expands to `WORD16_C(0xFFFF)`, a macro chain the
        /// bindings generator did not evaluate, which is why this is a
        /// function rather than a `declare_consts!` row: the binding side was
        /// a shim *call*, and `kat.rs` paired the two by hand. The binding is
        /// gone; the function stays so the call sites and the fixture's
        /// `WORD16_MAX` row keep their shape.
        #[must_use]
        pub const fn word16_max() -> u16 {
            word16_max_native()
        }

        /// The native `WORD16_MAX`.
        ///
        /// The single definition of the literal: [`word16_max`] forwards here
        /// rather than repeating `0xFFFF`, so there is one place to be wrong.
        #[must_use]
        pub const fn word16_max_native() -> u16 {
            0xFFFF
        }
    }
}
