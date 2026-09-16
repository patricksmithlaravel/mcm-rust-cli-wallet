//! Mochimo v3 addresses: a 20-byte tag at offset 0 and a 20-byte hash at
//! offset 20.

use crate::backend::selected as backend;
use crate::consts::{ADDR_HASH_LEN, ADDR_LEN, ADDR_TAG_LEN, PK_LEN};

pub type Address = [u8; ADDR_LEN];
pub type AddrHash = [u8; ADDR_HASH_LEN];
pub type Tag = [u8; ADDR_TAG_LEN];

/// `ripemd160(sha3_512(input))`, the reference's address hash.
pub fn hash_generate(input: &[u8]) -> AddrHash {
    backend::addr_hash_generate(input)
}

/// Builds an implicit address, which repeats the same 20 bytes in both halves.
pub fn from_implicit(tag: &Tag) -> Address {
    backend::addr_from_implicit(tag)
}

/// Hashes exactly `WOTS_PK_LEN` bytes — not the 2208 of a legacy WOTS+ address
/// — and forms the implicit address from the result. Fixture `C6` is the
/// negative control for that distinction.
pub fn from_wots(pk: &[u8; PK_LEN]) -> Address {
    backend::addr_from_wots(pk)
}

pub fn tag_of(addr: &Address) -> &[u8] {
    &addr[..ADDR_TAG_LEN]
}

pub fn hash_of(addr: &Address) -> &[u8] {
    &addr[ADDR_TAG_LEN..]
}

/// `sha3` at each of the four widths `sha3.h:44` declares compatible, exposed
/// because group C pins the two halves of [`hash_generate`] separately.
///
/// # Four names, not one `outlen`
///
/// This was once `sha3(input, &mut [u8])`, mirroring the C's runtime
/// `outlen`. That signature made every length a caller could name part of the
/// public API, including `outlen >= 100`, where the reference's `rsiz` underflows
/// and `sha3_final` writes out of bounds. Splitting the
/// width into the type makes an unsupported one a name that does not exist,
/// which is a compile error at the call site rather than a value reaching
/// `sha3_init`.
///
/// Only [`sha3_512`] is on the address path; [`sha3_256`] is
/// `peach.c:212`'s. The other two have no caller in the reference and are here
/// because the oracle covers them and the width is one constant apart — see
/// `backend::native::sha3_224` for why "no caller today" stopped being the
/// deciding question.
pub fn sha3_224(input: &[u8]) -> [u8; crate::consts::SHA3LEN224] {
    backend::sha3_224(input)
}

/// SHA3-256. See [`sha3_224`].
pub fn sha3_256(input: &[u8]) -> [u8; crate::consts::SHA3LEN256] {
    backend::sha3_256(input)
}

/// SHA3-384. See [`sha3_224`].
pub fn sha3_384(input: &[u8]) -> [u8; crate::consts::SHA3LEN384] {
    backend::sha3_384(input)
}

/// SHA3-512, the address path's width. See [`sha3_224`].
pub fn sha3_512(input: &[u8]) -> [u8; crate::consts::SHA3LEN512] {
    backend::sha3_512(input)
}

/// `ripemd160(input)`, exposed for the same reason as [`sha3`] — and
/// **total over every input length**.
///
/// # The reference-faulting class is routed, not forwarded
///
/// The reference corrupts its own stack for `input.len() % 64 >= 56`,
/// which once made this safe public function end
/// the process — attacker-shaped input, since the caller chooses the slice.
/// The foreign-function `ripemd160` was given that class as an `unsafe`
/// contract and this wrapper made to answer
/// the class with `native::ripemd160` instead: RustCrypto's `ripemd`, correct
/// over the whole range, anchored on exactly this class by the 26 group RX
/// vectors (`@noble/hashes`, an independent implementation of the published
/// algorithm — see `fixtures/group_rx_ripemd.json`).
///
/// On the defined domain (`len % 64 < 56`) the selected backend is called
/// exactly as before, and the group HS sweep (`tests/kat.rs`) is the evidence
/// that it agrees with the reference there. So this is a class-scoped,
/// call-site-scoped routing, taken only over the lengths the reference has no
/// defined behaviour for at all.
///
/// `tests/kat.rs::rx_ripemd160` replays the RX vectors through **this**
/// function and compares every digest to the recorded `@noble/hashes` value.
pub fn ripemd160(input: &[u8]) -> [u8; 20] {
    if input.len() % 64 >= 56 {
        return ripemd160_on_faulting_class(input);
    }
    ripemd160_on_defined_domain(input)
}

/// The faulting-class arm: RustCrypto, the implementation group RX anchors.
#[cfg(feature = "native")]
fn ripemd160_on_faulting_class(input: &[u8]) -> [u8; 20] {
    crate::backend::native::ripemd160(input)
}

/// The defined-domain arm, through the selected backend.
fn ripemd160_on_defined_domain(input: &[u8]) -> [u8; 20] {
    backend::ripemd160(input)
}

// ---------------------------------------------------------------------------
// The destination identifier
// ---------------------------------------------------------------------------
//
// The first live run found that this crate's CLI could not be funded from its
// own output: it printed a bare 40-hex tag and the shipped Chrome wallet
// refuses that outright. What every Mochimo v3 client actually takes is
// **Base58 over the tag followed by its CRC16**, and the reference composes it
// in three statements at `tx.c:269-271`:
//
// ```c
// word8 tag[ADDR_TAG_LEN + 2];                        /* tx.c:241 */
// put16(tag + ADDR_TAG_LEN, crc16(tag, ADDR_TAG_LEN));
// base58_encode(tag, sizeof(tag), base58_tag);
// ```
//
// The shipped TypeScript agrees, and is where the *checksum byte order* is
// visible as a decision rather than as a call:
// `reference/mochimo-wots/src/utils/tag-utils.ts:9-15` builds `csumBytes` as
// `[csum & 0xFF, (csum >> 8) & 0xFF]` — little-endian.
//
// **`put16` itself is not the authority for that, and the distinction matters
// here.** `extended-c/src/extlib.c:67-70` is a bare dereference —
// `*((word16 *) buff) = value` — with no swap and no endianness macro, so it
// is little-endian because the hosts are, not because the function says so.
// The reference's own authority is its unit tests:
// `extended-c/src/test/extlib-put16.c` asserts `put16(array, 0x7fff)` yields
// `{0xff, 0x7f}` and `extlib-get16.c` the inverse. On our side the byte order
// is pinned by group C's KAT rather than by anything in `put16`, which is
// the host-endian class in a new place: `no_native_endian_conversions_anywhere_in_
// the_crate` cannot see a C function's host dependence.
//
// **Composed here from the three public primitives rather than from
// `backend::native::tag_with_crc16`**, which is behind `raw-backend` and is
// the *native* backend's copy. Going through [`crate::crc16::crc16`],
// [`crate::bytes::put16`] and [`crate::base58::encode`] means this build
// performs the composition the reference's `tx_bot_init` performs, through
// the same three functions, and group C pins it.

use crate::error::Error;

/// The shortest Base58 a 22-byte tag payload can encode to, and the longest.
///
/// **Both ends are witnessed by fixtures rather than reasoned about**, and
/// `tests/cli.rs::the_two_destination_forms_cannot_collide`
/// re-derives them from group C's own strings: `C7`'s all-zero tag gives
/// exactly [`TAG_BASE58_MIN_CHARS`] (twenty-two `'1'`s, one per leading zero
/// byte) and `C8`'s all-`ff` tag gives exactly [`TAG_BASE58_MAX_CHARS`], with
/// the thousand-entry `crc16_base58_corpus` inside the window throughout.
///
/// # What the window is for, and what it is not for
///
/// It is **not** the acceptance rule. [`tag_from_base58`] accepts a string
/// because it decodes to twenty-two bytes whose last two are the CRC16 of the
/// first twenty; the window is checked first for two reasons that are both
/// about the *reference decoder*, not about the tag:
///
/// * the C's `base58_decode` is O(n²) in the input length, so an operator who
///   pastes a megabyte of anything into `send <to>` would otherwise buy a
///   quadratic loop before being told it is not a tag;
/// * a length refusal can say *what a destination looks like*, where a
///   decode-then-length refusal can only say what came out.
///
/// # And it is what makes the two accepted forms disjoint
///
/// A bare hex tag is forty characters. [`TAG_BASE58_MAX_CHARS`] is thirty-one,
/// so **no string is valid in both forms** and accepting both introduces no
/// ambiguity. That is not an arithmetic coincidence: a forty-character Base58
/// string decodes to at least twenty-nine bytes, never twenty-two, and
/// `tests/cli.rs::the_two_destination_forms_cannot_collide` states the bound as
/// a walk over the whole forty-character space rather than as a claim.
pub const TAG_BASE58_MIN_CHARS: usize = 22;

/// See [`TAG_BASE58_MIN_CHARS`].
pub const TAG_BASE58_MAX_CHARS: usize = 31;

/// Why a string is not a tag in the reference form.
///
/// Separate from [`crate::Error`] because every arm is about *text an operator
/// typed*, and the thing that matters about each is what the operator should
/// do next. `Display` is the whole point of the type: it is what the CLI puts
/// on the terminal, so I4's message-quality clause governs it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NotATag {
    /// Outside the length window a 22-byte payload can encode to. Reported
    /// before decoding — see [`TAG_BASE58_MIN_CHARS`].
    Length {
        chars: usize,
    },
    /// Base58 refused it: a character outside the alphabet (`0`, `O`, `I`, `l`
    /// and everything non-alphanumeric are not in it), or a non-ASCII byte.
    NotBase58(Error),
    /// It decoded, to something that is not a 22-byte tag payload.
    PayloadLen {
        got: usize,
    },
    /// It decoded to 22 bytes whose last two are not the CRC16 of the first
    /// twenty. **This is the arm that earns the encoding**: the Base58 codec
    /// carries no checksum of its own (fixture `C12` alters a character and
    /// still decodes with `rc == 0`), so without this comparison a mistyped
    /// destination is a well-formed tag for an address nobody holds.
    Checksum {
        found: u16,
        computed: u16,
    },
}

impl core::fmt::Display for NotATag {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            NotATag::Length { chars } => write!(
                f,
                "it is {chars} character(s); a destination is Base58 over a tag and its \
                 checksum, which is {TAG_BASE58_MIN_CHARS} to {TAG_BASE58_MAX_CHARS}"
            ),
            NotATag::NotBase58(e) => write!(
                f,
                "it is not Base58 ({e}). The alphabet excludes 0, O, I and l, so a character \
                 that looks like a digit or a letter may not be one"
            ),
            NotATag::PayloadLen { got } => write!(
                f,
                "it is Base58 for {got} byte(s); a destination is {} (a {}-byte tag and a \
                 2-byte checksum)",
                ADDR_TAG_LEN + 2,
                ADDR_TAG_LEN
            ),
            NotATag::Checksum { found, computed } => write!(
                f,
                "the checksum does not match: the string carries {found:#06x} and the tag in it \
                 computes {computed:#06x}. One character is wrong -- this is the check that \
                 exists so a mistyped destination is refused here rather than paid to an \
                 address nobody holds"
            ),
        }
    }
}

/// The destination string for `tag`: Base58 over the tag and its CRC16.
///
/// `tx.c:269-271`'s composition, through the selected backend at every step.
/// This is the form `create`, `address` and `balance` print, and the only form
/// another Mochimo wallet will take.
pub fn tag_to_base58(tag: &Tag) -> crate::Result<String> {
    let mut payload = [0u8; ADDR_TAG_LEN + 2];
    let (body, checksum) = payload.split_at_mut(ADDR_TAG_LEN);
    body.copy_from_slice(tag);
    checksum.copy_from_slice(&crate::bytes::put16(crate::crc16::crc16(tag)));
    crate::base58::encode(&payload)
}

/// The inverse: the tag inside a destination string, or why it is not one.
///
/// # Total over arbitrary operator input
///
/// This is reached from `send <to>`, so every byte in it is chosen by
/// somebody else. Three classes are answered before the codec sees them —
/// the length window above, and inside [`crate::base58::decode`] the empty
/// string and the all-`'1'` class the reference decoder cannot survive
/// (`C-base58-degenerate`). Everything else the reference rejects through
/// `base58_map` with `EINVAL`, which arrives here as [`NotATag::NotBase58`].
/// Nothing in this function indexes, unwraps or asserts.
///
/// # It does **not** refuse the all-zero tag, and that is deliberate
///
/// `crc16` of twenty zero bytes is zero, so `1111111111111111111111` decodes
/// to twenty-two zero bytes whose checksum verifies, and this function returns
/// `Ok([0u8; 20])`. That is the reference's behaviour — group C's `C7` encodes
/// and decodes it like any other tag — and this is a codec, which must agree
/// with the reference. Whether a *wallet* should pay to it is a policy
/// question, answered `no` one layer up in
/// `cli::args::refuse_the_zero_tag`, where a human typed something.
///
/// # And it fuses validation with decoding, where the reference splits them
///
/// `tag-utils.ts` has two functions: `validateBase58Tag` compares the CRC16,
/// and `base58ToAddrTag` checks only that the payload is twenty-two bytes and
/// **returns the tag without validating it**. Fixture `CX-C12` records the
/// pair executed on one string — `validate_base58_tag: false` beside
/// `base58_to_addr_tag: "3f1fba…ca59"`. This function refuses that string.
/// The divergence is deliberate: no caller here has a use for an unvalidated
/// tag, and handing one back is how the CRC16 stops being a check.
pub fn tag_from_base58(text: &str) -> core::result::Result<Tag, NotATag> {
    let chars = text.chars().count();
    if !(TAG_BASE58_MIN_CHARS..=TAG_BASE58_MAX_CHARS).contains(&chars) {
        return Err(NotATag::Length { chars });
    }
    let raw = crate::base58::decode(text).map_err(NotATag::NotBase58)?;
    let payload: [u8; ADDR_TAG_LEN + 2] = raw
        .as_slice()
        .try_into()
        .map_err(|_| NotATag::PayloadLen { got: raw.len() })?;
    let (body, checksum) = payload.split_at(ADDR_TAG_LEN);
    let tag: Tag = match body.try_into() {
        Ok(t) => t,
        Err(_) => return Err(NotATag::PayloadLen { got: raw.len() }),
    };
    let carried: [u8; 2] = match checksum.try_into() {
        Ok(c) => c,
        Err(_) => return Err(NotATag::PayloadLen { got: raw.len() }),
    };
    let found = crate::bytes::get16(&carried);
    let computed = crate::crc16::crc16(&tag);
    if found != computed {
        return Err(NotATag::Checksum { found, computed });
    }
    Ok(tag)
}
