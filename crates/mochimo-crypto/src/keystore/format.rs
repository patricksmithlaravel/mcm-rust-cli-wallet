//! The snapshot format: one whole-state image, hand-written, little-endian,
//! fixed-width, canonical -- and, since version 3, **encrypted at rest**.
//!
//! # Layout (all integers little-endian)
//!
//! ```text
//! PLAINTEXT HEADER, 51 bytes -- and every byte of it is the AEAD's AAD:
//!   magic[8] = "MCMKSTOR" | version u16 = 4 | kdf_id u8 = 1 (Argon2id v1.3)
//!   | m_cost_kib u32 | t_cost u32 | p_cost u32 | salt[16] | nonce[12]
//!
//! CIPHERTEXT, 45 + 195*count bytes (ChaCha20 is a stream cipher, so the
//! ciphertext is exactly as long as the plaintext it covers):
//!   generation u64 | count u32 | master_present u8 | master[32]
//!     (enforced zero when master_present == 0)
//!   records[count], sorted by tag ascending, no duplicates, 195 bytes each
//!   (178 in version 3, which this build also READS -- below):
//!     tag[20] | kind u8 (0 derived / 1 imported)
//!     | body[32]  (derived: account_index u32 followed by 28 zero bytes;
//!                  imported: the root)
//!     | first[64] (imported: the first key's public seed and hash-address
//!                  image, the tail of the shipped `faddress`;
//!                  derived: 64 zero bytes, enforced)
//!     | stream[20] (the rotation-0 public key's hash -- the key stream's
//!                   public identity, both kinds)
//!     | wots_index u32
//!     | pending u8      0 none / 1 reserved / 2 settled, retained
//!     | spent_index u32 | digest[32]
//!     | figures u8      0 not recorded / 1 recorded
//!     | reserved_balance u64 | blk_to_live u64
//!       (every field after wots_index is zero when pending == 0; the two
//!        u64 are zero when figures == 0; spent_index + 1 == wots_index in
//!        both non-zero pending states)
//!
//! AEAD TAG, 16 bytes, last -- Poly1305 over the ciphertext with the
//! plaintext header as AAD. (Not to be confused with a record's `tag[20]`,
//! which is an account identifier; `TRAILER_LEN` is this one's constant and
//! the name is v2's, kept so every site that spoke of a trailer still reads.)
//! ```
//!
//! `HEADER_LEN`, `BODY_HEADER_LEN`, `RECORD_LEN` and `TRAILER_LEN` are the
//! four numbers above; `image_len` is the closed formula. **Do not take this
//! block's word for the decomposition** -- `known_answer_image_for_two_accounts`
//! asserts it twice, once symbolically and once as
//! `assert_eq!(image.len(), 502, "51 header + (45 + 2*195) body + 16 tag")`,
//! and an executing assertion outranks a comment. It is written down here
//! because that is what this header is for.
//!
//! `MAX_IMAGE_LEN` is `image_len(MAX_ACCOUNTS)` written out as its own sum, so
//! the two can disagree, and
//! `max_image_len_is_the_cap_image_and_one_record_more_is_refused` holds them
//! equal at the cap, holds one record over the cap above it, and holds
//! `read_header`'s gate to exactly the cap. A sum here that omits
//! `BODY_HEADER_LEN` lets a store at the 65,536 cap encode and be refused on
//! read, and nothing below the cap shows it: `45/178 < 1` puts the smallest
//! failing count at the cap itself. `MIN_IMAGE_LEN` is the other end of the
//! same range and carries the same 45 bytes.
//!
//! # What moved into the ciphertext, and why it is not just the roots
//!
//! `generation` and `count` were **plaintext header fields in version 2** and
//! are body fields now. A stolen file should not say how many accounts a
//! wallet holds or how many times it has been written to. The body also
//! carries the **master seed** since version 3, which is the change that let the
//! twenty-four-word prompt go; a v2 file has no such field,
//! which is why a v2 store is refused rather than upgraded -- below.
//!
//! What stays plaintext is exactly what a reader needs *before* it can
//! decrypt: the KDF's identity and parameters, the salt and the nonce. Those
//! are authenticated rather than merely present -- as AAD, an attacker who
//! rewrites `m_cost` down to 8 KiB to make a guess cheap derives a different
//! key and the tag fails. `read_header` also bounds `m_cost` **before**
//! anything allocates, because it is an instruction to allocate that many KiB
//! and it came out of a file.
//!
//! # Version 4, what version 3 becomes, and what versions 1 and 2 do not
//!
//! **Version 4 carries, per record, the two figures of the reserved spend
//! -- the ledger balance the plan was built against and the block-to-live
//! -- behind a presence flag, and retains the last settled reservation in
//! the same block under a third `pending` state**. It
//! does not carry the signed bytes: item 5c as written was rejected on width
//! (2,364 + 44 N bytes per reservation; a 905 MB `MAX_IMAGE_LEN` padded to
//! the wire's 256 destinations), with redundancy the reason nothing is lost
//! -- the artifact is a function of the store, the key and 60 bytes of wire
//! input, WOTS+ signing being deterministic.
//!
//! **A version-3 store is READ, not refused, and re-sealed as version 4 by
//! its next commit** -- the first migration this crate has done in place,
//! and the first version bump at which neither half of the refusal
//! argument -- representability, capability -- derives a refusal: v4
//! can say the figures are *not recorded* (`figures == 0`), which fabricates
//! nothing, and no operation of a v3 store depends on them -- `resign_reserved`,
//! `settle` and `sign_spend` read neither figure. A v3
//! record's `pending == 1` parses to `figures: None`; nothing else in it is
//! reinterpreted. `open` never rewrites the snapshot; the first `commit`
//! after it seals version 4 under the next generation, so the nonce is
//! fresh by construction, and the page of the command that made that write
//! says so (`Keystore::upgraded_from`). **The crossing is one-way**: an
//! older build then meets `got > supported` on a real file for the first
//! time and prints the fresh-directory advice -- which, for an open
//! reservation, is the second-signature route this migration exists to
//! avoid. The pinned v3 image (`testdata/keystore_v3_snapshot.bin`) is kept
//! byte for byte as the read-path oracle beside the v4 pin, and a v3 capture
//! with a reservation open exercises the declared-absent arm against a real
//! file (`testdata/keystore_v3_reserved_snapshot.bin`).
//!
//! v1 was `94` bytes per record with neither `first` nor `stream`.
//! **A v1 file is refused, not upgraded**, and that is derived rather than
//! preferred: a v1 derived record's stream identity is
//! `stream_id(derive_seed(master, i))` and the keystore never held a master;
//! a v1 imported record's first-key components are, by the finding v2 closes,
//! not in it either. The data an upgrade would need is not in the old file for
//! **either** kind, so an in-place rewrite cannot produce a valid record.
//! Migration is re-adding the accounts into a fresh directory.
//! `UnsupportedVersion` says so.
//!
//! **A v2 file is refused for the same reason one version along**, and this is
//! the part that looks different and is not: a v2 store holds every *record*
//! field a v3 store holds, so the obvious reading is that it could be
//! re-sealed. It cannot. A v3 body carries the master seed and a v2 file has
//! none -- the seed is a function of a phrase the store has never held, so it
//! is not a field an upgrade can compute. An in-place upgrade would produce a
//! v3 file that opens under the new password and whose every derived account
//! then reconciles as `Divergence::NoMasterForDerivedAccount` -- a refusal,
//! not a skip -- for a store the program had just said it migrated. Migration is `create --from-phrase` into a fresh directory, which
//! is what the phrase is for.
//!
//! A KDF id this build does not have gets the same reading one field along:
//! `UnsupportedVersion`, not `Corrupt`. An upgrade, not damage.
//!
//! # Why this shape
//!
//! Fixed widths make the image length a closed formula of `count`, so the
//! parser bounds every read before it happens and never indexes. Canonical
//! encoding -- enforced zero padding, enforced zero pending fields, enforced
//! zero `master` when absent, enforced tag order -- means one state has
//! exactly one image, which is what lets a KAT pin the bytes and lets the
//! atomicity proof compare files byte for byte.
//!
//! **The image still has that property under an AEAD, and the decision
//! that deferred encryption predicted it would not.** It was deferred on the ground
//! that *"an AEAD's per-write nonce ends the determinism three checks in this
//! tree are written on"* -- the KAT below,
//! `records_are_addressed_by_tag_not_position`, and the I3 crash proof's byte
//! comparisons. All three survived. The reason is that **entropy reaches this
//! crate only as an argument**: it can reach no generator, so the salt and the
//! per-open nonce seed are *parameters* the caller fills. Fixed entropy in,
//! deterministic image out. The nondeterminism is a parameter, not an ambient
//! fact, and a generator added to this graph would end all three comparisons
//! without failing anything that would say so.
//!
//! What that costs, stated because the split it justified was still right:
//! a byte comparison here is now a claim about the commit **and**
//! about the harness's fixed entropy, where the reopen-and-compare assertions
//! hold whatever the nonce is. Both are documented at the I3 site.
//!
//! # The tag is not the trailer it replaced
//!
//! Version 2 ended in a 32-byte `sha3_256` over every preceding byte. Version
//! 3 ends in Poly1305's 16 bytes, and the claim is a different one, not a
//! shorter one:
//!
//! * the **trailer** detected damage by anything that was not a writer. It was
//!   not authenticity -- whoever could write the file could recompute it --
//!   and not rollback protection;
//! * the **tag** detects damage by anything that does not hold the key, and
//!   covers the plaintext header as AAD. It is still **not** rollback
//!   protection: an older valid snapshot copied back verifies under the same
//!   password, because the salt lives in the header and does not move across
//!   rewrites. The shipped wallet's stale-backup hazard is I4's to detect, not the
//!   format's.
//!
//! The name `TRAILER_LEN` is kept so every site that spoke of a trailer still
//! reads.
//!
//! **The price of that is an operator's and it is real.** Under v2 each
//! malformation came back as a `Corrupt` variant naming the broken field.
//! Under v3 a flipped bit, a truncated file, a forged header field and a wrong
//! password are **one `WrongPassword`**, refused before a record byte is read.
//! That is deliberate -- an error distinguishing a damaged file from a wrong
//! password is a decryption oracle -- but it means somebody with a bit-rotted
//! store is told their password might be wrong, and will retype it several
//! times before suspecting the disk.
//!
//! # No C, and it holds by construction here
//!
//! The keystore was designed under the rule that a plaintext image never
//! transit the C's stack, which is why v2's trailer called `backend::native::sha3_256` directly
//! rather than through the backend wrapper -- a call-site convention somebody
//! had to keep. `argon2` and `chacha20poly1305` are pure Rust, so nothing in
//! the sealed path can reach `backend::selected` at all. See `super::crypt`.
//!
//! # What is enforced, and by what
//!
//! Version is read and dispatched *before* the KDF runs and before the tag is
//! checked, so a file from a version this build does not read (1, 2, or a
//! later one) reports `UnsupportedVersion` and not `WrongPassword` -- and an
//! operator holding an older wallet is told so without first paying seventy
//! milliseconds of Argon2 to be told the wrong thing; a version-3 file is
//! read (above), with its record width taken from the version word. `an_older_format_reports_unsupported_version_before_anything_else`
//! below proves the order by destroying a v1 file's last byte and still
//! getting `UnsupportedVersion`, which is the only way to see it: on a
//! well-formed file the two orders are indistinguishable.
//! `tests/keystore.rs` runs the same file through the public `Keystore::open`
//! on a real directory.
//!
//! `Corrupt` carries an offset and never a byte (I6). `count`
//! goes through `usize::try_from` and a hard cap before any allocation, and
//! everything after `crypt::open` is a check on *authenticated* bytes -- a
//! writer bug, not an attacker, and they stay because a canonical format with
//! unchecked canonicality is a format with two images for one state. No
//! panicking construct exists in this file outside `#[cfg(test)]`; the panic
//! census holds that at zero, and the every-prefix truncation test in
//! `tests/keystore.rs` is what makes the slice-indexing rule -- which the
//! census cannot see -- falsifiable.
//!
//! # Nothing checks this header against the layout it describes
//!
//! The checks in this tree count things and resolve names; **a header
//! describing a layout has neither a count nor a name to disagree with**. A
//! version change that leaves this block behind goes red nowhere, and the
//! block stays quotable as an argument while it is wrong. What stands against
//! that is the assertion named above, which executes.

use core::fmt;
use std::collections::BTreeMap;

use zeroize::Zeroizing;

use crate::account::{Account, AccountKind, AccountRecord, KeyMaterial, StreamId, WotsIndex, FIRST_KEY_LEN};
use crate::addr::Tag;
use super::crypt::{self, Kdf};
use crate::consts::{ADDR_TAG_LEN, SEED_LEN};
use crate::error::{Error, Result};
use crate::secret::Secret;

pub(crate) const MAGIC: [u8; 8] = *b"MCMKSTOR";
/// The version this build WRITES, and the newest it reads. It also reads
/// [`V3_VERSION`]; the module doc's "Version 4" section says what becomes of
/// such a file.
pub(crate) const VERSION: u16 = 4;
/// The one older version this build READS. A version-3
/// image goes through the same key derivation and the same AEAD -- the KDF
/// fields, salt and nonce sit at the same offsets -- with 178-byte records
/// and its reservation's figures declared absent, and is re-sealed as
/// [`VERSION`] by the store's next commit, never by `open`.
pub(crate) const V3_VERSION: u16 = 3;
/// The PLAINTEXT header, and everything in it is also the AEAD's additional
/// authenticated data: `magic[8] | version u16 | kdf_id u8 | m_cost u32 |
/// t_cost u32 | p_cost u32 | salt[16] | nonce[12]`.
///
/// It has to be plaintext because a reader needs every field of it to derive
/// the key before it can decrypt anything. It is authenticated because
/// otherwise an attacker could rewrite `m_cost` down to 8 KiB and hand the
/// file back; as AAD, that rewrite derives a different key and the tag fails.
pub(crate) const HEADER_LEN: usize =
    8 + 2 + 1 + 4 + 4 + 4 + crypt::SALT_LEN + crypt::NONCE_LEN;
/// `generation u64 | count u32 | master_present u8 | master[32]`, inside the
/// ciphertext.
///
/// **The master seed is store-level state and it is why this session exists.**
/// Before version 3 it was in no file: every command read twenty-four words from
/// the terminal and derived it. That is the mnemonic prompt working exactly as argued
/// and an interface nobody uses. It is here now because the AEAD is what makes
/// holding it safe -- the two findings were never separable.
///
/// When `master_present` is 0 the 32 bytes are enforced zero, the same
/// canonicality discipline the derived record's padding and the absent
/// pending fields already carry: one state, one image.
pub(crate) const BODY_HEADER_LEN: usize = 8 + 4 + 1 + SEED_LEN;
/// The version-4 record: version 3's 178 bytes, byte for byte and in v3's
/// order, then `figures u8 | reserved_balance u64 | blk_to_live u64`.
/// **The v3 prefix is spelled on one physical line on
/// purpose, and this sum is not written through [`V3_RECORD_LEN`]:**
/// `tests/invariants.rs::duplicate_key_streams_are_refused_within_one_keystore_not_across_stores`
/// asserts that exact substring through a comment stripper that keeps
/// newlines, as its anchor that the record still carries the key-stream
/// identity.
pub(crate) const RECORD_LEN: usize =
    ADDR_TAG_LEN + 1 + 32 + FIRST_KEY_LEN + ADDR_TAG_LEN + 4 + 1 + 4 + 32 + 1 + 8 + 8;
/// A version-3 record's width, frozen as a literal the way
/// `older_first_account` freezes 94 and 178: an old format's geometry is
/// never read through this module's live constant, which is 195 now.
pub(crate) const V3_RECORD_LEN: usize = 178;
/// **The AEAD tag, where version 2 had a `sha3_256` trailer.** Sixteen bytes
/// rather than thirty-two, and a different kind of claim: the trailer detected
/// damage by anything that was not a writer, and this detects damage by
/// anything that does not hold the key. The name is kept so every site that
/// spoke of a trailer still reads.
pub(crate) const TRAILER_LEN: usize = crypt::TAG_LEN;
/// The most accounts one snapshot holds. A wallet has tens of accounts; the
/// shipped restore hard-codes five. The cap exists so `count`
/// from an untrusted file bounds the allocation, not to describe a use.
pub(crate) const MAX_ACCOUNTS: usize = 1 << 16;
/// The longest image `read_header` admits: `image_len(MAX_ACCOUNTS)`, written
/// out as its own sum rather than derived from the formula, so the two can
/// disagree.
/// `max_image_len_is_the_cap_image_and_one_record_more_is_refused` holds them
/// equal at the cap and holds the gate that reads this to exactly it.
///
/// **`BODY_HEADER_LEN` is a term of this sum, and omitting it is invisible
/// below the cap.** Version 2's image is
/// `HEADER_LEN + count * RECORD_LEN + TRAILER_LEN`; version 3 puts a 45-byte
/// body header inside the ciphertext, so a sum written without it lets a
/// store at the cap encode and be refused on read, and `45/178 < 1` puts the
/// smallest failing count at the cap itself -- nothing below it can show the
/// fault. `max_image_len_is_the_cap_image_and_one_record_more_is_refused` is
/// the boundary test that does.
pub(crate) const MAX_IMAGE_LEN: usize =
    HEADER_LEN + BODY_HEADER_LEN + MAX_ACCOUNTS * RECORD_LEN + TRAILER_LEN;
/// The shortest image either read version's writer produces: `image_len(0)`,
/// an empty store. It carries no record term, so it is the one length both
/// read arms share. `read_header` reports it as the `min` of
/// its length `Range`. That field said `HEADER_LEN + TRAILER_LEN` until that test
/// -- version 2's minimum, 45 bytes short of version 3's, the same omission
/// as `MAX_IMAGE_LEN`'s at the other end of the range -- and the same test
/// holds it.
pub(crate) const MIN_IMAGE_LEN: usize = HEADER_LEN + BODY_HEADER_LEN + TRAILER_LEN;

const KIND_DERIVED: u8 = 0;
const KIND_IMPORTED: u8 = 1;

/// The two figures of a reserved spend that the record carries beside the
/// digest since format version 4: what the dead
/// reservation diagnosis compares against the ledger entry and
/// the tip, and what the block-to-live recovery renders. Not
/// secret. Both are plan inputs as `SpendPlan::new` took them: the balance is
/// `LedgerEntry::balance` at plan time -- the number `tx_val` will demand
/// `send + change + fee` equal exactly -- and `blk_to_live` is the caller's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Figures {
    /// The ledger balance the plan was built against, in nanoMochimo.
    pub reserved_balance: u64,
    /// The plan's block-to-live; zero never expires.
    pub blk_to_live: u64,
}

/// A key reserved for a spend that has not been settled -- or, in a
/// [`Slot`]'s `settled` field, the last settled reservation retained until
/// the index moves.
///
/// A reservation is written in the same commit that advances `wots_index`
/// to `spent_index + 1`; the retained settled block is that same block,
/// moved by the settle commit, which advances nothing. The parser refuses
/// any other relation, in both occupied states. Not secret: the digest is
/// the message being signed, and the index is public state. `figures` is
/// `None` for one origin only, the version-3 read arm -- a v3 record
/// carried neither figure, and the migrated state says *not recorded*
/// rather than inventing a value -- and a settle carries that `None`
/// forward unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pending {
    pub spent_index: WotsIndex,
    pub digest: [u8; 32],
    pub figures: Option<Figures>,
}

/// One account's slot in the live state. No `Debug`: it holds an `Account`,
/// which holds key material for the imported kind.
///
/// `pending` and `settled` are two fields on purpose, so that no reader of
/// `pending` can mistake a retained settled block for an open reservation:
/// `persist_advance` refuses on `pending` alone, and a retained
/// block never blocks it. Both `Some` is the one illegal state this shape
/// admits; the file cannot express it (one `pending u8`, three values) and
/// [`encode`] refuses it.
pub(crate) struct Slot {
    pub(crate) account: Account,
    pub(crate) pending: Option<Pending>,
    pub(crate) settled: Option<Pending>,
}

/// What the encoder reads per record: the account by reference plus the
/// values the caller may be overriding for the record it is about to commit.
/// No `Debug`, same reason as [`Slot`].
pub(crate) struct RecordRef<'a> {
    pub(crate) tag: Tag,
    pub(crate) account: &'a Account,
    pub(crate) wots_index: WotsIndex,
    pub(crate) pending: Option<Pending>,
    pub(crate) settled: Option<Pending>,
}

/// The parsed state: generation and the sorted slots.
pub(crate) struct Parsed {
    pub(crate) generation: u64,
    pub(crate) slots: BTreeMap<Tag, Slot>,
    /// The master seed, when the store holds one.
    pub(crate) master: Option<Secret<SEED_LEN>>,
}

/// The exact image length for `count` records, or `None` on overflow.
pub(crate) fn image_len(count: usize) -> Option<usize> {
    body_len(count)?
        .checked_add(HEADER_LEN)?
        .checked_add(TRAILER_LEN)
}

/// The PLAINTEXT length for `count` records: what the ciphertext's length is,
/// since a stream cipher does not change it. The WRITER's formula, over
/// [`RECORD_LEN`]; the parser asks [`body_len_at`] with the version it read.
pub(crate) fn body_len(count: usize) -> Option<usize> {
    body_len_at(VERSION, count)
}

/// The record width a read version uses: 178 for version 3, [`RECORD_LEN`]
/// for version 4. The one place the per-version width is chosen.
pub(crate) fn record_len_at(version: u16) -> usize {
    if version == V3_VERSION {
        V3_RECORD_LEN
    } else {
        RECORD_LEN
    }
}

/// [`body_len`] for a read version: the closed-formula length check is per
/// version, so a version-3 image is measured against 178-byte records.
pub(crate) fn body_len_at(version: u16, count: usize) -> Option<usize> {
    count.checked_mul(record_len_at(version))?.checked_add(BODY_HEADER_LEN)
}

/// Encode a sorted, duplicate-free record list into a canonical image.
///
/// The image lives in a `Zeroizing` buffer allocated at exact capacity, so
/// it never reallocates and leaves no un-zeroed copy behind. The caller
/// guarantees order and uniqueness (it builds from a `BTreeMap`); this
/// function checks both anyway, because a wrong image is a corrupt store.
pub(crate) fn encode(
    records: &[RecordRef<'_>],
    generation: u64,
    master: Option<&Secret<SEED_LEN>>,
    kdf: Kdf,
    salt: &[u8; crypt::SALT_LEN],
    key: &[u8; crypt::KEY_LEN],
    nonce: &[u8; crypt::NONCE_LEN],
) -> Result<Zeroizing<Vec<u8>>> {
    if records.len() > MAX_ACCOUNTS {
        return Err(Error::Range {
            what: "keystore account count",
            min: 0,
            max: MAX_ACCOUNTS as u64,
            got: records.len() as u64,
        });
    }
    let count = u32::try_from(records.len()).map_err(|_| Error::Range {
        what: "keystore account count",
        min: 0,
        max: u64::from(u32::MAX),
        got: records.len() as u64,
    })?;
    let len = image_len(records.len()).ok_or(Error::Corrupt {
        what: "image length overflow",
        offset: 0,
    })?;
    let kdf = kdf.checked()?;
    // The plaintext header, which is also the AAD. Built first and never
    // encrypted: a reader needs every byte of it to derive the key.
    let mut image: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(len));
    image.extend_from_slice(&MAGIC);
    image.extend_from_slice(&VERSION.to_le_bytes());
    image.push(crypt::KDF_ARGON2ID_V13);
    image.extend_from_slice(&kdf.m_cost_kib.to_le_bytes());
    image.extend_from_slice(&kdf.t_cost.to_le_bytes());
    image.extend_from_slice(&kdf.p_cost.to_le_bytes());
    image.extend_from_slice(salt);
    image.extend_from_slice(nonce);
    debug_len_matches(image.len(), HEADER_LEN)?;

    // The body. Everything from here to the tag is encrypted, so `generation`
    // and `count` -- which v2 carried in the clear -- are inside it now: a
    // stolen file should not say how many accounts a wallet has or how often
    // it has been written to.
    image.extend_from_slice(&generation.to_le_bytes());
    image.extend_from_slice(&count.to_le_bytes());
    match master {
        None => {
            image.push(0);
            image.extend_from_slice(&[0u8; SEED_LEN]);
        }
        Some(m) => {
            image.push(1);
            image.extend_from_slice(m.expose());
        }
    }

    let mut prev: Option<Tag> = None;
    for r in records {
        let record_offset = image.len();
        if let Some(p) = prev {
            if r.tag <= p {
                return Err(Error::Corrupt {
                    what: "records not strictly ascending by tag",
                    offset: record_offset,
                });
            }
        }
        prev = Some(r.tag);
        // **Both blocks present is refused here and only here**. The
        // record's one `pending u8` has three values -- none,
        // reserved, settled-retained -- so an image with both an open and a
        // settled block has no encoding: `parse_with_key` can never see the
        // state, no malformation row can reach it, and what has no image is
        // this function's mapping rather than a rule the parser applies. It
        // is not left to the producers (`persist_advance` overwrites the
        // retained block, `persist_settled` moves it), because "unreachable
        // by construction with nothing holding the construction" is what
        // the relation check below refused to leave as a comment. Defaulting would not be
        // neutral: preferring `settled` seals an open reservation as settled
        // and strands the balance at the reserved key; preferring `pending`
        // drops the block the reverted-settle report exists to read.
        if r.pending.is_some() && r.settled.is_some() {
            return Err(Error::Corrupt {
                what: "both an open and a settled reservation in one record",
                offset: record_offset,
            });
        }
        let (state, block) = match (r.pending, r.settled) {
            (Some(p), None) => (1u8, Some(p)),
            (None, Some(s)) => (2u8, Some(s)),
            _ => (0u8, None),
        };
        // **The relation the parser enforces, checked on the way OUT as well**
        // (the gap was reported before it was closed), in BOTH non-zero states
        // since version 4: a settled block is retained only until the index moves,
        // so the relation holds whenever the block is occupied, and
        // `persist_advance_to` must clear it rather than seal it. Every other
        // canonicality rule `parse_with_key` applies is unrepresentable in
        // this function's input -- the zero padding, the zero first-key
        // field, the zero pending fields, the zero absent master and, since
        // version 4, the figures flag and its zero figures are all constructed here
        // from a sum type -- and the tag order above is the one representable
        // inconsistency this function already refused. This is the other:
        // `RecordRef` carries `wots_index` and the block's `spent_index` as
        // independent fields. `persist_advance` and `persist_settled` are the
        // producers and build them together, so it was unreachable and still
        // is; what changed is that under an AEAD an image violating it would
        // be AUTHENTICATED garbage -- refused after the tag verifies, with
        // nothing to tell an operator it was a writer bug rather than a
        // damaged disk. Refused here, before anything is sealed, under the
        // parser's own `what`, so the two sides name one rule.
        // `encode_refuses_the_pending_relation_the_parser_refuses` holds this
        // side; the malformation table's `bad_pending` and `settled_relation`
        // rows reach the parser's side around this function, by re-sealing.
        // (The both-blocks refusal above is encode's alone and is not a third
        // member of the two representable inconsistencies this comment
        // counts: it has no parser counterpart by construction.)
        if let Some(p) = block {
            if p.spent_index.get().checked_add(1) != Some(r.wots_index.get()) {
                return Err(Error::Corrupt {
                    what: "pending index does not precede wots_index by one",
                    offset: record_offset,
                });
            }
        }
        image.extend_from_slice(&r.tag);
        let stream = match r.account.key_material() {
            KeyMaterial::Derived {
                account_index,
                stream,
            } => {
                image.push(KIND_DERIVED);
                image.extend_from_slice(&account_index.to_le_bytes());
                image.extend_from_slice(&[0u8; 28]);
                // A derived account's first key is a function of the master
                // seed, which no record holds, so there is nothing to store
                // and the field is enforced zero on the way back in.
                image.extend_from_slice(&[0u8; FIRST_KEY_LEN]);
                stream
            }
            KeyMaterial::Imported {
                root,
                first,
                stream,
            } => {
                image.push(KIND_IMPORTED);
                image.extend_from_slice(root.secret().expose());
                image.extend_from_slice(&first.to_bytes());
                stream
            }
        };
        image.extend_from_slice(stream.as_bytes());
        image.extend_from_slice(&r.wots_index.get().to_le_bytes());
        match block {
            None => {
                image.push(0);
                image.extend_from_slice(&[0u8; 4]);
                image.extend_from_slice(&[0u8; 32]);
                // The figures: flag and both values zero when no block is
                // occupied (the fourth canonicality rule).
                image.push(0);
                image.extend_from_slice(&[0u8; 8]);
                image.extend_from_slice(&[0u8; 8]);
            }
            Some(p) => {
                image.push(state);
                image.extend_from_slice(&p.spent_index.get().to_le_bytes());
                image.extend_from_slice(&p.digest);
                match p.figures {
                    // The migrated state: a block read from a version-3
                    // image carries no figures, and re-sealing it under
                    // version 4 says so rather than writing a value the
                    // store never observed.
                    None => {
                        image.push(0);
                        image.extend_from_slice(&[0u8; 8]);
                        image.extend_from_slice(&[0u8; 8]);
                    }
                    Some(f) => {
                        image.push(1);
                        image.extend_from_slice(&f.reserved_balance.to_le_bytes());
                        image.extend_from_slice(&f.blk_to_live.to_le_bytes());
                    }
                }
            }
        }
    }
    // Seal the body in place, with the header as AAD. Version 2 hashed here;
    // the tag replaces that hash and makes a stronger claim -- see
    // `TRAILER_LEN`.
    let (header, body) = image.split_at_mut(HEADER_LEN);
    let aad: Vec<u8> = header.to_vec();
    let tag = crypt::seal(key, nonce, &aad, body)?;
    image.extend_from_slice(&tag);
    debug_len_matches(image.len(), len)?;
    Ok(image)
}

/// The closed formula and the bytes written must agree; a disagreement is a
/// bug in this file, reported as `Corrupt` rather than trusted.
fn debug_len_matches(written: usize, expected: usize) -> Result<()> {
    if written == expected {
        Ok(())
    } else {
        Err(Error::Corrupt {
            what: "encoded length disagrees with the closed formula",
            offset: written,
        })
    }
}

/// A bounded cursor: every read goes through `take`, which fails closed with
/// the offset it stopped at. There is no indexing anywhere in the parser.
struct Cursor<'a> {
    rest: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn take<const N: usize>(&mut self, what: &'static str) -> Result<&'a [u8; N]> {
        match self.rest.split_first_chunk::<N>() {
            Some((head, tail)) => {
                self.rest = tail;
                self.offset += N;
                Ok(head)
            }
            None => Err(Error::Corrupt {
                what,
                offset: self.offset,
            }),
        }
    }
}

/// An image split into the four regions a v3 file has, with its header
/// already parsed and bounded.
///
/// A named type rather than a four-tuple of slices: the tuple was
/// `(Header, &[u8], &[u8], &[u8; TRAILER_LEN])` and nothing in it said which
/// slice was the AAD and which the ciphertext — two byte slices in a row whose
/// order is the whole meaning. Clippy objected to the complexity; the fix that
/// answers the objection is the one that makes the call sites readable.
pub(crate) struct Framed<'a> {
    /// The version word the file carries: [`VERSION`] or [`V3_VERSION`].
    /// The body parser takes its record width from it.
    pub(crate) version: u16,
    pub(crate) header: Header,
    /// The plaintext header bytes, verbatim — which are also the AAD.
    pub(crate) aad: &'a [u8],
    pub(crate) ciphertext: &'a [u8],
    pub(crate) tag: &'a [u8; TRAILER_LEN],
}

/// The first record's tag and kind of a version-1 or version-2 image, read
/// only when the image's length is exactly that version's closed formula.
///
/// The two layouts this crate ever wrote before this one -- v1 from
/// `cebd1b4` until `2e3fbe0`, v2 from `c4b3a3d` until `8062c9a`, the
/// commit before `0c07b65` landed v3 -- share a 22-byte plaintext
/// header, `magic[8] | version u16 | generation u64 | count u32`, and a
/// 32-byte sha3 trailer, and every record begins `tag[20] | kind u8`; they
/// differ in the record width, 94 and 178. So `22 + count * width + 32 ==
/// len` is the whole test of whether the bytes at 22..42 are a tag at all,
/// and it is what keeps a version-3 image under a forged version word --
/// whose bytes there are the KDF's `p_cost` tail, the salt and the head of
/// the nonce -- from being described as an account. The widths are frozen
/// literals, not this module's constants: an old format's geometry is never
/// read through the live `RECORD_LEN`, which is 195 since version 4 (v3's 178 is
/// `V3_RECORD_LEN`, frozen the same way, for the read arm). Every read goes through the same
/// `Cursor` the live parser uses, and a short read is `None`, never
/// `Corrupt`: the version was already the answer.
///
/// `testdata/keystore_v1_snapshot.bin` and `testdata/keystore_v2_snapshot.bin`
/// are the two captured files this is exercised against, here and in
/// `tests/keystore.rs`.
fn older_first_account(version: u16, image: &[u8]) -> Option<(Tag, AccountKind)> {
    const OLD_HEADER_LEN: usize = 8 + 2 + 8 + 4;
    const OLD_TRAILER_LEN: usize = 32;
    const V1_RECORD_LEN: usize = 94;
    const V2_RECORD_LEN: usize = 178;
    let record_len = match version {
        1 => V1_RECORD_LEN,
        2 => V2_RECORD_LEN,
        _ => return None,
    };
    let mut c = Cursor { rest: image, offset: 0 };
    c.take::<8>("magic").ok()?;
    c.take::<2>("version").ok()?;
    c.take::<8>("generation").ok()?;
    let count = usize::try_from(u32::from_le_bytes(*c.take::<4>("count").ok()?)).ok()?;
    let expected = count
        .checked_mul(record_len)?
        .checked_add(OLD_HEADER_LEN)?
        .checked_add(OLD_TRAILER_LEN)?;
    if count == 0 || image.len() != expected {
        return None;
    }
    let tag: Tag = *c.take::<ADDR_TAG_LEN>("first tag").ok()?;
    let kind = match c.take::<1>("first kind").ok()?[0] {
        0 => AccountKind::Derived,
        1 => AccountKind::Imported,
        _ => return None,
    };
    Some((tag, kind))
}

/// The plaintext header, as read off disk.
pub(crate) struct Header {
    pub(crate) kdf: Kdf,
    pub(crate) salt: [u8; crypt::SALT_LEN],
    pub(crate) nonce: [u8; crypt::NONCE_LEN],
}

/// Read and dispatch the plaintext header. **Nothing here needs the key**, and
/// nothing here trusts a value before bounding it.
///
/// The order is the same one version 2 kept and for the same reason: magic,
/// then version, then everything else. Two versions are accepted:
/// [`VERSION`] and [`V3_VERSION`], whose plaintext headers
/// are identical in layout. A file from a newer format reports
/// `UnsupportedVersion` -- "upgrade" -- rather than `Corrupt` -- "damaged" --
/// and a version-2 file, which every store written before version 3 is,
/// reports it too.
pub(crate) fn read_header(image: &[u8]) -> Result<Framed<'_>> {
    if image.len() > MAX_IMAGE_LEN {
        return Err(Error::Range {
            what: "keystore image length",
            min: MIN_IMAGE_LEN as u64,
            max: MAX_IMAGE_LEN as u64,
            got: image.len() as u64,
        });
    }
    let Some((body_and_header, tag)) = image.split_last_chunk::<TRAILER_LEN>() else {
        return Err(Error::Corrupt {
            what: "tag",
            offset: image.len(),
        });
    };
    let mut c = Cursor {
        rest: body_and_header,
        offset: 0,
    };
    let magic = c.take::<8>("magic")?;
    if *magic != MAGIC {
        return Err(Error::Corrupt {
            what: "magic",
            offset: 0,
        });
    }
    let version = u16::from_le_bytes(*c.take::<2>("version")?);
    if version != VERSION && version != V3_VERSION {
        return Err(Error::UnsupportedVersion {
            got: version,
            supported: VERSION,
            first_account: older_first_account(version, image),
        });
    }
    let kdf_id = c.take::<1>("kdf id")?[0];
    if kdf_id != crypt::KDF_ARGON2ID_V13 {
        // A KDF this build does not have is an upgrade, not damage -- the
        // same reading the version arm above gives, one field along. No
        // account is named: `got` is an id here, not a version, and the
        // bytes at 22..42 of this image are its salt.
        return Err(Error::UnsupportedVersion {
            got: u16::from(kdf_id),
            supported: u16::from(crypt::KDF_ARGON2ID_V13),
            first_account: None,
        });
    }
    let kdf = Kdf {
        m_cost_kib: u32::from_le_bytes(*c.take::<4>("kdf m_cost")?),
        t_cost: u32::from_le_bytes(*c.take::<4>("kdf t_cost")?),
        p_cost: u32::from_le_bytes(*c.take::<4>("kdf p_cost")?),
    }
    // Bounded BEFORE anything allocates: `m_cost` is an instruction to
    // allocate that many KiB and it came out of a file.
    .checked()?;
    let salt = *c.take::<{ crypt::SALT_LEN }>("kdf salt")?;
    let nonce = *c.take::<{ crypt::NONCE_LEN }>("nonce")?;
    debug_len_matches(c.offset, HEADER_LEN)?;
    let (header, ciphertext) = body_and_header.split_at(HEADER_LEN);
    if ciphertext.len() < BODY_HEADER_LEN {
        return Err(Error::Corrupt {
            what: "ciphertext shorter than a body header",
            offset: HEADER_LEN,
        });
    }
    Ok(Framed {
        version,
        header: Header { kdf, salt, nonce },
        aad: header,
        ciphertext,
        tag,
    })
}

/// Parse an image read from disk, with the key already derived.
///
/// Fail-closed at every step; see the module doc for the order (version before
/// anything, bounds before allocation, **decryption before any record byte is
/// believed**).
pub(crate) fn parse_with_key(image: &[u8], key: &[u8; crypt::KEY_LEN]) -> Result<Parsed> {
    let f = read_header(image)?;
    let aad: Vec<u8> = f.aad.to_vec();
    let mut body: Zeroizing<Vec<u8>> = Zeroizing::new(f.ciphertext.to_vec());
    // **One error for a wrong password, a flipped bit and a tampered header.**
    // See `crypt::open`.
    crypt::open(key, &f.header.nonce, &aad, &mut body, f.tag)?;

    // From here the bytes are authenticated, and every check below is about a
    // writer that authenticated garbage -- a bug in this file, not an
    // attacker. They stay because a canonical format with unchecked
    // canonicality is a format with two images for one state.
    let mut c = Cursor {
        rest: &body,
        offset: 0,
    };
    let generation = u64::from_le_bytes(*c.take::<8>("generation")?);
    let count = u32::from_le_bytes(*c.take::<4>("count")?);
    let count = usize::try_from(count).map_err(|_| Error::Corrupt {
        what: "count",
        offset: c.offset,
    })?;
    let master_present = c.take::<1>("master present")?[0];
    let master_bytes = c.take::<{ SEED_LEN }>("master seed")?;
    let master = match master_present {
        0 => {
            if master_bytes.iter().any(|&b| b != 0) {
                return Err(Error::Corrupt {
                    what: "master seed present flag is 0 with non-zero bytes",
                    offset: c.offset,
                });
            }
            None
        }
        1 => Some(Secret::new(*master_bytes)),
        _ => {
            return Err(Error::Corrupt {
                what: "master seed present flag is not 0 or 1",
                offset: c.offset,
            })
        }
    };
    if count > MAX_ACCOUNTS {
        return Err(Error::Range {
            what: "keystore account count",
            min: 0,
            max: MAX_ACCOUNTS as u64,
            got: count as u64,
        });
    }
    // The closed-formula length check is per read version: a version-3 body
    // is `45 + 178 * count`, a version-4 body `45 + 195 * count`.
    let expected = body_len_at(f.version, count).ok_or(Error::Corrupt {
        what: "image length overflow",
        offset: c.offset,
    })?;
    if body.len() != expected {
        return Err(Error::Corrupt {
            what: "image length disagrees with count",
            offset: c.offset,
        });
    }

    let mut slots: BTreeMap<Tag, Slot> = BTreeMap::new();
    let mut prev: Option<Tag> = None;
    for _ in 0..count {
        let record_offset = c.offset;
        let tag: Tag = *c.take::<ADDR_TAG_LEN>("tag")?;
        if let Some(p) = prev {
            if tag <= p {
                return Err(Error::Corrupt {
                    what: "records not strictly ascending by tag",
                    offset: record_offset,
                });
            }
        }
        prev = Some(tag);
        let kind = c.take::<1>("kind")?[0];
        // **`Zeroizing`, and that is a fix rather than a style**.
        // For an imported record these 32 bytes ARE the root. This was a bare
        // `[u8; 32]` until version 3: `Secret::new(body)` copied it into a type
        // that zeroizes and the stack copy stayed behind, live for the rest of
        // the iteration and then abandoned to whatever reused the frame. I6
        // says key material does not outlive its use, and a parser that
        // decrypts a root only to leave a plaintext copy on the stack is the
        // at-rest problem this session fixed reappearing in memory.
        let body: Zeroizing<[u8; 32]> = Zeroizing::new(*c.take::<32>("body")?);
        let first = *c.take::<FIRST_KEY_LEN>("first key components")?;
        let stream_id = StreamId::from_bytes(*c.take::<ADDR_TAG_LEN>("stream identity")?);
        let wots_index = WotsIndex::from_raw(u32::from_le_bytes(*c.take::<4>("wots_index")?));
        let pending_flag = c.take::<1>("pending flag")?[0];
        let spent_index = u32::from_le_bytes(*c.take::<4>("spent_index")?);
        let digest = *c.take::<32>("digest")?;
        // The figures: present in a version-4 record only. A version-3
        // record ends at the digest, and its reservation's figures are
        // *declared absent* -- `None` -- rather than read as zero, which is
        // the state the migration passes through without fabricating.
        let figures_bytes = if f.version == V3_VERSION {
            None
        } else {
            let flag = c.take::<1>("figures flag")?[0];
            let reserved_balance = u64::from_le_bytes(*c.take::<8>("reserved_balance")?);
            let blk_to_live = u64::from_le_bytes(*c.take::<8>("blk_to_live")?);
            Some((flag, reserved_balance, blk_to_live))
        };

        // The canonical rules, both arms: the state byte's domain
        // (0, 1 or 2 -- 2 only in a version-4 record, since no version-3
        // writer ever wrote it and the version-3 parser refused it); every
        // block field zero when no block is occupied; the relation in both
        // occupied states; and the figures flag's own domain and zero rule.
        let figures = match figures_bytes {
            None => None,
            Some((0, 0, 0)) => None,
            Some((0, _, _)) => {
                return Err(Error::Corrupt {
                    what: "figures not zero while figures == 0",
                    offset: record_offset,
                })
            }
            Some((1, reserved_balance, blk_to_live)) => Some(Figures {
                reserved_balance,
                blk_to_live,
            }),
            Some(_) => {
                return Err(Error::Corrupt {
                    what: "figures flag",
                    offset: record_offset,
                })
            }
        };
        let (pending, settled) = match pending_flag {
            0 => {
                if spent_index != 0 || digest != [0u8; 32] || figures_bytes.is_some_and(|(fl, _, _)| fl != 0) {
                    return Err(Error::Corrupt {
                        what: "pending fields not zero while pending == 0",
                        offset: record_offset,
                    });
                }
                (None, None)
            }
            1 | 2 if pending_flag == 1 || f.version != V3_VERSION => {
                if spent_index.checked_add(1) != Some(wots_index.get()) {
                    return Err(Error::Corrupt {
                        what: "pending index does not precede wots_index by one",
                        offset: record_offset,
                    });
                }
                let block = Pending {
                    spent_index: WotsIndex::from_raw(spent_index),
                    digest,
                    figures,
                };
                if pending_flag == 1 {
                    (Some(block), None)
                } else {
                    (None, Some(block))
                }
            }
            _ => {
                return Err(Error::Corrupt {
                    what: "pending flag",
                    offset: record_offset,
                })
            }
        };

        let record = match kind {
            KIND_DERIVED => {
                let (idx, pad) = body.split_first_chunk::<4>().ok_or(Error::Corrupt {
                    what: "body",
                    offset: record_offset,
                })?;
                if pad.iter().any(|b| *b != 0) {
                    return Err(Error::Corrupt {
                        what: "derived body padding not zero",
                        offset: record_offset,
                    });
                }
                if first.iter().any(|b| *b != 0) {
                    return Err(Error::Corrupt {
                        what: "derived first-key field not zero",
                        offset: record_offset,
                    });
                }
                AccountRecord::Derived {
                    tag,
                    account_index: u32::from_le_bytes(*idx),
                    stream_id,
                    wots_index,
                }
            }
            KIND_IMPORTED => AccountRecord::Imported {
                tag,
                root: Secret::<SEED_LEN>::new(*body),
                first_key: first,
                stream_id,
                wots_index,
            },
            _ => {
                return Err(Error::Corrupt {
                    what: "kind",
                    offset: record_offset,
                })
            }
        };
        // The verifying constructor, not a field-by-field rebuild: an
        // imported record whose components or identity disagree with its root
        // is refused here rather than restored (the account model's sentence, kept
        // true under a grown record). Reported as `Corrupt` with this
        // record's offset, because from the parser's side that is what it is.
        let account = Account::restore_from_record(record).map_err(|e| match e {
            Error::FirstAddressNotReproduced => Error::Corrupt {
                what: "imported record: the root does not reproduce the stored tag",
                offset: record_offset,
            },
            Error::StreamIdNotReproduced => Error::Corrupt {
                what: "imported record: the root does not reproduce the stored key-stream identity",
                offset: record_offset,
            },
            other => other,
        })?;
        slots.insert(
            tag,
            Slot {
                account,
                pending,
                settled,
            },
        );
    }
    if !c.rest.is_empty() {
        // Unreachable given the length equality above; kept as belt.
        return Err(Error::Corrupt {
            what: "trailing bytes",
            offset: c.offset,
        });
    }
    Ok(Parsed {
        generation,
        slots,
        master,
    })
}

impl fmt::Debug for Parsed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Parsed")
            .field("generation", &self.generation)
            .field("accounts", &self.slots.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    //! The format KAT: one hand-assembled image equals `encode`, and parses
    //! back. Runs under Miri, which is the only
    //! mechanism here that reaches an implicit panic path in the parser.
    //!
    //! # Where the expected values come from (two degrees of freedom)
    //!
    //! The encoder side computes every tag and stream identity from the
    //! account. The hand-assembled side carries **group F's own literals**, so
    //! the two can disagree:
    //!
    //! | value | this side | fixture |
    //! | --- | --- | --- |
    //! | imported tag | `05ff…800f` | `F-address-widths.account_tag` |
    //! | imported stream | `2587…ea8c` | `F-address-widths.wots_address[20..40]` at `wots_index: 0` |
    //! | imported components | `include_bytes!` tail | `F-widths_account_address.bin[2144..2208]` |
    //! | derived tag | `4d9b…fbe9` | `F-derive-account-1.tag` |
    //! | derived stream | computed from `F-derive-account-1.seed` | not recorded — see below |
    //!
    //! Group F does not record a stream identity for `F-derive-account-1`, so
    //! this side computes it by the **other route**: `derive_wots_key` on the
    //! fixture's recorded account `seed`, where the encoder reaches it through
    //! `Account::derive` from the master. A wrong `derive_account`/`stream_id`
    //! wiring reddens the byte comparison; a wrong `derive_wots_key` does not,
    //! and `tests/derive.rs` is what pins that primitive against the fixture.
    use super::*;
    use crate::consts::WOTS_ADDR_LEN;
    // Not under Miri: `PK_LEN`'s two readers are `expected_body` above and
    // the gated `known_answer_image_for_two_accounts`, so gating them
    // leaves the import itself with no user.
    #[cfg(not(miri))]
    use crate::consts::PK_LEN;

    /// `F-derive-account-1`'s master seed and tag (`group_f_derivation.json`).
    /// The encoder's side of the KAT takes the tag `Account::derive` computed;
    /// the hand-assembled side below carries this literal, which the
    /// TypeScript emitted -- two degrees of freedom, so a wrong
    /// `derive_account_tag` reddens the byte comparison here as well as in
    /// group F. Position 1.
    const DERIVED_MASTER: [u8; SEED_LEN] = [
        0x40, 0x8b, 0x28, 0x5c, 0x12, 0x38, 0x36, 0x00, 0x4f, 0x4b, 0x88, 0x42, 0xc8, 0x93,
        0x24, 0xc1, 0xf0, 0x13, 0x82, 0x45, 0x0c, 0x0d, 0x43, 0x9a, 0xf3, 0x45, 0xba, 0x7f,
        0xc4, 0x9a, 0xcf, 0x70,
    ];
    // Not under Miri: read only by `expected_body`, whose one caller
    // `known_answer_image_for_two_accounts` is gated out under Miri.
    #[cfg(not(miri))]
    const DERIVED_TAG: [u8; ADDR_TAG_LEN] = [
        0x4d, 0x9b, 0x31, 0xe4, 0x78, 0x74, 0x66, 0x8e, 0x45, 0x89, 0x5a, 0x1b, 0x93, 0x38,
        0x8e, 0x5a, 0xa9, 0xb6, 0xfb, 0xe9,
    ];
    /// `F-derive-account-1`'s account seed, for the second route to its
    /// stream identity (module doc above).
    // Not under Miri: same one reader, `expected_body`.
    #[cfg(not(miri))]
    const DERIVED_SEED: [u8; SEED_LEN] = [
        0xdc, 0x91, 0x7b, 0x56, 0x7b, 0x86, 0x0a, 0xfb, 0xb3, 0x6d, 0x0c, 0xcd, 0x87, 0xd0,
        0x4c, 0xac, 0x46, 0x63, 0x52, 0x24, 0x50, 0xee, 0xc8, 0x13, 0x7f, 0xe2, 0xdd, 0x04,
        0xd0, 0xff, 0x93, 0xb1,
    ];

    /// `F-address-widths`: the account seed, the 2208-byte first address the
    /// shipped wallet would store as `faddress`, its recorded account tag and
    /// the recorded rotation-0 address hash. The address is **embedded, not
    /// transcribed** -- the same idiom `tests/txwire.rs` uses for its wire
    /// images -- so no 2208-byte literal can drift from the fixture.
    const IMPORTED_ROOT: [u8; SEED_LEN] = [
        0x66, 0x4e, 0xdd, 0x3d, 0x3b, 0xf1, 0xa0, 0xe2, 0x9c, 0x93, 0x98, 0xdd, 0xc1, 0x61,
        0x14, 0xab, 0xc6, 0xd6, 0xb4, 0x32, 0xb1, 0xe5, 0xe4, 0xde, 0x26, 0x7c, 0x7e, 0x2a,
        0xe5, 0x3f, 0x58, 0x0b,
    ];
    const IMPORTED_ADDRESS: &[u8; WOTS_ADDR_LEN] =
        include_bytes!("../../../../fixtures/F-widths_account_address.bin");
    const IMPORTED_TAG: [u8; ADDR_TAG_LEN] = [
        0x05, 0xff, 0x0f, 0x69, 0xd4, 0xc1, 0xcd, 0x68, 0x2e, 0xd3, 0x34, 0x1c, 0x0b, 0x77,
        0x73, 0x05, 0x4b, 0x58, 0x80, 0x0f,
    ];
    // Not under Miri: same one reader, `expected_body`.
    #[cfg(not(miri))]
    const IMPORTED_STREAM: [u8; ADDR_TAG_LEN] = [
        0x25, 0x87, 0x87, 0x8a, 0xd3, 0x4d, 0x29, 0xcf, 0x2e, 0x4b, 0xe4, 0x83, 0x86, 0xae,
        0xc3, 0xa0, 0xc2, 0xa7, 0xea, 0x8c,
    ];

    fn two_accounts() -> Vec<(Tag, Account, Option<Pending>)> {
        let imported = Account::import(Secret::new(IMPORTED_ROOT), IMPORTED_ADDRESS)
            .expect("F-address-widths' root and first address are a pair");
        let derived = Account::derive(&Secret::new(DERIVED_MASTER), 1);
        let derived_tag = derived.tag();
        vec![
            (imported.tag(), imported, None),
            (derived_tag, derived, None),
        ]
    }

    fn refs(accts: &[(Tag, Account, Option<Pending>)]) -> Vec<RecordRef<'_>> {
        accts
            .iter()
            .map(|(tag, a, p)| RecordRef {
                tag: *tag,
                account: a,
                wots_index: a.wots_index(),
                pending: *p,
                settled: None,
            })
            .collect()
    }

    /// The hand-assembled PLAINTEXT header, independent of the encoder.
    ///
    /// **Still hand-assembled, because it is still plaintext.** Everything a
    /// reader needs to derive the key has to be in the clear, so this half of
    /// the image is exactly as checkable as the whole of a version-2 image
    /// was.
    // Not under Miri: built only by the gated
    // `known_answer_image_for_two_accounts`.
    #[cfg(not(miri))]
    fn expected_header(nonce: &[u8; crypt::NONCE_LEN]) -> Vec<u8> {
        let mut h: Vec<u8> = Vec::new();
        h.extend_from_slice(b"MCMKSTOR");
        h.extend_from_slice(&4u16.to_le_bytes());
        h.push(1); // kdf id: Argon2id v0x13
        h.extend_from_slice(&65536u32.to_le_bytes());
        h.extend_from_slice(&3u32.to_le_bytes());
        h.extend_from_slice(&1u32.to_le_bytes());
        h.extend_from_slice(&TEST_SALT);
        h.extend_from_slice(nonce);
        h
    }

    /// The hand-assembled PLAINTEXT BODY, independent of the encoder.
    ///
    /// # What an AEAD took away, and what it did not
    ///
    /// The decision deferring encryption predicted it would end the hand-assembled
    /// known-answer image, and for the *ciphertext* it does -- nobody
    /// hand-assembles a Poly1305 tag. What it does not touch is the thing the
    /// KAT was ever about: **the canonical plaintext**, byte for byte, with
    /// enforced padding and enforced order. That is still written out here by
    /// hand and still compared against what the encoder produced, with two
    /// degrees of freedom, exactly as in version 2. The comparison simply
    /// happens one decryption further in.
    ///
    /// What the ciphertext gets instead is an anchor OUTSIDE this
    /// implementation: `chacha20poly1305_matches_rfc8439` replays RFC 8439
    /// §2.8.2 at the point this KAT's AEAD actually runs, and
    /// `argon2id_v13_matches_the_rfc9106_vector` replays RFC 9106 §5.3 -- at
    /// 32 KiB/t=3/p=4 with a secret and associated data, which is NOT the
    /// point `test_key` derives at (8/1/1, neither). What the KDF anchor pins
    /// under this round trip is the algorithm, the version and the m/t/p
    /// mapping, not the parameter point. Both anchors are read literals
    /// checked against a vendored copy of the standard -- the anchoring floor
    /// with its transcription weakness removed, not the executed second
    /// implementation the anchoring rule calls the standard.
    // Not under Miri: built only by the gated
    // `known_answer_image_for_two_accounts`.
    #[cfg(not(miri))]
    fn expected_body(generation: u64) -> Vec<u8> {
        let mut expected: Vec<u8> = Vec::new();
        expected.extend_from_slice(&generation.to_le_bytes());
        expected.extend_from_slice(&2u32.to_le_bytes());
        expected.push(0);
        expected.extend_from_slice(&[0u8; SEED_LEN]);
        // record 1: imported (tag 05ff.. sorts first), root, the faddress
        // tail as components, the recorded stream, index 0, no pending
        expected.extend_from_slice(&IMPORTED_TAG);
        expected.push(1);
        expected.extend_from_slice(&IMPORTED_ROOT);
        expected.extend_from_slice(&IMPORTED_ADDRESS[PK_LEN..]);
        expected.extend_from_slice(&IMPORTED_STREAM);
        expected.extend_from_slice(&0u32.to_le_bytes());
        expected.push(0);
        expected.extend_from_slice(&[0u8; 4]);
        expected.extend_from_slice(&[0u8; 32]);
        // Version 4's tail: figures flag 0, reserved_balance 0, blk_to_live 0 -- the
        // seventeen bytes a record with no block carries as zeros.
        expected.push(0);
        expected.extend_from_slice(&[0u8; 8]);
        expected.extend_from_slice(&[0u8; 8]);
        // record 2: derived, the fixture tag, account_index 1 + 28 zeros, a
        // zero first-key field, and the stream reached from the fixture seed
        expected.extend_from_slice(&DERIVED_TAG);
        expected.push(0);
        expected.extend_from_slice(&1u32.to_le_bytes());
        expected.extend_from_slice(&[0u8; 28]);
        expected.extend_from_slice(&[0u8; FIRST_KEY_LEN]);
        // Spelled as `derive_wots_key(seed, 0).tag()` and NOT as
        // `stream_id(seed)`: routing both sides through the same wrapper is
        // one degree of freedom, and an injection that moved `stream_id`'s
        // rotation from 0 to 1 stayed green until this line was written
        // (two degrees of freedom; found by the harness written with it). The rotation is the thing
        // the identity's definition turns on, so the test states it.
        expected.extend_from_slice(&crate::derive::derive_wots_key(&Secret::new(DERIVED_SEED), 0).tag());
        expected.extend_from_slice(&0u32.to_le_bytes());
        expected.push(0);
        expected.extend_from_slice(&[0u8; 4]);
        expected.extend_from_slice(&[0u8; 32]);
        // Version 4's tail: figures flag 0, reserved_balance 0, blk_to_live 0 -- the
        // seventeen bytes a record with no block carries as zeros.
        expected.push(0);
        expected.extend_from_slice(&[0u8; 8]);
        expected.extend_from_slice(&[0u8; 8]);
        expected
    }

    pub(super) const TEST_SALT: [u8; crypt::SALT_LEN] = [0x5A; crypt::SALT_LEN];
    // No `TEST_NONCE_SEED` here: deriving the KAT's nonce through
    // `crypt::nonce_for` uses the same function the encoder calls, so the two
    // sides of the comparison move together. `KAT_NONCE` below is the literal
    // that keeps them apart.

    /// The key these tests encrypt under.
    ///
    /// Derived once and cached, because even at `CHEAP_FOR_TESTS` this is the
    /// most expensive thing the module does.
    ///
    /// **`CHEAP_FOR_TESTS`, and the reason is Miri, measured rather than
    /// guessed**. Miri interprets one Argon2 block compression in
    /// ~0.15 s. `Kdf::RECOMMENDED` is `m_cost_kib` 65536 at `t_cost` 3, so
    /// 196,608 compressions -- **about eight and a quarter hours of wall clock
    /// per derivation** (196,608 x 0.15 s = 29,491 s = 8.19 h), and this
    /// module performs two. A `cargo miri test` run was killed at 2h27m having
    /// produced no output, and this is where it was going -- nowhere near
    /// finishing. `keystore_harness::init` makes the same choice for the
    /// integration suite.
    ///
    /// Nothing is weakened: every assertion in this module reaches the image
    /// through `parse_with_key`, which takes the key directly and **never
    /// re-derives it from the header**. What the Miri run is for is preserved
    /// -- the same `argon2` and `chacha20poly1305` MIR is still interpreted,
    /// at a smaller trip count.
    ///
    /// **The residual, stated because it is a trap and not a nothing.**
    /// `seal_at` still passes `Kdf::RECOMMENDED` as the *header field*, so the
    /// KAT image now advertises 65536/3/1 in a header whose key was derived at
    /// 8/1/1. That is deliberate -- see `seal_at` -- and it is safe only while
    /// no test in this module derives a key from a header it just read. A test
    /// that did would silently get a different key. And Miri now walks Argon2
    /// at eight blocks and never at the shipped 65,536, so UB that only
    /// manifests above some block count is outside what a green run claims.
    fn test_key() -> &'static Zeroizing<[u8; crypt::KEY_LEN]> {
        use std::sync::OnceLock;
        static KEY: OnceLock<Zeroizing<[u8; crypt::KEY_LEN]>> = OnceLock::new();
        KEY.get_or_init(|| {
            crypt::derive_key(b"format-module-test-password", &TEST_SALT, Kdf::CHEAP_FOR_TESTS)
                .expect("derive")
        })
    }

    /// The KAT's nonce, a LITERAL.
    ///
    /// **Not `nonce_for(seed, generation)`**, and that is a repair rather than
    /// a simplification. Computing the nonce here with the same function the
    /// encoder calls moves the two sides of the comparison together: an
    /// injection replacing `nonce_for`'s hash with a bare generation counter
    /// leaves this KAT green. A literal has one degree of freedom, which is
    /// what a known-answer test is for.
    ///
    /// With a literal here the header is hand-assembled all the way through,
    /// and `nonce_for` is checked separately by
    /// `the_nonce_does_not_repeat_across_a_forked_store` — which asserts the
    /// property that actually matters and that a counter would break.
    const KAT_NONCE: [u8; crypt::NONCE_LEN] = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
    ];

    /// **`Kdf::RECOMMENDED` here is load-bearing and must NOT be cheapened**
    /// even though `test_key` was. It is the *header field*, not the
    /// cost of anything: `encode` takes the kdf and the key as separate
    /// arguments, so this costs nothing to leave at the shipped parameters.
    ///
    /// What depends on it is the `cheapened` row in
    /// `parser_refuses_each_malformation_with_the_right_variant`, which forges
    /// an in-bounds `m_cost` by writing `8u32` at bytes 11..15 and requires
    /// the result to reach the tag and fail as `WrongPassword`. If this were
    /// `CHEAP_FOR_TESTS` -- whose `m_cost_kib` IS 8 -- that write would land
    /// the bytes already there, the image would be unmodified, `parse_with_key`
    /// would succeed, and the row would fail while appearing to test a
    /// forgery. A vacuous negative control that still looks like one.
    fn seal_at(records: &[RecordRef<'_>], generation: u64) -> Zeroizing<Vec<u8>> {
        let nonce = KAT_NONCE;
        encode(
            records,
            generation,
            None,
            Kdf::RECOMMENDED,
            &TEST_SALT,
            test_key(),
            &nonce,
        )
        .expect("encode")
    }

    /// **The nonce does not repeat across a forked store**, which is the one
    /// way to break ChaCha20-Poly1305 with otherwise-correct code.
    ///
    /// Two copies of a store share a salt and therefore a key, and both
    /// advance from generation *N* with different contents. A restored backup
    /// is an ordinary thing to have, so a bare generation counter would reuse
    /// a nonce under one key — which leaks the XOR of the two bodies and hands
    /// over the Poly1305 key.
    ///
    /// This is the assertion the format KAT could not make: that one compares
    /// an image against a literal, and a nonce derived wrongly but
    /// *consistently* is invisible to it. Found by a fault-injection
    /// row, which turned the KDF's nonce into a counter and left
    /// the KAT green.
    #[test]
    fn the_nonce_does_not_repeat_across_a_forked_store() {
        let fork_a = [0x01u8; crypt::NONCE_SEED_LEN];
        let fork_b = [0x02u8; crypt::NONCE_SEED_LEN];
        // The fork: same generation, different opens.
        assert_ne!(
            crypt::nonce_for(&fork_a, 7),
            crypt::nonce_for(&fork_b, 7),
            "two opens of a forked store produced the SAME nonce at one generation. Under a \
             shared key that is keystream reuse -- the one way to break this AEAD with correct \
             code everywhere else. A bare generation counter does exactly this."
        );
        // Within one open the generation is what moves it.
        assert_ne!(
            crypt::nonce_for(&fork_a, 7),
            crypt::nonce_for(&fork_a, 8),
            "the nonce does not change with the generation"
        );
        // And it is a function, or nothing above is repeatable.
        assert_eq!(crypt::nonce_for(&fork_a, 7), crypt::nonce_for(&fork_a, 7));
    }

    // ---- Published vectors, as LITERALS, and where each literal is read back
    // from ----------------------------------------------------------------
    //
    // Every byte below is compared against the vendored standard's own text
    // by `published_vector_literals_match_the_vendored_rfc_text`, and each
    // vendored text is hashed against the value recorded when it was
    // fetched. The chain a reader can follow: a hash literal recorded at
    // fetch <-> the vendored bytes <-> the literal here (parsed back out of
    // its section) <-> this build's output (the two `*_matches_*` tests).
    // Four values, three comparisons, each with two independently written
    // sides. What no comparison here reaches is the first link
    // -- that the fetch WAS the publication -- which is a reader with curl
    // and shasum (`docs/standards/README.md`), and a fault-injection row
    // measured exactly that blindness.

    /// RFC 9106 §5.3, "Argon2id version number 19": the inputs.
    const RFC9106_PASSWORD: [u8; 32] = [0x01; 32];
    const RFC9106_SALT: [u8; 16] = [0x02; 16];
    const RFC9106_SECRET: [u8; 8] = [0x03; 8];
    const RFC9106_ASSOCIATED_DATA: [u8; 12] = [0x04; 12];
    /// "Memory: 32 KiB, Passes: 3, Parallelism: 4 lanes" -- in the roles the
    /// header's own struct gives them, so the vector runs through the same
    /// mapping a store does. Two of the four figures collide at 32 (memory
    /// and tag length), so the parameter-line needle in the provenance test
    /// pins the labelling of this const and nothing about the mapping; the
    /// m/t/p roles are pinned by the tag arithmetic (two fault-injection rows measured it).
    const RFC9106_KDF: Kdf = Kdf {
        m_cost_kib: 32,
        t_cost: 3,
        p_cost: 4,
    };
    /// RFC 9106 §5.3's recorded tag, thirty-two bytes. The one RFC 9106
    /// literal here that CAN be mistranscribed -- the four inputs are
    /// constant-fill arrays whose only degrees of freedom are the fill byte
    /// and a length the RFC's own label spells -- so it is the literal the
    /// provenance test actually protects.
    const RFC9106_TAG: [u8; 32] = [
        0x0d, 0x64, 0x0d, 0xf5, 0x8d, 0x78, 0x76, 0x6c, 0x08, 0xc0, 0x37, 0xa3, 0x4a, 0x8b, 0x53, 0xc9,
        0xd0, 0x1e, 0xf0, 0x45, 0x2d, 0x75, 0xb6, 0x5e, 0xb5, 0x25, 0x20, 0xe9, 0x6b, 0x01, 0xe6, 0x59,
    ];
    /// RFC 8439 §2.8.2: every value the AEAD anchor replays. The nonce is the
    /// RFC's "32-bit fixed-common part" followed by its "IV", and the
    /// provenance test reads the two halves back from their two labels, so
    /// the composition is stated rather than assumed.
    const RFC8439_KEY: [u8; 32] = [
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
    ];
    const RFC8439_NONCE: [u8; 12] = [
        0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    ];
    const RFC8439_AAD: [u8; 12] = [
        0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
    ];
    const RFC8439_PLAINTEXT: &[u8; 114] = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    const RFC8439_CIPHERTEXT: [u8; 114] = [
        0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2,
        0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6,
        0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
        0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29, 0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36,
        0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c, 0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58,
        0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
        0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
        0x61, 0x16,
    ];
    const RFC8439_TAG: [u8; 16] = [
        0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91,
    ];

    /// The standards, byte for byte as served (`docs/standards/README.md` has
    /// the URL, the date and the hash for each). `include_bytes!` and not
    /// `include_str!`, so the hash is over the file's bytes with no
    /// toolchain text handling in between -- RFC 9106 begins with a UTF-8
    /// byte-order mark that is part of what the hash pins. Compile-time
    /// inclusion also keeps the Miri run, which forbids the filesystem, able
    /// to interpret this module.
    const RFC9106_BYTES: &[u8] =
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/standards/rfc9106.txt"));
    const RFC8439_BYTES: &[u8] =
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/standards/rfc8439.txt"));
    const STANDARDS_README: &str =
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/standards/README.md"));
    /// `shasum -a 256` of each file as downloaded on 2026-09-06. The README
    /// carries the same two numbers as prose, and the provenance test
    /// requires them there: two statements of one value on purpose, so the
    /// copy a reader follows cannot drift from the asserted one.
    const RFC9106_SHA256: [u8; 32] = [
        0x85, 0x5c, 0x06, 0xf0, 0x60, 0x37, 0x9e, 0x34, 0x28, 0x5e, 0x83, 0xa2, 0x17, 0xe9, 0x06, 0x9b,
        0x5c, 0x72, 0xe1, 0x61, 0xa1, 0xe5, 0x4d, 0xf9, 0xaf, 0x5c, 0xd8, 0x8d, 0xbb, 0x23, 0x1f, 0x31,
    ];
    const RFC8439_SHA256: [u8; 32] = [
        0x25, 0xbe, 0xf7, 0x0f, 0xbf, 0x7a, 0x07, 0xff, 0x45, 0xc2, 0xfe, 0x4c, 0xb7, 0xc6, 0xce, 0x95,
        0x4e, 0xac, 0x68, 0x74, 0x13, 0xd8, 0x61, 0x06, 0x03, 0x26, 0x8b, 0x4e, 0x44, 0x15, 0x32, 0x4c,
    ];

    fn lower_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// The body of one numbered section of an RFC text: from its heading to
    /// the next heading named, both **at column zero**.
    ///
    /// Column zero is load-bearing and was found by running the extractor
    /// before writing it: every heading also appears, indented, in the table
    /// of contents, and a plain `find` returned the TOC entry -- thirty-one
    /// characters of nothing that the label lookups then failed on. Each
    /// heading must occur exactly once at column zero or the extractor
    /// refuses, so a heading that moves or duplicates is a red naming the
    /// heading rather than a different section read silently.
    fn rfc_section<'a>(text: &'a str, heading: &str, next_heading: &str) -> &'a str {
        let start = format!("\n{heading}\n");
        let end = format!("\n{next_heading}\n");
        assert_eq!(
            text.matches(&start).count(),
            1,
            "heading {heading:?} does not occur exactly once at column zero; the section \
             extractor would read the wrong span"
        );
        assert_eq!(
            text.matches(&end).count(),
            1,
            "heading {next_heading:?} does not occur exactly once at column zero; the section \
             extractor would read the wrong span"
        );
        let i = text.find(&start).expect("counted above");
        let j = text[i..].find(&end).expect("counted above") + i;
        &text[i..j]
    }

    /// The RFC's hex, wrapped across lines, as one space-separated string.
    /// `split_whitespace` also swallows RFC 8439's form feeds and the line
    /// breaks around its running page headers -- the headers themselves stay,
    /// harmlessly, because every needle below is anchored on a label.
    fn normalize_whitespace(s: &str) -> String {
        s.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    /// The bytes written between two labels in normalized RFC text. The
    /// labels are matched as substrings (RFC 9106's own labels contain
    /// spaces), each must occur exactly once in the section, and **every
    /// token between them must be exactly two hex digits** -- so a stray
    /// word, a wrapped label, or a byte too many or too few is a failure
    /// here rather than a near-miss somewhere else.
    fn hex_run_between(ws: &str, label: &str, next_label: &str) -> Vec<u8> {
        assert_eq!(ws.matches(label).count(), 1, "label {label:?} is not unique in the section");
        assert_eq!(
            ws.matches(next_label).count(),
            1,
            "label {next_label:?} is not unique in the section"
        );
        let i = ws.find(label).expect("counted") + label.len();
        let j = ws[i..].find(next_label).expect("counted") + i;
        hex_tokens(&ws[i..j], label)
    }

    /// As [`hex_run_between`], to the end of the section.
    fn hex_run_to_end(ws: &str, label: &str) -> Vec<u8> {
        assert_eq!(ws.matches(label).count(), 1, "label {label:?} is not unique in the section");
        let i = ws.find(label).expect("counted") + label.len();
        hex_tokens(&ws[i..], label)
    }

    fn hex_tokens(run: &str, label: &str) -> Vec<u8> {
        let bytes: Vec<u8> = run
            .split_whitespace()
            .map(|tok| {
                assert!(
                    tok.len() == 2 && tok.chars().all(|c| c.is_ascii_hexdigit()),
                    "after {label:?}: token {tok:?} is not two hex digits -- the run is not a \
                     bare hex dump, so the section or the label is wrong"
                );
                u8::from_str_radix(tok, 16).expect("two hex digits, checked")
            })
            .collect();
        assert!(!bytes.is_empty(), "after {label:?}: no hex at all");
        bytes
    }

    /// RFC 8439 writes its vectors as hexdump tables: `NNN` offset, up to
    /// sixteen bytes, an ASCII gutter. The rows a literal WOULD produce, the
    /// first carrying the table's label, so each can be required verbatim in
    /// the normalized section text. The gutter is not reproduced -- it
    /// follows the sixteenth byte and a needle ending at the byte is
    /// unaffected by it.
    fn hexdump_rows(label: &str, bytes: &[u8]) -> Vec<String> {
        bytes
            .chunks(16)
            .enumerate()
            .map(|(i, row)| {
                let hex: Vec<String> = row.iter().map(|b| format!("{b:02x}")).collect();
                let hex = hex.join(" ");
                if i == 0 {
                    format!("{label} 000 {hex}")
                } else {
                    format!("{:03} {hex}", i * 16)
                }
            })
            .collect()
    }

    /// **The KDF, against RFC 9106 §5.3** -- the Argon2id vector, a tag this
    /// project did not produce, reproduced through the wallet's own
    /// parameter mapping.
    ///
    /// `the_kdf_is_a_function_of_its_password_salt_and_parameters` below shows
    /// the KDF depends on its inputs; nothing about that says WHICH function
    /// it is. This does. `crypt::argon2id_v13` is the one straight-line path
    /// from a `Kdf` to the parameters Argon2 hashes with -- algorithm,
    /// version and the three roles named once, no branch -- and `derive_key`
    /// is that path called with an empty secret and no associated data. The
    /// RFC's vector, which carries both, runs through the same lines. A
    /// wrong role (`m` for `t`), a wrong version (0x10 for 0x13), a wrong
    /// algorithm (Argon2i), a secret or associated data silently dropped, or
    /// an `argon2 0.5.3` that disagreed with the RFC each give a different
    /// tag.
    ///
    /// What this does NOT pin: the parameter point a store is created at
    /// (`Kdf::RECOMMENDED`, 65536/3/1) -- the vector is at 32/3/4, and the
    /// value of the constant is the format KAT's claim (`expected_header`'s
    /// literals), not this test's. A fault-injection row showed the boundary.
    ///
    /// `hash_password_into_with_memory` takes neither a secret nor associated
    /// data, which is why the anchor reaches them through
    /// `Argon2::new_with_secret` and `ParamsBuilder::data` -- both in the
    /// pinned crate, ungated.
    ///
    /// **If this goes red, do not touch `RFC9106_TAG`.** It is compared to the
    /// vendored RFC text by `published_vector_literals_match_the_vendored_rfc_text`,
    /// so a transcription error reds there as well; a red here alone means
    /// the mapping or the crate disagrees with the standard. Changing the
    /// expectation to what this build produces would turn the anchor into a
    /// certificate the build signs for itself.
    #[test]
    fn argon2id_v13_matches_the_rfc9106_vector() {
        let mut out = [0u8; 32];
        crypt::argon2id_v13(
            RFC9106_KDF,
            &RFC9106_SECRET,
            &RFC9106_ASSOCIATED_DATA,
            &RFC9106_PASSWORD,
            &RFC9106_SALT,
            &mut out,
        )
        .expect("argon2id at RFC 9106's parameters");
        assert_eq!(
            out,
            RFC9106_TAG,
            "Argon2id disagrees with RFC 9106 §5.3's recorded tag at m=32 KiB, t=3, p=4, an \
             8-byte secret and 12 bytes of associated data. Three things can cause this and only \
             one is fixed by editing code: the literal was transcribed wrong (then \
             published_vector_literals_match_the_vendored_rfc_text is red too -- start there); \
             crypt::argon2id_v13's mapping from Kdf to Argon2's parameters, its algorithm or its \
             version is wrong (this red alone); or argon2 0.5.3 disagrees with the standard \
             (report it upstream). Do NOT edit RFC9106_TAG to match this build: an expectation \
             derived from the observed value certifies the observation, which this anchor exists \
             to prevent."
        );
        println!(
            "  KDF: RFC 9106 §5.3 Argon2id tag reproduced through crypt::argon2id_v13 (32 KiB, 3 \
             passes, 4 lanes, v0x13, secret and associated data driven)"
        );
    }

    /// `derive_key` agrees with the anchored function at one cheap parameter
    /// point, with an empty secret and no associated data.
    ///
    /// **This owns the call structure and nothing else.** `derive_key` calls
    /// `argon2id_v13`, so this is green by construction today and says so;
    /// what it guards is a `derive_key` given a route to Argon2 of its own --
    /// a copy-paste back of the old body, a merge -- at which point the RFC
    /// anchor stops saying anything about the wallet's entry point while
    /// staying green (a fault-injection row measured it). It compares `derive_key` to `argon2id_v13`
    /// at the same parameters, so it stays green when the mapping INSIDE
    /// `argon2id_v13` is wrong (measured too); `argon2id_v13_matches_the_rfc9106_vector`
    /// owns whether that mapping is right. And a faithful re-inline -- the
    /// same constructor, the same version, the same roles, written twice --
    /// leaves this green too (measured); the structural claim that the wallet has
    /// ONE route to Argon2 belongs to `invariants.rs`'s
    /// `the_wallet_has_one_route_to_argon2_and_it_is_the_anchored_one`.
    #[test]
    fn derive_key_agrees_with_the_anchored_argon2id_at_cheap_parameters() {
        let password = b"a password long enough to pass the floor";
        let mut direct = [0u8; crypt::KEY_LEN];
        crypt::argon2id_v13(Kdf::CHEAP_FOR_TESTS, &[], &[], password, &TEST_SALT, &mut direct)
            .expect("argon2id");
        let via = crypt::derive_key(password, &TEST_SALT, Kdf::CHEAP_FOR_TESTS).expect("derive");
        assert_eq!(
            *via,
            direct,
            "derive_key no longer routes through crypt::argon2id_v13, so the RFC 9106 anchor no \
             longer says anything about the wallet's entry point. This check owns ONLY that call \
             structure -- it compares derive_key to argon2id_v13 at the same parameters and stays \
             green if the mapping inside argon2id_v13 is wrong; \
             argon2id_v13_matches_the_rfc9106_vector owns whether that mapping is right."
        );
    }

    /// **The literals above are the standards' own text**, read back out of
    /// the vendored copies, and the vendored copies hash to what was recorded
    /// when they were fetched.
    ///
    /// The A2 audit's criticism of the AEAD anchor was exact: a published
    /// vector asserted with no on-disk copy is a citation to a document off
    /// disk, against the project's own sourcing rule. This is the on-disk
    /// copy, and this test is what makes it more than a copy: each file's
    /// SHA-256 is compared to the value recorded at fetch, then every
    /// replayed byte is parsed back out of its section with needles
    /// constructed from the literals (never written as strings).
    ///
    /// What it cannot see, stated: a vendored copy AND its hash literal AND
    /// the vector literal all edited together stay green here (a
    /// fault-injection row measured it). The `*_matches_*` tests are the arithmetic that still reds in
    /// that case, and the copy at rfc-editor.org is what a reader compares
    /// against; the hash assertion below establishes that the vendored copy
    /// has not moved since it was recorded, not that it is what the
    /// publisher serves.
    ///
    /// Within RFC 9106 §5, only the tag and the variant line tell the three
    /// vectors apart -- Argon2d, Argon2i and Argon2id share password, salt,
    /// secret and associated data byte for byte -- so the section is pinned
    /// to §5.3 explicitly before any byte is compared, and `RFC9106_TAG` is
    /// the literal this test actually protects.
    #[test]
    fn published_vector_literals_match_the_vendored_rfc_text() {
        // 1. The vendored files hash to what was recorded at fetch, and the
        //    README a reader follows carries the same two numbers.
        assert_eq!(
            crate::backend::native::sha256(RFC9106_BYTES),
            RFC9106_SHA256,
            "docs/standards/rfc9106.txt no longer hashes to the value recorded when it was \
             fetched (2026-09-06; docs/standards/README.md). That says the vendored copy moved, \
             NOT that it is or is not what rfc-editor.org serves -- this literal was typed from \
             the same fetch, so a wrong fetch is wrong on both sides and green here. Re-verify \
             by hand: curl -s https://www.rfc-editor.org/rfc/rfc9106.txt | shasum -a 256. Do \
             not update this literal to the file's new hash."
        );
        assert_eq!(
            crate::backend::native::sha256(RFC8439_BYTES),
            RFC8439_SHA256,
            "docs/standards/rfc8439.txt no longer hashes to the value recorded when it was \
             fetched (2026-09-06; docs/standards/README.md). The vendored copy moved; re-verify \
             against the publisher by hand and do not update this literal to the file's new \
             hash."
        );
        for (name, hash) in [("rfc9106", RFC9106_SHA256), ("rfc8439", RFC8439_SHA256)] {
            assert!(
                STANDARDS_README.contains(&lower_hex(&hash)),
                "docs/standards/README.md does not carry the {name} hash this test asserts; the \
                 copy a reader follows has drifted from the asserted one"
            );
        }
        let rfc9106 = core::str::from_utf8(RFC9106_BYTES).expect("vendored rfc9106.txt is UTF-8");
        let rfc8439 = core::str::from_utf8(RFC8439_BYTES).expect("vendored rfc8439.txt is UTF-8");

        // 2. RFC 9106 §5.3, pinned to §5.3 before any byte is read: the
        //    version, the parameters in their named roles, the four inputs
        //    and the tag.
        let ws = normalize_whitespace(rfc_section(
            rfc9106,
            "5.3.  Argon2id Test Vectors",
            "6.  IANA Considerations",
        ));
        let version = format!("Argon2id version number {}", u32::from(argon2::Version::V0x13));
        assert!(
            ws.contains(&version),
            "the extracted RFC 9106 section does not say {version:?}: either the section \
             extractor read the wrong span or the vector is not for the version this wallet \
             drives"
        );
        assert_eq!(
            ws.matches("version number").count(),
            1,
            "the extracted RFC 9106 section carries more than one vector; the span is wider than \
             §5.3 and the input comparisons below could pass on a neighbouring variant's bytes"
        );
        assert_eq!(
            ws.matches("Tag:").count(),
            1,
            "the extracted RFC 9106 section carries more than one tag; the span is wider than §5.3"
        );
        let params = format!(
            "Memory: {} KiB, Passes: {}, Parallelism: {} lanes, Tag length: {} bytes",
            RFC9106_KDF.m_cost_kib,
            RFC9106_KDF.t_cost,
            RFC9106_KDF.p_cost,
            RFC9106_TAG.len()
        );
        assert!(
            ws.contains(&params),
            "RFC 9106 §5.3 does not state the parameters as {params:?}; a field of RFC9106_KDF is \
             in the wrong role or has the wrong value"
        );
        assert_eq!(
            hex_run_between(&ws, "Password[32]:", "Salt[16]:"),
            RFC9106_PASSWORD,
            "RFC9106_PASSWORD is not the password RFC 9106 §5.3 records (transcription)"
        );
        assert_eq!(
            hex_run_between(&ws, "Salt[16]:", "Secret[8]:"),
            RFC9106_SALT,
            "RFC9106_SALT is not the salt RFC 9106 §5.3 records (transcription)"
        );
        assert_eq!(
            hex_run_between(&ws, "Secret[8]:", "Associated data[12]:"),
            RFC9106_SECRET,
            "RFC9106_SECRET is not the secret RFC 9106 §5.3 records (transcription)"
        );
        assert_eq!(
            hex_run_between(&ws, "Associated data[12]:", "Pre-hashing digest:"),
            RFC9106_ASSOCIATED_DATA,
            "RFC9106_ASSOCIATED_DATA is not the associated data RFC 9106 §5.3 records \
             (transcription)"
        );
        assert_eq!(
            hex_run_to_end(&ws, "Tag:"),
            RFC9106_TAG,
            "RFC9106_TAG is not the tag RFC 9106 §5.3 records -- a transcription error in the \
             literal, not a defect in the KDF; argon2id_v13_matches_the_rfc9106_vector will be \
             red for the same reason"
        );

        // 3. RFC 8439 §2.8.2: every replayed value, as the RFC's own hexdump
        //    rows; the tag as its colon-separated line; the nonce as the two
        //    labelled runs it is composed from.
        let ws = normalize_whitespace(rfc_section(
            rfc8439,
            "2.8.2.  Example and Test Vector for AEAD_CHACHA20_POLY1305",
            "3.  Implementation Advice",
        ));
        for (label, bytes) in [
            ("Plaintext:", &RFC8439_PLAINTEXT[..]),
            ("AAD:", &RFC8439_AAD[..]),
            ("Key:", &RFC8439_KEY[..]),
            ("Ciphertext:", &RFC8439_CIPHERTEXT[..]),
            ("32-bit fixed-common part:", &RFC8439_NONCE[..4]),
            ("IV:", &RFC8439_NONCE[4..]),
        ] {
            for row in hexdump_rows(label, bytes) {
                assert!(
                    ws.contains(&row),
                    "RFC 8439 §2.8.2's {label} table does not carry the row {row:?}; the RFC8439_* \
                     literal for it is not the RFC's (transcription), or the nonce is not \
                     fixed-common-part followed by IV"
                );
            }
        }
        assert_eq!(ws.matches("Tag:").count(), 1, "RFC 8439 §2.8.2 does not carry exactly one Tag:");
        let tag_line = ws[ws.find("Tag:").expect("counted") + "Tag:".len()..]
            .split_whitespace()
            .next()
            .expect("a token after Tag:");
        let tag: Vec<u8> = tag_line
            .split(':')
            .map(|tok| {
                assert!(
                    tok.len() == 2 && tok.chars().all(|c| c.is_ascii_hexdigit()),
                    "RFC 8439's tag line token {tok:?} is not two hex digits"
                );
                u8::from_str_radix(tok, 16).expect("two hex digits, checked")
            })
            .collect();
        assert_eq!(
            tag,
            RFC8439_TAG,
            "RFC8439_TAG is not the tag RFC 8439 §2.8.2 records -- a transcription error in the \
             literal, not a defect in the AEAD"
        );
        println!(
            "  provenance: both vendored RFC texts hash as recorded at fetch; RFC 9106 §5.3 and \
             RFC 8439 §2.8.2 each parsed back byte for byte against the literals replayed"
        );
    }

    /// **The AEAD, against RFC 8439 §2.8.2** -- a vector this project did not
    /// produce and cannot influence.
    ///
    /// The format KAT above proves the encoder and the decoder agree with each
    /// other. That is a round trip, and a round trip is blind to a primitive
    /// that is consistently wrong. The numbers here are a published
    /// standard's, so agreement is agreement with something outside this
    /// crate, this reference and this corpus -- a read literal against a
    /// vendored copy of the standard, which is the anchoring floor with its
    /// transcription weakness removed, not the executed second
    /// implementation the anchoring rule calls the standard.
    #[test]
    fn chacha20poly1305_matches_rfc8439() {
        let mut buf = RFC8439_PLAINTEXT.to_vec();
        let tag = crypt::seal(&RFC8439_KEY, &RFC8439_NONCE, &RFC8439_AAD, &mut buf).expect("seal");
        // RFC 8439 §2.8.2's recorded ciphertext -- all 114 bytes -- and
        // tag. Every input and both
        // outputs are read back out of the vendored RFC by
        // `published_vector_literals_match_the_vendored_rfc_text`.
        assert_eq!(
            buf.as_slice(),
            &RFC8439_CIPHERTEXT[..],
            "ChaCha20-Poly1305 disagrees with RFC 8439's recorded ciphertext"
        );
        assert_eq!(tag, RFC8439_TAG, "ChaCha20-Poly1305 disagrees with RFC 8439's recorded tag");
        // And it opens again, with the tag rejecting a flipped AAD byte --
        // which is what makes the header authenticated rather than merely
        // present.
        crypt::open(&RFC8439_KEY, &RFC8439_NONCE, &RFC8439_AAD, &mut buf, &tag).expect("open");
        let mut bad_aad = RFC8439_AAD;
        bad_aad[0] ^= 0x01;
        let mut sealed = RFC8439_PLAINTEXT.to_vec();
        let t2 = crypt::seal(&RFC8439_KEY, &RFC8439_NONCE, &RFC8439_AAD, &mut sealed).expect("seal");
        assert!(
            crypt::open(&RFC8439_KEY, &RFC8439_NONCE, &bad_aad, &mut sealed, &t2).is_err(),
            "a flipped AAD byte was accepted; the header is not authenticated"
        );
        println!("  AEAD: RFC 8439 §2.8.2 ciphertext and tag reproduced, AAD tamper refused");
    }

    /// **What this test owns: which inputs change the key. It does not own
    /// the identity of the function** -- `argon2id_v13_matches_the_rfc9106_vector`
    /// does, by replaying RFC 9106 §5.3's tag through `crypt::argon2id_v13`,
    /// the same path `derive_key` calls.
    ///
    /// `hash_password_into_with_memory` takes neither a secret nor associated
    /// data, which is why the anchor reaches them through
    /// `Argon2::new_with_secret` and `ParamsBuilder::data` instead.
    ///
    /// **The arms below are differences rather than values.** A hard-coded
    /// expectation for the no-secret case could only be taken from what the
    /// build produced, which is an expectation moved to fit an observation.
    /// Each arm fails on a plausible defect the round trip alone would miss:
    ///
    /// * a KDF that ignored the password -- every store would share a key;
    /// * a KDF that ignored the salt -- two stores under one password would
    ///   share a key, and the salt exists precisely to stop that;
    /// * a KDF that ignored its parameters -- raising `m_cost` later would buy
    ///   nothing while appearing to;
    /// * a KDF that was not a function -- unusable.
    ///
    /// The executed second implementation the anchoring rule calls the standard is
    /// **not owed** for this primitive, by decision: the
    /// hash-pinned published vector is the anchor class both keystore
    /// primitives share.
    #[test]
    fn the_kdf_is_a_function_of_its_password_salt_and_parameters() {
        let p1 = b"password one, long enough to pass";
        let p2 = b"password two, long enough to pass";
        let s1 = [0x11u8; crypt::SALT_LEN];
        let s2 = [0x22u8; crypt::SALT_LEN];
        // Cheap parameters: this test is about which inputs matter, not about
        // the cost of the shipped ones.
        let cheap = Kdf {
            m_cost_kib: 8,
            t_cost: 1,
            p_cost: 1,
        };
        let cheaper = Kdf {
            m_cost_kib: 16,
            t_cost: 1,
            p_cost: 1,
        };
        let k = |pw: &[u8], salt: &[u8; crypt::SALT_LEN], kdf: Kdf| {
            *crypt::derive_key(pw, salt, kdf).expect("derive")
        };
        assert_eq!(k(p1, &s1, cheap), k(p1, &s1, cheap), "the KDF is not a function");
        assert_ne!(k(p1, &s1, cheap), k(p2, &s1, cheap), "the KDF ignores the password");
        assert_ne!(k(p1, &s1, cheap), k(p1, &s2, cheap), "the KDF ignores the salt");
        assert_ne!(
            k(p1, &s1, cheap),
            k(p1, &s1, cheaper),
            "the KDF ignores its parameters, so raising m_cost would buy nothing"
        );
        // And the bound this build refuses before allocating.
        assert!(
            Kdf {
                m_cost_kib: crypt::MAX_M_COST_KIB + 1,
                t_cost: 1,
                p_cost: 1,
            }
            .checked()
            .is_err(),
            "an m_cost above the cap was accepted; a hostile file could name 64 GiB"
        );
        println!(
            "  KDF: password, salt and parameters each change the key; the function's identity \
             is argon2id_v13_matches_the_rfc9106_vector's claim, at 32 KiB/t=3/p=4 with a secret \
             and AD -- not at the shipped point"
        );
    }

    /// Not under Miri: its time is `two_accounts()`' four WOTS+ key generations
    /// plus four more inside the `parse_with_key` it checks the image with
    /// (1,515 s measured). The encode it compares byte for byte is the
    /// same `seal_at` call `good_image()` makes, which
    /// `an_older_format_reports_unsupported_version_before_anything_else` still
    /// pays for and interprets.
    #[cfg(not(miri))]
    #[test]
    fn known_answer_image_for_two_accounts() {
        let accts = two_accounts();
        let image = seal_at(&refs(&accts), 7);
        let nonce = KAT_NONCE;

        // 1. The header, hand-assembled and compared byte for byte. It is
        //    plaintext, so nothing about the AEAD weakened this.
        let expected_header = expected_header(&nonce);
        assert_eq!(expected_header.len(), HEADER_LEN);
        assert_eq!(&image[..HEADER_LEN], &expected_header[..], "the plaintext header");

        // 2. The length, still a closed formula of the record count.
        assert_eq!(image.len(), HEADER_LEN + BODY_HEADER_LEN + 2 * RECORD_LEN + TRAILER_LEN);
        assert_eq!(image.len(), 502, "51 header + (45 + 2*195) body + 16 tag");

        // 3. The body, hand-assembled and compared byte for byte -- through a
        //    decryption. This is the version-2 KAT, unchanged in what it
        //    checks and moved one step further in. Two degrees of freedom: the
        //    literal below and what the encoder built.
        let f = read_header(&image).expect("header");
        let mut plain: Zeroizing<Vec<u8>> = Zeroizing::new(f.ciphertext.to_vec());
        crypt::open(test_key(), &f.header.nonce, f.aad, &mut plain, f.tag).expect("decrypt");
        assert_eq!(&plain[..], &expected_body(7)[..], "the canonical plaintext body");

        // 4. And the ciphertext is NOT the plaintext, which is the whole point
        //    and is the arm that would have caught an encoder that forgot to
        //    call the AEAD at all.
        assert_ne!(&image[HEADER_LEN..HEADER_LEN + plain.len()], &plain[..]);

        let parsed = parse_with_key(&image, test_key()).expect("parse");
        assert_eq!(parsed.generation, 7);
        assert_eq!(parsed.slots.len(), 2);
        let mut roots = 0;
        for (tag, slot) in parsed.slots {
            match slot.account.to_record() {
                AccountRecord::Imported {
                    root,
                    first_key,
                    stream_id,
                    ..
                } => {
                    assert_eq!(tag, IMPORTED_TAG);
                    assert_eq!(root.expose(), &IMPORTED_ROOT);
                    assert_eq!(&first_key[..], &IMPORTED_ADDRESS[PK_LEN..]);
                    assert_eq!(stream_id.as_bytes(), &IMPORTED_STREAM);
                    roots += 1;
                }
                AccountRecord::Derived {
                    account_index,
                    stream_id,
                    ..
                } => {
                    assert_eq!(tag, DERIVED_TAG);
                    assert_eq!(account_index, 1);
                    assert_eq!(
                        stream_id.as_bytes(),
                        &crate::derive::derive_wots_key(&Secret::new(DERIVED_SEED), 0).tag()
                    );
                }
            }
        }
        assert_eq!(roots, 1);
    }

    /// A real version-1 `accounts.mks`, captured from the encoder at commit
    /// `2e3fbe0` -- the last commit before this format existed -- by creating
    /// a store and adding the two accounts the keystore harness seeded (an imported
    /// root `0xB7 * 32` under the unverified tag `0x1A * 20`, and
    /// `F-derive-account-1`). 242 bytes: `22 + 2*94 + 32`.
    ///
    /// It is here because the version-dispatch path has never been exercised
    /// against a file some other version actually wrote, and a hand-built
    /// "v1-shaped" buffer would only exercise this test's idea of v1.
    ///
    /// Embedded rather than transcribed, from the one copy in
    /// `crates/mochimo-crypto/testdata/` that `tests/keystore.rs` reads too --
    /// a captured input of our own, not oracle data (see that directory's
    /// README). A hex literal pasted twice is a literal that drifts once.
    const V1_SNAPSHOT: &[u8; 242] =
        include_bytes!("../../testdata/keystore_v1_snapshot.bin");

    /// A real version-2 `accounts.mks`, captured from the encoder at commit
    /// `8062c9a` -- the last commit whose encoder wrote v2 -- by creating a
    /// store and adding the harness's two group-F accounts
    /// (`testdata/README.md`). 410 bytes: `22 + 2*178 + 32`. The imported
    /// account sorts first, so bytes 22..42 are `IMPORTED_TAG` and byte 42
    /// is `1`. Embedded here and read by `tests/keystore.rs`, as the v1
    /// file is.
    const V2_SNAPSHOT: &[u8; 410] =
        include_bytes!("../../testdata/keystore_v2_snapshot.bin");

    /// The version-3 pin: 290 bytes at `Kdf::RECOMMENDED`,
    /// kept byte for byte as the v3 read-path oracle. Its header is read
    /// here; it is never decrypted under the
    /// interpreter (65536/3/1 is hours under Miri) -- the
    /// end-to-end open is `tests/keystore.rs`'s, `not(miri)`.
    const V3_SNAPSHOT: &[u8; 290] = include_bytes!("../../testdata/keystore_v3_snapshot.bin");

    /// A version-3 `accounts.mks` with a RESERVATION OPEN, captured at
    /// `Kdf::CHEAP_FOR_TESTS` by the encoder at `529017f` -- the last commit
    /// whose encoder wrote v3 -- from `Keystore::create`, `adopt_master`
    /// (`F-address-widths`' master, `00..1f`), `add(Account::derive(master,
    /// 0))` and `persist_advance(&tag, &[0xD1; 32])` under the harness's
    /// password, salt and nonce seed (`testdata/README.md`).
    /// 290 bytes: `51 + (45 + 178) + 16`, generation 3, index 1, a
    /// reservation at 0. Read here under the interpreter -- one Argon2 at
    /// 8/1/1 -- and by `tests/keystore.rs`, `tests/recon.rs` and
    /// `tests/cli.rs` through the public `open`. A derived record, so parsing
    /// it costs no WOTS+ generation.
    const V3_RESERVED_SNAPSHOT: &[u8; 290] =
        include_bytes!("../../testdata/keystore_v3_reserved_snapshot.bin");

    /// The key the captured v3 reservation was sealed under: the harness's
    /// password and salt at `CHEAP_FOR_TESTS`. Derived once and cached, as
    /// `test_key` is, so the two consumers below cost the interpreter one
    /// Argon2 rather than two.
    fn captured_key() -> &'static Zeroizing<[u8; crypt::KEY_LEN]> {
        use std::sync::OnceLock;
        static KEY: OnceLock<Zeroizing<[u8; crypt::KEY_LEN]>> = OnceLock::new();
        KEY.get_or_init(|| {
            crypt::derive_key(b"harness-password-not-for-real-use", &TEST_SALT, Kdf::CHEAP_FOR_TESTS)
                .expect("derive the captured file's key")
        })
    }

    /// A version this build does not read says **upgrade**, not damaged --
    /// and says it *before* anything else, which is the half a well-formed
    /// file cannot demonstrate on its own.
    ///
    /// # The migration decision for v2 -> v3: REFUSE, and it is derived
    ///
    /// The v2 change refused v1 -> v2 and derived the refusal rather than preferring
    /// it: the data an upgrade would need was not in the old file for either
    /// kind of record. v2 -> v3 looked different, and the
    /// difference is real -- a v2 store holds every record field a v3 store
    /// holds, so the ciphertext could in principle be written from it. **It is
    /// still refused, and for the same reason one version along.**
    ///
    /// A v3 body carries the **master seed**, and a v2 file does not have one.
    /// That is not a field an upgrade can compute: the seed is a function of a
    /// phrase the store has never held. So an in-place upgrade would produce a
    /// v3 file that opens under the new password and then refuses every
    /// command that needs a seed -- `Wallet::open` answering
    /// `NoMasterForDerivedAccount` for a store the program had just told the
    /// operator it had migrated. **The v1 refusal's derivation holding for a
    /// second transition**, not a fresh judgement.
    ///
    /// The secondary arguments point the same way and are secondary: nothing
    /// has shipped, so the population of v2 stores is one live wallet; and an
    /// upgrade path is code that runs once per store and is tested never.
    /// Migration is `create --from-phrase` into a fresh directory and then
    /// destroying the old one, which is the same answer v1 got and is the one
    /// the phrase exists for.
    #[test]
    fn an_older_format_reports_unsupported_version_before_anything_else() {
        // v1's OWN constants, written out. Spelling them with this module's
        // `HEADER_LEN` and `TRAILER_LEN` would describe v1 only for as long as
        // v1 and the current version agree about them, and a test describing
        // an old format through new constants breaks on every version bump
        // for no reason.
        const V1_HEADER_LEN: usize = 22; // magic 8 | version 2 | generation 8 | count 4
        const V1_RECORD_LEN: usize = 94;
        const V1_TRAILER_LEN: usize = 32; // sha3_256, before the AEAD tag replaced it
        assert_eq!(&V1_SNAPSHOT[..8], b"MCMKSTOR");
        assert_eq!(u16::from_le_bytes([V1_SNAPSHOT[8], V1_SNAPSHOT[9]]), 1);
        assert_eq!(
            V1_SNAPSHOT.len(),
            V1_HEADER_LEN + 2 * V1_RECORD_LEN + V1_TRAILER_LEN
        );

        // The first record's tag and kind are named with the version: v1's
        // imported account under the tag `0x1a * 20`,
        // whose kind byte at 42 is `1`.
        let v1_first = Some(([0x1a; ADDR_TAG_LEN], AccountKind::Imported));
        assert_eq!(
            parse_with_key(V1_SNAPSHOT, test_key()).err(),
            Some(Error::UnsupportedVersion {
                got: 1,
                supported: VERSION,
                first_account: v1_first,
            }),
            "a v1 file must report its version, not corruption"
        );

        // The load-bearing half: the same file with its last byte destroyed
        // still reports the version. Under v2 this proved the version was
        // dispatched before the HASH; under v3 it proves it is dispatched
        // before the KDF and the AEAD too -- which matters more, because
        // deriving a key first would make an operator holding an older wallet
        // wait seventy milliseconds of Argon2 to be told the wrong thing.
        let mut broken = *V1_SNAPSHOT;
        let last = broken.len() - 1;
        broken[last] ^= 0xff;
        assert_eq!(
            parse_with_key(&broken, test_key()).err(),
            Some(Error::UnsupportedVersion {
                got: 1,
                supported: VERSION,
                first_account: v1_first,
            }),
            "version must be dispatched BEFORE the body is authenticated"
        );

        // **And version 2, the one an operator actually holds**. `V2_SNAPSHOT`
        // is what the last encoder that wrote v2 produced for the harness's
        // two accounts, so this arm reads a genuine file rather than the v1
        // file with its version word overwritten. The
        // genuine file names its first account; the forged one -- a v1 body
        // under a v2 word, 242 bytes where a v2 image is 22 + n*178 + 32 --
        // names none, which is the length gate doing its job.
        assert_eq!(
            parse_with_key(V2_SNAPSHOT, test_key()).err(),
            Some(Error::UnsupportedVersion {
                got: 2,
                supported: VERSION,
                first_account: Some((IMPORTED_TAG, AccountKind::Imported)),
            }),
            "a version-2 store must be told to upgrade, not that it is damaged, and must name \
             its first account. It is refused rather than migrated because a v2 file holds no \
             master seed and an upgrade cannot compute one -- see this test's note."
        );
        let mut v2 = *V1_SNAPSHOT;
        v2[8..10].copy_from_slice(&2u16.to_le_bytes());
        assert_eq!(
            parse_with_key(&v2, test_key()).err(),
            Some(Error::UnsupportedVersion {
                got: 2,
                supported: VERSION,
                first_account: None,
            }),
            "a v1 body under a v2 version word fits no v2 layout and must name no account"
        );

        // The controls: with the version word forged to either version this
        // build READS, the same bytes are refused for some other reason --
        // never as `UnsupportedVersion` naming that version. Without this,
        // the arms above are satisfied by a parser that refuses everything.
        // Both arms today reach the KDF-id refusal: byte 10 of the v1
        // capture is its generation, 2, which is not a KDF id this build has
        // (the negative match was re-pointed from a literal `got: 3` that did
        // not track the constant).
        let mut forged = broken;
        forged[8..10].copy_from_slice(&VERSION.to_le_bytes());
        let err = parse_with_key(&forged, test_key()).err();
        assert!(
            !matches!(err, Some(Error::UnsupportedVersion { got, .. }) if got == VERSION) && err.is_some(),
            "a v1 body under the current version word was refused as UnsupportedVersion naming \
             {VERSION}: the parser calls the version it writes unsupported: {err:?}"
        );
        let mut forged3 = broken;
        forged3[8..10].copy_from_slice(&V3_VERSION.to_le_bytes());
        let err3 = parse_with_key(&forged3, test_key()).err();
        assert!(
            !matches!(err3, Some(Error::UnsupportedVersion { got, .. }) if got == V3_VERSION) && err3.is_some(),
            "a v1 body under a version-3 word was refused as UnsupportedVersion naming 3: the \
             version-3 read arm is gone: {err3:?}"
        );

        // A version-4 image under a forged version-3 word is refused by the
        // TAG, not read as version 3: the version word is inside the AAD, so
        // a downgrade of the word alone cannot make a v4 body parse under the
        // narrower width.
        let mut downgraded = good_image().to_vec();
        downgraded[8..10].copy_from_slice(&V3_VERSION.to_le_bytes());
        assert_eq!(
            parse_with_key(&downgraded, test_key()).err(),
            Some(Error::WrongPassword),
            "a version-4 image under a forged version-3 word was not refused by the tag; the \
             version word is part of the AAD and a downgrade must fail there"
        );

        // The version-3 pin's header is accepted -- nothing decrypted here.
        let framed = read_header(V3_SNAPSHOT).expect("the version-3 pin's header is read");
        assert_eq!(framed.version, V3_VERSION, "the pinned image is not version 3");
        assert_eq!(framed.header.kdf, Kdf::RECOMMENDED, "the pin advertises the shipped parameter point");

        // **The captured version-3 reservation reads with its figures ABSENT**:
        // the same key derivation, the same AEAD, a 178-byte
        // record, `pending == 1` parsing to `figures: None` and no settled
        // block -- the state the migration exists to carry without inventing
        // a balance the store never observed.
        let parsed = parse_with_key(V3_RESERVED_SNAPSHOT, captured_key())
            .expect("the captured version-3 reservation no longer parses: the v3 read arm moved");
        assert_eq!(parsed.generation, 3, "create, adopt, add, reserve: three commits after the empty image");
        assert_eq!(parsed.slots.len(), 1);
        let slot = parsed
            .slots
            .get(&IMPORTED_TAG)
            .expect("the capture's one account is F-address-widths' master at index 0, tag 05ff..");
        assert_eq!(slot.account.kind(), AccountKind::Derived);
        assert_eq!(slot.account.wots_index().get(), 1, "the reservation advanced the index to 1");
        assert_eq!(
            slot.pending,
            Some(Pending {
                spent_index: WotsIndex::from_raw(0),
                digest: [0xD1; 32],
                figures: None,
            }),
            "a version-3 reservation must read back with figures: None -- declared absent, not zero"
        );
        assert_eq!(slot.settled, None, "a version-3 record has no settled block to read");
        println!(
            "  version dispatch: v1 and v2 report upgrade before the KDF runs; forged words {VERSION} and \
             {V3_VERSION} over a v1 body are refused as {err:?} / {err3:?}; a v4 image under a v3 word \
             fails the tag; the v3 pin's header and the v3 reservation capture (figures: None) both read"
        );
    }

    /// The canonical image at generation 1, built once.
    ///
    /// Not a micro-optimisation: `two_accounts()` runs four WOTS+ generations
    /// (`Account::import` and `Account::derive`, two each), and this module is
    /// interpreted under Miri, where one costs about three minutes on this
    /// machine.
    /// Building it twice bought nothing — the KAT above already
    /// asserts what `encode` produces — so it is built once and the
    /// malformation rows mutate copies. No claim moves: every row below still
    /// starts from a full `encode` of the same two accounts.
    fn good_image() -> &'static [u8] {
        static IMAGE: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
        IMAGE.get_or_init(|| {
            let accts = two_accounts();
            seal_at(&refs(&accts), 1).to_vec()
        })
    }

    /// **The malformation table, re-derived around the AEAD**, and
    /// the re-derivation found something an operator will meet.
    ///
    /// # What collapsed, and what it costs
    ///
    /// Under version 2 every row here mutated the image, recomputed the sha3
    /// trailer, and got back the `Corrupt` variant naming the field it had
    /// broken. Under version 3 that is two different questions with two
    /// different answers, and the first one **erases the second**:
    ///
    /// * a change nobody authenticated -- a flipped bit, a truncated file, a
    ///   forged header field, a wrong password -- is refused by the tag,
    ///   before a single record byte is read, as
    ///   [`Error::WrongPassword`]. **One answer for all of them, deliberately**
    ///   (see `crypt::open`): an error that distinguished a damaged file from
    ///   a wrong password would tell an attacker which of his guesses was
    ///   closer.
    /// * a change a legitimate writer could have made -- the plaintext edited
    ///   and sealed again -- still reaches the canonicality checks and still
    ///   gets the variant naming the field.
    ///
    /// **The cost is real and belongs to the operator, not to this test.**
    /// Version 2 told somebody with a bit-rotted store that their file was
    /// damaged. Version 3 tells them the password might be wrong, and they
    /// will retype it several times before they consider the alternative. That
    /// is the price of not building a decryption oracle, and it is the right
    /// trade, but it is a price. What would fix it is a decision about the
    /// CLI's wording, not a change to this table.
    #[test]
    fn parser_refuses_each_malformation_with_the_right_variant() {
        let good = good_image();

        // --- Group A: what the AEAD refuses, and it is all one answer ------
        //
        // Each of these is a file no legitimate writer produced. Under v2 they
        // were four different `Corrupt` variants; they are one variant now,
        // and the rows are kept separate so the collapse is visible rather
        // than inferred from a shorter table.
        type Edit = Box<dyn Fn(&mut Vec<u8>)>;
        let unauthenticated: [(&str, Edit); 4] = [
            ("a flipped byte inside a record", Box::new(|v: &mut Vec<u8>| v[HEADER_LEN + 5] ^= 1) as Edit),
            ("a flipped byte in the tag", Box::new(|v: &mut Vec<u8>| { let n = v.len() - 1; v[n] ^= 1 })),
            // Salt at 8+2+1+4+4+4 = 23, nonce at 39. Both are inside the
            // AAD, so forging either changes the key or the nonce and the tag
            // fails -- which is what makes the header authenticated.
            ("a forged salt in the header", Box::new(|v: &mut Vec<u8>| v[23] ^= 0xff)),
            ("a forged nonce in the header", Box::new(|v: &mut Vec<u8>| v[HEADER_LEN - 1] ^= 0xff)),
        ];
        for (what, edit) in unauthenticated {
            let mut bad = good.to_vec();
            edit(&mut bad);
            assert_eq!(
                parse_with_key(&bad, test_key()).err(),
                Some(Error::WrongPassword),
                "{what}: an unauthenticated change must be refused by the tag, as one answer"
            );
        }
        // **A forged KDF PARAMETER is refused earlier and more precisely, and
        // that corrects what this session first wrote.** `Kdf::checked` bounds
        // `m_cost` before anything allocates or derives, so an out-of-range
        // value never reaches the AEAD at all -- it is `Range`, naming the
        // field. Only an in-BOUNDS forgery reaches the tag. The distinction
        // matters because the first version of `Kdf`'s note said flatly that
        // altering the parameters "derives a different key and the tag fails";
        // that is true of the in-bounds case and wrong about the one an
        // attacker would actually try, which is to drive the cost to nothing.
        let mut absurd = good.to_vec();
        absurd[11..15].copy_from_slice(&(crypt::MAX_M_COST_KIB + 1).to_le_bytes());
        assert!(
            matches!(parse_with_key(&absurd, test_key()), Err(Error::Range { what: "keystore kdf m_cost", .. })),
            "an m_cost above the cap must be refused before anything allocates, by name"
        );
        let mut cheapened = good.to_vec();
        cheapened[11..15].copy_from_slice(&8u32.to_le_bytes());
        assert_eq!(
            parse_with_key(&cheapened, test_key()).err(),
            Some(Error::WrongPassword),
            "an in-bounds forged m_cost must reach the tag and fail there"
        );

        // And the same answer for the right file under the wrong key, which is
        // what makes the rows above indistinguishable from a typo.
        // `CHEAP_FOR_TESTS` and NOT `RECOMMENDED`, and it must stay pinned to
        // whatever `test_key` uses. This row exists to show that a different
        // PASSWORD produces a key that fails the tag; if the parameters
        // differed too, the row would no longer isolate the password as the
        // cause. The two move together or the row stops meaning what it says.
        let other = crypt::derive_key(
            b"a different password entirely",
            &TEST_SALT,
            Kdf::CHEAP_FOR_TESTS,
        )
        .expect("derive");
        assert_eq!(
            parse_with_key(good, &other).err(),
            Some(Error::WrongPassword),
            "the wrong key must give the same answer as a damaged file"
        );

        // --- Group B: what canonicality refuses, reached by re-sealing -----
        //
        // These are files a writer with the key could have produced, so the
        // AEAD passes them and the parser's own rules are what refuse.

        // pending == 1 but spent_index does not precede wots_index by one
        let bad_pending = reseal(good, |p| p[BODY_HEADER_LEN + PENDING_FLAG_OFF] = 1);
        assert!(matches!(
            parse_with_key(&bad_pending, test_key()),
            Err(Error::Corrupt { what: "pending index does not precede wots_index by one", .. })
        ));

        // duplicate tag: copy record 1's tag over record 2's
        let dup = reseal(good, |p| {
            p.copy_within(BODY_HEADER_LEN..BODY_HEADER_LEN + ADDR_TAG_LEN, BODY_HEADER_LEN + RECORD_LEN)
        });
        assert!(matches!(
            parse_with_key(&dup, test_key()),
            Err(Error::Corrupt { what: "records not strictly ascending by tag", .. })
        ));

        // a derived record whose first-key field is not zero
        let dirty = reseal(good, |p| p[BODY_HEADER_LEN + RECORD_LEN + FIRST_OFF] = 1);
        assert!(matches!(
            parse_with_key(&dirty, test_key()),
            Err(Error::Corrupt { what: "derived first-key field not zero", .. })
        ));

        // Version 3's own canonicality rule: the master-seed flag is 0 and the
        // bytes are not. One state, one image -- the same discipline the
        // derived padding and the absent pending fields already carry.
        let dirty_master = reseal(good, |p| p[8 + 4 + 1] = 0xff);
        assert!(matches!(
            parse_with_key(&dirty_master, test_key()),
            Err(Error::Corrupt { what: "master seed present flag is 0 with non-zero bytes", .. })
        ));
        let bad_flag = reseal(good, |p| p[8 + 4] = 2);
        assert!(matches!(
            parse_with_key(&bad_flag, test_key()),
            Err(Error::Corrupt { what: "master seed present flag is not 0 or 1", .. })
        ));

        // --- Version 4's rows: the state byte's domain, the settled
        // relation, the figures flag's domain and zero rule, and the state-0
        // zero rule over the seventeen new bytes. Record 1 sits at
        // wots_index 0, so a row that wants to reach a check past the relation
        // moves the index to 1 first.
        let bad_state = reseal(good, |p| p[BODY_HEADER_LEN + PENDING_FLAG_OFF] = 3);
        assert!(
            matches!(parse_with_key(&bad_state, test_key()), Err(Error::Corrupt { what: "pending flag", .. })),
            "bad_state: a pending byte of 3 was not refused as an unknown state"
        );
        let settled_relation = reseal(good, |p| p[BODY_HEADER_LEN + PENDING_FLAG_OFF] = 2);
        assert!(
            matches!(
                parse_with_key(&settled_relation, test_key()),
                Err(Error::Corrupt { what: "pending index does not precede wots_index by one", .. })
            ),
            "settled_relation: a settled block whose spent_index does not precede wots_index by one \
             was not refused -- the relation must hold in BOTH occupied states"
        );
        let bad_figures = reseal(good, |p| {
            p[BODY_HEADER_LEN + WOTS_INDEX_OFF] = 1;
            p[BODY_HEADER_LEN + PENDING_FLAG_OFF] = 1;
            p[BODY_HEADER_LEN + FIGURES_FLAG_OFF] = 2;
        });
        assert!(
            matches!(parse_with_key(&bad_figures, test_key()), Err(Error::Corrupt { what: "figures flag", .. })),
            "bad_figures: a figures byte of 2 was not refused"
        );
        let zero_flag_balance = reseal(good, |p| {
            p[BODY_HEADER_LEN + WOTS_INDEX_OFF] = 1;
            p[BODY_HEADER_LEN + PENDING_FLAG_OFF] = 1;
            p[BODY_HEADER_LEN + RESERVED_BALANCE_OFF] = 7;
        });
        assert!(
            matches!(
                parse_with_key(&zero_flag_balance, test_key()),
                Err(Error::Corrupt { what: "figures not zero while figures == 0", .. })
            ),
            "figures_zero_dirty: a reserved balance under figures == 0 was not refused"
        );
        let zero_flag_btl = reseal(good, |p| {
            p[BODY_HEADER_LEN + WOTS_INDEX_OFF] = 1;
            p[BODY_HEADER_LEN + PENDING_FLAG_OFF] = 1;
            p[BODY_HEADER_LEN + BTL_OFF] = 7;
        });
        assert!(
            matches!(
                parse_with_key(&zero_flag_btl, test_key()),
                Err(Error::Corrupt { what: "figures not zero while figures == 0", .. })
            ),
            "figures_zero_dirty: a block-to-live under figures == 0 was not refused"
        );
        let figures_without_block = reseal(good, |p| p[BODY_HEADER_LEN + FIGURES_FLAG_OFF] = 1);
        assert!(
            matches!(
                parse_with_key(&figures_without_block, test_key()),
                Err(Error::Corrupt { what: "pending fields not zero while pending == 0", .. })
            ),
            "figures_without_block: a figures flag under pending == 0 was not refused by the \
             state-0 zero rule"
        );
        // The version-3 read arm's own domain: a v3 writer never wrote state 2
        // and the v3 parser refused it, so the read arm does too. Reached by
        // re-sealing the captured v3 reservation under its own key.
        let v3_state_2 = reseal_with(captured_key(), V3_RESERVED_SNAPSHOT, |p| {
            p[BODY_HEADER_LEN + PENDING_FLAG_OFF] = 2
        });
        assert!(
            matches!(parse_with_key(&v3_state_2, captured_key()), Err(Error::Corrupt { what: "pending flag", .. })),
            "a version-3 image never carries pending state 2, and the v3 read arm accepted one"
        );

        // --- Group C: every prefix, and one byte too many ------------------
        //
        // Unchanged in intent and it is what makes the no-indexing rule
        // falsifiable. A truncated file cannot authenticate, so
        // most of these are the AEAD's -- the point is that none of them
        // panics.
        for n in 0..good.len() {
            assert!(parse_with_key(&good[..n], test_key()).is_err(), "prefix {n} parsed");
        }
        let mut longer = good.to_vec();
        longer.push(0);
        assert!(parse_with_key(&longer, test_key()).is_err());

        // The control: the untouched image still parses, so none of the above
        // is satisfied by a parser that refuses everything.
        assert!(parse_with_key(good, test_key()).is_ok(), "the good image stopped parsing");
        println!(
            "  malformations: 5 refused by the tag as one answer, 12 by canonicality (5 older, 7 \
             added with version 4 -- one of them the version-3 arm's), {} prefixes",
            good.len()
        );
    }

    /// Field offsets inside one record, derived from the layout above rather
    /// than typed as numbers, so a field that moves moves these with it. The
    /// version-4 offsets extend the same chain; `BTL_OFF + 8` is the record.
    const FIRST_OFF: usize = ADDR_TAG_LEN + 1 + 32;
    const STREAM_OFF: usize = FIRST_OFF + FIRST_KEY_LEN;
    const WOTS_INDEX_OFF: usize = STREAM_OFF + ADDR_TAG_LEN;
    const PENDING_FLAG_OFF: usize = WOTS_INDEX_OFF + 4;
    const SPENT_OFF: usize = PENDING_FLAG_OFF + 1;
    const DIGEST_OFF: usize = SPENT_OFF + 4;
    const FIGURES_FLAG_OFF: usize = DIGEST_OFF + 32;
    const RESERVED_BALANCE_OFF: usize = FIGURES_FLAG_OFF + 1;
    const BTL_OFF: usize = RESERVED_BALANCE_OFF + 8;

    /// Decrypt an image, hand its PLAINTEXT to `edit`, and re-seal it.
    ///
    /// **This replaced `recompute_trailer`, and the difference is the whole
    /// shape of the malformation table.** Under version 2 a row mutated the
    /// image and recomputed the hash, so the parser then met a well-formed
    /// file with one field wrong and answered with the variant for that field.
    /// Under version 3 a mutation the writer did not authenticate is refused
    /// by the AEAD before any field is read -- so a row that wants to reach a
    /// canonicality check has to produce a file a legitimate writer could have
    /// produced, which means editing the plaintext and sealing it again.
    ///
    /// Rows that do NOT re-seal are still rows; they just test the AEAD
    /// instead, and they all get the same answer. See the table.
    fn reseal(image: &[u8], edit: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
        reseal_with(test_key(), image, edit)
    }

    /// [`reseal`] under a caller's key -- the captured version-3 file's,
    /// for the one row that reaches the v3 arm's own domain.
    fn reseal_with(key: &[u8; crypt::KEY_LEN], image: &[u8], edit: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
        let f = read_header(image).expect("header");
        let aad = f.aad.to_vec();
        let mut plain: Zeroizing<Vec<u8>> = Zeroizing::new(f.ciphertext.to_vec());
        crypt::open(key, &f.header.nonce, &aad, &mut plain, f.tag).expect("decrypt");
        let mut edited = plain.to_vec();
        edit(&mut edited);
        let new_tag = crypt::seal(key, &f.header.nonce, &aad, &mut edited).expect("seal");
        let mut out = aad;
        out.extend_from_slice(&edited);
        out.extend_from_slice(&new_tag);
        out
    }

    /// **`MAX_IMAGE_LEN` is the cap's own image, and one record more is
    /// refused** -- the boundary test the audit said the fix owed, made on
    /// the length functions and the gate rather than by building the 11.6 MB
    /// image.
    ///
    /// Four arms, and what each would miss without the others:
    ///
    /// * `image_len(MAX_ACCOUNTS) == MAX_IMAGE_LEN` -- the constant is a
    ///   hand-written sum and `image_len` a formula, two degrees of freedom.
    ///   This is the arm a missing `BODY_HEADER_LEN` fails, and the only one
    ///   that can: `45/178 < 1` puts the smallest failing count AT the cap,
    ///   so no store below it shows the fault.
    /// * `image_len(MAX_ACCOUNTS + 1) > MAX_IMAGE_LEN` -- the cap means *one
    ///   record more is refused*. Redundant with the equality today, on
    ///   purpose: it is the arm that survives if someone later "simplifies"
    ///   `MAX_IMAGE_LEN` into `image_len(MAX_ACCOUNTS)` and turns the equality
    ///   into a tautology.
    /// * `read_header` admits a buffer of exactly `MAX_IMAGE_LEN` bytes past
    ///   its length gate -- it then fails at the magic, which is the evidence
    ///   it got past -- and refuses `MAX_IMAGE_LEN + 1` as `Range` naming both
    ///   bounds. The gate's own polarity, which the arithmetic arms cannot
    ///   see. Two zeroed allocations of 11.6 MB, of which eight bytes are read
    ///   (the magic) and none: not an image, and not the 65,536-record round trip
    ///   the audit named,
    ///   which only this module could build (`encode` is crate-private and
    ///   the public route is 65,536 fsynced commits) and which Miri would
    ///   interpret for hours.
    /// * `image_len(0) == MIN_IMAGE_LEN` -- the other end of the same range,
    ///   where the same 45 bytes were missing from the `Range` the gate
    ///   reports.
    ///
    /// What this does NOT reach, stated: `encode`'s refusal of 65,537 records
    /// and `parse_with_key`'s refusal of `count > MAX_ACCOUNTS` are one
    /// comparison each against `MAX_ACCOUNTS`, and neither is driven; the cap
    /// round trip that would drive both is the thing declined above.
    #[test]
    fn max_image_len_is_the_cap_image_and_one_record_more_is_refused() {
        assert_eq!(
            image_len(MAX_ACCOUNTS),
            Some(MAX_IMAGE_LEN),
            "MAX_IMAGE_LEN is not image_len(MAX_ACCOUNTS): a store at the account cap encodes \
             and is then refused on read by the length gate. This is the defect the audit \
             found -- the constant and the formula disagree, by BODY_HEADER_LEN \
             ({BODY_HEADER_LEN}) when the body header is what was forgotten -- and nothing \
             below the cap can show it"
        );
        let one_more =
            image_len(MAX_ACCOUNTS + 1).expect("one record past the cap does not overflow usize");
        assert!(
            one_more > MAX_IMAGE_LEN,
            "one record more than the cap ({one_more} bytes) is admitted by MAX_IMAGE_LEN \
             ({MAX_IMAGE_LEN}); the cap no longer means one record more is refused"
        );
        assert_eq!(
            image_len(0),
            Some(MIN_IMAGE_LEN),
            "MIN_IMAGE_LEN is not image_len(0): the Range read_header reports names a minimum \
             no version-3 writer produces"
        );
        // The gate itself. Zeroed buffers, not images: the arms above pin the
        // constant, this pins the comparison that reads it.
        let at_cap = vec![0u8; MAX_IMAGE_LEN];
        let verdict = read_header(&at_cap).err();
        assert!(
            matches!(verdict, Some(Error::Corrupt { what: "magic", offset: 0 })),
            "a buffer of exactly MAX_IMAGE_LEN bytes did not get past read_header's length gate \
             to the magic check: {verdict:?}. The gate refuses the cap's own image"
        );
        let over = vec![0u8; MAX_IMAGE_LEN + 1];
        let verdict = read_header(&over).err();
        assert!(
            matches!(
                verdict,
                Some(Error::Range { what: "keystore image length", min, max, got })
                    if got == (MAX_IMAGE_LEN + 1) as u64
                        && min == MIN_IMAGE_LEN as u64
                        && max == MAX_IMAGE_LEN as u64
            ),
            "a buffer one byte over MAX_IMAGE_LEN was not refused by the length gate as Range \
             naming both bounds: {verdict:?}"
        );
        println!(
            "  image cap: image_len({MAX_ACCOUNTS}) == MAX_IMAGE_LEN == {MAX_IMAGE_LEN}; one \
             record more is {one_more} and refused; the gate admits exactly the cap; \
             image_len(0) == MIN_IMAGE_LEN == {MIN_IMAGE_LEN}"
        );
    }

    /// **`encode` refuses the pending relation `parse_with_key` refuses**, so
    /// the encoder can no longer emit an image its own parser calls corrupt
    /// (the gap was reported before it was closed), and
    /// since version 4 in both occupied states, with the figures carried and the
    /// migrated shape kept absent.
    ///
    /// Arms, each with two degrees of freedom. A reservation built the way
    /// `persist_advance` builds one (`spent_index + 1 == wots_index`, the
    /// figures recorded) is sealed and comes back through the parser with
    /// every field intact -- the first time the encoder's occupied arm runs
    /// in this module, the KAT's two records carrying none. The migrated
    /// shape (`figures: None`) comes back `None`, not `Some(0, 0)`: an
    /// encoder that wrote the flag as 1 over zeros would fabricate a recorded
    /// zero balance, which is the fabrication the migration refuses. A SETTLED block
    /// round-trips as settled, with its figures, and no open reservation
    /// beside it. Four inconsistent relations, in each occupied state,
    /// including the one whose `+ 1` overflows, are refused before anything
    /// is sealed, as `Corrupt` under the parser's own `what`, so the two
    /// sides name one rule. The parser's side stays independently held by
    /// `parser_refuses_each_malformation_with_the_right_variant`, whose
    /// `bad_pending` and `settled_relation` rows reach it by re-sealing an
    /// edited plaintext AROUND this function; deleting either check reds
    /// exactly one test.
    /// Not under Miri: its time is a second `two_accounts()` and the parses it
    /// checks against -- 1,906 s measured, the most expensive test in
    /// this module. Both refusals are reached before a byte is written, and the
    /// encoder they guard is interpreted through `good_image()` on the ungated
    /// side.
    #[cfg(not(miri))]
    #[test]
    fn encode_refuses_the_pending_relation_the_parser_refuses() {
        let accts = two_accounts();
        let (tag, account, _) = &accts[0];
        let digest = [0xD1u8; 32];
        let figures = Figures {
            reserved_balance: 5_000_000,
            blk_to_live: 4_242,
        };
        let at_zero = |figures: Option<Figures>| Pending {
            spent_index: WotsIndex::from_raw(0),
            digest,
            figures,
        };

        // 1. An open reservation with its figures, as persist_advance builds one.
        let consistent = [RecordRef {
            tag: *tag,
            account,
            wots_index: WotsIndex::from_raw(1),
            pending: Some(at_zero(Some(figures))),
            settled: None,
        }];
        let image = seal_at(&consistent, 3);
        let parsed = parse_with_key(&image, test_key()).expect(
            "encode or parse refused a reservation built as persist_advance builds one \
             (spent_index 0 under wots_index 1, figures recorded)",
        );
        let slot = parsed
            .slots
            .get(tag)
            .expect("the record is in the parsed state");
        assert_eq!(
            slot.account.wots_index().get(),
            1,
            "wots_index did not round-trip beside a reservation"
        );
        assert_eq!(
            slot.pending,
            Some(at_zero(Some(figures))),
            "the reservation, figures included, did not round-trip through encode and parse"
        );
        assert_eq!(slot.settled, None, "an open reservation came back with a settled block beside it");

        // 2. The migrated shape: figures absent stays absent.
        let migrated = [RecordRef {
            tag: *tag,
            account,
            wots_index: WotsIndex::from_raw(1),
            pending: Some(at_zero(None)),
            settled: None,
        }];
        let parsed = parse_with_key(&seal_at(&migrated, 4), test_key()).expect("the migrated shape seals and parses");
        assert_eq!(
            parsed.slots.get(tag).expect("in the parsed state").pending,
            Some(at_zero(None)),
            "figures: None did not round-trip as None. An encoder that writes the flag as 1 over \
             zeros fabricates a recorded zero balance for a migrated reservation, which the \
             declared-absent state exists to avoid"
        );

        // 3. The settled block, retained with its figures.
        let settled = [RecordRef {
            tag: *tag,
            account,
            wots_index: WotsIndex::from_raw(1),
            pending: None,
            settled: Some(at_zero(Some(figures))),
        }];
        let parsed = parse_with_key(&seal_at(&settled, 5), test_key()).expect("a settled block seals and parses");
        let slot = parsed.slots.get(tag).expect("in the parsed state");
        assert_eq!(
            slot.settled,
            Some(at_zero(Some(figures))),
            "the retained settled block did not round-trip with its figures"
        );
        assert_eq!(slot.pending, None, "a settled block came back as an open reservation");

        // 4. The relation, refused in both occupied states.
        let mut refused = 0usize;
        for (spent, wots, why) in [
            (1u32, 1u32, "spent_index equal to wots_index"),
            (0, 2, "spent_index two behind wots_index"),
            (1, 0, "spent_index ahead of wots_index"),
            (u32::MAX, 0, "spent_index at u32::MAX, where the + 1 overflows"),
        ] {
            let block = Pending {
                spent_index: WotsIndex::from_raw(spent),
                digest,
                figures: Some(figures),
            };
            for (state, pending, settled) in [("open", Some(block), None), ("settled", None, Some(block))] {
                let bad = [RecordRef {
                    tag: *tag,
                    account,
                    wots_index: WotsIndex::from_raw(wots),
                    pending,
                    settled,
                }];
                let err = encode(&bad, 3, None, Kdf::RECOMMENDED, &TEST_SALT, test_key(), &KAT_NONCE).err();
                assert!(
                    matches!(
                        err,
                        Some(Error::Corrupt {
                            what: "pending index does not precede wots_index by one",
                            ..
                        })
                    ),
                    "encode sealed a {state} block with {why} ({spent} under {wots}), or refused it \
                     under another name: {err:?}. The parser refuses exactly this relation, so an \
                     image encode emits here is authenticated garbage -- refused after the tag \
                     verifies, indistinguishable to an operator from a damaged file"
                );
                refused += 1;
            }
        }
        assert_eq!(refused, 8);
        println!(
            "  encode: a reservation with figures, the migrated shape and a settled block each \
             round-trip; {refused} inconsistent blocks refused before sealing, under the parser's own \
             name"
        );
    }

    /// One derived account, built once for the tests that need a record and
    /// nothing about its contents: `Account::derive` is two WOTS+
    /// generations, each about three minutes under Miri on this machine, so
    /// it is cached the way `good_image` is rather than
    /// paid per test.
    // Not under Miri: its one caller,
    // `encode_refuses_both_an_open_and_a_settled_block_in_one_record`, is
    // gated out under Miri for the two WOTS+ generations this cache pays.
    #[cfg(not(miri))]
    fn one_account() -> &'static (Tag, Account) {
        static ACCOUNT: std::sync::OnceLock<(Tag, Account)> = std::sync::OnceLock::new();
        ACCOUNT.get_or_init(|| {
            let a = Account::derive(&Secret::new(DERIVED_MASTER), 1);
            (a.tag(), a)
        })
    }

    /// **`encode` refuses both an open and a settled block in one record**
    /// -- the one illegal state the two-field `Slot`
    /// admits, and the one rule that is the encoder's alone.
    ///
    /// It has no parser counterpart by construction: the record's one
    /// `pending u8` has three values, so the state has no image and
    /// `parse_with_key` never sees it. It is refused here rather than left to
    /// the producers (`persist_advance` overwrites the retained block,
    /// `persist_settled` moves it) because a construction with nothing
    /// holding it is a comment. Defaulting either way is a
    /// loss: preferring `settled` seals an open reservation as settled and
    /// strands the balance at the reserved key; preferring `pending` drops
    /// the block the reverted-settle report exists to read. The controls:
    /// each half alone seals.
    /// Not under Miri: its time is `one_account()`'s two WOTS+ key generations
    /// (385 s measured) and what it pins is one early return. The
    /// encoder's own path is walked by `good_image()`, which the ungated
    /// `an_older_format_reports_unsupported_version_before_anything_else` pays
    /// for.
    #[cfg(not(miri))]
    #[test]
    fn encode_refuses_both_an_open_and_a_settled_block_in_one_record() {
        let (tag, account) = one_account();
        let block = Pending {
            spent_index: WotsIndex::from_raw(1),
            digest: [0xD2; 32],
            figures: Some(Figures {
                reserved_balance: 1,
                blk_to_live: 0,
            }),
        };
        let record = |pending: Option<Pending>, settled: Option<Pending>| {
            [RecordRef {
                tag: *tag,
                account,
                wots_index: WotsIndex::from_raw(2),
                pending,
                settled,
            }]
        };
        let err = encode(&record(Some(block), Some(block)), 3, None, Kdf::RECOMMENDED, &TEST_SALT, test_key(), &KAT_NONCE).err();
        assert!(
            matches!(
                err,
                Some(Error::Corrupt {
                    what: "both an open and a settled reservation in one record",
                    ..
                })
            ),
            "encode sealed a record carrying both an open and a settled block, or refused it under \
             another name: {err:?}. The record's one pending byte cannot express both, so whichever \
             the encoder picked would be a silent default over the other"
        );
        // The controls: either half alone is a record the parser reads back.
        for (what, pending, settled) in [("open", Some(block), None), ("settled", None, Some(block))] {
            let image = encode(&record(pending, settled), 3, None, Kdf::RECOMMENDED, &TEST_SALT, test_key(), &KAT_NONCE)
                .unwrap_or_else(|e| panic!("the {what} half alone did not seal: {e}"));
            let parsed = parse_with_key(&image, test_key()).unwrap_or_else(|e| panic!("the {what} half alone did not parse: {e}"));
            let slot = parsed.slots.get(tag).expect("in the parsed state");
            assert_eq!((slot.pending, slot.settled), (pending, settled), "the {what} half did not round-trip");
        }
        println!("  encode: both blocks in one record refused before sealing; each half alone round-trips");
    }
}
