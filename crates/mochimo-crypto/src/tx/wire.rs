//! The native transaction construction path: owned types and the wire codec.
//!
//! This is the decided shape: **ordinary Rust types with a
//! serializer at the boundary** — no self-referential buffer, no stored
//! offsets, no `Pin`, no `unsafe`. The reference's transaction container
//! keeps fifteen interior pointers as a memoized index over
//! one buffer; `tx__init` computes every one of them from three option bytes
//! and `tx_read` recomputes them all before copying anything.
//! These types keep the index and drop the memoization: the
//! serializer is where the index is spent.
//!
//! The layout is designed from the wire format as the reference defines it,
//! not from the container struct:
//!
//! - header: `options[4]`, `src_addr[40]`, `chg_addr[40]`, `send_total[8]`,
//!   `change_total[8]`, `fee_total[8]`, `blk_to_live[8]` — 116 bytes;
//! - `MDST_COUNT` destinations of `tag[20]`, `ref[16]`, `amount[8]` — 44
//!   bytes each, where `MDST_COUNT = options[2] + 1`
//!   in 1..=256 (there is no `MAX_DESTINATIONS` macro — the
//!   bound is `mdst[256]` plus the `word8` range);
//! - WOTS+ validation data: `signature[2144]`, `pub_seed[32]`, `adrs[32]`;
//! - an optional trailer: `nonce[8]`, `id[32]`.
//!   `tx_read` accepts a wire image with the trailer whole, absent, or
//!   partial.
//!
//! Multi-byte numbers are little-endian; the four 64-bit header fields
//! (`send_total`, `change_total`, `fee_total`, `blk_to_live`) and the nonce
//! are `u64` here and cross onto the wire through
//! `to_le_bytes`/`from_le_bytes`, the one endian seam, little-endian by
//! decision (`docs/specification.md`, *Integers*).
//!
//! # The serializer takes what it is given
//!
//! `send_total`, `fee_total` and the rest are **fields, not computations**.
//! `mdst_val` is where the reference decides whether
//! `send_total` equals the amount tally and whether `fee_total` covers
//! `count × mfee`; a serializer that "helpfully" recomputed either would be
//! unable to reproduce the `D19-totals`/`D19-fees` wire images, whose totals
//! the reference deliberately emitted wrong. Building a transaction a
//! validator would accept is the caller's job — and a wallet-layer concern.
//!
//! # What is enforced, and by what
//!
//! - The destination count is fenced at construction ([`Transaction::new`](crate::tx::wire::Transaction::new),
//!   [`Transaction::set_dsts`](crate::tx::wire::Transaction::set_dsts)), so [`Transaction::to_wire`](crate::tx::wire::Transaction::to_wire) is infallible:
//!   the one invalid state these types could otherwise represent — a count of
//!   0 or above 256, which no fixture can carry because the reference cannot
//!   emit it — is answered with a type rather than with a branch no fixture
//!   could reach.
//! - This file contains no `unsafe` (the confinement scan allow-list does not
//!   include it) and no panicking construct (the panic census: a serializer
//!   takes caller-controlled input, and a panic there is a denial of
//!   service). **The absence of implicit panic paths — indexing, truncating
//!   casts on unchecked values — is NOT enforced by any scan**: the census
//!   cannot see them. What actually checks it is Miri walking the
//!   round-trip test plus review; parsing here goes through `split_first_chunk`
//!   and `get`, never an index.
//!
//! # What the verification establishes, and what it cannot
//!
//! The codec is checked against group D: every wire image the reference
//! emitted round-trips byte for byte and reproduces the recorded offsets and
//! digests (`tests/kat.rs::reference_verdicts_native`, `tests/txwire.rs`).
//! The construction differential against the C container and the framing
//! agreement with `tx_read` over arbitrary bytes went with the binding. But
//! `tx_val` needs an open ledger and is not
//! callable offline, so **no wire image in the corpus is a transaction the C
//! accepted end to end** — `D17`'s recorded booleans are the reference's own
//! comparators over the emitted bytes, and the path that acts on them never
//! ran (`rule_not_evaluated`). A transaction these types serialize correctly
//! can still be rejected by a real node — for a ledger reason, a balance
//! tally, or a block-to-live range, none of which any vector exercises.
//! Verified against layout, encoding and two offline validators is not
//! "known to work"; the place the difference will surface is testnet.
//!
//! # The two digests, and the trailer the node writes
//!
//! `tx_hash` is one `sha256` over one of two prefixes of the
//! wire image: `TX_HASH_MESSAGE` stops at the validation data — the first
//! [`Transaction::dsa_off`](crate::tx::wire::Transaction::dsa_off) bytes, the message a signature is over — and
//! `TX_HASH_ID` stops at the trailer's `id`, so it covers the nonce as well.
//! [`Transaction::message_digest`](crate::tx::wire::Transaction::message_digest) and [`Transaction::id_digest`](crate::tx::wire::Transaction::id_digest) are those
//! two, and they hash bytes this module writes rather than bytes it slices out
//! of `to_wire`, so no index is involved. `process_tx` zeroes
//! the nonce and writes `TX_HASH_ID` into the trailer *after* validation,
//! which is why whatever trailer a wallet sends is ignored
//! by the node and why [`Transaction::seal`](crate::tx::wire::Transaction::seal) writes exactly that pair.
//!
//! The hash is `backend::selected`'s `sha256`: the bytes are public, so the
//! zeroization argument that puts the keystore trailer and `wots::sign` on
//! `native` by name does not apply here, and the alias is used the way every
//! other public-data site uses it. The digest is replayed against the
//! `Ds1-N*` vectors' recorded `message_hash`/`id_hash` in `tests/txwire.rs`.

use crate::backend::selected as backend;
use crate::consts::wire::{SIZEOF_MDST, SIZEOF_TXHDR, SIZEOF_TXTLR, SIZEOF_WOTSVAL};
use crate::consts::{ADDR_LEN, ADDR_REF_LEN, ADDR_TAG_LEN, HASHLEN, SIG_LEN};
use crate::error::{Error, Result};

use super::{DAT_MDST, DSA_WOTS, MAX_DESTINATIONS};

/// One destination: `MDST` on the wire.
///
/// `reference` is the 16-byte destination reference field. Its *grammar*
/// (enforced by `mdst_val__reference`) is a
/// validator concern, not a serializer one: these bytes are emitted as given,
/// which is what lets `D16-badref`'s reference-rejected image round-trip.
/// The validator this crate applies before a spend is laid out is
/// `mesh::spend::reference_is_valid`, a transcription of the node's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Destination {
    /// `MDST::tag` — the destination address tag, 20 bytes.
    pub tag: [u8; ADDR_TAG_LEN],
    /// `MDST::ref` — the destination reference, 16 bytes, zero-filled where
    /// unused.
    pub reference: [u8; ADDR_REF_LEN],
    /// `MDST::amount` — little-endian on the wire.
    pub amount: u64,
}

impl Destination {
    /// The 44-byte `MDST` image: `tag ‖ ref ‖ amount`,
    /// the amount little-endian. What [`Transaction::to_wire`](crate::tx::wire::Transaction::to_wire) emits for a
    /// destination, and the key `mdst_val`'s sort compares — `memcmp` over
    /// the whole struct, so a builder that orders destinations
    /// by this image orders them the way the validator requires.
    pub fn mdst_image(&self) -> [u8; SIZEOF_MDST] {
        let mut out = [0u8; SIZEOF_MDST];
        let (tag, rest) = out.split_at_mut(ADDR_TAG_LEN);
        let (reference, amount) = rest.split_at_mut(ADDR_REF_LEN);
        tag.copy_from_slice(&self.tag);
        reference.copy_from_slice(&self.reference);
        amount.copy_from_slice(&self.amount.to_le_bytes());
        out
    }
}

/// The WOTS+ validation data: `WOTSVAL` on the wire.
///
/// Held inline rather than boxed, so this module has no allocation site of
/// its own beyond the destination list. Nothing here is secret: a signature,
/// a public seed and a hash-function address scheme are all public wire data,
/// which is why deriving `Debug` is sound where a key holder could not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WotsVal {
    /// `WOTSVAL::signature`, 2144 bytes.
    pub signature: [u8; SIG_LEN],
    /// `WOTSVAL::pub_seed`.
    pub pub_seed: [u8; 32],
    /// `WOTSVAL::adrs`. The reference documents a required tail for a *valid*
    /// transaction; `tx_val__wots` enforces it, this type
    /// does not — `Ds7` records the reference rejecting exactly that, over an
    /// image that still parses and round-trips.
    pub adrs: [u8; 32],
}

/// The transaction trailer: `TXTLR` on the wire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Trailer {
    /// `TXTLR::nonce` — little-endian on the wire.
    pub nonce: u64,
    /// `TXTLR::id` — the transaction ID hash.
    pub id: [u8; HASHLEN],
}

/// A transaction with owned fields, serializable to the reference's wire
/// image.
///
/// The destination list is private because it carries the type's one
/// invariant: **1..=256 destinations**, the range `MDST_COUNT = options[2]+1`
/// can express. Everything else is plain data and public.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transaction {
    /// `TXHDR::src_addr` — tag half at offset 0, hash half at offset 20.
    pub src_addr: [u8; ADDR_LEN],
    /// `TXHDR::chg_addr`.
    pub chg_addr: [u8; ADDR_LEN],
    /// `TXHDR::send_total`.
    pub send_total: u64,
    /// `TXHDR::change_total`.
    pub change_total: u64,
    /// `TXHDR::fee_total`. The container aliases this pointer `tx_fee`;
    /// the header struct's own name is kept here.
    pub fee_total: u64,
    /// `TXHDR::blk_to_live`.
    pub blk_to_live: u64,
    /// `options[3]`, reserved. Read by nothing in the reference, but present
    /// on the wire and accepted non-zero by `tx_read`, so it is carried
    /// rather than assumed — a parse/serialize round trip must preserve it.
    pub reserved: u8,
    /// The destination list; 1..=256 enforced at every write.
    dsts: Vec<Destination>,
    /// The WOTS+ validation data.
    pub wots: WotsVal,
    /// The trailer, present in the disk form and absent in the network form
    /// (the node accepts both).
    pub trailer: Option<Trailer>,
}

/// Reads the next `N` bytes off the front of `rest`, or reports what was
/// missing. The only cursor this module has; nothing here indexes.
fn take<'a, const N: usize>(rest: &mut &'a [u8], what: &'static str) -> Result<&'a [u8; N]> {
    match rest.split_first_chunk::<N>() {
        Some((head, tail)) => {
            *rest = tail;
            Ok(head)
        }
        None => Err(Error::Length {
            what,
            expected: N,
            got: rest.len(),
        }),
    }
}

impl Transaction {
    /// A transaction with the given destinations and every other field zero.
    ///
    /// Rejects a destination count outside 1..=256 — the one state these
    /// types could represent that the wire cannot. All other fields are
    /// public: set them directly.
    pub fn new(dsts: Vec<Destination>) -> Result<Self> {
        Self::check_count(dsts.len())?;
        Ok(Transaction {
            src_addr: [0; ADDR_LEN],
            chg_addr: [0; ADDR_LEN],
            send_total: 0,
            change_total: 0,
            fee_total: 0,
            blk_to_live: 0,
            reserved: 0,
            dsts,
            wots: WotsVal {
                signature: [0; SIG_LEN],
                pub_seed: [0; 32],
                adrs: [0; 32],
            },
            trailer: None,
        })
    }

    fn check_count(n: usize) -> Result<()> {
        if n == 0 || n > usize::from(MAX_DESTINATIONS) {
            return Err(Error::Range {
                what: "destination count",
                min: 1,
                max: u64::from(MAX_DESTINATIONS),
                got: n as u64,
            });
        }
        Ok(())
    }

    /// The destination list.
    pub fn dsts(&self) -> &[Destination] {
        &self.dsts
    }

    /// Replaces the destination list, holding the 1..=256 invariant.
    pub fn set_dsts(&mut self, dsts: Vec<Destination>) -> Result<()> {
        Self::check_count(dsts.len())?;
        self.dsts = dsts;
        Ok(())
    }

    /// The destination count, as `MDST_COUNT` would report it.
    pub fn dst_count(&self) -> u16 {
        // Lossless: the constructor and setter bound the length at 256.
        self.dsts.len() as u16
    }

    /// Offset of the validation data: `sizeof(TXHDR) + sizeof(MDST) * count`.
    /// Equal to the signed length the corpus records.
    pub fn dsa_off(&self) -> usize {
        SIZEOF_TXHDR + SIZEOF_MDST * self.dsts.len()
    }

    /// Offset of the trailer: `dsaoff + sizeof(WOTSVAL)`.
    pub fn tlr_off(&self) -> usize {
        self.dsa_off() + SIZEOF_WOTSVAL
    }

    /// The full transaction size, trailer included: `tlroff + sizeof(TXTLR)`.
    /// This is the container's `tx_sz` whether or not the wire
    /// form carried the trailer, because `tx_read` recomputes it from the
    /// option bytes alone.
    pub fn tx_sz(&self) -> usize {
        self.tlr_off() + SIZEOF_TXTLR
    }

    /// The length [`Self::to_wire`] will emit: `tx_sz` with the trailer,
    /// `tx_sz - sizeof(TXTLR)` without.
    pub fn wire_len(&self) -> usize {
        match self.trailer {
            Some(_) => self.tx_sz(),
            None => self.tx_sz() - SIZEOF_TXTLR,
        }
    }

    /// The signed prefix: header and destinations, the first
    /// [`Self::dsa_off`] bytes of the image and the whole of what
    /// `TX_HASH_MESSAGE` covers.
    fn write_signed_prefix(&self, w: &mut Vec<u8>) {
        w.push(DAT_MDST); // options[0]
        w.push(DSA_WOTS); // options[1]
        // options[2] is zero-based. Lossless: the list is
        // bounded at 256 by the constructor and setter, so len - 1 <= 255.
        w.push((self.dsts.len() - 1) as u8);
        w.push(self.reserved); // options[3]
        w.extend_from_slice(&self.src_addr);
        w.extend_from_slice(&self.chg_addr);
        w.extend_from_slice(&self.send_total.to_le_bytes());
        w.extend_from_slice(&self.change_total.to_le_bytes());
        w.extend_from_slice(&self.fee_total.to_le_bytes());
        w.extend_from_slice(&self.blk_to_live.to_le_bytes());
        for d in &self.dsts {
            w.extend_from_slice(&d.mdst_image());
        }
    }

    /// The validation data, `WOTSVAL`.
    fn write_wots(&self, w: &mut Vec<u8>) {
        w.extend_from_slice(&self.wots.signature);
        w.extend_from_slice(&self.wots.pub_seed);
        w.extend_from_slice(&self.wots.adrs);
    }

    /// Serializes to the wire image, byte for byte as the reference lays it
    /// out. Infallible: the only unrepresentable state is fenced at
    /// construction.
    pub fn to_wire(&self) -> Vec<u8> {
        let mut w = Vec::with_capacity(self.wire_len());
        self.write_signed_prefix(&mut w);
        self.write_wots(&mut w);
        if let Some(t) = &self.trailer {
            w.extend_from_slice(&t.nonce.to_le_bytes());
            w.extend_from_slice(&t.id);
        }
        w
    }

    /// `TX_HASH_MESSAGE`: `sha256` over the header and
    /// destinations — the first [`Self::dsa_off`] bytes — which is the
    /// message a WOTS+ signature is over. Group D records it as
    /// `signed_len`; `tx_sign` in the fixture generator hashes exactly this.
    pub fn message_digest(&self) -> [u8; HASHLEN] {
        let mut w = Vec::with_capacity(self.dsa_off());
        self.write_signed_prefix(&mut w);
        backend::sha256(&w)
    }

    /// `TX_HASH_ID`: `sha256` over everything up to the
    /// trailer's `id`, so the nonce is included. The nonce hashed is the one
    /// this value holds, or zero when the trailer is absent — the form
    /// `process_tx` produces and the mesh middleware echoes.
    pub fn id_digest(&self) -> [u8; HASHLEN] {
        let nonce = self.trailer.as_ref().map_or(0, |t| t.nonce);
        self.id_digest_with_nonce(nonce)
    }

    fn id_digest_with_nonce(&self, nonce: u64) -> [u8; HASHLEN] {
        let mut w = Vec::with_capacity(self.tlr_off() + 8);
        self.write_signed_prefix(&mut w);
        self.write_wots(&mut w);
        w.extend_from_slice(&nonce.to_le_bytes());
        backend::sha256(&w)
    }

    /// Writes the trailer the node itself writes after validation:
    /// nonce zero, `id = TX_HASH_ID`. What a wallet
    /// sends here is overwritten on receipt, so sealing is for the wallet's
    /// own bookkeeping — the id is what `/mempool` and
    /// `/construction/submit` name the transaction by — not for the node.
    pub fn seal(&mut self) {
        let id = self.id_digest_with_nonce(0);
        self.trailer = Some(Trailer { nonce: 0, id });
    }

    /// Parses a wire image, accepting exactly what `tx_read` accepts.
    ///
    /// The checks run in the reference's order: header length,
    /// then the two type bytes (only `TXDAT_MDST` and
    /// `TXDSA_WOTS`, anything else before any further arithmetic), then the
    /// length window `tx_sz - sizeof(TXTLR) <= len <= tx_sz`.
    ///
    /// A partial trailer — any of the 39 lengths strictly inside the window —
    /// is **zero-extended**, reproducing the reference's state after its
    /// `memset` and partial `memcpy`. So
    /// `to_wire(from_wire(x)) == x` holds for the two canonical lengths, and
    /// for the partial lengths it produces the full-trailer image the
    /// reference's own container would hold; the round-trip differential
    /// against the C container checked precisely that equivalence and went
    /// with the binding. What remains is the group D round trip in
    /// `tests/txwire.rs`.
    pub fn from_wire(bytes: &[u8]) -> Result<Transaction> {
        if bytes.len() < SIZEOF_TXHDR {
            return Err(Error::Length {
                what: "transaction wire header",
                expected: SIZEOF_TXHDR,
                got: bytes.len(),
            });
        }
        let mut r = bytes;
        let options = take::<4>(&mut r, "options")?;
        if options[0] != DAT_MDST {
            return Err(Error::Range {
                what: "TXDAT type byte",
                min: u64::from(DAT_MDST),
                max: u64::from(DAT_MDST),
                got: u64::from(options[0]),
            });
        }
        if options[1] != DSA_WOTS {
            return Err(Error::Range {
                what: "TXDSA type byte",
                min: u64::from(DSA_WOTS),
                max: u64::from(DSA_WOTS),
                got: u64::from(options[1]),
            });
        }
        let ndst = usize::from(options[2]) + 1; // zero-based
        let reserved = options[3];
        let tx_sz = SIZEOF_TXHDR + SIZEOF_MDST * ndst + SIZEOF_WOTSVAL + SIZEOF_TXTLR;
        if bytes.len() > tx_sz || bytes.len() < tx_sz - SIZEOF_TXTLR {
            return Err(Error::Range {
                what: "transaction wire length",
                min: (tx_sz - SIZEOF_TXTLR) as u64,
                max: tx_sz as u64,
                got: bytes.len() as u64,
            });
        }

        let src_addr = *take::<ADDR_LEN>(&mut r, "src_addr")?;
        let chg_addr = *take::<ADDR_LEN>(&mut r, "chg_addr")?;
        let send_total = u64::from_le_bytes(*take::<8>(&mut r, "send_total")?);
        let change_total = u64::from_le_bytes(*take::<8>(&mut r, "change_total")?);
        let fee_total = u64::from_le_bytes(*take::<8>(&mut r, "fee_total")?);
        let blk_to_live = u64::from_le_bytes(*take::<8>(&mut r, "blk_to_live")?);

        let mut dsts = Vec::with_capacity(ndst);
        for _ in 0..ndst {
            let tag = *take::<ADDR_TAG_LEN>(&mut r, "destination tag")?;
            let reference = *take::<ADDR_REF_LEN>(&mut r, "destination reference")?;
            let amount = u64::from_le_bytes(*take::<8>(&mut r, "destination amount")?);
            dsts.push(Destination {
                tag,
                reference,
                amount,
            });
        }

        let signature = *take::<SIG_LEN>(&mut r, "wots signature")?;
        let pub_seed = *take::<32>(&mut r, "wots pub_seed")?;
        let adrs = *take::<32>(&mut r, "wots adrs")?;

        // The window check bounded what remains to 0..=sizeof(TXTLR). Empty
        // is the network form; anything else is a whole or partial trailer,
        // zero-extended.
        let trailer = if r.is_empty() {
            None
        } else {
            let mut padded = [0u8; SIZEOF_TXTLR];
            match padded.get_mut(..r.len()) {
                Some(dst) => dst.copy_from_slice(r),
                // Unreachable while the window check above holds; kept as an
                // error rather than a panic so no input can take this module
                // down even if that reasoning rots.
                None => {
                    return Err(Error::Length {
                        what: "transaction trailer",
                        expected: SIZEOF_TXTLR,
                        got: r.len(),
                    })
                }
            }
            let mut t: &[u8] = &padded;
            let nonce = u64::from_le_bytes(*take::<8>(&mut t, "trailer nonce")?);
            let id = *take::<HASHLEN>(&mut t, "trailer id")?;
            Some(Trailer { nonce, id })
        };

        Ok(Transaction {
            src_addr,
            chg_addr,
            send_total,
            change_total,
            fee_total,
            blk_to_live,
            reserved,
            dsts,
            wots: WotsVal {
                signature,
                pub_seed,
                adrs,
            },
            trailer,
        })
    }
}
