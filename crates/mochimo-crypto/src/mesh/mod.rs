//! The Mesh API client: what the wallet asks the network and what it
//! sends it. Three reads and one write over the middleware in
//! `reference/mochimo-mesh` (a recon source, never an oracle),
//! which delegates its wire work to `reference/go_mcminterface`; both are
//! pinned, and every behaviour cited below was read at those pins and
//! captured live from `api.mochimo.org` into `fixtures/group_n_mesh_live.json`
//! (a specification capture of one server at one block).
//!
//! # What is verified here
//!
//! Request bodies are built from typed values ([`codec`]) and are byte-equal
//! to the bodies the capture sent, whose replies are the ones recorded, so
//! "the server accepted this exact request" is the recorded fact. Response
//! bodies are parsed by hand with every field's presence, type, width and
//! range checked before it becomes a Rust value; the address the ledger
//! returns must begin with the tag asked for. The chain's current address for
//! a tag must equal the address of the key this keystore would sign with next
//! before anything is reserved ([`spend::SpendPlan::new`]). Every parser is
//! total over truncations and byte flips of every captured body
//! (`tests/mesh.rs`): a malformed reply is an error, never a panic, because a
//! panic on network input is a denial of service.
//!
//! # What a 200 from `submit` means
//!
//! **The bytes left the process; nothing more.** `constructionSubmitHandler`
//! decodes the hex with
//! `TransactionFromHex`, hands it to `SubmitTransaction`, and that function
//! writes the bytes as `OP_TX` to
//! each of a set of picked nodes, one raw frame per socket, and returns
//! `nil` as soon as one of those writes completes **without reading a
//! reply** from any of them. Nothing is validated on the way ("Validate the signed
//! transaction - TODO LATER"). The `hash` in the reply is computed by the
//! middleware from the bytes it received with the nonce forced to zero, which
//! is why [`MeshClient::submit`] refuses a reply whose hash is not the id of
//! the bytes it sent — the acknowledgement is then about something else.
//! Not accepted, not validated, not in a block: a caller learns acceptance
//! only by observing the chain, and that observation is reconciliation's.
//!
//! # The `tx_val` residue, at this site
//!
//! `tx_val` runs on the node against an open ledger, and **no
//! image in the corpus has ever been through it**. What this
//! crate checks a transaction against offline is layout, `mdst_val` and
//! `tx_val__wots`; the ledger arms — exact balance equality, the block-to-live
//! window, the source/change relation as the ledger sees it — are outside
//! every fixture, and nothing in `cargo test` reaches them.
//!
//! **Two of the three have now run once, on a live node and not in this
//! suite.** One live run submitted a transaction this crate built and the chain carried
//! it in block 1078535: `send + change + fee` equalled the ledger
//! balance exactly, and `src_addr`/`chg_addr` carried one tag over two hash
//! halves — the relation `tx.c:739` enforces, which no group D wire image
//! carries (all 43 were measured). The block-to-live window was **not**
//! exercised: `blk_to_live` was 0 and `tx.c:723` checks only non-zero values.
//! Acceptance there was inferred from the ledger moving, not read off a
//! verdict — `/construction/submit` returns before any reply.
//!
//! So a transaction these types build can still satisfy every check this crate
//! runs and be rejected on a ledger reason, for every shape that run did not have:
//! multiple destinations, a non-zero `MDST::ref`, a zero change, a live
//! block-to-live range. **This paragraph said the arms were unexercised "until
//! `mesh_submission_is_unconfirmed_without_a_funded_account` clears" until
//! recently**, and that was wrong three ways: the name had already retired, its
//! successor was about *authorship* — who assembled a submission, which no
//! read-only capture can establish — and no marker in this tree has "the
//! ledger arms are exercised" as its clearing condition. That is knowledge,
//! not debt: it is recorded in `docs/specification.md`'s *Open items* table
//! (authorship of a submitted transaction), and what would move it is fixture
//! data from a capture taken at submission time.
//!
//! # What this module does not do
//!
//! It does not reconcile (I4), does not settle (`persist_settled` is never
//! called from here), does not decide expiry, and does not re-sign. Each of
//! those is named where it is stopped at.

use core::fmt;

use crate::addr::{Address, Tag};
use crate::consts::HASHLEN;
use crate::error::{Error, Result};

pub mod codec;
pub mod hex;
#[cfg(feature = "mesh-http")]
pub mod http;
pub mod spend;

pub use spend::{SignedTransaction, SpendPlan};

/// The middleware's request-body cap: `http.MaxBytesReader(w, r.Body,
/// 30*1024)` in `maxRequestSizeMiddleware`.
/// Enforced here too, so an oversize body is a named refusal rather than a
/// dropped connection. A 256-destination signed image is 13,628 bytes —
/// 27,256 hex characters plus the envelope — and fits.
pub const MAX_REQUEST_BYTES: usize = 30 * 1024;
/// This crate's response-body cap: every documented reply is under a
/// kilobyte, and the cap bounds the allocation before it happens.
pub const MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// How bytes reach the middleware. `path` is the endpoint (`"/call"`), `body`
/// an already-serialised JSON request; the return is the body of a 200
/// response, at most [`MAX_RESPONSE_BYTES`] of it. Not sealed: the test tree
/// fakes it with recorded bodies, and nothing in it touches key material.
pub trait Transport {
    fn post(&self, path: &str, body: &[u8]) -> Result<Vec<u8>>;
}

/// A block the middleware named: index and hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainTip {
    pub index: u64,
    pub hash: [u8; HASHLEN],
}

/// What `/call tag_resolve` returns: the ledger's current entry for a tag,
/// which is what makes I5's restore scan target-directed — the
/// full 40-byte address, tag half then current hash half, and the balance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LedgerEntry {
    pub address: Address,
    /// nanoMochimo.
    pub balance: u64,
}

/// What `/account/balance` returns: the balance and the block the middleware
/// had cached when it answered. The address is resolved and discarded by that
/// handler, which is why [`LedgerEntry`] comes from `/call` instead.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BalanceAt {
    /// nanoMochimo.
    pub balance: u64,
    pub tip: ChainTip,
}

/// A transaction id: `TX_HASH_ID` with the nonce zero.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TxId(pub [u8; HASHLEN]);

impl fmt::Debug for TxId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TxId({})", hex::encode(&self.0))
    }
}

/// The client: one transport, eight operations -- four the wallet needs to
/// spend, and four read-only ones the explorer verbs use.
#[derive(Debug)]
pub struct MeshClient<T: Transport> {
    transport: T,
}

impl<T: Transport> MeshClient<T> {
    pub fn new(transport: T) -> MeshClient<T> {
        MeshClient { transport }
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// `POST /network/status`: the current block.
    pub fn network_status(&self) -> Result<ChainTip> {
        let reply = self.transport.post("/network/status", &codec::request_network_status())?;
        codec::parse_network_status(&reply)
    }

    /// `POST /call tag_resolve`: the ledger's current entry for `tag`. An
    /// unknown tag is [`Error::Mesh`] with the middleware's code 4.
    pub fn resolve_tag(&self, tag: &Tag) -> Result<LedgerEntry> {
        let reply = self.transport.post("/call", &codec::request_tag_resolve(tag))?;
        codec::parse_tag_resolve(&reply, tag)
    }

    /// `POST /account/balance` for `tag`.
    pub fn balance(&self, tag: &Tag) -> Result<BalanceAt> {
        let reply = self.transport.post("/account/balance", &codec::request_account_balance(tag))?;
        codec::parse_account_balance(&reply)
    }

    /// `POST /block` by index: the block and every transaction in it.
    ///
    /// **Index 0 is the current block, not genesis** (`getBlock`,
    /// `block_handler.go:56-80`, routes by number only when `Index != 0`).
    /// Callers that mean a named block refuse 0 before they get here.
    pub fn block_by_index(&self, index: u64) -> Result<codec::MeshBlock> {
        let reply = self.transport.post("/block", &codec::request_block_by_index(index))?;
        codec::parse_block(&reply)
    }

    /// `POST /block` by hash. The middleware reads a hash from its own
    /// archive folder, so a not-found here is about that deployment's
    /// archive rather than about the chain.
    pub fn block_by_hash(&self, hash: &[u8; HASHLEN]) -> Result<codec::MeshBlock> {
        let reply = self.transport.post("/block", &codec::request_block_by_hash(hash))?;
        codec::parse_block(&reply)
    }

    /// `POST /search/transactions` by transaction hash: the indexer's own
    /// rendering of one transaction, which differs from `/block`'s and is
    /// not reconciled with it (see [`codec::MeshTransaction::metadata`]).
    ///
    /// Served only where the deployment set `EnableIndexer`; where it did
    /// not, the handler answers an internal error rather than an empty page.
    pub fn search_by_hash(&self, hash: &[u8; HASHLEN]) -> Result<codec::SearchPage> {
        let reply = self.transport.post("/search/transactions", &codec::request_search_by_hash(hash))?;
        codec::parse_search(&reply)
    }

    /// `POST /search/transactions` by account tag, newest first,
    /// at most `limit` rows.
    ///
    /// `limit` must be in `1..=100`: outside that the handler ignores it and
    /// uses its own default of 10, so a caller
    /// that passed 250 would be answered with ten rows and no indication.
    /// The command line refuses the count before it reaches here.
    pub fn search_by_account(&self, tag: &Tag, limit: u64) -> Result<codec::SearchPage> {
        let reply = self
            .transport
            .post("/search/transactions", &codec::request_search_by_account(tag, limit))?;
        codec::parse_search(&reply)
    }

    /// `POST /construction/submit` with the whole wire image. `Ok` means the
    /// middleware wrote the bytes to a node's socket and echoed their id;
    /// see the module doc for what that does and does not establish. A reply
    /// naming any other id is [`Error::SubmitIdMismatch`].
    pub fn submit(&self, signed: &SignedTransaction) -> Result<TxId> {
        self.submit_wire(&signed.wire(), signed.id())
    }

    /// The same `POST /construction/submit` over a wire image the caller
    /// already holds -- the retry artifact `send` printed -- and the id the
    /// caller computed for it, which the echo must match. [`Self::submit`] is
    /// this over the signed transaction's own bytes and id. Nothing here
    /// judges the bytes, because nothing here can: the `submit` verb parses
    /// and re-serializes them before it calls this, and the node validates.
    pub fn submit_wire(&self, wire: &[u8], id: TxId) -> Result<TxId> {
        let body = codec::request_submit_wire(wire)?;
        let reply = self.transport.post("/construction/submit", &body)?;
        let echoed = codec::parse_submit(&reply)?;
        if echoed != id {
            return Err(Error::SubmitIdMismatch);
        }
        Ok(echoed)
    }
}
