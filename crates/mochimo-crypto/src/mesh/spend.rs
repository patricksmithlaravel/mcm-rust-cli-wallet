//! Building the transaction a wallet signs, and attaching the signature the
//! keystore released — locally, from parts this crate holds, never from
//! bytes a server returned.
//!
//! # Why local
//!
//! The shipped wallet asks the Mesh middleware to construct the unsigned
//! transaction and signs whatever comes back, with no comparison to the
//! change, amount or fee it asked for (re-derived by execution in group M).
//! A middleware that is malicious, buggy or merely a different
//! version chooses what that wallet signs. Here the middleware chooses
//! nothing: [`SpendPlan::new`] lays out every byte of the signed prefix from
//! the keystore's addresses, the caller's destinations and fee, and one
//! observation of the chain; [`SignedTransaction::attach`] puts the
//! keystore's signature beside it and re-validates the whole image the way
//! the node will; the bytes sent are `wire()`, unchanged.
//!
//! # The one server-supplied number in the signed bytes, and why it cannot steal
//!
//! `change_total` is `balance − send − fee`, and the balance comes from the
//! chain through `/call tag_resolve`. It is deliberately taken from **one**
//! call: `/account/balance` on a tag runs the same `QueryTagResolve`
//! (`accountBalanceHandler`, `account_handler.go`), so a second endpoint is
//! not a second opinion, and a disagreement between the two would be a block
//! boundary rather than evidence. What makes one call defensible is the
//! node's own rule: `tx_val` requires `send + change + fee` to equal the
//! ledger balance **exactly** (`tx.c:776-792`, `EMCM_TXTOTAL`). A lied
//! balance, high or low, makes the totals disagree with the ledger and the
//! transaction is rejected; change goes to this wallet's own next key in
//! either case. A wrong balance is a rejected transaction, never a theft.
//!
//! # What is refused before anything is reserved
//!
//! Each refusal mirrors a `tx_val`/`mdst_val` arm at the cited line and is
//! **pre-flight**: none is anchored on a node's verdict, because `tx_val`
//! needs an open ledger and has never run on any image this crate has built
//! or the corpus holds. The two that have a recorded
//! reference verdict are the WOTS+ checks ([`verify_wots`], ten group D
//! verdicts) and the destination order (`D12-sorted`/`D12-unsorted`, verdicts
//! the corpus records and this crate no longer executes — see
//! `tests/kat.rs::reference_verdicts_native`). The rest are what the node
//! will say, read off its source.
//!
//! The destination reference grammar is enforced here since S10, by
//! [`reference_is_valid`]: a transcription, state for state, of the node's
//! `mdst_val__reference` (`tx.c:510-573` at the corpus's pinned commit,
//! refused as `EMCM_XTXREF` at `tx.c:626`). It was deliberately not
//! restated for a time -- a restated state machine agrees with itself, and
//! the corpus records the reference's verdict on two values only
//! (`D16-badref`) -- and restating became admissible when the reference
//! could be read at its pinned commit in the public repository and the
//! transcription pinned there: at the function's own stated examples, at the
//! corpus's two points, and at the shapes the examples leave open
//! (`tests/spend.rs::the_reference_rule_is_the_references_own`), with no
//! node consulted. The serializer's stance is unchanged: it emits the bytes
//! given, and the rule is applied before them.
//!
//! Deliberately **not** enforced here: the node's *configured* fee (`Myfee`,
//! `tx.c:1034`), of which only the protocol floor is knowable offline; the
//! block-to-live window (`bnum <= btl <= bnum + 0x100`, `tx.c:724-734`),
//! whose bound is a literal inside `tx_val` that can neither be bound nor
//! restated without becoming a second `valid_op` — `blk_to_live` is the
//! caller's, zero (no expiry, the only value the node does not check) unless
//! set; and ledger equality *at validation time*, which a payment landing
//! between observation and validation can break — the retry is a rebuilt
//! plan under a fresh reservation, and whether the reserved digest may be
//! re-signed instead is the reconciliation session's decision.
//!
//! # The flow is composed by the caller
//!
//! No function here names `sign_spend`; the route scan behind I1 holds one
//! signer in the crate and this module is not it. The sequence, executed in
//! `tests/spend.rs`:
//!
//! ```text
//! a    = keystore.spend_addresses(&tag, &access)?
//! e    = client.resolve_tag(&tag)?                 e.address must be a.source
//! plan = SpendPlan::new(&a, &e, dsts, fee, btl)?   every refusal below
//! r    = keystore.persist_advance(&tag, &plan.digest(), plan.figures())?
//!        r.index() == plan.position().advanced()   the caller's own check
//! keystore.check_spend(&plan.digest(), &r, &access)?   optional: the same checks on a borrowed
//!                                                      receipt; `Wallet::reserve_and_sign` skips it
//! sig  = keystore.sign_spend(&plan.digest(), r, access)?
//! tx   = SignedTransaction::attach(&plan, &sig)?   recovery, then sealed
//! keep tx.wire() outside the format                the retry artifact
//! id   = client.submit(&tx)?                       a socket write, not a verdict
//! ```

use crate::account::WotsIndex;
use crate::addr::{self, Address};
use crate::consts::{ADDR_REF_LEN, HASHLEN, MFEE};
use crate::error::{Error, Result};
use crate::keystore::{Figures, SpendAddresses, SpendSignature};
use crate::tx::wire::{Destination, Transaction, WotsVal};
use crate::wots::{self, Adrs};

use super::{LedgerEntry, TxId};

/// The node's validator for a destination's 16-byte reference field
/// (`MDST::ref`, `types.h:407-418`), transcribed from `mdst_val__reference`
/// at `tx.c:510-573` of the reference at the corpus's pinned commit,
/// `bbbaceabe5c21b5d8a094cf34c050d28e4ae93f4`, where its refusal is
/// `EMCM_XTXREF` (`tx.c:626`).
///
/// State for state. The C's states are `START`, `DIGIT_DASH`, `DIGIT`,
/// `UPPER_DASH`, `UPPER` and `ZERO`, and the enum below carries the same
/// names; the C's `START` falls through into `DIGIT_DASH`'s test, so both
/// accept an uppercase letter, and that fall-through is the one arm written
/// twice here. Its classifiers are the C's own locale-independent
/// `ascii_isdigit` and `ascii_isupper` (`'0'..='9'`, `'A'..='Z'`), which
/// [`u8::is_ascii_digit`] and [`u8::is_ascii_uppercase`] are; a high-bit
/// byte matches neither. The loop runs over all sixteen bytes and the
/// machine must end in `ZERO`, `DIGIT` or `UPPER`.
///
/// What that says: all-NUL is valid; otherwise a sequence of groups, each
/// all uppercase or all digits, neighbouring groups of different kinds,
/// separated by single dashes, no leading or trailing dash, NUL-terminated
/// with every byte after the first NUL zero; sixteen non-NUL bytes ending
/// in a group are valid.
///
/// The corpus pins it at two points, `D16-badref`'s accepted `AB-00-EF` and
/// refused `AB-CD-EF`; the table in
/// `tests/spend.rs::the_reference_rule_is_the_references_own` pins the rest
/// against the C's stated examples and the shapes they leave open -- not
/// against a node, which has judged none of those bytes.
#[must_use]
pub fn reference_is_valid(reference: &[u8; ADDR_REF_LEN]) -> bool {
    #[derive(Clone, Copy)]
    enum State {
        Start,
        DigitDash,
        Digit,
        UpperDash,
        Upper,
        Zero,
    }
    let mut state = State::Start;
    for &c in reference {
        state = match state {
            State::Start if c == 0 => State::Zero,
            State::Start if c.is_ascii_digit() => State::Digit,
            State::Start | State::DigitDash if c.is_ascii_uppercase() => State::Upper,
            State::UpperDash if c.is_ascii_digit() => State::Digit,
            State::Digit if c.is_ascii_digit() => State::Digit,
            State::Digit if c == b'-' => State::DigitDash,
            State::Digit if c == 0 => State::Zero,
            State::Upper if c.is_ascii_uppercase() => State::Upper,
            State::Upper if c == b'-' => State::UpperDash,
            State::Upper if c == 0 => State::Zero,
            State::Zero if c == 0 => State::Zero,
            _ => return false,
        };
    }
    matches!(state, State::Zero | State::Digit | State::Upper)
}

/// A spend laid out and checked, before any key is reserved.
///
/// Holds the header values and the destinations — not a
/// [`Transaction`], so it bears no signature and building one is not a route
/// the I1 scan must allow-list. The unsigned image is rebuilt from these
/// fields whenever it is needed, and the digest cached here is
/// `TX_HASH_MESSAGE` over exactly that image.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpendPlan {
    position: WotsIndex,
    src_addr: Address,
    chg_addr: Address,
    send_total: u64,
    change_total: u64,
    fee_total: u64,
    blk_to_live: u64,
    /// `entry.balance` as `new` observed it -- see [`SpendPlan::balance`].
    balance: u64,
    dsts: Vec<Destination>,
    digest: [u8; HASHLEN],
}

impl SpendPlan {
    /// Lays out and checks a spend. The refusals, in order:
    ///
    /// 1. `entry.address != addresses.source` —
    ///    [`Error::ChainAddressMismatch`]. The chain does not hold this tag at
    ///    the key this store signs with next; I4's divergence, stopped at.
    /// 2. a destination count outside `1..=256` — `Error::Range`, from
    ///    [`Transaction::new`].
    /// 3. a zero amount — [`Error::ZeroAmount`] (`tx.c:607`).
    /// 4. a destination carrying the source's tag —
    ///    [`Error::DestinationIsSource`] (`tx.c:612`).
    /// 5. the amount tally overflowing — [`Error::Overflow`] (`tx.c:616`).
    /// 6. a reference the node's rule refuses — [`Error::InvalidReference`]
    ///    (`tx.c:626`, [`reference_is_valid`]).
    /// 7. `fee_total < MFEE × count` — [`Error::FeeBelowMinimum`]
    ///    (`tx.c:621,636`; `tx_val`'s own `fee >= MFEE` at `:747` is implied
    ///    for one destination or more).
    /// 8. `send + fee > balance` — [`Error::InsufficientBalance`]; the change
    ///    is the remainder, so `send + change + fee == balance` holds by
    ///    construction against the observation (`tx.c:776-792`).
    ///
    /// Destinations are **sorted** by their 44-byte image (`tx.c:601`,
    /// `EMCM_TXMDSTSORT`), duplicates kept: a transform rather than a
    /// refusal, so callers do not each reimplement the validator's key.
    pub fn new(
        addresses: &SpendAddresses,
        entry: &LedgerEntry,
        mut dsts: Vec<Destination>,
        fee_total: u64,
        blk_to_live: u64,
    ) -> Result<SpendPlan> {
        if entry.address != addresses.source {
            return Err(Error::ChainAddressMismatch {
                position: addresses.position.get(),
            });
        }
        dsts.sort_by_key(Destination::mdst_image);
        // The count bound, through the one place it is stated.
        let mut tx = Transaction::new(dsts)?;

        let src_tag = addr::tag_of(&addresses.source);
        let mut send_total: u64 = 0;
        for (index, d) in tx.dsts().iter().enumerate() {
            if d.amount == 0 {
                return Err(Error::ZeroAmount { index });
            }
            if d.tag == src_tag {
                return Err(Error::DestinationIsSource { index });
            }
            send_total = send_total
                .checked_add(d.amount)
                .ok_or(Error::Overflow { what: "send total" })?;
            if !reference_is_valid(&d.reference) {
                return Err(Error::InvalidReference { index });
            }
        }
        let count = u64::from(tx.dst_count());
        let min_fee = MFEE.checked_mul(count).ok_or(Error::Overflow { what: "fee floor" })?;
        if fee_total < min_fee {
            return Err(Error::FeeBelowMinimum {
                fee: fee_total,
                min: min_fee,
            });
        }
        let needed = send_total
            .checked_add(fee_total)
            .ok_or(Error::Overflow { what: "send plus fee" })?;
        let change_total = entry
            .balance
            .checked_sub(needed)
            .ok_or(Error::InsufficientBalance {
                balance: entry.balance,
                needed,
            })?;

        tx.src_addr = addresses.source;
        tx.chg_addr = addresses.change;
        tx.send_total = send_total;
        tx.change_total = change_total;
        tx.fee_total = fee_total;
        tx.blk_to_live = blk_to_live;
        let digest = tx.message_digest();

        Ok(SpendPlan {
            position: addresses.position,
            src_addr: tx.src_addr,
            chg_addr: tx.chg_addr,
            send_total,
            change_total,
            fee_total,
            blk_to_live,
            balance: entry.balance,
            dsts: tx.dsts().to_vec(),
            digest,
        })
    }

    /// `TX_HASH_MESSAGE` over the unsigned image: what `persist_advance`
    /// reserves the key for and what `sign_spend` signs.
    pub fn digest(&self) -> [u8; HASHLEN] {
        self.digest
    }

    /// The position the plan was built for: the key that must sign it.
    /// The account tag this spend is from: the tag half of `src_addr`, which
    /// `SpendPlan::new` took from the keystore's own `SpendAddresses`.
    ///
    /// Added so `Wallet::reserve_and_sign` reserves against the plan
    /// rather than against a tag passed beside it — a plan for one account
    /// reserved against another is then unrepresentable rather than checked.
    #[must_use]
    pub fn tag(&self) -> crate::addr::Tag {
        let mut tag = [0u8; crate::consts::ADDR_TAG_LEN];
        tag.copy_from_slice(addr::tag_of(&self.src_addr));
        tag
    }

    pub fn position(&self) -> WotsIndex {
        self.position
    }

    pub fn source(&self) -> &Address {
        &self.src_addr
    }

    pub fn change(&self) -> &Address {
        &self.chg_addr
    }

    pub fn send_total(&self) -> u64 {
        self.send_total
    }

    pub fn change_total(&self) -> u64 {
        self.change_total
    }

    pub fn fee_total(&self) -> u64 {
        self.fee_total
    }

    pub fn blk_to_live(&self) -> u64 {
        self.blk_to_live
    }

    /// The ledger balance the plan was built against: `entry.balance` as
    /// [`SpendPlan::new`] observed it, the number `tx_val` will demand
    /// `send + change + fee` equal exactly (`tx.c:776-792`). Stored at
    /// construction rather than summed from the three totals, so what the
    /// keystore records for the reservation is the
    /// observation itself and not a value derived from three other fields;
    /// `tests/spend.rs` asserts the sum agrees, as the second degree of
    /// freedom. The decision that added the figures named the sum; its
    /// reason -- no second, later read of the number -- is met either way.
    pub fn balance(&self) -> u64 {
        self.balance
    }

    /// The two figures a version-4 record carries for this plan's
    /// reservation: [`SpendPlan::balance`] and
    /// [`SpendPlan::blk_to_live`], composed here so no caller assembles a
    /// record field by hand.
    pub fn figures(&self) -> Figures {
        Figures {
            reserved_balance: self.balance(),
            blk_to_live: self.blk_to_live(),
        }
    }

    /// The destinations, in wire order.
    pub fn dsts(&self) -> &[Destination] {
        &self.dsts
    }

    /// The unsigned image these fields describe: zero validation data, no
    /// trailer. Private, so the only route from a plan to a signature-bearing
    /// value is [`SignedTransaction::attach`].
    fn unsigned(&self) -> Result<Transaction> {
        let mut tx = Transaction::new(self.dsts.clone())?;
        tx.src_addr = self.src_addr;
        tx.chg_addr = self.chg_addr;
        tx.send_total = self.send_total;
        tx.change_total = self.change_total;
        tx.fee_total = self.fee_total;
        tx.blk_to_live = self.blk_to_live;
        Ok(tx)
    }
}

/// A transaction with its signature attached, re-validated, and sealed.
///
/// Holds a [`Transaction`] and so bears a signature; its one constructor is
/// the route scan's Reader entry for this module — every input is public
/// data and no signer is reached.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedTransaction {
    tx: Transaction,
}

impl SignedTransaction {
    /// Attaches `sig` to the image `plan` describes, and refuses to unless
    /// it validates the way the node will validate it:
    ///
    /// * `sig.spent_index` must be `plan.position()` —
    ///   [`Error::PositionMismatch`];
    /// * `pk_from_sig` from the words the key started from must recover
    ///   `sig.public_key` — [`Error::SignatureDoesNotRecover`] naming the
    ///   public key;
    /// * the assembled image must pass [`verify_wots`] — the same recovery
    ///   from the wire's own `adrs`, plus `tx_val__wots`'s two comparisons.
    ///
    /// **The `adrs` on the wire is the state `pk_from_sig` leaves behind**,
    /// not the words the key started from. `tx_val__wots` compares the
    /// supplied `adrs` against the post-recovery one (`tx.c:681`), and the
    /// reference requires the last twelve bytes to be a specific triple
    /// (`types.h:441-443`); that triple is what every WOTS+ chain walk ends
    /// on, so taking it from the recovery reproduces it without restating it.
    /// `Ds7` records the reference rejecting an image whose tail is one byte
    /// off; the Ds6 images pin this byte for byte in `tests/spend.rs`.
    ///
    /// The trailer is then sealed: nonce zero, `id = TX_HASH_ID`, the pair
    /// the node writes itself after validation (`tx.c:1286-1287`).
    pub fn attach(plan: &SpendPlan, sig: &SpendSignature) -> Result<SignedTransaction> {
        if sig.spent_index != plan.position {
            return Err(Error::PositionMismatch {
                planned: plan.position.get(),
                signed: sig.spent_index.get(),
            });
        }
        let mut tx = plan.unsigned()?;
        let digest = tx.message_digest();
        let mut adrs: Adrs = sig.adrs;
        let recovered = wots::pk_from_sig(&sig.signature, &digest, &sig.pub_seed, &mut adrs);
        if *recovered != *sig.public_key {
            return Err(Error::SignatureDoesNotRecover { what: "public key" });
        }
        tx.wots = WotsVal {
            signature: *sig.signature,
            pub_seed: sig.pub_seed,
            adrs: adrs.le_image(),
        };
        verify_wots(&tx)?;
        tx.seal();
        Ok(SignedTransaction { tx })
    }

    /// The whole wire image, trailer included: what `/construction/submit`
    /// forwards byte for byte, and the retry artifact a caller keeps outside
    /// the keystore format.
    pub fn wire(&self) -> Vec<u8> {
        self.tx.to_wire()
    }

    /// The transaction id the node will store: `TX_HASH_ID` with the nonce
    /// zero, which is what `/construction/submit` echoes and `/mempool`
    /// lists.
    pub fn id(&self) -> TxId {
        TxId(self.tx.id_digest())
    }

    /// The signed length, `dsa_off`, and the full length, for a caller
    /// reporting what it is about to send.
    pub fn lengths(&self) -> (usize, usize) {
        (self.tx.dsa_off(), self.tx.wire_len())
    }
}

/// `tx_val__wots` (`tx.c:653-694`) over an assembled image, without the
/// tail literal: recover the public key from the wire's own `adrs` over
/// `TX_HASH_MESSAGE`; the post-recovery `adrs` must equal the wire's
/// (`tx.c:681`'s first comparison, which for a real signature also settles
/// the second — a wrong tail is a different post-state, as `Ds7` records);
/// and the recovered key's address hash must be the source's hash half
/// (`tx.c:687-689`). `Ok` is the verdict the reference recorded for `D1v`,
/// `Ds8b` and the four `Ds6` images; the `Err` names which comparison
/// failed (`Ds7`: the address scheme; `Ds8`–`Ds11`: the source hash).
pub fn verify_wots(tx: &Transaction) -> Result<()> {
    let digest = tx.message_digest();
    let supplied = Adrs::from_le_image(&tx.wots.adrs);
    let mut working = supplied;
    let recovered = wots::pk_from_sig(&tx.wots.signature, &digest, &tx.wots.pub_seed, &mut working);
    if working != supplied {
        return Err(Error::SignatureDoesNotRecover {
            what: "address scheme",
        });
    }
    let address = addr::from_wots(&recovered);
    if addr::hash_of(&address) != addr::hash_of(&tx.src_addr) {
        return Err(Error::SignatureDoesNotRecover {
            what: "source address hash",
        });
    }
    Ok(())
}
