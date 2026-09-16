//! `mcm-wallet` — the command layer.
//!
//! The binary is `src/bin/mcm-wallet.rs`; everything it does is here, generic
//! over [`Medium`] and [`Transport`] so the tests drive every command against
//! the scriptable chain rather than against a mock of the wallet.
//!
//! # What this layer is not allowed to hold
//!
//! **A `Wallet` and a mutable `Keystore` at once.** The commands that hold a
//! mutable store are the pre-gate ones — [`create`], [`restore`] and
//! [`reconcile`] — and none of them names a signer or a `Wallet`; every
//! other command takes a `Wallet`, returns rendered text, and never names a
//! signer. `Wallet::store` is `&`-only and there is no `store_mut`, but the
//! crate cannot see whether a caller reached around the gate some other way,
//! so the CLI's own structure is the enforcement and
//! `invariants.rs::the_cli_cannot_reach_around_the_wallet` scans these files
//! for the names that would defeat it.
//!
//! **Why `status` and `reconcile` run before the gate**: a
//! one-shot process meets a divergence *before* a `Wallet` can exist, because
//! `Wallet::open` refuses on one. See [`reconcile`]'s module doc.
//!
//! Returning `Report` rather than a signature-bearing type is load-bearing
//! twice: it keeps these functions out of the route scan's flagged set by
//! construction rather than by allow-listing, and it is what lets every
//! refusal be *rendered and read back* in a test.
//!
//! # The three residues
//!
//! A CLI is where a human meets this project's three unfalsified claims, and
//! rendering them softly is worse than not rendering them:
//!
//! * **submit is a socket write, not a verdict.** `/construction/submit`
//!   writes `OP_TX` to one node and returns before any reply, echoing an id it
//!   computed locally. The output says so.
//! * **`tx_val` has never run offline.** Every check this program can make can
//!   pass on a transaction a node then rejects for a ledger, balance-tally or
//!   block-to-live reason.
//! * **the retry artifact is losable.** `send` prints the signed bytes and
//!   says what they are for, because the operator has to know the hex matters
//!   *before* they discard it.
//!
//! I4's message-quality clause governs all of this, not only
//! `Wallet::open`'s refusal: a message that satisfies the letter and produces
//! a workaround is the failure the invariant exists to prevent.

pub mod address;
pub mod args;
pub mod create;
pub mod discover;
pub mod reconcile;
pub mod restore;

use crate::addr::Tag;
use crate::consts::{ADDR_LEN, ADDR_REF_LEN, ADDR_TAG_LEN, HASHLEN, MFEE, SEED_LEN};
use crate::keystore::{KeyAccess, Keystore, Medium};
use crate::mesh::spend::SpendPlan;
use crate::mesh::codec;
use crate::mesh::{MeshClient, SignedTransaction, Transport, TxId};
use crate::account::WotsIndex;
use crate::recon::{AccountStatus, ChainPosition, Divergence, Expiry, Reservation};
use crate::tx::wire::Destination;
use crate::wallet::{Settlement, Wallet};
use crate::{Error, Result, Secret};

use args::{Command, Spend};

/// What the process exits with. A refusal is never `0`.
///
/// The split is by **what the operator does next**, which is why a transport
/// failure is not its own code: unreachable-during-open is a wallet that did
/// not open (2), unreachable-during-a-command is a command that did not happen
/// (3), and the remedy differs by *when* rather than by kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Code {
    /// The command did what it says.
    Ok = 0,
    /// argv did not parse.
    Usage = 1,
    /// The wallet refused to open: reconciliation found a divergence (I4).
    StartupRefused = 2,
    /// The wallet opened and the command was refused.
    Refused = 3,
}

/// Rendered output and the code to exit with.
pub struct Report {
    pub text: String,
    pub code: Code,
}

impl Report {
    fn ok(text: String) -> Report {
        Report {
            text,
            code: Code::Ok,
        }
    }
    fn refused(text: String) -> Report {
        Report {
            text,
            code: Code::Refused,
        }
    }
}

fn hex_bytes(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

/// **The one place this program turns a tag into something an operator
/// copies**.
///
/// Every command that shows a tag calls this, so what `create` prints, what
/// `address` prints, what `balance` prints and what a refusal names are the
/// same string for the same twenty bytes. Four separate call sites of
/// [`hex_bytes`] would be four chances to print a form no other wallet takes.
///
/// # The rule this establishes, and it is narrower than "print Base58"
///
/// **A destination is printed only where it is the ANSWER to the question
/// asked.** Where the program is naming back something the operator supplied
/// -- `address <tag>`'s no-such-account refusal, say -- it renders hex
/// instead. That is not inconsistency: a Base58 string on screen has been
/// taught by `create`, `address` and `balance` to mean *where money goes*, so
/// echoing an unrecognised argument in that form puts a payable-looking string
/// in front of an operator at the exact moment the program is telling them it
/// knows nothing about it. Hex there is unmistakably *the thing you named*.
///
/// # Why the error is propagated rather than answered with hex
///
/// A fallback would be a second identifier printed at exactly the moment the
/// first one could not be produced, and the operator has no way to tell which
/// kind of string they are looking at. Refusing says the one true thing: this
/// program cannot presently tell you where to send money. The branch is not
/// reachable for a tag — [`crate::base58::encode`] refuses only a NULL or
/// empty input and this payload is twenty-two bytes — which
/// is stated here rather than asserted, because no input reaches it and a
/// marker nobody can discharge is worse than knowledge.
fn destination(tag: &Tag) -> crate::Result<String> {
    crate::addr::tag_to_base58(tag)
}

/// A refusal that names the tag it is about, for the paths that cannot
/// propagate. Used only where a `Report` is already being built for another
/// reason.
fn cannot_render(tag: &Tag, e: &Error) -> Report {
    Report::refused(format!(
        "cannot render the destination for the tag whose hex is {}: {e}",
        hex_bytes(tag)
    ))
}

/// **`needs_master` is gone, and its subject went with it**.
///
/// It answered *does this invocation need the operator to type twenty-four
/// words?* -- a question with a per-command answer, because the seed was
/// reconstructed from a prompt and some commands could avoid it. The seed now
/// lives inside the encrypted store, so the question collapsed: **nothing can
/// be read out of the file without the password**, including the account list
/// `address` prints. Every command needs it and there is no arm to get wrong.
///
/// What did NOT collapse is the other half of that function's finding, and it
/// is asserted by `tests/cli.rs::the_listing_needs_no_node_and_no_seed`: the
/// listing still derives nothing and asks no node. It needs the password
/// because the bytes are encrypted, not because it needs a key. (One more
/// command runs without the password: `submit`, which opens no
/// store at all, and the binary dispatches it before the prompt as it does
/// `create`.)
/// The access an account's kind demands, chosen **per account**.
///
/// Built fresh at each call site rather than threaded: `KeyAccess` is neither
/// `Copy` nor `Clone` -- it borrows a `Secret` and the crate declines to make
/// key access duplicable by derive -- and `reserve_and_sign` takes it by
/// value. Constructing one is a store view and a reference copy.
///
/// The choice is
/// `recon::access_for`'s, the same one `Wallet::open`, `status` and
/// `reconcile` already made: the master for a derived account, the stored root
/// for an imported one. Its two refusals become the errors the call sites
/// already render -- a tag the store does not hold is `NoSuchAccount`, and a
/// derived account in a store holding no master is the same key-access
/// mismatch the store-wide choice produced, since `key_at` refuses
/// `StoredRoot` for a derived record. `access_for` returns no other
/// divergence; the last arm names the class so a widening of it is a
/// refusal here rather than a silent route.
fn key_access<'a, M: Medium>(
    store: &Keystore<M>,
    tag: &Tag,
    master: Option<&'a Secret<SEED_LEN>>,
) -> crate::Result<KeyAccess<'a>> {
    match crate::recon::access_for(store, tag, master) {
        Ok(access) => Ok(access),
        Err(Divergence::NoMasterForDerivedAccount { .. }) => Err(Error::KeyAccessMismatch {
            kind: crate::account::AccountKind::Derived,
        }),
        Err(Divergence::CannotReconcile { cause, .. }) => Err(cause),
        Err(_) => Err(Error::ReconciliationRefused {
            what: "the store's view of this account could not choose its key access",
        }),
    }
}

/// Run one command. The store is consumed: every command but `restore` turns
/// it into a `Wallet` and nothing hands it back.
pub fn run<M: Medium, T: Transport>(
    store: Keystore<M>,
    client: MeshClient<T>,
    command: &Command,
) -> Report {
    // **The seed comes out of the store, not off the terminal**: the password
    // that opened the file is what produced it.
    // Cloned because the store is consumed into a `Wallet` below and the seed
    // has to outlive that move; `Secret` zeroizes, and both copies go when this
    // function returns.
    let master = match store.master() {
        Ok(m) => m.cloned(),
        Err(e) => {
            return Report {
                text: format!("{e}"),
                code: Code::StartupRefused,
            }
        }
    };
    let master = master.as_ref();
    // The pre-gate commands. `restore`, and `address` -- which is
    // the command the deadlock was about, because a `Wallet` refuses a tag the
    // ledger has never held and that is exactly when you need an address to
    // fund -- and `status` and `reconcile`, which act on a divergence
    // and so cannot sit behind a constructor that refuses on one. `create`
    // never reaches here: there is no store to hand in.
    match command {
        Command::Restore { account, scan_to } => {
            return cmd_restore(store, &client, master, *account, *scan_to)
        }
        Command::Address { tag, account } => return cmd_address(&store, tag.as_ref(), *account, master),
        // `discover` sits beside `address` for the same reason and one
        // more: it asks the node about tags the store does NOT hold, and
        // `Wallet::open` refuses a store whose accounts the node does not
        // resolve -- which is the state a sweep exists to report on.
        Command::Discover { to } => return cmd_discover(&store, &client, master, *to),
        // No store at all: the artifact is the input. The binary reaches
        // `run_submit` before it opens one; a caller that hands a store in
        // gets it dropped, unread.
        Command::Submit { artifact } => return cmd_submit(&client, artifact),
        // The explorer verbs, for the same reason: the node is the whole
        // input. The binary reaches `run_explorer` before it prompts.
        Command::LookupTransaction { hash } => return cmd_transaction(&client, hash),
        Command::RecentTransactions { tag, count } => {
            return cmd_recent_transactions(&client, tag, *count)
        }
        Command::Block { at } => return cmd_block(&client, at),
        Command::Blocks { count } => return cmd_blocks(&client, *count),
        Command::Status { tag, scan_to } => return cmd_status(&store, &client, tag, master, *scan_to),
        Command::Reconcile { tag, advance_to } => {
            return cmd_reconcile(store, &client, tag, master, *advance_to)
        }
        _ => {}
    }

    let mut w = match Wallet::open(store, client, master) {
        Ok(w) => w,
        Err(refusal) => {
            return Report {
                text: format!("{refusal}{}", next_steps(&refusal.diverged)),
                code: Code::StartupRefused,
            }
        }
    };

    // An imported-only store has no master and reconciles through the stored
    // root; a derived account with no master never reaches here, because
    // `open` already refused it.
    match command {
        Command::Restore { .. }
        | Command::Address { .. }
        | Command::Discover { .. }
        | Command::Create { .. }
        | Command::Status { .. }
        | Command::Reconcile { .. }
        | Command::Submit { .. }
        | Command::LookupTransaction { .. }
        | Command::RecentTransactions { .. }
        | Command::Block { .. }
        | Command::Blocks { .. } => handled_before_the_wallet(),
        Command::Balance => cmd_balance(&w),
        Command::Settle { tag } => cmd_settle(&mut w, tag, master),
        Command::Send(s) => cmd_send(&mut w, s, master),
        Command::Resign(s) => cmd_resign(&mut w, s, master),
    }
}

/// The in-program spelling of the action a report names, per account, after
/// the report -- and only for the arms an action exists for: an `Ahead` names
/// the `reconcile` line with its index filled in, an `Unlocated` names the
/// `status --scan-to` search and the `reconcile` line to follow it with. The
/// other arms' ACTION lines already say what to do and no command here does
/// it (a refutation pass found a blanket footer false on five of six arms).
///
/// The tag is printed already in its `0x` form so nothing is assembled by
/// hand; a mistyped hex tag reaches `status`/`reconcile`'s no-such-account
/// arm, which pays nobody.
fn next_steps(diverged: &[Divergence]) -> String {
    let mut out = String::new();
    for d in diverged {
        let Divergence::IndexMismatch { tag, found, .. } = d else { continue };
        let t = format!("0x{}", hex_bytes(tag));
        match found {
            ChainPosition::Ahead { index, .. } => out.push_str(&format!(
                "\n\nIn this program, for account {t}: after reading the report above, \
                 `reconcile {t} --advance-to {}` takes the acknowledged path. It derives \
                 index {} again, compares it to the chain, and advances only on a match.",
                index.get(),
                index.get()
            )),
            ChainPosition::Unlocated { .. } => out.push_str(&format!(
                "\n\nIn this program, for account {t}: `status {t} --scan-to <M>` walks \
                 indices 0 through M and reports the index it finds, writing nothing; then \
                 `reconcile {t} --advance-to <N>` with the index it named takes the \
                 acknowledged path, deriving N again and advancing only on a match."
            )),
            ChainPosition::Behind { .. } => {}
        }
    }
    out
}

/// The pre-gate commands cannot reach the dispatch below. A `match` arm rather
/// than a wildcard so that adding a command is a compile error here rather than
/// a silent fall-through, and a `Report` rather than `unreachable!()` because
/// the panic census is right: a CLI that panics on an internal invariant is a
/// CLI that panics.
fn handled_before_the_wallet() -> Report {
    Report::refused("this command is handled before the wallet opens".into())
}

fn cmd_restore<M: Medium, T: Transport>(
    mut store: Keystore<M>,
    client: &MeshClient<T>,
    master: Option<&Secret<SEED_LEN>>,
    account: u32,
    scan_to: Option<u32>,
) -> Report {
    let Some(m) = master else {
        return Report::refused(
            "restore derives an account from the master seed, and none was supplied.".into(),
        );
    };
    match restore::restore_account(&mut store, client, m, account, scan_to) {
        Ok(r) => {
            let restored_tag = match destination(&r.found.tag) {
                Ok(d) => d,
                Err(e) => return cannot_render(&r.found.tag, &e),
            };
            let what = match r.held_at {
                None => "added to the store at that index, in one write".to_string(),
                Some(stored) if stored == r.found.index => format!(
                    "already in the store, at that same index {}; nothing was written",
                    stored.get()
                ),
                Some(stored) => format!(
                    "ALREADY IN THE STORE, at index {} -- and NOT moved. Restore builds an \
                     account the store lacks; moving one it holds is reconciliation, which \
                     shows you the whole store's report first. Run `status 0x{}` to see it and \
                     `reconcile 0x{} --advance-to {}` to act on it.",
                    stored.get(),
                    hex_bytes(&r.found.tag),
                    hex_bytes(&r.found.tag),
                    r.found.index.get()
                ),
            };
            Report::ok(format!(
                "restored account {account}\n  destination  {}\n  index    {} (from the chain, \
                 never assumed)\n  address  {}\n  balance  {} nanoMCM\n  {what}\n\nthe index came from \
                 scanning derived addresses against the one the chain holds for this tag. \
                 Position 0 is a match like any other, never a default.{}",
                restored_tag,
                r.found.index.get(),
                hex_bytes(&r.found.address),
                r.found.balance,
                upgrade_line(&store)
            ))
        }
        // The flag is this program's; the library text names the remedy in
        // its own words and this line gives it a spelling.
        Err(f @ crate::recon::RestoreFailure::NoIndexReproducesTheAddress { scanned, .. }) => {
            Report::refused(format!(
                "{f}\n\nIn this program: `restore --account {account} --scan-to <M>` walks \
                 indices 0 through M instead of 0 through {}. Each index costs one key \
                 derivation.",
                scanned.saturating_sub(1)
            ))
        }
        Err(f) => Report {
            text: format!("{f}"),
            code: Code::Refused,
        },
    }
}

/// One account's state, in the words `balance` and `status` both use.
///
/// Shared so the two commands cannot drift into describing the same three
/// states differently.
fn state_of(status: &AccountStatus) -> String {
    match status {
        AccountStatus::InSync { .. } => "in sync".to_string(),
        // The live line is byte for byte what it was before the diagnosis, and a dead
        // reservation REPLACES it rather than extending it: the old words are
        // literally true and useless beside a dead reservation, and the live line
        // is asserted by equality as a control. The figures go
        // on their own lines beside it, through [`reservation_lines`].
        AccountStatus::SpendOutstanding {
            spent_index,
            reservation,
            ..
        } => match reservation {
            Reservation::Recorded(d) if d.is_dead() => format!(
                "RESERVED SPEND at index {} is DEAD -- the signed artifact can no longer be accepted",
                spent_index.get()
            ),
            _ => format!(
                "SPEND OUTSTANDING at index {} -- not yet seen on the chain",
                spent_index.get()
            ),
        },
        AccountStatus::SpendLanded { spent_index, .. } => format!(
            "spend from index {} has landed -- run `settle`",
            spent_index.get()
        ),
    }
}

/// The reserved spend's two figures and what each says, one line per figure,
/// in the same words on `status` (two-space indent), `balance` (four) and
/// `settle` (two). The words come from one place so
/// the three pages cannot drift, which is `state_of`'s argument again.
///
/// Additive by design: a recorded reservation always gets BOTH lines, each
/// carrying its own verdict, so a reservation dead by both causes says both.
/// A migrated reservation (figures not recorded, format version 3) gets one
/// line saying so and no verdict -- neither live nor dead can be told from
/// the store. A dead reservation gets a closing line that names what
/// is NOT decided (the route out) and states the price of the
/// only other route as a fact, in the unit the audit measured it in; it instructs nothing --
/// no refusal is on these pages, and the route out is escalated.
///
/// What each phrase rests on, read on disk: a deposit credits by tag in place
/// and `tx_val` demands
/// `send + change + fee` equal the balance exactly, so a
/// moved balance is dead for good; block N is the last block that can carry
/// btl N, and `txclean` drops it against the
/// next block, so the artifact is dead once the tip
/// reaches the value; zero never expires.
/// The block-to-live marker in `tests/cli.rs` harvests every decimal token of `status`
/// and `balance` against a ceiling of 64; these lines add the block-to-live
/// and the tip to a page that carried four.
fn reservation_lines(spent_index: WotsIndex, reservation: &Reservation, indent: &str) -> String {
    let mut out = String::new();
    match reservation {
        Reservation::Unrecorded => out.push_str(&format!(
            "{indent}reserved figures  not recorded: this reservation was written under format \
             version 3, which carried neither the balance nor the block-to-live. Whether the \
             artifact can still be accepted cannot be told from this store; the next write \
             re-seals the store as version 4 with the figures declared absent.\n"
        )),
        Reservation::Recorded(d) => {
            let b = d.figures.reserved_balance;
            if d.balance_moved {
                out.push_str(&format!(
                    "{indent}reserved balance  {b} nanoMCM when the spend was built; the ledger holds {} \
                     now. A deposit landed on this tag, and the node demands the signed totals \
                     equal the balance EXACTLY, so the artifact can no longer \
                     be accepted.\n",
                    d.balance_now
                ));
            } else {
                out.push_str(&format!(
                    "{indent}reserved balance  {b} nanoMCM when the spend was built (the ledger holds the \
                     same now)\n"
                ));
            }
            let btl = d.figures.blk_to_live;
            let expiry = match &d.expiry {
                Expiry::NoExpiry => format!("{btl} (never expires)"),
                Expiry::Below { tip } => format!(
                    "{btl} (the node accepts it only while the tip is at or below {btl}, and refuses \
                     it if {btl} is below the tip when it arrives; the tip is {tip})"
                ),
                Expiry::Reached { tip } => format!(
                    "{btl} -- the tip is {tip}: the block-to-live has passed and the artifact can no \
                     longer be accepted"
                ),
                Expiry::Unreadable { cause } => format!(
                    "{btl} (the node accepts it only while the tip is at or below {btl}, and refuses \
                     it if {btl} is below the tip when it arrives); the tip could not be read \
                     ({cause}), so whether it has passed is UNCHECKED here -- not assumed live"
                ),
            };
            out.push_str(&format!("{indent}block-to-live     {expiry}\n"));
            if d.is_dead() {
                // This build offers no route out, on purpose. The first two sentences
                // are the specification's, word for word (*The block-to-live
                // sits inside the signed digest*).
                out.push_str(&format!(
                    "{indent}A dead reservation has no route out: the whole balance at the reserved \
                     key is reachable only by a signature from that key, and the only signature \
                     this wallet will ever produce from that key is the one already produced. No \
                     command offers a second one, on purpose: a second, different signature under \
                     the key at index {} is the key reuse this wallet's refusals exist to prevent, \
                     and its price would be the whole balance at that key.\n",
                    spent_index.get()
                ));
            }
        }
    }
    out
}

/// The one-way crossing, on the page of the command that made it: a
/// version-3 store is read as it is and re-sealed as
/// version 4 by its first commit, after which an older build meets `got >
/// supported` on a real file for the first time and prints the
/// fresh-directory advice -- which, for an open reservation, is the
/// second-signature route. Empty for every store that did not cross under
/// this handle, which is every store this build created and every version-3
/// store a read-only command opened: `open` never rewrites the snapshot, and
/// `status`, `balance` and `address` do not call this. The detector for an
/// `upgraded_from` that reports the crossing before it has happened is the
/// pin test's fourth arm, not a page.
fn upgrade_line<M: Medium>(store: &Keystore<M>) -> String {
    match store.upgraded_from() {
        Some(from) => format!(
            "\n\nThis store was written in format version {} by this command (it was version {from} \
             until now). An older build of this wallet will no longer open \
             it; this build and later ones do. Nothing was retyped and nothing needs to be.",
            crate::keystore::format::VERSION
        ),
        None => String::new(),
    }
}

fn cmd_balance<M: Medium, T: Transport>(w: &Wallet<M, T>) -> Report {
    let accounts = w.accounts();
    if accounts.is_empty() {
        return Report::ok("no accounts in this store.".into());
    }
    let mut out = String::new();
    for (tag, status) in accounts {
        let state = state_of(status);
        let dest = match destination(tag) {
            Ok(d) => d,
            Err(e) => return cannot_render(tag, &e),
        };
        // Padded to the widest a destination can be, because Base58 is
        // variable-width (22 to 31) where the old hex rendering was not, and
        // a right-aligned amount column measured from a moving left edge is
        // worse than no alignment: it looks deliberate.
        out.push_str(&format!(
            "{dest:<width$}  {:>20} nanoMCM  index {}  {}\n",
            status.balance(),
            status.index().get(),
            state,
            width = crate::addr::TAG_BASE58_MAX_CHARS
        ));
        // The reserved figures under the account's row, in `status`'s words.
        // The row itself is unchanged.
        if let AccountStatus::SpendOutstanding {
            spent_index,
            reservation,
            ..
        } = status
        {
            out.push_str(&reservation_lines(*spent_index, reservation, "    "));
        }
    }
    Report::ok(out)
}

/// Where to receive. **No wallet, no chain** — see `cli::address`.
///
/// # The first line is the destination, bare, and that is a decision
///
/// Machine-readable answer first, prose after: an operator copies line one, a
/// script reads line one, and neither has to know how this program formats a
/// paragraph. The rendered form is Base58 rather than hex because **it is the
/// only one of the two that catches a typo** — the Base58 payload carries a
/// CRC16 and [`crate::addr::tag_from_base58`] checks it, where a mistyped hex
/// tag is a perfectly well-formed tag for an address nobody holds and the
/// funds are gone with nothing refused.
///
/// # The hex that remains is a different object, not a second spelling
///
/// The 40-byte ledger address is printed too, indented and labelled. It is
/// not a destination and cannot be confused for one: it is eighty characters
/// where a destination is twenty-two to thirty-one, every other wallet
/// refuses it on sight, and this program's own `send <to>` refuses it as
/// longer than a tag. So there is never a *pair* of strings on screen both of
/// which are "where to send" — which is the transcription hazard printing two
/// forms of one identifier would create.
fn cmd_address<M: Medium>(
    store: &Keystore<M>,
    tag: Option<&Tag>,
    account: Option<u32>,
    master: Option<&Secret<SEED_LEN>>,
) -> Report {
    if let Some(n) = account {
        return cmd_address_of_unstored_account(store, n, master);
    }
    let Some(tag) = tag else {
        return cmd_accounts(store);
    };
    match key_access(store, tag, master).and_then(|access| address::address_of(store, tag, &access)) {
        Ok(w) => match destination(tag) {
            Err(e) => cannot_render(tag, &e),
            Ok(dest) => Report::ok(format!(
            "{dest}\n  address  {}\n  index    {}\n\nThe first line is this account's \
             DESTINATION -- Base58 over the tag and its CRC16, the form every Mochimo wallet \
             takes. Give that to whoever is paying you. It is computed from this store alone: \
             no node was asked, and it is the destination whether or not the chain has ever \
             heard of this tag.\n\nThe indented `address` is the 40-byte entry the \
             LEDGER WILL HOLD for this account at this index. Before the first credit the \
             ledger holds nothing at all, and the entry the first credit creates comes from \
             the tag alone -- it matches this line only because a derived account at index 0 \
             has its tag in both halves. It is not a destination: no wallet takes it, and \
             neither does this one.",
            hex_bytes(&w.address),
            w.index.get()
        )),
        },
        // **Hex, not the destination form**, and deliberately: `dest` here is
        // a re-rendering of what the operator typed for an account this store
        // does not hold. Printing it as Base58 would put a string in exactly
        // the shape this program teaches means *where money goes* on screen at
        // the moment it is saying it knows nothing about it -- and an operator
        // who pasted the wrong tag would be one glance from paying it.
        Err(Error::NoSuchAccount) => Report::refused(format!(
            "no account for the tag {} in this store -- that is the tag you named, in hex so it \
             cannot be mistaken for somewhere to send funds.\n  `create` makes an account; \
             `restore --account N` adds one the chain already knows; `address` with no argument \
             lists what is here.",
            hex_bytes(tag)
        )),
        Err(e) => Report::refused(format!("{e}")),
    }
}

/// `address --account N`: the destination of an account this store does
/// **not** hold, derived from the master it does hold and stored nowhere.
///
/// # The decision this carries out
///
/// `create` derives account 0 and nothing else, and `restore --account N`
/// adds an account only after the chain resolves its tag -- so nobody could
/// be *given* a second account's destination, because the store could not
/// hold an account the chain had never seen. The operator decided on
/// 2026-09-14 to open that loop here, read-only: derive account N, print
/// the destination and the position-0 ledger address exactly as
/// `address <tag>` does, store nothing. Once the destination has been paid,
/// `restore --account N` asks the chain where the account sits and adds it
/// at that position -- 0 for a first credit -- with the same tag as this
/// page. No invariant moves: `Wallet::open`'s refusal on a never-funded
/// account stays, and this is the route around it, not through it.
///
/// # What it writes, reserves and asks: nothing
///
/// The store is borrowed immutably, so a write here is a compile error, and
/// `tests/cli.rs` holds the snapshot bytes identical across the call. No
/// node is asked: the address is a function of the seed.
///
/// # Two refusals
///
/// A store holding no master (imported accounts only) can derive nothing.
/// An account the store already holds is refused rather than answered:
/// its position may be past 0, and position 0's address is one the chain
/// may no longer hold, so `address <destination>` is the page for it.
fn cmd_address_of_unstored_account<M: Medium>(
    store: &Keystore<M>,
    account: u32,
    master: Option<&Secret<SEED_LEN>>,
) -> Report {
    let Some(master) = master else {
        return Report::refused(
            "this store holds no master seed (its accounts are imported), so no account can be \
             derived from it; `address <destination>` prints a stored account's address. Nothing \
             was written."
                .into(),
        );
    };
    let tag = crate::derive::derive_account_tag(master, account);
    let dest = match destination(&tag) {
        Ok(d) => d,
        Err(e) => return cannot_render(&tag, &e),
    };
    match store.view(&tag) {
        Ok(Some(view)) => {
            return Report::refused(format!(
                "account {account} is already in this store (its destination is {dest}, at index \
                 {}); run `address {dest}` for the address it will next present -- position 0's \
                 address is one the chain may no longer hold. Nothing was written.",
                view.wots_index.get()
            ))
        }
        Ok(None) => {}
        Err(e) => return Report::refused(format!("{e}")),
    }
    let address = crate::recon::derived_address_at(master, account, WotsIndex::ZERO);
    Report::ok(format!(
        "{dest}\n  address  {}\n  index    0\n\nNOT STORED. Account {account} was derived from this \
         store's master seed and written nowhere: nothing was written, nothing reserved, no node \
         asked. The first line is its DESTINATION -- Base58 over the tag and its CRC16, the form \
         every Mochimo wallet takes -- and the indented `address` is the 40-byte entry the ledger \
         will hold at index 0 once it is paid. Give the destination to whoever is paying you; once \
         it has been paid, run `restore --account {account}`, which asks the chain where the \
         account sits and adds it to this store at that position (0 for a first credit), under \
         this same tag. Until then the store does not hold it and `balance` will not show it.",
        hex_bytes(&address)
    ))
}

/// `discover [--to N]`: what the node says about accounts `0..=N` derived
/// from the master this store holds.
///
/// # The page's one rule
///
/// **Nothing here says an account does not exist.** The header states the
/// extent searched and how many indices the node resolved; the table lists
/// every index that resolved and every index this store holds; the indices
/// the node did not resolve are named, as indices the node did not resolve,
/// beside the three states that answer conflates. `cli::discover`'s module
/// doc argues it, and it is the reason the default of 64 is defensible:
/// not because 64 is the right number of accounts to look for, but because
/// the number searched is printed on the page and `--to` changes it.
///
/// # What it writes: nothing
///
/// The store is borrowed immutably. No wallet is constructed, no
/// reservation is taken, nothing is signed, and `tests/cli.rs` holds the
/// snapshot bytes identical across the call.
fn cmd_discover<M: Medium, T: Transport>(
    store: &Keystore<M>,
    client: &MeshClient<T>,
    master: Option<&Secret<SEED_LEN>>,
    to: u32,
) -> Report {
    let Some(master) = master else {
        return Report::refused(
            "this store holds no master seed (its accounts are imported), so no account index \
             can be derived from it and there is nothing to sweep; `address` with no argument \
             lists what this store holds. Nothing was written."
                .into(),
        );
    };
    let sweep = match discover::sweep(store, client, master, to) {
        Ok(s) => s,
        Err(discover::SweepFailure::ChainUnreachable {
            account,
            searched,
            cause,
        }) => {
            return Report::refused(format!(
                "the sweep stopped at account index {account}: {cause}\n  {searched} of {} index(es) \
                 were searched. The node was not asked about index {account} or anything above it, \
                 so this page reports NO extent and says nothing at all about those indices -- a \
                 partial sweep printed as a whole one would be asserting absence by omission.\n  \
                 Nothing was written. Fix the node and run it again.",
                u64::from(to) + 1
            ))
        }
    };

    let mut rows = String::new();
    let mut unresolved: Vec<u32> = Vec::new();
    for s in &sweep.sightings {
        // Every index the node resolved, and every index this store holds
        // whatever the node said, gets its own row. A held account the node
        // does not resolve is exactly the emptied-account window, and
        // hiding it would hide the one row an operator most needs.
        if s.entry.is_none() && s.held.is_none() {
            unresolved.push(s.account);
            continue;
        }
        let dest = match destination(&s.tag) {
            Ok(d) => d,
            Err(e) => return cannot_render(&s.tag, &e),
        };
        let balance = match &s.entry {
            Some(e) => nano_and_mcm(i128::from(e.balance)),
            None => "not resolved by the node".to_string(),
        };
        let held = match s.held {
            None => String::new(),
            Some((kind, index)) => format!(
                "  IN THIS STORE ({}, at key index {})",
                match kind {
                    crate::account::AccountKind::Derived => "derived",
                    crate::account::AccountKind::Imported => "imported",
                },
                index.get()
            ),
        };
        rows.push_str(&format!(
            "  {:>5}  {dest:<width$}  {balance}{held}\n",
            s.account,
            width = crate::addr::TAG_BASE58_MAX_CHARS
        ));
    }

    let mut out = format!(
        "searched account indices 0..={to} from this store's master seed -- {} index(es), one \
         node call each. The node resolved {} of them.\n\n{rows}",
        u64::from(to) + 1,
        sweep.resolved()
    );
    if !unresolved.is_empty() {
        out.push_str(&format!(
            "  the node did not resolve {} index(es):{}\n",
            unresolved.len(),
            wrapped_indices(&unresolved)
        ));
    }
    out.push_str(&format!(
        "\n`did not resolve` is what was OBSERVED, and this page does NOT say those accounts do \
         not exist -- it cannot. The node answers `account not found` for a tag the ledger has no \
         entry for, for a tag it holds at ZERO balance, and for a lookup that failed, and it does \
         not tell the three apart; never funded, a node serving another chain, and a seed that is \
         not the one that made the account all produce the first of them. What is reported per \
         index is the node's answer and nothing beyond it.\n\n\
         The extent is 0..={to} because that is what was asked for: `discover --to N` searches \
         0..=N for any N from 1 to {}, and the number searched is on the first line so it can be \
         raised when it is too small. An index the node resolved is added to this store by \
         `restore --account N`. An index you expected to see and do not is a reason to check the \
         node and the seed, not a verdict.\n\n\
         Nothing was written: no account was added, nothing reserved, nothing signed, and the \
         store is unchanged.",
        args::DISCOVER_MAX_TO
    ));
    Report::ok(out)
}

/// A list of indices, sixteen to a line, each line indented under the count
/// that introduces it. A thousand unresolved indices is a legitimate answer
/// and one very long line is not a way to print it.
fn wrapped_indices(indices: &[u32]) -> String {
    let mut out = String::new();
    for (i, n) in indices.iter().enumerate() {
        if i % 16 == 0 {
            out.push_str("\n   ");
        }
        out.push_str(&format!(" {n}"));
    }
    out
}

/// `address` with no tag: what this store holds, from the records alone.
///
/// **No seed and no node**, which is the point — this is the route back to a
/// destination for an operator who has one and cannot name it, including the
/// one `create` just refused the confirmation for.
fn cmd_accounts<M: Medium>(store: &Keystore<M>) -> Report {
    let held = match address::accounts_in(store) {
        Ok(h) => h,
        Err(e) => return Report::refused(format!("{e}")),
    };
    if held.is_empty() {
        return Report::ok(
            "no accounts in this store. `create` makes one; `restore --account N` adds one the \
             chain already knows."
                .into(),
        );
    }
    // **A header, and it is load-bearing rather than decorative.** `address
    // <tag>` puts a bare destination on line one so an operator copies line
    // one and a script reads it. If this listing did the same, a script whose
    // tag argument went missing -- an unquoted empty shell variable -- would
    // silently receive a well-formed destination for whatever account happens
    // to sort first, and publish it. The header makes line one something no
    // parser mistakes for a destination, so the dropped argument fails loudly.
    let mut out = format!("{} account(s) in this store:\n", held.len());
    for h in &held {
        let dest = match destination(&h.tag) {
            Ok(d) => d,
            Err(e) => return cannot_render(&h.tag, &e),
        };
        out.push_str(&format!(
            "  {dest:<width$}  index {}  {}\n",
            h.index.get(),
            match h.kind {
                crate::account::AccountKind::Derived => "derived",
                crate::account::AccountKind::Imported => "imported",
            },
            width = crate::addr::TAG_BASE58_MAX_CHARS
        ));
    }
    out.push_str(
        "\nEach line begins with a DESTINATION -- give one to whoever is paying you. Read from \
         the store's own records: no node was asked and no seed was needed, so this works \
         before the account has any funds and without the phrase. `address <destination>` adds \
         the 40-byte ledger address, and that one does need the seed.",
    );
    Report::ok(out)
}

/// `status`: one account, reconciled now, **before the gate**.
///
/// Exit 0 whenever the comparison ran and produced an answer -- in sync, a
/// spend state, or a divergence, which is an answer about the account and not
/// a refusal of the command; the report goes to stdout with it. Exit 3 when
/// the question could not be asked: the chain unreachable, no master for a
/// derived account, a tag the store does not hold. `Code::StartupRefused` is
/// not borrowed for a divergence here: no wallet was opened, and that code's
/// one meaning is that one refused to.
fn cmd_status<M: Medium, T: Transport>(
    store: &Keystore<M>,
    client: &MeshClient<T>,
    tag: &Tag,
    master: Option<&Secret<SEED_LEN>>,
    scan_to: Option<u32>,
) -> Report {
    match reconcile::account_status(store, client, tag, master, scan_to) {
        // **Rendered, not `{s:?}`**. It was the derived `Debug` of
        // `AccountStatus`, whose `InSync` arm carries a 40-byte `Address`, so
        // this command printed the ledger address as a forty-element DECIMAL
        // byte array -- a third spelling of an object `address` shows in hex
        // and `balance` names by its destination, agreeing with neither, and
        // matching nothing an operator could look up. It contained no `{:02x}`
        // and no `hex` symbol, so a pass over "where does the CLI render an
        // identifier" keyed on hex sites went straight past it.
        Ok(s) => match destination(tag) {
            Err(e) => cannot_render(tag, &e),
            Ok(dest) => {
                // After the state line: the ledger address for an in-sync
                // account, or the reserved figures on their own lines for an
                // outstanding one -- never appended to
                // the state line itself.
                let tail = match &s {
                    AccountStatus::InSync { address, .. } => format!("\n  address  {}", hex_bytes(address)),
                    AccountStatus::SpendOutstanding {
                        spent_index,
                        reservation,
                        ..
                    } => {
                        let lines = reservation_lines(*spent_index, reservation, "  ");
                        format!("\n{}", lines.trim_end_matches('\n'))
                    }
                    AccountStatus::SpendLanded { .. } => String::new(),
                };
                Report::ok(format!(
                    "{dest}\n  balance  {} nanoMCM\n  index    {}\n  state    {}{tail}",
                    s.balance(),
                    s.index().get(),
                    state_of(&s),
                ))
            }
        },
        Err(Divergence::CannotReconcile {
            cause: Error::NoSuchAccount,
            ..
        }) => Report::refused(no_such_account(tag)),
        // The same text `open`'s refusal prints -- one rendering, so what the
        // operator reads when a command reports is what they read when the
        // wallet refuses to start -- with the in-program spelling of its
        // action, and a note that `balance` refuses this store until it is
        // acted on.
        Err(d @ (Divergence::IndexMismatch { .. }
        | Divergence::ReservationUnexplained { .. }
        | Divergence::TagUnresolved { .. })) => match destination(tag) {
            Err(e) => cannot_render(tag, &e),
            Ok(dest) => Report::ok(format!(
                "{dest}\n  state    DIVERGED -- this account would refuse the wallet at startup \
                 (I4). Nothing was changed.\n\n{d}{}",
                next_steps(core::slice::from_ref(&d))
            )),
        },
        Err(d) => Report::refused(format!("{d}")),
    }
}

/// The refusal for a tag this store does not hold, shared by `status` and
/// `reconcile`: hex, not the destination form, for the reason `address`'s
/// arm gives -- it is the string the operator typed, echoed where the
/// program is saying it knows nothing about it.
fn no_such_account(tag: &Tag) -> String {
    format!(
        "no account for the tag {} in this store -- that is the tag you named, in hex so it \
         cannot be mistaken for somewhere to send funds. `address` with no argument lists what \
         is here.",
        hex_bytes(tag)
    )
}

/// `settle`: the page carries the reservation's diagnosis when it stands
/// -- a dead one drops the `resign` prescription, since
/// re-signing dead bytes reproduces bytes the ledger will refuse -- and the
/// crossing line when the settle was the first write over a version-3 store.
fn cmd_settle<M: Medium, T: Transport>(
    w: &mut Wallet<M, T>,
    tag: &Tag,
    master: Option<&Secret<SEED_LEN>>,
) -> Report {
    let outcome = match key_access(w.store(), tag, master) {
        Ok(access) => w.settle_if_landed(tag, &access),
        Err(e) => Err(e),
    };
    let upgrade = upgrade_line(w.store());
    match outcome {
        Ok(Settlement::Settled {
            spent_index,
            index,
        }) => Report::ok(format!(
            "settled: the chain holds this tag at the change key.\n  spent index {}  ->  next \
             index {}\nthe reservation is cleared and the account can spend again. The settled \
             block is kept in the record until the next spend or advance, so a reorg that \
             reverts it is reported with the digest it settled.{upgrade}",
            spent_index.get(),
            index.get()
        )),
        Ok(Settlement::StillOutstanding {
            spent_index,
            reservation,
        }) => {
            let lines = reservation_lines(spent_index, &reservation, "  ");
            let dead = matches!(&reservation, Reservation::Recorded(d) if d.is_dead());
            Report::ok(if dead {
                format!(
                    "NOT settled: the chain still holds this tag at the key that signed (index {}), \
                     and the reserved artifact can no longer be accepted -- the spend will never \
                     land. The store was not advanced.\n{lines}",
                    spent_index.get()
                )
            } else {
                format!(
                    "NOT settled: the chain still holds this tag at the key that signed (index {}).\nThe \
                     spend has not landed. It may never -- submission is a socket write, not a verdict. \
                     If the retry artifact is lost, `resign` rebuilds it.\n{lines}",
                    spent_index.get()
                )
            })
        }
        Ok(Settlement::NothingPending { index }) => Report::ok(format!(
            "nothing is reserved for this tag; it is at index {}.",
            index.get()
        )),
        Err(e) => Report::refused(format!("{e}")),
    }
}

/// The destinations as the wire wants them, with `all` already resolved.
///
/// `amount` is `None` only for the keyword `all`, and only ever at a single
/// destination (the parser enforces both), so `resolved` is the whole balance
/// less the fee and is used exactly once. The planner sorts this list by its
/// 44-byte image afterwards; the order here is the operator's.
fn spend_destinations(s: &Spend, resolved: u64) -> Vec<Destination> {
    s.dsts
        .iter()
        .map(|d| Destination {
            tag: d.to,
            reference: d.reference,
            amount: d.amount.unwrap_or(resolved),
        })
        .collect()
}

/// What a zero change means, said on the page that creates it.
///
/// A change of zero empties the account, and the Mesh's tag resolution
/// answers *account not found* for a tag it holds at zero balance -- the
/// middleware's quorum discards the entry. `Wallet::open` fails closed on
/// that answer, so the gated verbs refuse until the tag is paid again. The
/// route to the socket meanwhile is `submit`, which opens no store.
///
/// Printed whenever the change is zero, not only for the `all` keyword: an
/// operator who typed `balance − fee` by hand reaches exactly the same state
/// and is owed the same warning.
fn emptying_notice(plan: &SpendPlan, settle_arg: &str) -> String {
    if plan.change_total() != 0 {
        return String::new();
    }
    format!(
        "\nTHIS EMPTIES THE ACCOUNT. The change is zero, so nothing returns to your next key \
         under {settle_arg}.\n  The Mesh reports a tag it holds at zero balance as \"account not \
         found\", which it does not distinguish from never funded or from a failed lookup, so \
         once this lands `balance`, `settle`, `send` and `resign` on this account will refuse to \
         open until it is paid again.\n  Keep the artifact below. `submit` writes it to the \
         socket without opening the store, and is the route to a node while the account reads as \
         not found.\n"
    )
}

/// Lay the spend out, resolving `all` against the same ledger observation the
/// plan is built on.
///
/// **Why this unrolls `Wallet::plan` instead of calling it.** `plan` is
/// `spend_addresses` + `resolve_tag` + `SpendPlan::new`, and for `all` the
/// amount is a function of the balance that middle call returns. Reading the
/// balance first and then calling `plan` would be two observations of a
/// moving number: if a credit landed between them the change would not be
/// zero and `all` would quietly fail to empty the account. Unrolled, there is
/// one `resolve_tag` -- the same one `plan` makes, no more -- and the amount
/// and the plan are computed from the same `entry`.
///
/// Without `all` this is `plan` exactly, and takes the same route.
fn plan_spend<M: Medium, T: Transport>(
    w: &Wallet<M, T>,
    s: &Spend,
    access: &KeyAccess<'_>,
) -> Result<SpendPlan> {
    if !s.spends_everything() {
        return w.plan(&s.tag, access, spend_destinations(s, 0), s.fee_total, s.blk_to_live);
    }
    let addresses = w.spend_addresses(&s.tag, access)?;
    let entry = w.client().resolve_tag(&s.tag)?;
    let amount = spend_all_amount(entry.balance, s.fee_total)?;
    SpendPlan::new(
        &addresses,
        &entry,
        spend_destinations(s, amount),
        s.fee_total,
        s.blk_to_live,
    )
}

/// `balance − fee`, or the refusal that says why there is nothing to send.
///
/// A balance at or below the fee leaves nothing for a destination, and a
/// destination amount of zero is refused by the node's own rule, so this is
/// reported as the insufficient balance it is rather than as a zero amount
/// the operator never typed.
fn spend_all_amount(balance: u64, fee_total: u64) -> Result<u64> {
    match balance.checked_sub(fee_total) {
        Some(0) | None => Err(Error::InsufficientBalance {
            balance,
            needed: fee_total.saturating_add(1),
        }),
        Some(amount) => Ok(amount),
    }
}

/// The destinations `resign` rebuilds the reserved plan from.
///
/// `all` is reproducible: it resolves against the balance now, and if the
/// balance is what it was when the reservation was made the amount is the
/// same and the digest matches. If it moved, the amount differs, the digest
/// differs, and `resign` refuses as a different transaction -- which is
/// correct, because the bytes that were signed encode the old amount and
/// those are the only bytes the reserved key will ever produce.
fn resign_destinations<M: Medium, T: Transport>(
    w: &Wallet<M, T>,
    s: &Spend,
    access: &KeyAccess<'_>,
) -> Result<Vec<Destination>> {
    if !s.spends_everything() {
        return Ok(spend_destinations(s, 0));
    }
    let _ = access;
    let entry = w.client().resolve_tag(&s.tag)?;
    let amount = spend_all_amount(entry.balance, s.fee_total)?;
    Ok(spend_destinations(s, amount))
}

/// The lines of the page that list what is being sent, one per destination.
///
/// Every destination is shown in the checksummed form whichever form was
/// typed, with its amount and its reference when it has one, so the whole
/// spend can be compared against the payees before anything is signed. The
/// order is the operator's, not the wire's: it is what they typed and what
/// `resign` will demand back.
fn destination_lines(dsts: &[Destination]) -> core::result::Result<String, (Tag, Error)> {
    let mut out = String::new();
    for (i, d) in dsts.iter().enumerate() {
        let shown = destination(&d.tag).map_err(|e| (d.tag, e))?;
        out.push_str(&format!("  {:>3}. {} nanoMCM\n       to  {shown}\n", i + 1, d.amount));
        let r = reference_line("       ref ", &d.reference);
        if !r.is_empty() {
            out.push_str(&r);
        }
    }
    Ok(out)
}

/// The `ref` line of `send`'s page and the `reference` line of `resign`'s,
/// present only when a reference was given: the field's ASCII up to its
/// first NUL, which `--ref` guarantees, so the operator sees the text they
/// typed beside the other figures `resign` will demand. Empty for the zero
/// field, so a page without the flag is what it was before the flag existed.
fn reference_line(label: &str, field: &[u8; ADDR_REF_LEN]) -> String {
    if *field == [0u8; ADDR_REF_LEN] {
        return String::new();
    }
    let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    format!("{label}{}\n", String::from_utf8_lossy(&field[..end]))
}

/// The block-to-live, rendered so the operator can record it beside the
/// artifact.
///
/// The value is inside the signed digest (`blk_to_live` is the last field of
/// `TXHDR`) and `resign` refuses without it, and once no
/// command printed it in any labelled or decimal form. What each phrase
/// rests on, read on disk: zero can never expire; a non-zero
/// value expires for every block number greater than it,
/// which a block enforces against its own number and the queue against the
/// NEXT block, so the transaction is dead once the tip reaches the value; and
/// on arrival a node refuses a value more than 256 blocks past its tip.
///
/// The first mitigation, and no longer the only copy: the record carries the
/// value (format version 4) and `status`/`balance` render it
/// from the store on its own line through `reservation_lines`, which is what
/// `tests/cli.rs::the_block_to_live_is_recovered_from_the_store_without_knowing_the_value`
/// performs -- an operator who lost this page recovers the reservation from
/// the pages alone. This line stays because the value belongs
/// beside the bytes it is signed into.
fn block_to_live_line(blk_to_live: u64) -> String {
    if blk_to_live == 0 {
        "0 (never expires: a node that holds the transaction keeps it until it lands)"
            .to_string()
    } else {
        // The whole of the node's rule, both sides: a value below the tip
        // at arrival is refused as surely as one more than 256 blocks past
        // it, and this page is where an operator who typed `--btl` below the
        // tip learns why the node dropped it.
        // The plan builder still takes no block number; nothing here asks
        // the chain.
        format!(
            "{blk_to_live} (the node accepts it only while the tip is at or below {blk_to_live}, \
             and refuses it on arrival if {blk_to_live} is below the tip or more than 256 blocks \
             past it)"
        )
    }
}

/// The residue block `send` prints beside the artifact.
fn artifact_notices(wire_hex: &str) -> String {
    format!(
        "RETRY ARTIFACT -- save this before going further:\n\n{wire_hex}\n\nThese are the signed \
         bytes. If submission fails and you lose them, `resign` is the only recovery, and it \
         needs the SAME destination, amount, fee, block-to-live and reference (`--ref`, if one \
         was given) -- anything else is refused as a different transaction. The block-to-live is printed above; record it with the \
         bytes, because nothing else keeps it.\n\nThis transaction passed every check that can \
         be run offline. The node applies the ledger, the balance tally and the block-to-live \
         range after we are gone, and a rejection there is silent to this program.\n"
    )
}

/// What `send` says under a refused socket write: the artifact on the page
/// is the only copy there is.
const SEND_REFUSAL: &str =
    "The reservation is open and the artifact above is the only copy. Save it.";

/// What `resign` says under a refused socket write.
///
/// The artifact is NOT the only copy -- `resign` reproduces it -- so the
/// page says what to do rather than what to save. It claims only the
/// store: a submission can fail after the body is on the socket, so whether
/// the bytes reached a node is not knowable here, and `settle` is what
/// answers it once the chain has moved.
fn resign_refusal(settle_arg: &str) -> String {
    format!(
        "The store was not changed and the reservation is still open. Whether these bytes \
         reached the node is not known here -- a submission can fail after the body is on the \
         socket. `settle {settle_arg}` once the chain has moved says whether they landed; \
         `resign` with the same values reproduces them and tries the socket again."
    )
}

/// **The submission and its two renderings, shared by `send` and `resign`**.
///
/// One tail rather than two so the two commands that write to the socket
/// cannot drift into describing the write differently -- `state_of`'s
/// argument, applied to the residue this program most needs to render
/// exactly: a 200 from `/construction/submit` is a socket write, not a
/// verdict. `on_refusal` is the one sentence that differs,
/// because what the operator holds afterwards differs: after `send` the
/// artifact on the page is the only copy; after `resign` it is not, since
/// `resign` reproduces it. The exit code is `Refused` on either failure,
/// for the reason `Code` gives: a write that did not happen is a command
/// that did not happen. The page is complete before the write on both
/// arms, so the artifact reaches the operator whatever the socket does --
/// on stdout with exit 0, on stderr with exit 3, `main` routing by the
/// code alone (recorded as `resign`'s accepted cost).
///
/// The type is the mechanism, not a check: this takes a
/// `&SignedTransaction`, and the only values the two callers can hand it
/// are the one `reserve_and_sign` released behind the receipt and the one
/// `resign_pending` digest-checked against the store's reservation.
fn ship<M: Medium, T: Transport>(
    w: &Wallet<M, T>,
    signed: &SignedTransaction,
    settle_arg: &str,
    mut page: String,
    on_refusal: &str,
) -> Report {
    match w.submit(signed) {
        Ok(id) => {
            page.push_str(&submitted_block(&id, settle_arg));
            Report::ok(page)
        }
        Err(e) => {
            page.push_str(&format!("\nsubmission FAILED: {e}\n{on_refusal}"));
            Report::refused(page)
        }
    }
}

/// What a successful write says, on every page that makes one: `send`'s,
/// `resign`'s and `submit`'s. One function, so the sentence that a 200 is a
/// socket write and not acceptance cannot drift between the three.
fn submitted_block(id: &TxId, settle_arg: &str) -> String {
    format!(
        "\nsubmitted: the node accepted the SOCKET WRITE. THIS IS NOT ACCEPTANCE OF THE \
         TRANSACTION.\n  id {}  (computed locally, echoed back -- not the node's \
         verdict)\n\nThe node validates after we are gone. Run `settle {}` once the \
         chain has moved to learn what actually happened.",
        hex_bytes(&id.0),
        settle_arg
    )
}

/// `submit <artifact-hex>`: the artifact `send` printed, written to the
/// socket as it is.
///
/// # The hole this closes
///
/// After a spend empties an account the Mesh reports its tag as not found,
/// `Wallet::open` refuses, and an operator holding a valid signed artifact
/// had no product route to the socket: `resign` needs the node to resolve
/// the tag first. This command needs no store, opens none and asks no
/// password: the artifact is the operator's input and the socket the only
/// output. It reserves nothing, signs nothing and writes nothing to disk;
/// the binary reaches it before the password prompt, as it does `create`.
///
/// # What it refuses, and what it does not judge
///
/// The hex must decode; the bytes must parse as a transaction through
/// `tx::wire::Transaction`; and the parsed transaction must re-serialize to
/// exactly the bytes given -- a partial trailer, which `from_wire`
/// zero-extends, is refused rather than repaired, because the bytes on the
/// socket would not be the bytes the operator holds. That is layout only.
/// This crate has no transaction validator and this command does not
/// pretend to one: a signature that does not recover, a passed
/// block-to-live, a balance the ledger no longer holds are the node's to
/// refuse, silently, exactly as `send`'s page says. Every refusal here is
/// made before any socket is opened, and the page says so.
///
/// # The page
///
/// The `submitted:` block is `send`'s, from [`submitted_block`], so the
/// sentence that a 200 is a socket write and not acceptance is the same
/// sentence; `settle` is named with the source tag read out of the
/// artifact's own header.
fn cmd_submit<T: Transport>(client: &MeshClient<T>, artifact_hex: &str) -> Report {
    const NOTHING: &str =
        "Nothing was written to the socket, nothing to disk, and no store was opened.";
    let bytes = match crate::mesh::hex::decode(artifact_hex.trim(), "artifact") {
        Ok(b) => b,
        Err(e) => return Report::refused(format!("the artifact is not hex: {e}\n{NOTHING}")),
    };
    let tx = match crate::tx::wire::Transaction::from_wire(&bytes) {
        Ok(tx) => tx,
        Err(e) => {
            return Report::refused(format!(
                "the artifact does not parse as a transaction: {e}\n{NOTHING}"
            ))
        }
    };
    // Byte-identical or refused: layout is the whole of what is judged here.
    if tx.to_wire() != bytes {
        return Report::refused(format!(
            "the artifact is not a whole transaction image: {} bytes were given and the \
             transaction they describe is {} bytes, so the bytes on the socket would not be the \
             bytes you hold. A truncated or padded artifact is refused rather than repaired.\n\
             {NOTHING}",
            bytes.len(),
            tx.wire_len()
        ));
    }
    let mut source = [0u8; crate::consts::ADDR_TAG_LEN];
    source.copy_from_slice(&tx.src_addr[..crate::consts::ADDR_TAG_LEN]);
    let settle_arg = match destination(&source) {
        Ok(d) => d,
        Err(e) => return cannot_render(&source, &e),
    };
    let mut page = format!(
        "submitting {} bytes ({} hex characters) from {settle_arg}\n\nNo store was opened and no \
         password asked: the artifact is the input, and this command's one job is to reach the \
         socket. It reserves nothing, signs nothing and writes nothing to disk. The bytes were \
         checked for layout only -- this program has no transaction validator -- so a signature \
         that does not recover, a passed block-to-live or a balance the ledger no longer holds is \
         refused by the node, silently.\n",
        bytes.len(),
        bytes.len() * 2
    );
    match client.submit_wire(&bytes, TxId(tx.id_digest())) {
        Ok(id) => {
            page.push_str(&submitted_block(&id, &settle_arg));
            Report::ok(page)
        }
        Err(e) => {
            page.push_str(&format!(
                "\nsubmission FAILED: {e}\nThe artifact is unchanged and still yours. Whether the \
                 bytes reached a node before the failure is not knowable here; `settle {settle_arg}` \
                 answers it once the chain has moved, and this command can be run again."
            ));
            Report::refused(page)
        }
    }
}

/// [`cmd_submit`] for the binary, which reaches it before any store is
/// opened -- the one command besides `create` that `run` never sees from
/// there.
pub fn run_submit<T: Transport>(client: &MeshClient<T>, artifact_hex: &str) -> Report {
    cmd_submit(client, artifact_hex)
}

/// The four read-only verbs for the binary, which reaches them **before the
/// password prompt and before any store is opened**, exactly as it reaches
/// `submit`.
///
/// `--dir` is still required of them by the parser, as of every verb, and is
/// not read, created or locked: an operator can ask a node about a block
/// with no wallet on the machine at all. A command this is called with that
/// is not one of the four is a caller error, and is reported as one rather
/// than silently doing nothing.
pub fn run_explorer<T: Transport>(client: &MeshClient<T>, command: &Command) -> Report {
    match command {
        Command::LookupTransaction { hash } => cmd_transaction(client, hash),
        Command::RecentTransactions { tag, count } => cmd_recent_transactions(client, tag, *count),
        Command::Block { at } => cmd_block(client, at),
        Command::Blocks { count } => cmd_blocks(client, *count),
        other => Report::refused(format!(
            "internal: {other:?} is not one of the read-only verbs and cannot be run without a store"
        )),
    }
}

fn cmd_send<M: Medium, T: Transport>(
    w: &mut Wallet<M, T>,
    s: &Spend,
    master: Option<&Secret<SEED_LEN>>,
) -> Report {
    let plan = match key_access(w.store(), &s.tag, master).and_then(|access| plan_spend(w, s, &access)) {
        Ok(p) => p,
        Err(e) => return Report::refused(format!("{e}")),
    };
    let signed = match key_access(w.store(), &s.tag, master) {
        Ok(access) => match w.reserve_and_sign(&plan, access) {
            Ok(t) => t,
            Err(e) => return Report::refused(format!("{e}")),
        },
        Err(e) => return Report::refused(format!("{e}")),
    };
    let settle_arg = match destination(&s.tag) {
        Ok(d) => d,
        Err(e) => return cannot_render(&s.tag, &e),
    };
    // **Where the money is going, read back in the checksummed form**.
    //
    // A `send` page that showed the artifact, the locally-computed id and a
    // `settle <src>` hint would leave the value of `<to>` visible only inside
    // two thousand characters of wire hex -- defeating the argument for
    // printing Base58 everywhere else, on the one path where money actually
    // moves. An operator who supplied `0x`-hex, the form with no checksum,
    // needs the chance to compare what this program understood against what
    // the payee's wallet says.
    //
    // The list is read off the PLAN, not off argv, so the page cannot
    // disagree with the bytes: the planner sorted the destinations into the
    // node's own order, and that is the order signed and submitted.
    let listed = match destination_lines(plan.dsts()) {
        Ok(l) => l,
        Err((tag, e)) => return cannot_render(&tag, &e),
    };
    let wire_hex = hex_bytes(&signed.wire());
    // The block-to-live beside the other three values `resign` will demand,
    // and the crossing line when this reservation is the first write over a
    // version-3 store -- which an ordinary `send` is, since `reserve_and_sign`
    // commits before it signs.
    let out = format!(
        "sending {} nanoMCM to {} destination(s)\n{listed}  from   {settle_arg}\n  fee    {} total \
         (the node's floor is {MFEE} per destination, {} here)\n  change {} to your own next key \
         under this tag\n  btl    {}\n\nCheck every destination against its payee before going \
         further. Each is shown in the checksummed form whichever form you typed, so it can be \
         compared character for character with what their wallet shows. They are listed in the \
         order that goes on the wire, which the layout sorts and which need not be the order you \
         typed.\n{}\n{}{}",
        plan.send_total(),
        plan.dsts().len(),
        plan.fee_total(),
        MFEE.saturating_mul(u64::try_from(plan.dsts().len()).unwrap_or(u64::MAX)),
        plan.change_total(),
        block_to_live_line(plan.blk_to_live()),
        emptying_notice(&plan, &settle_arg),
        artifact_notices(&wire_hex),
        upgrade_line(w.store())
    );
    ship(w, &signed, &settle_arg, out, SEND_REFUSAL)
}

/// `resign`: reproduce the reserved artifact and **submit it**.
///
/// What it rests on is the type and the gate below it, not a check here:
/// the bytes `resign_pending` returns are, by its digest comparison, the
/// store's own reservation signed by the reserved key, so nothing this
/// command ships is bytes this wallet did not sign, and there is no state
/// in which it ships with no reservation behind it. What that does NOT
/// cover is whether the matched reservation is still live: a passed
/// block-to-live is in no plan input, so an expired reservation reproduces
/// and is written under `submitted:` exactly as `send` writes one -- the
/// expired-reservation scenario. `status`, `balance` and `settle` say the
/// reservation is dead before an operator reaches this verb; whether this
/// verb should refuse or warn instead of shipping is the route-out question,
/// which is open. (A moved balance never reaches the write: the
/// balance is a plan input, so the rebuilt digest differs and
/// `DigestMismatch` refuses first.)
///
/// What the write does and does not establish is [`ship`]'s text, `send`'s
/// own; the exit-0 page is on stdout and the exit-3 page on stderr, the
/// artifact on whichever the socket decides. The page is built BEFORE the
/// destination is rendered, so a render failure returns the reproduction
/// with the refusal appended rather than in place of it: this page may be
/// the only rendering of the only bytes that can move those funds.
///
/// There are two refusal arms and they refuse for different reasons. A plan
/// that is not the reserved one signs nothing and ships nothing, which the
/// wrong-spend test in `tests/cli.rs` holds at the socket (a fault-injection
/// row is the injection). A reservation the chain has already moved past has
/// nothing to reproduce at all, and its page names `settle` and says what the
/// chain does and does not establish -- the arm a run against mainnet asked
/// for, where the chain-address guard's three-cause divergence page had been
/// standing in and naming the wrong verb.
fn cmd_resign<M: Medium, T: Transport>(
    w: &mut Wallet<M, T>,
    s: &Spend,
    master: Option<&Secret<SEED_LEN>>,
) -> Report {
    let access = match key_access(w.store(), &s.tag, master) {
        Ok(access) => access,
        Err(e) => return Report::refused(format!("{e}")),
    };
    let dsts = match resign_destinations(w, s, &access) {
        Ok(d) => d,
        Err(e) => return Report::refused(format!("{e}")),
    };
    // The page lists them in the order the planner will put them on the wire,
    // which is the same sort `SpendPlan::new` applies, so `send`'s page and
    // this one list the same spend the same way.
    let mut listed_dsts = dsts.clone();
    listed_dsts.sort_by_key(Destination::mdst_image);
    match w.resign_pending(&s.tag, &access, dsts, s.fee_total, s.blk_to_live) {
        Ok(signed) => {
            let wire_hex = hex_bytes(&signed.wire());
            // The value that matched, on the page that replaces the lost
            // one; then the artifact; then the write.
            let listed = match destination_lines(&listed_dsts) {
                Ok(l) => l,
                Err((tag, e)) => return cannot_render(&tag, &e),
            };
            let page = format!(
                "reproduced {} destination(s)\n{listed}block-to-live {}\n{}\nThese are the SAME \
                 bytes the original signing produced -- the reserved key signed the reserved \
                 digest again, which WOTS+ determinism makes byte-identical. No second signature \
                 was created.\n",
                listed_dsts.len(),
                block_to_live_line(s.blk_to_live),
                artifact_notices(&wire_hex)
            );
            let settle_arg = match destination(&s.tag) {
                Ok(d) => d,
                Err(e) => return Report::refused(format!("{page}\ncannot render the destination for the tag whose hex is {}: {e}", hex_bytes(&s.tag))),
            };
            ship(w, &signed, &settle_arg, page, &resign_refusal(&settle_arg))
        }
        Err(Error::DigestMismatch) => Report::refused(
            "this is not the spend that was reserved.\n  `resign` rebuilds the reserved plan and \
             compares it to what the store recorded; the destination, amount, fee, \
             block-to-live or reference differs.\n  ACTION: re-run with the exact values the \
             original `send` used, `--ref` included if one was given. Nothing was signed."
                .into(),
        ),
        // **The page a live chain asked for.** Until it did, this state --
        // the chain standing at the reservation's change key -- reached the
        // operator as the chain-address guard's three-cause divergence page,
        // which named `reconcile` and none of whose causes applied. The
        // destination is rendered here rather than before the match because
        // the success path deliberately builds its page first (see this
        // function's doc); an unrenderable tag still gets an answer it can
        // act on, since `settle` takes the hex form too.
        Err(Error::ReservationLanded {
            spent_index,
            settled_index,
        }) => {
            let settle_arg =
                destination(&s.tag).unwrap_or_else(|_| format!("0x{}", hex_bytes(&s.tag)));
            Report::refused(format!(
                "the chain has moved past the key this reservation holds, so there is nothing \
                 left to reproduce.\n  The chain holds this tag at the key at position \
                 {settled_index}, which is the change key of the reservation at position \
                 {spent_index} -- the state reconciliation calls a landed spend, and the one \
                 `settle` resolves.\n  ACTION: `settle {settle_arg}`, which re-reads the chain, \
                 clears the reservation and keeps the settled block, so a reorg that reverts it \
                 is reported with the digest it settled. Nothing was reserved, nothing was \
                 signed, and nothing reached the socket here.\n  What was observed is the chain \
                 standing at the change key, not which transaction put it there: a change \
                 address follows the POSITION and not the transaction, so any spend from the \
                 reserved key leaves the tag exactly here. `transaction <hash>` on the id the \
                 original `send` printed is what names it."
            ))
        }
        Err(e) => Report::refused(format!("{e}")),
    }
}

/// `reconcile`: the acknowledged path, **before the gate**.
///
/// The whole store's report is printed first, on every path including the
/// success path, because the evidence that this advance is wrong most often
/// lives in another account's report and the write is the most dangerous one
/// this program makes. Exit 0 on the advance, 3 on every refusal.
fn cmd_reconcile<M: Medium, T: Transport>(
    mut store: Keystore<M>,
    client: &MeshClient<T>,
    tag: &Tag,
    master: Option<&Secret<SEED_LEN>>,
    advance_to: u32,
) -> Report {
    let reviewed = match reconcile::advance_acknowledged(&mut store, client, tag, master, advance_to) {
        Ok(r) => r,
        Err(e) => return Report::refused(format!("{e}")),
    };
    // The report of every diverged account as it stood before the decision,
    // each in the words `balance` uses when it refuses -- one rendering per
    // account -- under a header that says what this page is, because
    // `StartupRefusal`'s own header ("WALLET WILL NOT START") would read as a
    // refusal of this command on the path where it advanced.
    let report = if reviewed.reports.is_empty() {
        String::new()
    } else {
        let mut r = format!(
            "THE STORE BEFORE THIS DECISION: {} of {} account(s) diverged. Read every report \
             below -- the evidence that one account's advance is wrong is most often in \
             another account's.\n\n",
            reviewed.reports.len(),
            reviewed.accounts
        );
        for d in &reviewed.reports {
            r.push_str(&format!("{d}\n\n"));
        }
        r
    };
    let others = reviewed.reports.iter().filter(|d| d.tag() != *tag).count();
    let still = if others > 0 {
        format!(
            "\n{others} other account(s) in the report above are still diverged; `balance` \
             refuses this store until each is reconciled."
        )
    } else {
        String::new()
    };
    match reviewed.outcome {
        reconcile::Outcome::NotHeld => Report::refused(no_such_account(tag)),
        reconcile::Outcome::NothingToReconcile(_) => Report::refused(format!(
            "{report}account 0x{}: not diverged; there is nothing to reconcile.{still}",
            hex_bytes(tag)
        )),
        reconcile::Outcome::SecondInstanceSignal { other } => Report::refused(format!(
            "{report}NOT ADVANCED. Account 0x{} shows a spend this wallet did not make -- a \
             reservation the chain explains at neither of its keys -- which is the signal that \
             a SECOND WALLET is live on this seed. Advancing account 0x{} would hand that wallet \
             the key at index {advance_to} as well. Find the other wallet first (compare the key \
             streams above); nothing was written.",
            hex_bytes(&other),
            hex_bytes(tag)
        )),
        reconcile::Outcome::NoAdvance { target: None } => Report::refused(format!(
            "{report}This divergence has no advance to acknowledge. Advancing is only correct \
             when the chain is AHEAD of the local index, at an index the walk confirmed; the \
             report above says what the walk found, and for this account it walked indices 0 \
             through {advance_to} as well as the window. Nothing was written.{still}"
        )),
        reconcile::Outcome::NoAdvance { target: Some(t) } => Report::refused(format!(
            "{report}--advance-to {advance_to} does not match the index this divergence reports \
             ({t}). Type the number in the report above. Nothing was written.{still}"
        )),
        reconcile::Outcome::Advanced { index } => Report::ok(format!(
            "{report}advanced account 0x{} to index {index} after operator review. Index {index} \
             was derived and its address compared to the one the chain holds before anything was \
             written; the report above is what was acknowledged. The key at every skipped \
             position is now unreachable by this wallet, which is the point: they may already \
             have signed.{still}{}",
            hex_bytes(tag),
            upgrade_line(&store)
        )),
    }
}

// ---------------------------------------------------------------------------
// The explorer verbs: a node, and nothing else
// ---------------------------------------------------------------------------

/// nanoMCM rendered beside its MCM, which is the figure a person reads.
///
/// One MCM is 1,000,000,000 nanoMCM. The sign is
/// carried, because a source operation is a debit.
fn nano_and_mcm(v: i128) -> String {
    // The leading `-` is `minus` and not `sign`: the I1 scan's taint set is a
    // fixpoint over function NAMES, `wots.rs::sign` is in it, and a local of
    // that name in any body reads as a function that reaches the signer. The
    // scan is name-based on purpose; this keeps it exact.
    let a = v.unsigned_abs();
    let whole = a / 1_000_000_000;
    let frac = a % 1_000_000_000;
    let minus = if v < 0 { "-" } else { "" };
    format!("{minus}{a} nanoMCM ({minus}{whole}.{frac:09} MCM)")
}

/// A Mesh timestamp: milliseconds since the epoch, as the middleware sends
/// it. Rendered as the integer seconds and the raw value, because this crate
/// carries no calendar and will not invent one.
fn stamp(ms: i64) -> String {
    format!("{ms} ms since the epoch ({} s)", ms / 1_000)
}

/// An operation's address, rendered for a person where it can be.
///
/// The Mesh sends a 20-byte tag for the accounts it indexes and a 40-byte
/// ledger address elsewhere; the first is what a person holds and is shown
/// in the checksummed Base58 form beside its hex, and the second is shown as
/// hex with a word saying what it is, because a ledger address is not a
/// destination and must never be pasted as one.
fn explorer_address(text: &str) -> String {
    let body = text.strip_prefix("0x").unwrap_or(text);
    if body.len() == ADDR_TAG_LEN * 2 {
        let mut tag = [0u8; ADDR_TAG_LEN];
        for (i, b) in tag.iter_mut().enumerate() {
            match body.get(i * 2..i * 2 + 2).and_then(|p| u8::from_str_radix(p, 16).ok()) {
                Some(v) => *b = v,
                None => return text.to_owned(),
            }
        }
        return match destination(&tag) {
            Ok(d) => format!("{d}  ({text})"),
            Err(_) => text.to_owned(),
        };
    }
    if body.len() == ADDR_LEN * 2 {
        return format!("{text}  (a 40-byte ledger address: tag then the key's hash -- not a destination)");
    }
    text.to_owned()
}

/// The sentence every page that reads `/search/transactions` carries.
const SEARCH_CONVENTION: &str = "read from /search/transactions, the Mesh's indexer. That endpoint \
     replays rows written when the block was first seen: the source is debited its GROSS amount \
     and the change comes back as its own destination. /block re-parses the wire and shows the \
     NET debit with no change operation. Both are correct and this page does not reconcile them.";

/// The sentence every page that reads `/block` carries.
const BLOCK_CONVENTION: &str = "read from /block, which re-parses the wire: a source is debited \
     its NET amount and the change does not appear as an operation. The indexer's \
     /search/transactions shows the same transaction gross, with the change as a destination.";

fn operation_lines(ops: &[codec::Operation], indent: &str) -> String {
    let mut out = String::new();
    for op in ops {
        out.push_str(&format!("{indent}{:>2}. {:<21} {}\n", op.index, op.kind, nano_and_mcm(op.amount)));
        out.push_str(&format!("{indent}    {}\n", explorer_address(&op.address)));
        if !op.memo.is_empty() {
            out.push_str(&format!("{indent}    memo {}\n", op.memo));
        }
    }
    out
}

fn metadata_lines(meta: &[(String, String)], indent: &str) -> String {
    let mut out = String::new();
    for (k, v) in meta {
        out.push_str(&format!("{indent}{k} = {v}\n"));
    }
    out
}

/// `transaction <hash>`: one transaction from the indexer.
pub fn cmd_transaction<T: Transport>(client: &MeshClient<T>, hash: &[u8; HASHLEN]) -> Report {
    let page = match client.search_by_hash(hash) {
        Ok(p) => p,
        Err(e) => return Report::refused(explorer_refusal(&e)),
    };
    let Some(tx) = page.transactions.first() else {
        return Report::refused(format!(
            "no transaction with hash {} is in this node's index.\n  The indexer holds what it saw \
             when each block arrived; a transaction still in the mempool is not there, and a \
             deployment that runs no indexer answers nothing at all.\n  Nothing was read but the \
             node.",
            hex_bytes(hash)
        ));
    };
    let mut out = format!("transaction {}\n", hex_bytes(&tx.hash));
    if let Some(b) = tx.block {
        out.push_str(&format!("  in block {} ({})\n", b.index, hex_bytes(&b.hash)));
    }
    if let Some(ms) = tx.timestamp_ms {
        out.push_str(&format!("  at       {}\n", stamp(ms)));
    }
    out.push_str(&format!("  {} operation(s)\n", tx.operations.len()));
    out.push_str(&operation_lines(&tx.operations, "    "));
    if !tx.metadata.is_empty() {
        out.push_str("  metadata, in the endpoint's own spelling:\n");
        out.push_str(&metadata_lines(&tx.metadata, "    "));
    }
    out.push_str(&format!("\n{SEARCH_CONVENTION}\n"));
    Report::ok(out)
}

/// `recent-transactions <tag> [--count N]`: what touched a tag, newest first.
pub fn cmd_recent_transactions<T: Transport>(client: &MeshClient<T>, tag: &Tag, count: u64) -> Report {
    let page = match client.search_by_account(tag, count) {
        Ok(p) => p,
        Err(e) => return Report::refused(explorer_refusal(&e)),
    };
    let shown = match destination(tag) {
        Ok(d) => d,
        Err(e) => return cannot_render(tag, &e),
    };
    let mut out = format!(
        "recent transactions for {shown}\n  {} of {} row(s), newest first\n",
        page.transactions.len(),
        page.total_count
    );
    if page.transactions.is_empty() {
        out.push_str(
            "  (none: this node's index holds no transaction for this tag. A tag never paid has \
             none; so has every tag when the deployment runs no indexer.)\n",
        );
    }
    for tx in &page.transactions {
        let touched: i128 = tx
            .operations
            .iter()
            .filter(|o| o.address.strip_prefix("0x").unwrap_or(&o.address) == hex_bytes(tag))
            .map(|o| o.amount)
            .sum();
        let out_ops = tx.operations.iter().any(|o| {
            o.kind == codec::OP_SOURCE && o.address.strip_prefix("0x").unwrap_or(&o.address) == hex_bytes(tag)
        });
        let in_ops = tx.operations.iter().any(|o| {
            o.kind == codec::OP_DESTINATION && o.address.strip_prefix("0x").unwrap_or(&o.address) == hex_bytes(tag)
        });
        let direction = match (out_ops, in_ops) {
            (true, true) => "both",
            (true, false) => "out",
            (false, true) => "in",
            (false, false) => "--",
        };
        let memo = tx
            .operations
            .iter()
            .find(|o| !o.memo.is_empty())
            .map(|o| o.memo.clone())
            .unwrap_or_default();
        out.push_str(&format!(
            "  block {:>9}  {}  {:<4}  {}\n",
            tx.block.map_or(0, |b| b.index),
            hex_bytes(&tx.hash),
            direction,
            nano_and_mcm(touched)
        ));
        if !memo.is_empty() {
            out.push_str(&format!("                    memo {memo}\n"));
        }
    }
    if let Some(n) = page.next_offset {
        out.push_str(&format!("  more rows exist; the endpoint's next offset is {n}\n"));
    }
    out.push_str(&format!("\n{SEARCH_CONVENTION}\n"));
    Report::ok(out)
}

/// `block <number|hash>`: one block, with its reward and what it moved.
pub fn cmd_block<T: Transport>(client: &MeshClient<T>, at: &args::BlockAt) -> Report {
    let block = match match at {
        args::BlockAt::Index(i) => client.block_by_index(*i),
        args::BlockAt::Hash(h) => client.block_by_hash(h),
    } {
        Ok(b) => b,
        Err(e) => {
            let mut text = explorer_refusal(&e);
            if matches!(at, args::BlockAt::Hash(_)) {
                text.push_str(
                    "\n  A block is served by hash only from the deployment's own archive folder, \
                     so a not-found here is about that archive rather than about the chain. The \
                     index always works.",
                );
            }
            return Report::refused(text);
        }
    };

    // The reward transaction is the one carrying a REWARD operation.
    let (rewards, spends): (Vec<_>, Vec<_>) = block
        .transactions
        .iter()
        .partition(|t| t.operations.iter().any(|o| o.kind == codec::OP_REWARD));
    // **What "moved" means here, and why.** Every DESTINATION_TRANSFER of
    // every non-reward transaction. On THIS endpoint a source is debited its
    // net and the change is not an operation, so the destinations are
    // exactly value delivered to payees. The reward is excluded: it is newly
    // minted, not moved, and folding it in would make the figure mean
    // nothing an operator can use. The fee is excluded and shown on its own.
    let moved: i128 = spends
        .iter()
        .flat_map(|t| t.operations.iter())
        .filter(|o| o.kind == codec::OP_DESTINATION)
        .map(|o| o.amount)
        .sum();
    let fees: i128 = block
        .transactions
        .iter()
        .flat_map(|t| t.operations.iter())
        .filter(|o| o.kind == codec::OP_FEE)
        .map(|o| o.amount)
        .sum();

    let mut out = format!(
        "block {}\n  hash     {}\n  parent   {} ({})\n  at       {}\n",
        block.block.index,
        hex_bytes(&block.block.hash),
        block.parent.index,
        hex_bytes(&block.parent.hash),
        stamp(block.timestamp_ms)
    );
    match rewards.first().and_then(|t| t.operations.iter().find(|o| o.kind == codec::OP_REWARD)) {
        Some(r) => {
            out.push_str(&format!("  reward   {}\n    to     {}\n", nano_and_mcm(r.amount), explorer_address(&r.address)));
        }
        None => out.push_str("  reward   none in this block\n"),
    }
    out.push_str(&format!(
        "  spends   {}\n  moved    {}  (every destination of every non-reward transaction; the \
         reward is newly minted, not moved, and is not counted)\n  fees     {}\n",
        spends.len(),
        nano_and_mcm(moved),
        nano_and_mcm(fees)
    ));
    for t in &spends {
        let dests = t.operations.iter().filter(|o| o.kind == codec::OP_DESTINATION).count();
        let total: i128 = t
            .operations
            .iter()
            .filter(|o| o.kind == codec::OP_DESTINATION)
            .map(|o| o.amount)
            .sum();
        out.push_str(&format!(
            "    {}  {} destination(s)  {}\n",
            hex_bytes(&t.hash),
            dests,
            nano_and_mcm(total)
        ));
    }
    out.push_str(&format!("\n{BLOCK_CONVENTION}\n"));
    Report::ok(out)
}

/// `blocks [--count N]`: the tip and the N newest, one row each.
pub fn cmd_blocks<T: Transport>(client: &MeshClient<T>, count: u64) -> Report {
    let tip = match client.network_status() {
        Ok(t) => t,
        Err(e) => return Report::refused(explorer_refusal(&e)),
    };
    let mut out = format!("the {count} newest block(s); the tip is {}\n", tip.index);
    for i in 0..count {
        let Some(index) = tip.index.checked_sub(i) else { break };
        // Index 0 is the tip to this endpoint, never genesis, so the walk
        // stops above it rather than ask for a page about another block.
        if index == 0 {
            break;
        }
        match client.block_by_index(index) {
            Ok(b) => out.push_str(&format!(
                "  {:>9}  {}  {}  {} transaction(s)\n",
                b.block.index,
                hex_bytes(&b.block.hash),
                stamp(b.timestamp_ms),
                b.transactions.len()
            )),
            Err(e) => return Report::refused(format!("{}\n  The tip was read; block {index} was not.", explorer_refusal(&e))),
        }
    }
    Report::ok(out)
}

/// A failed explorer read, said in the operator's terms.
///
/// The Mesh answers its own failures as HTTP 200 carrying a code, which the
/// codec has already turned into `Error::Mesh`; an internal error from
/// `/search/transactions` most often means the deployment runs no indexer,
/// which is its default, and saying so is the
/// difference between a useful page and a number.
fn explorer_refusal(e: &Error) -> String {
    let mut text = format!("{e}");
    if matches!(e, Error::Mesh { code: 1, .. }) {
        text.push_str(
            "\n  The Mesh's search endpoint answers an internal error when its indexer database \
             is not initialised, and a deployment runs no indexer unless it was configured to. \
             This node may simply not index; another may.",
        );
    }
    text.push_str("\n  Nothing was read but the node: no store was opened and no password asked.");
    text
}
