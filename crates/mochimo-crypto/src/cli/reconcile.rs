//! `status <tag> [--scan-to <M>]` and `reconcile <tag> --advance-to <N>` —
//! the two commands that act on a divergence, and therefore run before the
//! gate.
//!
//! # Why these are not `Wallet` methods in the CLI
//!
//! `Wallet::open` is the only constructor and it refuses when any account is
//! diverged (I4). A one-shot process that opens a wallet in order to act on a
//! divergence therefore cannot act: both commands were once dispatched
//! behind `Wallet::open`, so `reconcile <tag>
//! --advance-to N` with the exact index the report named exited with the same
//! startup refusal that had named it, and `status` could show a divergence
//! only for a tag the store did not hold. The acknowledged path every I4
//! report told the operator to take did not exist in the shipped binary.
//! Measured by a probe before any edit; the one CLI test of `reconcile`
//! asserted that refusal under a comment describing the mismatch check.
//!
//! So both run on the `Keystore` directly, through `recon`, the way `restore`
//! does (move commands to where a third already was rather than carve
//! exceptions into `open`). The gate they honour is the acknowledgement,
//! not the wallet type: [`recon::advance_after_operator_review`] takes an
//! `OperatorAcknowledgement` that can only be built from a `Divergence`,
//! re-runs the comparison under the same scope, and refuses a target the live
//! divergence does not name. `Wallet::advance_after_operator_review` remains
//! for a long-running process in which a divergence appears after open, and
//! delegates to the same function.
//!
//! # What the gated path supplied, and this module keeps
//!
//! `Wallet::open` reconciled **every** account and rendered every failing one,
//! because the evidence that one account's advance is wrong most often lives
//! in another — a second account showing a spend this wallet did not make is
//! the live-second-wallet signal I4's third cause is about. So
//! [`advance_acknowledged`] reconciles the whole store first, hands every
//! report back for the caller to print **before** anything is written (on the
//! success path too), and refuses the advance outright while any other account
//! reports a reservation the chain explains at neither of its keys.
//!
//! # What that means for the containment rule
//!
//! The CLI's rule is: **no command holds a `Wallet` and a mutable `Keystore`
//! at once; the commands that hold a mutable store are the pre-gate ones
//! (`create`, `restore`, `reconcile`), and none of them reaches a signer.**
//! This module names no wallet type and no signer, and its only store write
//! is through a function that takes an `OperatorAcknowledgement`;
//! `invariants.rs::the_cli_cannot_reach_around_the_wallet` holds that
//! mechanically: it is a pre-gate module there, and
//! `advance_after_operator_review(` is permitted in this file alone.

use crate::addr::Tag;
use crate::consts::SEED_LEN;
use crate::keystore::{Keystore, Medium};
use crate::mesh::{MeshClient, Transport};
use crate::recon::{self, AccountStatus, Divergence, OperatorAcknowledgement, ScanScope};
use crate::{Error, Secret};

/// The diagnostic scope an invocation asks for: the default window and
/// ceiling, or the ceiling raised to walk `0..=to` when the operator named an
/// index.
///
/// `to` is inclusive as the operator reads it — "scan to 500" walks index 500
/// — so the ceiling is one more. The parser refuses `u32::MAX`, so the add
/// cannot overflow; `saturating_add` keeps this file free of a panicking
/// construct regardless.
fn scope_to(to: Option<u32>) -> ScanScope {
    match to {
        Some(m) => ScanScope::DIAGNOSTIC.with_ceiling(m.saturating_add(1)),
        None => ScanScope::DIAGNOSTIC,
    }
}

/// `status`: the same comparison `Wallet::open` makes, for one account,
/// reported without refusing — and reported *at all* when the
/// account is diverged, which behind the gate it never was.
#[allow(clippy::result_large_err)]
pub fn account_status<M: Medium, T: Transport>(
    store: &Keystore<M>,
    client: &MeshClient<T>,
    tag: &Tag,
    master: Option<&Secret<SEED_LEN>>,
    scan_to: Option<u32>,
) -> core::result::Result<AccountStatus, Divergence> {
    let access = recon::access_for(store, tag, master)?;
    recon::reconcile_account_with(store, client, tag, &access, &scope_to(scan_to))
}

/// What `reconcile` decided, after reading the whole store.
pub enum Outcome {
    /// The store advanced the named account to the acknowledged index.
    Advanced { index: u32 },
    /// The named account reconciles cleanly; there was nothing to advance past.
    NothingToReconcile(AccountStatus),
    /// The named account is diverged and no advance was made. `target` is the
    /// index the live report names when it names one; `None` when advancing
    /// is not the remedy for this divergence (behind, unlocated, unreachable,
    /// a reservation the chain explains at neither key).
    NoAdvance { target: Option<u32> },
    /// Another account in this store reports a spend this wallet did not make
    /// — a second wallet is live on this seed — so nothing was advanced.
    SecondInstanceSignal { other: Tag },
    /// The store does not hold the tag.
    NotHeld,
}

/// What `reconcile` read and did: every diverged account's report as it
/// stood before the decision, in tag order, and the decision.
pub struct Reviewed {
    pub reports: Vec<Divergence>,
    pub accounts: usize,
    pub outcome: Outcome,
}

/// `reconcile`: reconcile every account, then advance the named one only if
/// the live report names exactly the index the operator typed.
///
/// The operator's number is a hypothesis, not an instruction. It raises the
/// walk's ceiling to `advance_to + 1`, so the diagnostic covers `0..=advance_to`
/// as well as the window; if `address(advance_to)` is the address the chain
/// holds, the report is `Ahead { index: advance_to }` exactly as it would be
/// had the window found it, and the acknowledgement is built from that
/// report. If the chain is at some other index the walk reaches, the report
/// names *that* index and the acknowledgement the operator holds is refused
/// as not matching it; if the walk finds nothing, there is no acknowledgement
/// at all. Either way nothing is written.
pub fn advance_acknowledged<M: Medium, T: Transport>(
    store: &mut Keystore<M>,
    client: &MeshClient<T>,
    tag: &Tag,
    master: Option<&Secret<SEED_LEN>>,
    advance_to: u32,
) -> core::result::Result<Reviewed, Error> {
    let tags = store.tags()?;
    let accounts = tags.len();
    let mut reviewed = Reviewed {
        reports: Vec::new(),
        accounts,
        outcome: Outcome::NotHeld,
    };
    if !tags.contains(tag) {
        return Ok(reviewed);
    }
    let scope = scope_to(Some(advance_to));

    // The whole store first, the named account under the raised ceiling and
    // every other under the default scope.
    let mut named: Option<core::result::Result<AccountStatus, Divergence>> = None;
    for t in &tags {
        let this = t == tag;
        let result = match recon::access_for(store, t, master) {
            Err(d) => Err(d),
            Ok(access) => recon::reconcile_account_with(
                store,
                client,
                t,
                &access,
                if this { &scope } else { &ScanScope::DIAGNOSTIC },
            ),
        };
        if let Err(d) = &result {
            reviewed.reports.push(d.clone());
        }
        if this {
            named = Some(result);
        }
    }
    let divergence = match named {
        Some(Ok(status)) => {
            reviewed.outcome = Outcome::NothingToReconcile(status);
            return Ok(reviewed);
        }
        Some(Err(d)) => d,
        // `tags.contains(tag)` above, so the loop visited it.
        None => return Ok(reviewed),
    };

    // The second-wallet signal: a spend this wallet did not make, on any
    // other account of the same store.
    if let Some(other) = reviewed
        .reports
        .iter()
        .find(|d| d.tag() != *tag && matches!(d, Divergence::ReservationUnexplained { .. }))
        .map(Divergence::tag)
    {
        reviewed.outcome = Outcome::SecondInstanceSignal { other };
        return Ok(reviewed);
    }

    let Some(ack) = OperatorAcknowledgement::of(&divergence) else {
        reviewed.outcome = Outcome::NoAdvance { target: None };
        return Ok(reviewed);
    };
    if ack.target().get() != advance_to {
        reviewed.outcome = Outcome::NoAdvance {
            target: Some(ack.target().get()),
        };
        return Ok(reviewed);
    }
    let access = match recon::access_for(store, tag, master) {
        Ok(a) => a,
        // Unreachable in practice -- the same call succeeded a moment ago
        // for this tag -- and answered as the refusal it would be.
        Err(d) => {
            reviewed.reports.push(d);
            reviewed.outcome = Outcome::NoAdvance { target: None };
            return Ok(reviewed);
        }
    };
    let receipt = recon::advance_after_operator_review(store, client, tag, &access, ack, &scope)?;
    reviewed.outcome = Outcome::Advanced {
        index: receipt.index().get(),
    };
    Ok(reviewed)
}
