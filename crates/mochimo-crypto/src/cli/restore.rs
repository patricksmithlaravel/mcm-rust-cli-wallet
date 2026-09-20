//! `restore --account <N> [--scan-to <M>]` — store construction from a seed.
//!
//! # Why this is not a `Wallet` method (reported before it was built)
//!
//! Restore needs [`Keystore::add`], which is `&mut`, and the `Wallet` exposes
//! no mutable store: `Wallet::store` is `&`-only and there is deliberately no
//! `store_mut`. So `restore` cannot run through a wallet, and the choice was
//! to add a method to the gated type or to run before the gate exists.
//!
//! **It runs before.** Restore is store *construction*: it signs nothing, and
//! the account it adds is reconciled by the *next* command's `Wallet::open` —
//! setting the index so that reconciliation passes is the entire point of it.
//! The alternative widens the gated type to mutate a store outside a
//! reconciled state, which buys nothing and costs the property that a
//! `Wallet`'s store is one reconciliation already agreed with.
//!
//! # One commit, and never an account the store already holds
//!
//! This once added the account at index zero and advanced it in
//! a **second** commit, so a failure between the two left a derived account on
//! disk at zero — I5's own catastrophe — under a message saying no index was
//! assumed; and it **advanced an account the store already held** whenever the
//! chain was ahead, with no report, no acknowledgement and exit 0, which is the
//! silent advance I4 exists to make unrepresentable (found by the refutation
//! pass). Now the account is built at the found index in memory
//! and committed once, and an account already held is reported and not
//! touched: reconciling a held account is `reconcile`'s job, with the whole
//! store's report in front of the operator.
//!
//! # What that means for the constraint, stated exactly
//!
//! The CLI's rule is not *never touch a mutable store* — it is **no command
//! holds a `Wallet` and a mutable `Keystore` at the same time, and the
//! commands that hold a mutable store are the pre-gate ones** (`create`,
//! `restore`, `reconcile`), none of which reaches a signer. This is one of
//! them, it writes only through `add`, and
//! `invariants.rs::the_cli_cannot_reach_around_the_wallet` is what says so
//! mechanically rather than by this paragraph.

use crate::account::{Account, WotsIndex};
use crate::keystore::{Keystore, Medium};
use crate::mesh::{MeshClient, Transport};
use crate::recon::{self, RestoreFailure, RestoredAccount, ScanScope};

use crate::consts::SEED_LEN;
use crate::Secret;

/// What a restore did, for rendering.
pub struct Restored {
    pub found: RestoredAccount,
    /// `Some(stored)` when the store already held the tag, at `stored`: the
    /// scan still ran and its index is still reported, but nothing was
    /// written. `None` when the account was added at `found.index`.
    pub held_at: Option<WotsIndex>,
}

/// Derive account `account_index`, ask the chain where its tag sits, and put
/// it in the store at that index — walking `0..=scan_to` when the operator
/// raised the ceiling, the default recovery range otherwise.
///
/// The index comes from the chain, never from a default — I5's clause is
/// unconditional, and [`RestoreFailure`] has no fallback variant.
pub fn restore_account<M: Medium, T: Transport>(
    store: &mut Keystore<M>,
    client: &MeshClient<T>,
    master: &Secret<SEED_LEN>,
    account_index: u32,
    scan_to: Option<u32>,
) -> core::result::Result<Restored, RestoreFailure> {
    let scope = match scan_to {
        // Inclusive as the operator reads it; the parser refuses `u32::MAX`.
        Some(m) => ScanScope::RESTORE.with_ceiling(m.saturating_add(1)),
        None => ScanScope::RESTORE,
    };
    let found = recon::restore_account_index_with(client, master, account_index, &scope, &recon::Cancel::NEVER)?;

    let cannot_store = |cause| RestoreFailure::CannotStore {
        tag: found.tag,
        cause,
    };

    if let Some(view) = store.view(&found.tag).map_err(cannot_store)? {
        return Ok(Restored {
            found,
            held_at: Some(view.wots_index),
        });
    }

    // Built at the found index in memory, then ONE commit. `advance_to`
    // refuses a target not strictly ahead, and position 0 is where a derived
    // account starts, so it is called only when there is somewhere to go.
    let mut account = Account::derive(master, account_index);
    if found.index.get() > WotsIndex::ZERO.get() {
        account.advance_to(found.index).map_err(cannot_store)?;
    }
    store.add(account).map_err(cannot_store)?;
    Ok(Restored { found, held_at: None })
}
