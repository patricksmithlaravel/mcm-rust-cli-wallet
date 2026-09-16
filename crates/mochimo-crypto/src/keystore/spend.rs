//! The two addresses a spend needs, derived from the store and dropped:
//! the current key's (the source) and the next key's (the change), under the
//! same kind, tag and stream checks [`Keystore::sign_spend`] runs.
//!
//! # What this is, and is not
//!
//! It reads the store, not the chain. The chain-side comparison — is the
//! address the ledger holds for this tag the [`SpendAddresses::source`]
//! this store would sign with — is `mesh::spend::SpendPlan::new`'s
//! [`Error::ChainAddressMismatch`], and that comparison is a **spend-time
//! guard**, not I4's startup reconciliation — which is `Wallet::open`'s, the
//! wallet's only constructor, green as
//! `invariants.rs::startup_refuses_divergence_at_the_wallet_layer_not_at_the_keystore`.
//! The two are still distinct and both are wanted: a store that
//! reconciled at open can be overtaken by the chain before the spend is built.
//! **This sentence once said I4 "remains owed"**, naming the
//! pre-clearing marker; the bound that survives the rename is that a raw
//! [`Keystore`] is still reachable, so what is enforced is that a *`Wallet`'s*
//! users cannot spend unreconciled. A mismatch is stopped
//! at, never advanced past: three causes present the same way and only one
//! is safe to advance through.
//!
//! # The positions
//!
//! `position` is the account's stored index — the key `persist_advance`
//! reserves next and the key `sign_spend` signs with — so the source address
//! is the key at `position` under the account tag, and the change address is
//! the key at `position + 1` under the same tag: the v3 arrangement in which
//! the tag half is constant across a spend and the hash half rotates
//! (`tx_val` requires the tags equal and the hashes different).
//! Both keys come from [`Keystore::key_at`], which is the
//! derivation `sign_spend` uses, so what a plan is built for and what key
//! signs it cannot drift apart.
//!
//! An account with a reservation outstanding is refused here with
//! [`Error::PendingUnresolved`] before any network round trip, which is what
//! `persist_advance` would say later; nothing here can settle it.

use crate::account::WotsIndex;
use crate::addr::{Address, Tag};
use crate::error::{Error, Result};

use super::sign::KeyAccess;
use super::{Keystore, Medium};

/// What a spend is built for: the tag, the position that will sign, and the
/// two addresses. Public data (no key material), so `Debug` is derived.
///
/// Constructible only through the keystore, for a wallet build: by
/// [`Keystore::spend_addresses`], or, inside the crate, from addresses
/// [`Keystore::address_at`] just derived (the resign path). A plan built
/// over addresses somebody typed would pay change to a key nobody holds,
/// and `#[non_exhaustive]` keeps that from being a one-line mistake outside
/// the crate. The test tree's [`SpendAddresses::unverified`] exists under
/// the `raw-backend` feature alone, which no dependent has; the downstream
/// probe in `tests/signing.rs` compiles a default-features dependent and
/// finds it unnameable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct SpendAddresses {
    /// The account tag; the tag half of both addresses.
    pub tag: Tag,
    /// The stored index: the key that will sign. `persist_advance` reserves
    /// exactly this position and mints a receipt attesting `position + 1`.
    pub position: WotsIndex,
    /// `tag ‖ hash(pk at position)` — the address the chain must currently
    /// hold for the tag, and `src_addr` on the wire.
    pub source: Address,
    /// `tag ‖ hash(pk at position + 1)` — `chg_addr` on the wire, where the
    /// balance minus send and fee returns.
    pub change: Address,
}

impl SpendAddresses {
    /// Addresses that did NOT come out of a keystore, for a caller that holds
    /// them from elsewhere -- the test tree's byte-identity proofs over the
    /// reference's own images are the case in the tree, and the test tree is
    /// the only place this exists: it is under `raw-backend`, on for every
    /// test target through the crate's dev-dependency on itself and never
    /// for a dependent, the way the raw signer is held. The name is the
    /// warning: `SpendPlan::new` still refuses a `source` the chain does not
    /// hold, but nothing verifies that `change` is a key anybody holds, and a
    /// plan built over a mistyped change address pays the remainder to
    /// nobody.
    #[cfg(feature = "raw-backend")]
    pub fn unverified(tag: Tag, position: WotsIndex, source: Address, change: Address) -> SpendAddresses {
        SpendAddresses {
            tag,
            position,
            source,
            change,
        }
    }

    /// Addresses the keystore derived one at a time -- the resign path,
    /// which rebuilds a reserved spend from [`Keystore::address_at`] at the
    /// reserved position and the current one. Crate-private, so the type's
    /// rule holds for every caller outside: what reaches a plan came out of
    /// a keystore.
    pub(crate) fn of_derived_addresses(tag: Tag, position: WotsIndex, source: Address, change: Address) -> SpendAddresses {
        SpendAddresses {
            tag,
            position,
            source,
            change,
        }
    }
}

impl<M: Medium> Keystore<M> {
    /// The address of this account's key at `position`, under the account
    /// tag: `tag ‖ hash(pk at position)`.
    ///
    /// Reconciliation's primitive. It is **the same derivation
    /// `sign_spend` uses** — [`Keystore::key_at`], with every kind, tag and
    /// stream refusal that carries — so the address a divergence report
    /// compares against the chain and the key that would sign there cannot
    /// drift apart. That is the same reason [`Keystore::spend_addresses`]
    /// routes through it.
    ///
    /// Unlike `spend_addresses` this does **not** refuse an outstanding
    /// reservation: reconciling an account with a spend in flight is exactly
    /// when the question is asked, and the two positions it must ask about
    /// (`spent_index` and `spent_index + 1`) are the ones a reservation
    /// names. The derived key is dropped before this returns.
    pub fn address_at(&self, tag: &Tag, position: WotsIndex, access: &KeyAccess<'_>) -> Result<Address> {
        let (_, slots) = self.live()?;
        let slot = slots.get(tag).ok_or(Error::NoSuchAccount)?;
        Ok(self.key_at(slots, slot, position, access)?.address(tag))
    }

    /// The addresses a spend from `tag` is built for. Refuses an unknown
    /// tag, an outstanding reservation, an index at its ceiling, and every
    /// kind/tag/stream mismatch `sign_spend` refuses, by the same names.
    /// Every derived key is dropped before this returns.
    pub fn spend_addresses(&self, tag: &Tag, access: &KeyAccess<'_>) -> Result<SpendAddresses> {
        let (_, slots) = self.live()?;
        let slot = slots.get(tag).ok_or(Error::NoSuchAccount)?;
        if let Some(p) = slot.pending {
            return Err(Error::PendingUnresolved {
                spent_index: p.spent_index.get(),
            });
        }
        let position = slot.account.wots_index();
        let next = position.advanced()?;
        let source = self.key_at(slots, slot, position, access)?.address(tag);
        let change = self.key_at(slots, slot, next, access)?.address(tag);
        Ok(SpendAddresses {
            tag: *tag,
            position,
            source,
            change,
        })
    }
}
