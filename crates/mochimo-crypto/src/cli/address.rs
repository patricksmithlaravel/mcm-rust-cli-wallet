//! `address` — the address to fund, computed before there is anything to fund.
//!
//! # Why this is outside the `Wallet` gate
//!
//! **This is the command the deadlock was about.** Every command that goes
//! through `Wallet::open` reconciles every account and refuses when the node
//! does not resolve a tag — and a tag that has never been paid is one the node
//! cannot resolve, and the refusal names three readings of that, a never-paid
//! tag among them. Asking where to send the first payment is
//! exactly the moment that is true, so an `address` behind the gate can only
//! answer once its answer is no longer needed.
//!
//! It sits where `restore` and `create` are: it opens no wallet, signs nothing,
//! and asks the chain nothing. `Wallet::open`'s refusal is untouched — it was
//! argued on the case where absence genuinely cannot be told from a wrong
//! seed, and carving an exception into it would be more surface
//! than moving two commands to where a third already was.
//!
//! # It needs the master seed, and that is not incidental
//!
//! An address is a function of the seed: the store holds account records, not
//! addresses, and the record's `first[64]` is populated for imported accounts
//! only. So a derived account's address can only be computed from the master,
//! and this command prompts for exactly the reason `balance` does. An
//! imported account answers from its stored root and does not prompt.
//!
//! # Which address
//!
//! The one the account will next present: `wots_index` from the store's own
//! record, through the same `key_at` that `sign_spend` uses, so what this
//! prints and what would sign there cannot drift apart. For a store fresh from
//! `create` that is position 0 — the implicit first address, tag half equal to
//! hash half.
//!
//! # And with no tag, the store itself — which needs no seed either
//!
//! [`accounts_in`] is a different question from [`address_of`] and answers it
//! from a different place. An **address** is a function of the seed, so
//! `address_of` needs one. A **destination** is a function of the tag alone,
//! and the tag is in the record — so listing the store reads bytes that are
//! already on disk, derives nothing, and prompts for nothing.
//!
//! That distinction is what makes the listing the route back after `create`
//! exits 3: the operator who has just mistyped three words of their phrase is
//! the last operator who should be asked to type all twenty-four to find out
//! where their money goes.

use crate::addr::{Address, Tag};
use crate::keystore::{KeyAccess, Keystore, Medium};
use crate::{Error, Result};

/// One account, as the store records it. No seed, no node.
///
/// `Debug` and the comparisons are safe on this and are not on much else in
/// this crate: every field is a public identifier or a position, and no
/// derivation of it reaches key material. It carries them because
/// `outcome::Outcome` holds a list of these and is itself compared in tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Held {
    pub tag: Tag,
    pub kind: crate::account::AccountKind,
    pub index: crate::account::WotsIndex,
}

/// Every account the store holds, in the store's own order.
///
/// Reads records. Computes no address, takes no [`KeyAccess`], and asks
/// nothing of any node.
pub fn accounts_in<M: Medium>(store: &Keystore<M>) -> Result<Vec<Held>> {
    let mut out = Vec::new();
    for tag in store.tags()? {
        if let Some(v) = store.view(&tag)? {
            out.push(Held {
                tag: v.tag,
                kind: v.kind,
                index: v.wots_index,
            });
        }
    }
    Ok(out)
}

/// The address `tag` will next present, and the index it sits at.
pub struct Where {
    pub address: Address,
    pub index: crate::account::WotsIndex,
}

/// Look up `tag` in the store and compute its current address.
///
/// Refuses a tag the store does not hold — with no chain consulted, so the
/// refusal is about this store and says nothing about the ledger.
pub fn address_of<M: Medium>(
    store: &Keystore<M>,
    tag: &Tag,
    access: &KeyAccess<'_>,
) -> Result<Where> {
    let view = store.view(tag)?.ok_or(Error::NoSuchAccount)?;
    let address = store.address_at(tag, view.wots_index, access)?;
    Ok(Where {
        address,
        index: view.wots_index,
    })
}
