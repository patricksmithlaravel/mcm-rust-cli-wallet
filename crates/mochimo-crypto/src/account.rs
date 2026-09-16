//! The account model: what an account is, how key material is held, and how
//! derived and imported accounts differ.
//!
//! A Mochimo account is a permanent 20-byte tag over a rotating WOTS+ key:
//! every spend commits the next key's address hash into `chg_addr`, so the
//! index advance *is* the spend, expressed on-chain. This
//! module gives that arrangement Rust types. It deliberately contains no
//! keystore, no signing, and no derivation — those are later sessions — and
//! every absence below is a decision with its reason at the site.
//!
//! # Why an enum and not a flag
//!
//! The shipped wallet models the derived/imported distinction as
//! `index?: number` beside an always-present `seed` string. That shape has four representable states — index present or absent, seed
//! meaningful as a derivation product or as an imported root — and two of
//! them are lies. Its restore routine walks derived indices and silently
//! drops imported accounts, which is exactly I8's loss mode: nothing errors,
//! the funds stay addressable on chain, and the only key that could move
//! them is gone.
//!
//! [`KeyMaterial`] is an enum with two states, both true. A `match` over it
//! that avoids a wildcard arm cannot be written without confronting
//! `Imported`; a restore-shaped function typed over [`AccountRecord`] cannot
//! rebuild an imported account out of thin air because the derived record
//! carries no secret *by type*. What the enum makes unrepresentable is the
//! flag shape's two lying states: an "imported" account with no stored root,
//! and a "derived" account carrying a root nothing derived.
//!
//! It is deliberately **not** `#[non_exhaustive]`: that attribute forces
//! downstream wildcard arms, which un-forces the `Imported` arm and
//! re-enables exactly the silent omission I8 forbids. For the same reason
//! there is no `hardware` variant, although the reference's `AccountType`
//! union names one — nothing in scope implements a hardware path, and a dead
//! variant that every match must mention trains readers to write the
//! wildcard this design exists to keep out. Recorded here rather than merely
//! omitted (the variant question re-opens if a hardware path is
//! ever in scope).
//!
//! # Where `wots_index` lives, and what it means
//!
//! Both kinds rotate, so the index is a field of [`Account`], not of the key
//! variant. Its *meaning* differs — a position in the master seed's
//! derivation stream for a derived account, a count of rotations from a
//! retained root for an imported one — but that difference is fully
//! determined by which [`KeyMaterial`] variant sits beside it, so the
//! variant already expresses it at the type level and a second encoding
//! would just be a place for the two to disagree.
//!
//! [`WotsIndex`] is a `u32` with no sentinel domain. The shipped wallet's
//! `wotsIndex: -1` is a three-way ambiguous value — first-key sentinel, scan
//! not-found, and scan beyond-bound are indistinguishable, and the shipped
//! reconciliation writes that ambiguity back into the account. An unsigned
//! index makes that defect class unrepresentable here.
//!
//! **The correspondence to the shipped numbering is decided: ours is the
//! shipped index plus one** (decided with group F's vectors in hand).
//! [`WotsIndex::ZERO`] is the shipped `-1` — the first key, whose secret is
//! the account seed itself and whose public seed and hash address came from
//! the generator `deriveSeed(master, account_index)` left behind; a position
//! `n >= 1` is the shipped `n - 1`, the key `deriveSeed(account_seed, n - 1)`
//! produces. The mapping is forced rather than chosen: the sentinel names a
//! real key holding the account's initial funds, and an unsigned domain can
//! put it nowhere but at 0. [`WotsIndex::rotation`] carries the shift;
//! [`WotsIndex::to_shipped`] / [`WotsIndex::from_shipped`] are the external
//! representation for a shipped JSON backup, total in both directions.
//!
//! **What the mapping exposes: an imported account's first key is not
//! reconstructible from its root.** Its public seed and hash address came
//! from a generator seeded by the *master* seed, which an imported account
//! never had; the shipped wallet keeps them as `faddress` and rebuilds the
//! first key from that, not from the seed.
//! So they are **stored**:
//! [`KeyMaterial::Imported`] carries `first` beside the root and has no
//! constructor that omits it, which makes I8's loss mode — a never-spent
//! imported account that cannot sign at position 0 — unrepresentable rather
//! than refused at signing time.
//!
//! The imported variant carries the first key's components beside the root,
//! which is what makes that loss mode unrepresentable rather than merely
//! refused.
//! `invariants.rs::imported_first_key_is_verified_against_the_root_not_against_an_mcm_capture`
//! holds it, and its bound is that the pair is group F's seen from the
//! imported side — nothing here reads an `.mcm` file.
//!
//! # The signing seam, as a signature
//!
//! The contract this module establishes, to be implemented over a keystore:
//!
//! ```text
//! fn sign_spend(&mut self, digest: &[u8; 32], receipt: AdvanceReceipt)
//!     -> Result<wots::Signature>
//! ```
//!
//! where the receipt must satisfy `receipt.tag() == self.tag()` and
//! `receipt.index()` equal to this account's index after the advance the
//! receipt attests. [`AdvanceReceipt`] is unforgeable outside this crate
//! (private fields, no constructor, no `Clone`), and it is **bound** — it
//! names the tag and index whose durability it witnesses, because an
//! unbound receipt could be minted against one account and spent against
//! another, or hoarded and replayed stale. Minting is `pub(crate)`: a
//! receipt witnesses a *persisted* advance, and nothing in this session can
//! honestly mint one, so nothing public does.
//!
//! # What this establishes, and what it cannot
//!
//! **I1 is enforced, and not by this module alone.** The seam
//! above is implemented by `keystore::sign::sign_spend`, which consumes the
//! receipt and re-checks the store's live state against it; `wots::sign` and
//! `wots::internals` are crate-private, and the backend seam is crate-private
//! outside the test tree's `raw-backend` feature, so no dependent can name a
//! raw signer. What this module contributes is the receipt's
//! shape -- unforgeable, bound, consumed -- and the two bounds the marker
//! `key_signs_once_per_keystore_with_the_raw_signer_crate_private_not_absent`
//! carries in its name: the gate is per keystore, and the signer is
//! crate-private rather than absent. One thing this model made possible and
//! the signing path found: the same 32-byte seed under two tags is two indices over one
//! key stream, because a rotation key is a function of the seed alone.
//! `Keystore::add` and `sign_spend` refuse the halves they can see; the half a
//! reopen defeats closed with format v2, when every record grew a stored stream
//! identity: the marker is green as
//! `duplicate_key_streams_are_refused_within_one_keystore_not_across_stores`,
//! and the bound is one store. This said "the red" and named the
//! pre-clearing spelling for some time after.
//!
//! [`Account::derive`] computes the tag — `ripemd160(sha3_512(first_pk))`,
//! the tag half of the first key's implicit address — from the master seed
//! and the position (the unverified derived constructor is gone). The
//! imported constructor still takes the tag **unverified**, and its name
//! says so: verifying it needs the first address's public components, which
//! the root does not contain (above), so the verifying `import` arrives with
//! the variant that stores them. `imported_account_restores_from_stored_seed`
//! (the census test behind I8's marker) is the external customer that forces
//! it to be public at all.
//!
//! Import confers no exclusivity: whoever imported the root still holds the
//! bytes it came from, and the master seed re-derives every derived account.
//! What the types enforce is a **no-re-exposure regime** — the only path
//! that hands key material back out is the consuming [`Account::to_record`],
//! the same conspicuous-door convention as [`Secret::expose`].
//!
//! Deliberately absent, each a decision: `Clone`/`Copy`/`Default`/
//! `PartialEq` on [`Account`], [`KeyMaterial`], [`ImportedRoot`] and
//! [`AdvanceReceipt`] (a cloned account is two spend paths advancing one
//! index; a defaulted account is a fabricated key at index zero, I5's
//! forbidden assumption; equality over key material is variable-time), and
//! serde anywhere (`Deserialize` would be a forged-tag constructor, an
//! arbitrary-index setter and an I6 plaintext boundary in one derive).
//! The compile-fail suite pins the absences: `ui/fail/account_*.rs`.

use crate::addr::Tag;
use crate::consts::SEED_LEN;
use crate::error::{Error, Result};
use crate::secret::Secret;
use crate::wots::Adrs;
use core::fmt;


/// A Mochimo account: a permanent tag, key material, and the rotation index.
///
/// Fields are private on purpose; the compile-fail cases
/// `account_literal_is_not_constructible` and
/// `account_wots_index_is_not_assignable` pin that external code can neither
/// assemble one by literal nor write the index. `#[must_use]` because a
/// discarded account is a discarded root when the account is imported.
#[must_use]
pub struct Account {
    tag: Tag,
    key: KeyMaterial,
    wots_index: WotsIndex,
}

/// How an account's key material is held.
///
/// `pub(crate)`: a `pub` enum's variant fields are exactly as visible as the
/// enum, so publishing this type would let external code fabricate
/// `Derived { account_index }` values for free. External code inspects
/// accounts through [`AccountKind`] instead, which carries no payload.
pub(crate) enum KeyMaterial {
    /// Recomputable from the master seed at this position. Holds no secret:
    /// the master seed is not this account's to keep.
    Derived {
        account_index: u32,
        stream: StreamId,
    },
    /// The stored root is the only copy this crate will ever see. Retained
    /// on rotation — change keys derive *from* it — and
    /// never replaced.
    ///
    /// `first` is not optional and there is no constructor that omits it:
    /// an imported account whose position-0 key cannot be rebuilt is
    /// the state I8's loss mode lives in, and it is unrepresentable here
    /// rather than refused at signing time.
    Imported {
        root: ImportedRoot,
        first: FirstKey,
        stream: StreamId,
    },
}

/// An imported account's first-key public components: the 64 bytes at the
/// tail of the shipped `faddress` (`pub_seed` then the hash-address image),
/// which the extension memcpys back at `wotsIndex === -1`.
///
/// Private fields and no public constructor: the only way to one is
/// [`Account::import`] or [`Account::restore_from_record`], both of which
/// refuse components the root does not reproduce. Holds no secret — the
/// components are public — but it sits inside a type that does, so `Debug` is
/// hand-written like everything in this module's neighbourhood.
///
/// **Why 64 bytes and not 2208.** The public key is `wots::pkgen(root,
/// pub_seed, adrs)`, so storing it would store a value the other three
/// determine. And the twelve bytes the shipped format overlays on the address
/// image (the generator's 12-byte tag) do not matter: the
/// reference writes address words 5, 6 and 7 before every use —
/// `set_chain_addr` per chain, `set_hash_addr` per step, and
/// `set_key_and_mask` twice per `thash_f` — so their incoming values never
/// reach a hash. Measured: `pkgen` from the overlaid words reproduces
/// `F-widths_account_address.bin`'s public key byte for byte.
pub struct FirstKey {
    pub_seed: [u8; SEED_LEN],
    adrs: Adrs,
}

impl FirstKey {
    /// The 64 bytes as they sit in a `faddress` and in the keystore record:
    /// `pub_seed ‖ adrs.le_image()`.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; FIRST_KEY_LEN] {
        let mut out = [0u8; FIRST_KEY_LEN];
        out[..SEED_LEN].copy_from_slice(&self.pub_seed);
        out[SEED_LEN..].copy_from_slice(&self.adrs.le_image());
        out
    }

    pub(crate) fn pub_seed(&self) -> &[u8; SEED_LEN] {
        &self.pub_seed
    }

    pub(crate) fn adrs(&self) -> Adrs {
        self.adrs
    }
}

/// The width of [`FirstKey`]'s byte form: a WOTS+ public seed and a hash
/// address image, the tail of a 2208-byte shipped address.
pub const FIRST_KEY_LEN: usize = SEED_LEN + 32;

/// The payload-free public face of [`KeyMaterial`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccountKind {
    Derived,
    Imported,
}

/// The public identity of a key **stream** — a 32-byte seed and every
/// rotation key it produces — computed by [`crate::derive::stream_id`], which
/// is where the argument for *this* value lives.
///
/// The type is here rather than beside its computation because it is a field
/// of [`AccountRecord`], and records exist in builds without the derivation.
///
/// Public data: the address hash of a key, the same twenty bytes a v3 address
/// carries in the clear. `Debug` renders the hex and comparison is derived on
/// purpose — this type exists to be compared, and it is not secret.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StreamId([u8; crate::consts::ADDR_TAG_LEN]);

impl StreamId {
    /// From the twenty bytes a record carries. Public because
    /// [`AccountRecord`] is data rather than authority: a forged one is
    /// refused where it matters — `Keystore::add` recomputes the identity of
    /// the account being added, `Account::restore_from_record` recomputes an
    /// imported account's from its root, and `Keystore::sign_spend`
    /// re-derives a derived account's from the master.
    #[must_use]
    pub fn from_bytes(bytes: [u8; crate::consts::ADDR_TAG_LEN]) -> StreamId {
        StreamId(bytes)
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8; crate::consts::ADDR_TAG_LEN] {
        &self.0
    }
}

impl fmt::Debug for StreamId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StreamId(")?;
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        f.write_str(")")
    }
}

/// An imported account's retained root.
///
/// This is the struct `no_holder_of_key_material_derives_debug` exists to
/// scan for: it holds a [`Secret`] and hand-writes `Debug`, and a derived
/// `Debug` here is how a root ends up in a log file.
pub struct ImportedRoot {
    secret: Secret<SEED_LEN>,
}

impl ImportedRoot {
    /// Crate-private borrow for the keystore's encoder; see
    /// [`Account::key_material`].
    pub(crate) fn secret(&self) -> &Secret<SEED_LEN> {
        &self.secret
    }
}

/// The rotation position. Forward-only; no sentinel values.
///
/// `Debug` is derived on purpose — the index is public state, not secret,
/// and hiding it would only make divergence reports (I4) worse. Pinned by
/// `wots_index_debug_prints_the_number`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct WotsIndex(u32);

/// Evidence that an account's advanced index is durable.
///
/// Unforgeable outside the crate (private fields, no public constructor, no
/// `Clone`), and bound to the `(tag, index)` it attests — see the module
/// doc's seam contract. Minted only by crate code, behind the persist step,
/// in the keystore session; [`AdvanceReceipt::attesting`] is `pub(crate)`
/// so nothing public can mint a witness to a persistence that never ran.
#[must_use]
pub struct AdvanceReceipt {
    tag: Tag,
    index: WotsIndex,
}

/// The persistent *content* of an account — what a keystore must hold, said
/// as a type. Not an on-disk format: encoding, encryption and layout are the
/// keystore's decisions.
///
/// The load-bearing asymmetry is structural: `Derived` has **no root
/// field**, so a restore path typed over records cannot fabricate imported
/// key material and cannot lose it by "rebuilding what it can" — the
/// `Imported` arm is the only source of the root, and the compiler demands
/// the arm. Fields are public because a record is data, not authority: a
/// forged record restores to exactly the account the same public
/// constructors would build, no more.
pub enum AccountRecord {
    Derived {
        tag: Tag,
        account_index: u32,
        /// The key stream this account's seed defines
        /// ([`crate::derive::stream_id`]). Carried because it cannot be
        /// recomputed without the master seed, which no record holds; it is
        /// re-derived and compared where the master *is* in hand -- at
        /// `Keystore::add`, since the store holds its master (format v3),
        /// and at `Keystore::sign_spend` always.
        stream_id: StreamId,
        wots_index: WotsIndex,
    },
    Imported {
        tag: Tag,
        root: Secret<SEED_LEN>,
        /// [`FirstKey::to_bytes`]. Verified against `root` and `tag` by
        /// [`Account::restore_from_record`], so a forged triple fails rather
        /// than restoring.
        first_key: [u8; FIRST_KEY_LEN],
        /// As above, and here it *is* recomputable from `root` — so the
        /// restore recomputes it and refuses a disagreement.
        stream_id: StreamId,
        wots_index: WotsIndex,
    },
}

impl Account {
    /// Build an imported account from the pair a `.mcm` entry carries: the
    /// 32-byte retained root and the 2208-byte first address the shipped
    /// wallet stores as `faddress`.
    ///
    /// **Verifying, and the tag is computed rather than supplied.** The
    /// address's public key must be `wots::pkgen(root, pub_seed, adrs)` over
    /// its own tail, or the pair is refused
    /// ([`Error::FirstAddressNotReproduced`]); the tag is then the tag half
    /// of that key's implicit address. So a forged tag on an imported
    /// account is **unconstructible**.
    ///
    /// What this does **not** establish: nothing reads an `.mcm` file. The
    /// pair is data in hand; how it is parsed off disk is not this module's.
    #[cfg(feature = "native")]
    pub fn import(
        root: Secret<SEED_LEN>,
        first_address: &[u8; crate::consts::WOTS_ADDR_LEN],
    ) -> Result<Account> {
        let mut components = [0u8; FIRST_KEY_LEN];
        components.copy_from_slice(&first_address[crate::consts::PK_LEN..]);
        let (pk, tag) = imported_parts(&root, &components);
        if pk[..] != first_address[..crate::consts::PK_LEN] {
            return Err(Error::FirstAddressNotReproduced);
        }
        let stream = crate::derive::stream_id(&root);
        Ok(Account {
            tag,
            key: KeyMaterial::Imported {
                root: ImportedRoot { secret: root },
                first: first_key_from(&components),
                stream,
            },
            wots_index: WotsIndex::ZERO,
        })
    }

    /// Build a derived account at a position in the master seed's stream,
    /// computing its tag: `deriveAccountTag(master, account_index)` in the
    /// shipped scheme (`crate::derive::derive_account_tag`, pinned by group
    /// F). The account starts at [`WotsIndex::ZERO`], the first key. The
    /// master seed is not retained; `native`-gated with the derivation.
    ///
    /// Also computes the account's [`StreamId`] — one further WOTS+
    /// generation, so this is two rather than one. It is the price of I1
    /// across accounts: the identity has to be persisted, and
    /// this is the one place a derived account's can be computed.
    #[cfg(feature = "native")]
    pub fn derive(master: &Secret<SEED_LEN>, account_index: u32) -> Account {
        let derived = crate::derive::derive_account(master, account_index);
        Account {
            tag: derived.tag(),
            key: KeyMaterial::Derived {
                account_index,
                stream: crate::derive::stream_id(derived.seed()),
            },
            wots_index: WotsIndex::ZERO,
        }
    }

    /// The account's permanent 20-byte tag. Returned by value; `Tag` is a
    /// `Copy` array and the tag is not secret.
    pub fn tag(&self) -> Tag {
        self.tag
    }

    /// Which kind of key material this account holds.
    pub fn kind(&self) -> AccountKind {
        match self.key {
            KeyMaterial::Derived { .. } => AccountKind::Derived,
            KeyMaterial::Imported { .. } => AccountKind::Imported,
        }
    }

    /// The current rotation position.
    pub fn wots_index(&self) -> WotsIndex {
        self.wots_index
    }

    /// Crate-private borrowing door for the keystore's encoder, beside the
    /// consuming public one (`to_record`). The encoder cannot consume a held
    /// account, and a borrow that never leaves the crate re-exposes nothing.
    pub(crate) fn key_material(&self) -> &KeyMaterial {
        &self.key
    }

    /// Move the rotation position forward to `target`, refusing anything that
    /// is not strictly ahead. The keystore's reconciliation path (I4/I5) needs
    /// a forward jump; a backward one is the rollback every invariant forbids,
    /// so it is unrepresentable here rather than checked by callers.
    pub(crate) fn advance_to(&mut self, target: WotsIndex) -> Result<()> {
        if target.get() <= self.wots_index.get() {
            return Err(Error::Range {
                what: "wots index",
                min: u64::from(self.wots_index.get()) + 1,
                max: u64::from(u32::MAX),
                got: u64::from(target.get()),
            });
        }
        self.wots_index = target;
        Ok(())
    }

    /// Advance the rotation position in memory, returning the new index.
    ///
    /// Forward-only: there is no inverse, and overflow is an error rather
    /// than a wrap, because a wrap *is* a rollback to zero — the worst
    /// possible value. This is the in-memory half of the seam; the persist
    /// glue orders it against durability and mints the receipt (module doc).
    pub fn advance(&mut self) -> Result<WotsIndex> {
        self.wots_index = self.wots_index.advanced()?;
        Ok(self.wots_index)
    }

    /// Consume the account into its persistent content.
    ///
    /// This is the one door key material leaves through — conspicuous and
    /// consuming, the constructor's inverse. A caller that wants the root
    /// bytes must take the whole account apart to get them, in one place a
    /// review can find.
    pub fn to_record(self) -> AccountRecord {
        match self.key {
            KeyMaterial::Derived {
                account_index,
                stream,
            } => AccountRecord::Derived {
                tag: self.tag,
                account_index,
                stream_id: stream,
                wots_index: self.wots_index,
            },
            KeyMaterial::Imported {
                root,
                first,
                stream,
            } => AccountRecord::Imported {
                tag: self.tag,
                root: root.secret,
                first_key: first.to_bytes(),
                stream_id: stream,
                wots_index: self.wots_index,
            },
        }
    }

    /// Rebuild an account from its persistent content.
    ///
    /// The `Imported` arm carries the stored root through — it is the only
    /// place a restored imported account's key material can come from, which
    /// is I8's demand made structural. The `Derived` arm rebuilds from the
    /// position alone; re-deriving the actual key material needs the master
    /// seed, which no record holds.
    ///
    /// **Fallible, and that is what keeps the account model's sentence
    /// true under a grown record.** A record's fields are public because a
    /// record is data rather than authority — *a forged record restores to
    /// exactly the account the same public constructors would build, no
    /// more.* With first-key components and a stream identity in it, that
    /// only stays true if this constructor applies [`Account::import`]'s
    /// checks, so it does: the imported arm recomputes the tag and the
    /// stream from the root and its components and refuses a disagreement
    /// ([`Error::FirstAddressNotReproduced`], [`Error::StreamIdNotReproduced`]).
    /// A forged imported triple now **fails** rather than restoring, which is
    /// strictly stronger than v1's promise.
    ///
    /// **The asymmetry is inherent and is not a gap being papered over.** A
    /// derived record's tag and stream cannot be recomputed here — both need
    /// the master — so both are trusted between `open` and the next
    /// signature, where `Keystore::sign_spend` re-derives and compares them
    /// (`DerivedTagNotReproduced`, `StreamIdNotReproduced`), and at
    /// `Keystore::add` when the store holds its master. The keystore's
    /// trailer is an AEAD tag under the store key, which is authenticity
    /// for whoever holds the password and nothing for whoever does not: a
    /// party that could forge these fields holds the password and could
    /// already replace the root outright, so the re-checks are what stop a
    /// forged record from being *acted on*, whoever wrote it.
    #[cfg(feature = "native")]
    pub fn restore_from_record(record: AccountRecord) -> Result<Account> {
        match record {
            AccountRecord::Derived {
                tag,
                account_index,
                stream_id,
                wots_index,
            } => Ok(Account {
                tag,
                key: KeyMaterial::Derived {
                    account_index,
                    stream: stream_id,
                },
                wots_index,
            }),
            AccountRecord::Imported {
                tag,
                root,
                first_key,
                stream_id,
                wots_index,
            } => {
                let (_pk, computed_tag) = imported_parts(&root, &first_key);
                if computed_tag != tag {
                    return Err(Error::FirstAddressNotReproduced);
                }
                let computed_stream = crate::derive::stream_id(&root);
                if computed_stream != stream_id {
                    return Err(Error::StreamIdNotReproduced);
                }
                Ok(Account {
                    tag,
                    key: KeyMaterial::Imported {
                        root: ImportedRoot { secret: root },
                        first: first_key_from(&first_key),
                        stream: computed_stream,
                    },
                    wots_index,
                })
            }
        }
    }
}

/// The 64 bytes as a [`FirstKey`]. Total: any 64 bytes are a public seed and
/// an address image. What makes a pair *right* is [`imported_parts`], and
/// every caller of this runs it first.
#[cfg(feature = "native")]
fn first_key_from(components: &[u8; FIRST_KEY_LEN]) -> FirstKey {
    let mut pub_seed = [0u8; SEED_LEN];
    pub_seed.copy_from_slice(&components[..SEED_LEN]);
    let mut image = [0u8; 32];
    image.copy_from_slice(&components[SEED_LEN..]);
    FirstKey {
        pub_seed,
        adrs: Adrs::from_le_image(&image),
    }
}

/// What a `(root, components)` pair determines: the position-0 public key and
/// the account tag. The **one** place the two are computed, shared by
/// [`Account::import`] and [`Account::restore_from_record`], so the verifying
/// constructor and the parser cannot drift apart — the same "one derivation,
/// one set of refusals" arrangement `Keystore::key_at` uses.
///
/// One WOTS+ generation. The key stream's identity is a **second** one
/// ([`crate::derive::stream_id`]) and is deliberately not computed here: both
/// callers reject a pair on the tag first, and paying for an identity nobody
/// will use doubles the cost of every refusal — which the parser makes once
/// per imported record per open, and which Miri interprets at roughly three
/// hundred seconds a generation.
#[cfg(feature = "native")]
fn imported_parts(
    root: &Secret<SEED_LEN>,
    components: &[u8; FIRST_KEY_LEN],
) -> (crate::wots::PublicKey, Tag) {
    let first = first_key_from(components);
    let mut working = first.adrs;
    let pk = crate::wots::pkgen(root, &first.pub_seed, &mut working);
    let implicit = crate::addr::from_wots(&pk);
    let mut tag = [0u8; crate::consts::ADDR_TAG_LEN];
    tag.copy_from_slice(crate::addr::tag_of(&implicit));
    (pk, tag)
}

impl WotsIndex {
    /// The first position — the shipped wallet's `-1`, the account's first
    /// key (module doc). `to_shipped()` is `-1` and `rotation()`
    /// is `None`.
    pub const ZERO: WotsIndex = WotsIndex(0);

    /// The position as a number, for display and comparison.
    pub fn get(self) -> u32 {
        self.0
    }

    /// Crate-private constructor for the keystore's parser, which reads a
    /// position that an earlier commit made durable. Not public: a public
    /// constructor from `u32` is an index setter.
    pub(crate) const fn from_raw(raw: u32) -> WotsIndex {
        WotsIndex(raw)
    }

    /// The next position, or `Error::Range` on overflow — never a wrap.
    ///
    /// The range the refusal names is the domain of positions: `u32::MAX`
    /// is a valid position, the last one, and it is the one that cannot be
    /// advanced from.
    pub fn advanced(self) -> Result<WotsIndex> {
        match self.0.checked_add(1) {
            Some(next) => Ok(WotsIndex(next)),
            None => Err(Error::Range {
                what: "wots index",
                min: 0,
                max: u64::from(u32::MAX),
                got: u64::from(self.0),
            }),
        }
    }

    /// The rotation this position names in the shipped derivation, or `None`
    /// for the first key: position `n >= 1` is
    /// `deriveSeed(account_seed, n - 1)` through the first-key construction
    /// (`crate::derive::derive_wots_key`); position 0 is the account's first
    /// key, which is not a rotation product.
    pub fn rotation(self) -> Option<u32> {
        self.0.checked_sub(1)
    }

    /// The shipped wallet's `wotsIndex` for this position: `self - 1`, so
    /// [`WotsIndex::ZERO`] reads as the shipped `-1`.
    pub fn to_shipped(self) -> i64 {
        i64::from(self.0) - 1
    }

    /// From a shipped `wotsIndex`: `-1` is [`WotsIndex::ZERO`], `n >= 0` is
    /// position `n + 1`. Anything below `-1` or above `u32::MAX - 1` names no
    /// position and is refused, so the correspondence is total in both
    /// directions over the values that exist. The shipped scan's ambiguous
    /// `-1` write-back lands on the first key, exactly as the
    /// shipped selector reads it.
    pub fn from_shipped(shipped: i64) -> Result<WotsIndex> {
        let ours = shipped
            .checked_add(1)
            .ok_or(Error::ShippedIndex { got: shipped })?;
        u32::try_from(ours)
            .map(WotsIndex)
            .map_err(|_| Error::ShippedIndex { got: shipped })
    }
}

impl AdvanceReceipt {
    /// Mint a receipt attesting that `tag`'s advance to `index` is durable.
    ///
    /// `pub(crate)`, and it demands a [`crate::keystore::Durable`] witness —
    /// a token constructed at exactly one site in the crate, the `Ok` arm
    /// after the keystore's directory fsync (a source scan holds that count
    /// at one). So a receipt cannot be minted by any path that did not run
    /// the four durable steps to completion: not an error path, not a test
    /// helper outside `cfg(test)`, not a future module that forgets the
    /// order. This sat behind `#[cfg(test)]` until something persisted; the
    /// keystore is the persist step.
    #[cfg(feature = "native")]
    pub(crate) fn attesting(
        tag: Tag,
        index: WotsIndex,
        _witness: crate::keystore::Durable,
    ) -> AdvanceReceipt {
        AdvanceReceipt { tag, index }
    }

    /// The tag whose advance this receipt attests.
    pub fn tag(&self) -> Tag {
        self.tag
    }

    /// The index this receipt attests as durable.
    pub fn index(&self) -> WotsIndex {
        self.index
    }
}

impl AccountRecord {
    /// The record's tag, whichever kind it is.
    pub fn tag(&self) -> Tag {
        match self {
            AccountRecord::Derived { tag, .. } => *tag,
            AccountRecord::Imported { tag, .. } => *tag,
        }
    }
}

// Every Debug below is hand-written. A derived Debug on any of these is how
// key material reaches a log file, and `no_holder_of_key_material_derives_debug`
// scans for exactly that; the renderings are pinned by unit tests.

impl fmt::Debug for Account {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Account")
            .field("tag", &TagHex(&self.tag))
            .field("key", &self.key)
            .field("wots_index", &self.wots_index)
            .finish()
    }
}

impl fmt::Debug for KeyMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyMaterial::Derived {
                account_index,
                stream,
            } => f
                .debug_struct("Derived")
                .field("account_index", account_index)
                .field("stream", stream)
                .finish(),
            KeyMaterial::Imported { root, first, stream } => f
                .debug_struct("Imported")
                .field("root", root)
                .field("first", first)
                .field("stream", stream)
                .finish(),
        }
    }
}

/// The components are public data, but rendering 64 bytes into a log line is
/// noise; the account tag already identifies the key. Hand-written like every
/// `Debug` in this module, so the holder scan sees no derive here either.
impl fmt::Debug for FirstKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FirstKey(<64 public bytes>)")
    }
}



impl fmt::Debug for ImportedRoot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ImportedRoot(<redacted>)")
    }
}

impl fmt::Debug for AdvanceReceipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AdvanceReceipt")
            .field("tag", &TagHex(&self.tag))
            .field("index", &self.index)
            .finish()
    }
}

impl fmt::Debug for AccountRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AccountRecord::Derived {
                tag,
                account_index,
                stream_id,
                wots_index,
            } => f
                .debug_struct("Derived")
                .field("tag", &TagHex(tag))
                .field("account_index", account_index)
                .field("stream_id", stream_id)
                .field("wots_index", wots_index)
                .finish(),
            AccountRecord::Imported {
                tag,
                stream_id,
                wots_index,
                ..
            } => f
                .debug_struct("Imported")
                .field("tag", &TagHex(tag))
                .field("root", &"<redacted>")
                .field("stream_id", stream_id)
                .field("wots_index", wots_index)
                .finish(),
        }
    }
}

/// Lowercase-hex rendering for the (non-secret) tag in Debug output.
struct TagHex<'a>(&'a Tag);

impl fmt::Debug for TagHex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    /// The last position cannot be advanced from, and the refusal names
    /// the domain it is at the end of: `u32::MAX` itself, not one short of
    /// it.
    #[test]
    fn advanced_at_the_ceiling_names_u32_max_as_the_last_position() {
        let last = super::WotsIndex::from_raw(u32::MAX);
        let err = last.advanced().err();
        assert_eq!(
            err,
            Some(crate::Error::Range {
                what: "wots index",
                min: 0,
                max: u64::from(u32::MAX),
                got: u64::from(u32::MAX),
            }),
            "advanced() at the ceiling did not name u32::MAX as the last position: {err:?}"
        );
        let one_below = super::WotsIndex::from_raw(u32::MAX - 1).advanced().unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(one_below.get(), u32::MAX, "u32::MAX is a position, reachable by advancing from the one below it");
    }

    use super::*;

    fn tag_of(byte: u8) -> Tag {
        [byte; 20]
    }

    /// `F-address-widths`' account seed and its 2208-byte first address --
    /// a real pair, since `Account::import` refuses one that is not. The
    /// address is embedded rather than transcribed (`tests/txwire.rs`'s
    /// idiom), so no literal here can drift from the fixture.
    // Not under Miri: its only readers are the four tests gated out for
    // their key-generation cost, so under that cfg it has none.
    #[cfg(not(miri))]
    #[cfg(feature = "native")]
    const WIDTHS_ROOT: [u8; SEED_LEN] = [
        0x66, 0x4e, 0xdd, 0x3d, 0x3b, 0xf1, 0xa0, 0xe2, 0x9c, 0x93, 0x98, 0xdd, 0xc1, 0x61,
        0x14, 0xab, 0xc6, 0xd6, 0xb4, 0x32, 0xb1, 0xe5, 0xe4, 0xde, 0x26, 0x7c, 0x7e, 0x2a,
        0xe5, 0x3f, 0x58, 0x0b,
    ];
    // Not under Miri: read only by `widths_import` and the gated tests.
    #[cfg(not(miri))]
    #[cfg(feature = "native")]
    const WIDTHS_ADDRESS: &[u8; crate::consts::WOTS_ADDR_LEN] =
        include_bytes!("../../../fixtures/F-widths_account_address.bin");
    /// The tag that pair produces -- `F-address-widths.account_tag`, emitted
    /// by the TypeScript, not read back from `import`.
    // Not under Miri: compared only by the gated
    // `debug_never_reveals_key_material` and its two neighbours.
    #[cfg(not(miri))]
    #[cfg(feature = "native")]
    const WIDTHS_TAG: Tag = [
        0x05, 0xff, 0x0f, 0x69, 0xd4, 0xc1, 0xcd, 0x68, 0x2e, 0xd3, 0x34, 0x1c, 0x0b, 0x77,
        0x73, 0x05, 0x4b, 0x58, 0x80, 0x0f,
    ];

    // Not under Miri: called only by `debug_never_reveals_key_material`,
    // `restore_refuses_a_record_that_disagrees_with_its_own_root` and
    // `records_round_trip_both_kinds_in_crate`, all gated out under Miri.
    #[cfg(not(miri))]
    #[cfg(feature = "native")]
    fn widths_import() -> Account {
        Account::import(Secret::new(WIDTHS_ROOT), WIDTHS_ADDRESS).expect("a real pair")
    }

    /// Not under Miri: all but a moment of its time is the two WOTS+ key
    /// generations inside `Account::import` (372 s of the interpreter's,
    /// against under a second for a unit test that generates no key).
    /// `tests/miri.rs::native_backend_is_clean_under_miri` walks every primitive
    /// one generation drives, and `Account::import` itself stays interpreted
    /// through `keystore::format`'s `two_accounts`, which the ungated parser
    /// tests build; what is left here is the text a `Debug` impl writes.
    #[cfg(feature = "native")]
    #[cfg(not(miri))]
    #[test]
    fn debug_never_reveals_key_material() {
        let acct = widths_import();
        assert_eq!(acct.tag(), WIDTHS_TAG, "import must compute the fixture's tag");

        let rendered = format!("{acct:?}");
        assert_eq!(
            rendered,
            "Account { tag: 05ff0f69d4c1cd682ed3341c0b7773054b58800f, \
             key: Imported { root: ImportedRoot(<redacted>), \
             first: FirstKey(<64 public bytes>), \
             stream: StreamId(2587878ad34d29cf2e4be48386aec3a0c2a7ea8c) }, \
             wots_index: WotsIndex(0) }"
        );
        let alternate = format!("{acct:#?}");
        // The root's first bytes, in both hex spellings, must appear nowhere.
        for out in [&rendered, &alternate] {
            assert!(!out.contains("664edd") && !out.contains("664EDD"));
        }

        let record = acct.to_record();
        let rec_rendered = format!("{record:?}");
        assert_eq!(
            rec_rendered,
            "Imported { tag: 05ff0f69d4c1cd682ed3341c0b7773054b58800f, \
             root: \"<redacted>\", \
             stream_id: StreamId(2587878ad34d29cf2e4be48386aec3a0c2a7ea8c), \
             wots_index: WotsIndex(0) }"
        );
        assert!(!rec_rendered.contains("664edd"));

        let receipt =
            AdvanceReceipt::attesting(tag_of(0x11), WotsIndex::ZERO, crate::keystore::Durable::for_test());
        assert_eq!(
            format!("{receipt:?}"),
            "AdvanceReceipt { tag: 1111111111111111111111111111111111111111, \
             index: WotsIndex(0) }"
        );
    }

    /// An imported account is constructible **only** from a pair the root
    /// reproduces, so the tag cannot be forged and position 0 is always
    /// available. The unverified constructor is gone.
    /// Not under Miri: its time is three `Account::import` calls, six WOTS+ key
    /// generations (1,123 s measured). What it pins is the comparison
    /// made after the generation, and the generation is walked by
    /// `tests/miri.rs` and reached by the ungated parser tests' `two_accounts`.
    #[cfg(feature = "native")]
    #[cfg(not(miri))]
    #[test]
    fn import_refuses_a_first_address_the_root_does_not_reproduce() {
        // One byte of the public key, flipped: everything else is the real
        // pair, so only the reproduction check can fail.
        let mut forged = *WIDTHS_ADDRESS;
        forged[0] ^= 0x01;
        assert_eq!(
            Account::import(Secret::new(WIDTHS_ROOT), &forged).err(),
            Some(Error::FirstAddressNotReproduced)
        );

        // And a different root against the real address.
        let mut other = WIDTHS_ROOT;
        other[31] ^= 0x01;
        assert_eq!(
            Account::import(Secret::new(other), WIDTHS_ADDRESS).err(),
            Some(Error::FirstAddressNotReproduced)
        );

        // A *junk* pair is still accepted, and that is the point of the
        // stream identity: any (pub_seed, adrs) reproduces some public key
        // under this root, giving a different tag over the SAME key stream.
        // `Keystore::add` is what refuses it.
        let mut junk = *WIDTHS_ADDRESS;
        junk[crate::consts::PK_LEN] ^= 0x01; // one byte of the public seed
        let pk = {
            let mut components = [0u8; FIRST_KEY_LEN];
            components.copy_from_slice(&junk[crate::consts::PK_LEN..]);
            imported_parts(&Secret::new(WIDTHS_ROOT), &components).0
        };
        junk[..crate::consts::PK_LEN].copy_from_slice(&pk[..]);
        let aliased = Account::import(Secret::new(WIDTHS_ROOT), &junk).expect("a valid pair");
        assert_ne!(aliased.tag(), WIDTHS_TAG, "a junk first key gives another tag");
        assert_eq!(
            crate::derive::stream_id(&Secret::new(WIDTHS_ROOT)),
            match aliased.key_material() {
                KeyMaterial::Imported { stream, .. } => *stream,
                KeyMaterial::Derived { .. } => unreachable!(),
            },
            "and the same key stream, which is what the identity names"
        );
    }

    /// A forged record does not restore: the imported arm recomputes the tag
    /// and the identity from the root and refuses a disagreement, which is
    /// what keeps the account model's "restores to exactly the account the same
    /// public constructors would build" true now that the record is bigger.
    /// Not under Miri: its time is the key generations inside `Account::import`
    /// and `Account::restore_from_record` (1,323 s measured, the most
    /// expensive unit test in the crate). `restore_from_record` is interpreted
    /// regardless -- `parse_with_key` calls it for every record it reads, and
    /// the ungated parser tests read the canonical image.
    #[cfg(feature = "native")]
    #[cfg(not(miri))]
    #[test]
    fn restore_refuses_a_record_that_disagrees_with_its_own_root() {
        let good = widths_import().to_record();
        let (tag, root, first_key, stream_id, wots_index) = match good {
            AccountRecord::Imported {
                tag,
                root,
                first_key,
                stream_id,
                wots_index,
            } => (tag, root, first_key, stream_id, wots_index),
            AccountRecord::Derived { .. } => unreachable!(),
        };

        let mut wrong_tag = tag;
        wrong_tag[0] ^= 0x01;
        assert_eq!(
            Account::restore_from_record(AccountRecord::Imported {
                tag: wrong_tag,
                root: root.clone(),
                first_key,
                stream_id,
                wots_index,
            })
            .err(),
            Some(Error::FirstAddressNotReproduced)
        );

        let mut wrong_stream = *stream_id.as_bytes();
        wrong_stream[0] ^= 0x01;
        assert_eq!(
            Account::restore_from_record(AccountRecord::Imported {
                tag,
                root: root.clone(),
                first_key,
                stream_id: StreamId::from_bytes(wrong_stream),
                wots_index,
            })
            .err(),
            Some(Error::StreamIdNotReproduced)
        );

        // The untouched record still restores -- so the two reds above are
        // the checks firing, not the record being unrestorable.
        assert!(Account::restore_from_record(AccountRecord::Imported {
            tag,
            root,
            first_key,
            stream_id,
            wots_index,
        })
        .is_ok());
    }

    #[test]
    fn wots_index_debug_prints_the_number() {
        // The index is public state, not secret; hiding it would only make
        // I4's divergence reports worse. This pin records the decision.
        assert_eq!(format!("{:?}", WotsIndex::ZERO), "WotsIndex(0)");
    }

    #[test]
    fn wots_index_maps_onto_the_shipped_numbering_totally() {
        // ours = shipped + 1, in both directions, at the edges.
        assert_eq!(WotsIndex::ZERO.to_shipped(), -1);
        assert_eq!(WotsIndex::ZERO.rotation(), None);
        assert_eq!(WotsIndex(1).to_shipped(), 0);
        assert_eq!(WotsIndex(1).rotation(), Some(0));
        assert_eq!(WotsIndex(u32::MAX).rotation(), Some(u32::MAX - 1));
        assert_eq!(WotsIndex::from_shipped(-1).ok(), Some(WotsIndex::ZERO));
        assert_eq!(WotsIndex::from_shipped(0).ok(), Some(WotsIndex(1)));
        assert_eq!(
            WotsIndex::from_shipped(i64::from(u32::MAX) - 1).ok(),
            Some(WotsIndex(u32::MAX))
        );
        for shipped in [-2i64, i64::MIN, i64::from(u32::MAX), i64::MAX] {
            assert_eq!(
                WotsIndex::from_shipped(shipped).err(),
                Some(Error::ShippedIndex { got: shipped }),
                "shipped {shipped} must name no position"
            );
        }
        for ours in [0u32, 1, 2, u32::MAX - 1, u32::MAX] {
            let back = WotsIndex::from_shipped(WotsIndex(ours).to_shipped()).ok();
            assert_eq!(back, Some(WotsIndex(ours)), "round trip at {ours}");
        }
    }

    /// Not under Miri: its time is the two WOTS+ generations inside
    /// `Account::derive` (386 s measured), and the `WotsIndex` arithmetic
    /// it then asserts is walked under the interpreter in under a second by
    /// `advanced_at_the_ceiling_names_u32_max_as_the_last_position`, ungated.
    #[cfg(feature = "native")]
    #[cfg(not(miri))]
    #[test]
    fn advance_is_monotonic_and_overflow_is_an_error_not_a_wrap() {
        let mut acct = Account::derive(&Secret::new([0x5Au8; SEED_LEN]), 3);
        assert_eq!(acct.wots_index().get(), 0);
        let first = acct.advance();
        assert_eq!(first.ok().map(WotsIndex::get), Some(1));
        let second = acct.advance();
        assert_eq!(second.ok().map(WotsIndex::get), Some(2));
        assert_eq!(acct.wots_index().get(), 2);

        // A wrap is a rollback to the worst value; pin the error instead.
        let max = WotsIndex(u32::MAX);
        assert_eq!(
            max.advanced().err(),
            Some(Error::Range {
                what: "wots index",
                min: 0,
                // `u32::MAX` itself: the last position.
                max: u64::from(u32::MAX),
                got: u64::from(u32::MAX),
            })
        );
    }

    #[test]
    fn receipt_binds_the_tag_and_index_it_attests() {
        let receipt =
            AdvanceReceipt::attesting(tag_of(0x33), WotsIndex(7), crate::keystore::Durable::for_test());
        assert_eq!(receipt.tag(), tag_of(0x33));
        assert_eq!(receipt.index().get(), 7);
    }

    /// Not under Miri: its time is the key generations inside `Account::import`,
    /// `Account::derive` and two `Account::restore_from_record` calls (1,127 s
    /// measured). The round trip itself is a struct-to-enum copy over
    /// fixed-size arrays, and every constructor under it stays interpreted
    /// through the ungated parser tests.
    #[cfg(feature = "native")]
    #[cfg(not(miri))]
    #[test]
    fn records_round_trip_both_kinds_in_crate() {
        // The external, census-checked round-trip is
        // tests/invariants.rs::imported_account_restores_from_stored_seed;
        // this is the in-module smoke test of the same path.
        let mut imported = widths_import();
        let advanced = imported.advance();
        assert_eq!(advanced.ok().map(WotsIndex::get), Some(1));
        let restored = Account::restore_from_record(imported.to_record()).expect("restore");
        assert_eq!(restored.kind(), AccountKind::Imported);
        assert_eq!(restored.tag(), WIDTHS_TAG);
        assert_eq!(restored.wots_index().get(), 1);
        match restored.to_record() {
            AccountRecord::Imported { root, .. } => {
                assert_eq!(root.expose(), &WIDTHS_ROOT);
            }
            AccountRecord::Derived { .. } => {
                panic!("imported account restored as derived");
            }
        }

        let derived = Account::derive(&Secret::new([0x5Au8; SEED_LEN]), 9);
        let restored = Account::restore_from_record(derived.to_record()).expect("restore");
        assert_eq!(restored.kind(), AccountKind::Derived);
        match restored.to_record() {
            AccountRecord::Derived { account_index, .. } => {
                assert_eq!(account_index, 9);
            }
            AccountRecord::Imported { .. } => {
                panic!("derived account restored as imported");
            }
        }
    }
}
