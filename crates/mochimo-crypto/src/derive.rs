//! The shipped extension's seed derivation, ported from the TypeScript in
//! `reference/mochimo-wallet` — `redux/utils/derivation.ts`,
//! `crypto/digestRandomGenerator.ts` and `core/MasterSeed.ts` — and the
//! first-key construction it hands to `WOTS.generateRandomAddress`
//! (`reference/mochimo-wots/src/protocol/wots.ts:335`).
//!
//! # What this is checked against, and what that establishes
//!
//! Group F (`fixtures/group_f_derivation.json`) is a **specification
//! capture**: the extension's own code, executed and recorded, with no second
//! implementation anywhere
//! (`invariants.rs::group_f_is_specification_not_crosscheck`). A port agreeing
//! with it proves the port matches the extension, which is the whole
//! requirement here — it proves nothing about whether the extension is right,
//! and porting against it does not upgrade it into an oracle.
//!
//! **No differential existed and none is faked.** The C reference's wallet
//! derives keys by a different scheme entirely (`src/bin/wallet.c`'s
//! `rndbytes`, seeded with a global `Password`), so there was never a
//! reference counterpart to compare against. What stands in its place is weaker and is
//! named as weaker: the group F KAT (`tests/kat.rs`, every field), the three
//! landmine vectors below, boundary enumeration where the domain is finite
//! (`tests/derive.rs`), and fault injection on every convention in this file.
//! The WOTS+ step alone (`wots::pkgen`) has the full three-mechanism standard
//! behind it; nothing above it does.
//!
//! # The scheme
//!
//! `deriveSeed(seed, id)`: `SHA-512(seed ‖ intToBytes(id))` is fed as seed
//! material to a fresh [`DigestRandomGenerator`], which then draws the 32-byte
//! WOTS+ secret. **The generator continues** — the same stream then supplies
//! the 2208 bytes `generateRandomAddress` asks for, of which bytes
//! `2144..2176` become the WOTS+ public seed and `2176..2208` the hash
//! address, read as eight **little-endian** words (the memory image — the CX
//! crosscheck established that this is how the TypeScript reads its `addr`
//! parameter). `wots_pkgen(secret, pub_seed, adrs)` then gives the
//! public key; the v3 address hash is over those 2144 bytes alone.
//!
//! An account is `deriveSeed(master, account_index)`; its tag is the tag half
//! of the implicit address of that first key. A rotation is
//! `deriveSeed(account_seed, rotation)` through the same construction. The
//! index that names a rotation in this crate is [`crate::account::WotsIndex`],
//! whose correspondence to the shipped numbering is decided: ours is the
//! shipped index plus one (`account.rs`'s module doc).
//!
//! # Three conventions that coexist in one scheme (the landmines)
//!
//! Each is reproduced deliberately, pinned by its own vector, and fault-
//! injected in `tests/` so that flipping any one goes red at its own name:
//!
//! 1. **Two integer encodings on one path.** [`index_bytes`] is four bytes
//!    **big-endian** (`intToBytes`, `digestRandomGenerator.ts:3`) and carries
//!    the account or rotation index; [`counter_bytes`] is four bytes
//!    **little-endian** in an eight-byte buffer (`digestAddCounter`, `:35`)
//!    and carries the generator's counters. Picking one convention for both
//!    produces valid-looking, wrong keys. `F-counter-endianness`.
//! 2. **The seed cycles on the ninth call, not the tenth.** `stateCounter`
//!    starts at 1 and is post-incremented, so the `% 10 == 0` test first
//!    passes when the counter *entering* the call was 9. Period 10, phase off
//!    by one from the naive reading. `F-prng-cycle-phase`.
//! 3. **Chunking is visible.** `nextBytes(n)` runs `ceil(n / 64)` whole states
//!    and discards what the last did not need; two calls of 32 are not one
//!    call of 64. `F-prng-chunking`.
//!
//! A fourth landmine is **not** here because it is not on the live path:
//! `WOTSWallet.componentsGenerator`'s ASCII round-trip corrupts bytes ≥ 0x80,
//! and both live entry points pass a random generator to `WOTSWallet.create`,
//! taking the `if (randomGenerator)` branch (`derivation.ts` lines 8 and 40;
//! `F-high-byte-seed` records zero calls into it, `F-ascii-control` proves the
//! counter can be non-zero). Deliberately not ported; recorded, not owed.
//!
//! # What is secret here
//!
//! The generator's state and seed are derived from key material and hold
//! enough to reproduce every key downstream, so both are `Zeroizing` and the
//! type's `Debug` redacts them. [`DerivedSeed`], [`WotsKey`] and
//! [`DerivedAccount`] hold a [`Secret`] and hand-write `Debug` for the same
//! reason (`invariants.rs::no_holder_of_key_material_derives_debug`).
//!
//! # Residue
//!
//! Two implicit panic classes exist in this file and neither is counted by
//! the panic census: constant slice indexing on fixed-size
//! buffers, and `copy_from_slice` between constant-width sources and
//! destinations. Every width is a constant of the layout (or a chunk of at
//! most 64 bytes), and the Miri run walks the code. This
//! sentence is where both classes are declared.

use core::fmt;

use sha2::{Digest, Sha512};
use zeroize::Zeroizing;

use crate::account::StreamId;
use crate::addr::{self, Address, Tag};
use crate::consts::{ADDR_TAG_LEN, PK_LEN, SEED_LEN, WOTS_ADDR_LEN};
use crate::secret::Secret;
use crate::wots::{self, Adrs, PublicKey};

/// SHA-512's output width, which is also the generator's state and seed width
/// (`digestRandomGenerator.ts:29-30`: both buffers are 64 zero bytes).
const STATE_LEN: usize = 64;

/// The legacy 12-byte tag's width and position: the last twelve bytes of a
/// 2208-byte address (`reference/mochimo-wots/src/protocol/tag.ts:7,57`).
const LEGACY_TAG_LEN: usize = 12;

/// `intToBytes(id)`: four bytes, **big-endian** (`digestRandomGenerator.ts:3-10`).
///
/// Carries the account index into `deriveSeed` and the rotation index into
/// `deriveWotsSeedAndAddress`. JS `>>` operates on the value as a 32-bit
/// integer, so a `u32` reproduces every value the shipped code can produce,
/// including the `-1` its outer layer rejects and its inner layer computes
/// (`F-derive-seed-negative` is `u32::MAX` here).
#[must_use]
pub fn index_bytes(id: u32) -> [u8; 4] {
    id.to_be_bytes()
}

/// `digestAddCounter(counter)`: the low 32 bits **little-endian**, then four
/// zero bytes (`digestRandomGenerator.ts:35-48`).
///
/// The other convention in the same scheme. `u64` because the shipped
/// counters are JS numbers that never wrap; the `as u32` is JS's own
/// `>>> 8` ToUint32 truncation, exact for every count below 2^53 and
/// unreachable in practice (a wrap needs 2^32 states, 256 GiB of output).
#[must_use]
pub fn counter_bytes(counter: u64) -> [u8; 8] {
    let low = (counter as u32).to_le_bytes();
    [low[0], low[1], low[2], low[3], 0, 0, 0, 0]
}

fn sha512(parts: &[&[u8]]) -> [u8; STATE_LEN] {
    let mut h = Sha512::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// The extension's `DigestRandomGenerator` (`crypto/digestRandomGenerator.ts:21`),
/// a BouncyCastle-style digest PRNG over SHA-512.
///
/// Both buffers start as 64 zero bytes and both counters at **1**
/// (`:23-24, :29-30`). `F-prng-unseeded` pins the first draw with nothing
/// added, so a wrong origin fails there rather than 2144 bytes later.
pub struct DigestRandomGenerator {
    seed: Zeroizing<[u8; STATE_LEN]>,
    state: Zeroizing<[u8; STATE_LEN]>,
    /// `stateCounter`, read before increment (`:70`).
    state_counter: u64,
    /// `seedCounter`, read before increment (`:59`).
    seed_counter: u64,
}

impl DigestRandomGenerator {
    /// `CYCLE_COUNT` (`digestRandomGenerator.ts:22`).
    pub const CYCLE_COUNT: u64 = 10;

    /// A fresh generator: zero state, zero seed, both counters at 1.
    #[must_use]
    pub fn new() -> Self {
        DigestRandomGenerator {
            seed: Zeroizing::new([0u8; STATE_LEN]),
            state: Zeroizing::new([0u8; STATE_LEN]),
            state_counter: 1,
            seed_counter: 1,
        }
    }

    /// `cycleSeed()` (`:57-63`): `seed = SHA-512(seed ‖ counter_bytes(seedCounter++))`.
    fn cycle_seed(&mut self) {
        let ctr = counter_bytes(self.seed_counter);
        self.seed_counter = self.seed_counter.wrapping_add(1);
        *self.seed = sha512(&[&*self.seed, &ctr]);
    }

    /// `generateState()` (`:65-77`):
    /// `state = SHA-512(counter_bytes(stateCounter++) ‖ state ‖ seed)`, then
    /// the cycle test **on the incremented counter** — which is landmine 2.
    fn generate_state(&mut self) {
        let ctr = counter_bytes(self.state_counter);
        self.state_counter = self.state_counter.wrapping_add(1);
        *self.state = sha512(&[&ctr, &*self.state, &*self.seed]);
        if self.state_counter.is_multiple_of(Self::CYCLE_COUNT) {
            self.cycle_seed();
        }
    }

    /// `addSeedMaterial(m)` (`:79-84`): `seed = SHA-512(m ‖ seed)`. The
    /// material goes **first**; `F-prng-seeded` pins the order.
    pub fn add_seed_material(&mut self, material: &[u8]) {
        *self.seed = sha512(&[material, &*self.seed]);
    }

    /// `nextBytes(out.len())` (`:86-103`): one fresh state per 64-byte chunk,
    /// the tail of the last state discarded. Landmine 3 — a generator that
    /// buffered the tail for the next call would pass any test drawing 32
    /// bytes once and fail `F-prng-chunking`.
    pub fn fill(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(STATE_LEN) {
            self.generate_state();
            chunk.copy_from_slice(&self.state[..chunk.len()]);
        }
    }

    /// How many times the seed has cycled. Observable so a test can locate
    /// the cycle by watching this move across calls, which is how
    /// `F-prng-cycle-phase` records it; the bytes are the stronger pin.
    #[must_use]
    pub fn seed_cycles(&self) -> u64 {
        self.seed_counter.saturating_sub(1)
    }

    /// How many states have been generated so far.
    #[must_use]
    pub fn states_generated(&self) -> u64 {
        self.state_counter.saturating_sub(1)
    }
}

impl Default for DigestRandomGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for DigestRandomGenerator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DigestRandomGenerator")
            .field("states_generated", &self.states_generated())
            .field("seed_cycles", &self.seed_cycles())
            .field("state", &"<redacted>")
            .field("seed", &"<redacted>")
            .finish()
    }
}

/// What `deriveSeed` returns (`derivation.ts:18-31`): the 32-byte secret and
/// the generator **as it was left**, which the first-key construction keeps
/// drawing from.
pub struct DerivedSeed {
    secret: Secret<SEED_LEN>,
    prng: DigestRandomGenerator,
}

impl DerivedSeed {
    /// The 32-byte secret the generator produced first.
    #[must_use]
    pub fn secret(&self) -> &Secret<SEED_LEN> {
        &self.secret
    }

    /// Take the secret and the continuing generator apart.
    #[must_use]
    pub fn into_parts(self) -> (Secret<SEED_LEN>, DigestRandomGenerator) {
        (self.secret, self.prng)
    }
}

impl fmt::Debug for DerivedSeed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DerivedSeed")
            .field("secret", &self.secret)
            .field("prng", &self.prng)
            .finish()
    }
}

/// `Derivation.deriveSeed(seed, id)` (`derivation.ts:18-31`).
///
/// `SHA-512(seed ‖ index_bytes(id))` → a fresh generator's seed material →
/// 32 bytes drawn. `seed` is a slice because the shipped function is called
/// with both a master seed and an account seed; both are 32 bytes on the live
/// path, and `F-derive-seed` pins 0, 1, 2, 255, 256 and 65536 — the last
/// three straddling the byte boundaries of the big-endian index, which is
/// where a wrong-endianness port first diverges.
#[must_use]
pub fn derive_seed(seed: &[u8], id: u32) -> DerivedSeed {
    let local = Zeroizing::new(sha512(&[seed, &index_bytes(id)]));
    let mut prng = DigestRandomGenerator::new();
    prng.add_seed_material(&*local);
    let mut secret = Zeroizing::new([0u8; SEED_LEN]);
    prng.fill(&mut *secret);
    DerivedSeed {
        secret: Secret::new(*secret),
        prng,
    }
}

/// A WOTS+ key as the extension constructs one: the secret, the public seed
/// and hash address the generator supplied, and the public key they produce.
pub struct WotsKey {
    secret: Secret<SEED_LEN>,
    pub_seed: [u8; SEED_LEN],
    /// The words `wots_pkgen` **started** from — the generator's bytes as a
    /// little-endian image. Signing re-runs the same addressing from here.
    adrs: Adrs,
    pk: PublicKey,
}

impl WotsKey {
    /// The signing secret.
    #[must_use]
    pub fn secret(&self) -> &Secret<SEED_LEN> {
        &self.secret
    }

    /// The public seed: generator bytes `2144..2176`.
    #[must_use]
    pub fn pub_seed(&self) -> &[u8; SEED_LEN] {
        &self.pub_seed
    }

    /// The hash address `wots_pkgen` started from: generator bytes
    /// `2176..2208` as eight little-endian words.
    #[must_use]
    pub fn adrs(&self) -> Adrs {
        self.adrs
    }

    /// The 2144-byte WOTS+ public key.
    #[must_use]
    pub fn public_key(&self) -> &[u8; PK_LEN] {
        &self.pk
    }

    /// `addr_from_wots(pk)`: the implicit v3 address, tag half equal to hash
    /// half. This is the address an account's **first** key answers to, and
    /// its tag half is the account tag (executed by the KAT).
    #[must_use]
    pub fn implicit_address(&self) -> Address {
        addr::from_wots(&self.pk)
    }

    /// The tag half of [`WotsKey::implicit_address`].
    #[must_use]
    pub fn tag(&self) -> Tag {
        let mut tag = [0u8; ADDR_TAG_LEN];
        tag.copy_from_slice(addr::tag_of(&self.implicit_address()));
        tag
    }

    /// The 40-byte v3 address under an account tag: `tag ‖ hash_of(pk)`, which
    /// is what `deriveWotsSeedAndAddress` returns as `address`
    /// (`derivation.ts:48`; `WotsAddress.setTag` then `bytes()[..40]`).
    #[must_use]
    pub fn address(&self, tag: &Tag) -> Address {
        let implicit = self.implicit_address();
        let mut out = [0u8; ADDR_TAG_LEN * 2];
        out[..ADDR_TAG_LEN].copy_from_slice(tag);
        out[ADDR_TAG_LEN..].copy_from_slice(addr::hash_of(&implicit));
        out
    }

    /// The 2208-byte legacy address `generateRandomAddress` returns
    /// (`wots.ts:347-373`): `pk ‖ pub_seed ‖ adrs ‖ tag12`, the twelve-byte
    /// tag overlaid on the last twelve bytes (`tag.ts:57`).
    ///
    /// `wots_pkgen` mutates address words 5, 6 and 7 as it runs (group A's
    /// `adrs_in_words`/`adrs_out_words` pairs show exactly those three), and
    /// the overlay covers bytes `2196..2208` — exactly those three words. So
    /// the pre-pkgen image and the post-pkgen image agree on every byte the
    /// overlay leaves, and this function needs neither to have kept the
    /// mutated state nor to guess the TypeScript's. `F-widths_account_address`
    /// and `F-acct{0,1}_address` pin it byte for byte.
    #[must_use]
    pub fn legacy_address(&self, tag12: &[u8; LEGACY_TAG_LEN]) -> Box<[u8; WOTS_ADDR_LEN]> {
        let mut out = Box::new([0u8; WOTS_ADDR_LEN]);
        out[..PK_LEN].copy_from_slice(&self.pk[..]);
        out[PK_LEN..PK_LEN + SEED_LEN].copy_from_slice(&self.pub_seed);
        out[PK_LEN + SEED_LEN..].copy_from_slice(&self.adrs.le_image());
        out[WOTS_ADDR_LEN - LEGACY_TAG_LEN..].copy_from_slice(tag12);
        out
    }
}

impl fmt::Debug for WotsKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WotsKey")
            .field("secret", &self.secret)
            .field("pub_seed", &"<redacted>")
            .field("adrs", &"<redacted>")
            .field("tag", &TagHex(self.tag()))
            .finish()
    }
}

/// The first-key construction: `WOTSWallet.create(name, secret, v3tag,
/// generator)` with a generator supplied →
/// `WOTS.generateRandomAddress` (`wallet.ts:245`, `wots.ts:335-373`), driven
/// by the generator `deriveSeed` left behind.
///
/// The generator fills a 2208-byte buffer in **one** call (35 states, the
/// last 32 bytes of the 35th discarded); `pub_seed` is bytes `2144..2176`,
/// the address words are `2176..2208`, and `wots_pkgen` writes the public key
/// over `0..2144`. The 12-byte tag `create` passes to `generateRandomAddress`
/// never reaches the public key — it is overlaid on address words the
/// generation overwrites anyway — which is why `deriveAccountTag`'s key and
/// `deriveAccount`'s first address are the same key under two tags.
#[must_use]
pub fn first_key(derived: DerivedSeed) -> WotsKey {
    let (secret, mut prng) = derived.into_parts();
    let mut buf = Zeroizing::new([0u8; WOTS_ADDR_LEN]);
    prng.fill(&mut *buf);

    let mut pub_seed = [0u8; SEED_LEN];
    pub_seed.copy_from_slice(&buf[PK_LEN..PK_LEN + SEED_LEN]);
    let mut image = [0u8; 32];
    image.copy_from_slice(&buf[PK_LEN + SEED_LEN..WOTS_ADDR_LEN]);
    let adrs = Adrs::from_le_image(&image);

    let mut working = adrs;
    let pk = wots::pkgen(&secret, &pub_seed, &mut working);
    WotsKey {
        secret,
        pub_seed,
        adrs,
        pk,
    }
}

/// The first key **rebuilt from stored public components** rather than from a
/// generator: what the shipped wallet does at `wotsIndex === -1`, where it
/// memcpys `faddress` back into the generation buffer instead of deriving
/// anything (`redux/selectors/accountSelectors.ts:24-31`).
///
/// This is the imported account's route to position 0, and it is the reason
/// [`crate::account::Account::import`] takes the 2208-byte address at all: the
/// components are a function of the *master* seed and are in no sense
/// recoverable from `secret`. The caller supplies them from a record that has
/// already been verified against the root -- `Account::import` on the way in,
/// `Account::restore_from_record` on the way back -- so nothing here re-checks
/// them; this function is total over any 64 bytes.
///
/// Symmetric with [`first_key`] in everything but where the two public values
/// come from, and it produces the same `WotsKey` shape, so `sign_spend`'s two
/// kinds share one signing path.
#[must_use]
pub fn first_key_from_components(
    secret: Secret<SEED_LEN>,
    pub_seed: &[u8; SEED_LEN],
    adrs: Adrs,
) -> WotsKey {
    let mut working = adrs;
    let pk = wots::pkgen(&secret, pub_seed, &mut working);
    WotsKey {
        secret,
        pub_seed: *pub_seed,
        adrs,
        pk,
    }
}

/// `Derivation.deriveAccountTag(master, account_index)` (`derivation.ts:6-16`):
/// the tag half of the first key's implicit address.
#[must_use]
pub fn derive_account_tag(master: &Secret<SEED_LEN>, account_index: u32) -> Tag {
    first_key(derive_seed(master.expose(), account_index)).tag()
}

/// One rotation of an account's key: `deriveSeed(account_seed, rotation)`
/// through the first-key construction — the `secret`/`wotsWallet` half of
/// `Derivation.deriveWotsSeedAndAddress` (`derivation.ts:33-49`).
///
/// `rotation` is the **shipped** numbering (the extension's `wotsIndex`, from
/// 0); the crate's [`crate::account::WotsIndex`] maps onto it by
/// [`crate::account::WotsIndex::rotation`]. The shipped function
/// also takes the account tag as hex and refuses any length but 20; the tag
/// does not enter the key, so it is not a parameter here — the caller applies
/// it with [`WotsKey::address`], and a wrong-width tag is unrepresentable as
/// a [`Tag`]. Its `wotsIndex < 0` refusal is unrepresentable in the same way.
#[must_use]
pub fn derive_wots_key(account_seed: &Secret<SEED_LEN>, rotation: u32) -> WotsKey {
    first_key(derive_seed(account_seed.expose(), rotation))
}

/// The key stream a 32-byte seed defines, named by **the rotation-0 public
/// key's hash**.
///
/// # Why this key and not another
///
/// A rotation key is `derive_wots_key(seed, r)` — a function of the seed
/// alone — so one seed under two tags is one key stream with two indices, and
/// I1 falls with nothing computing a wrong answer. Naming
/// the stream needs a value that is the same **for both kinds of account**
/// and computable where each is built: from the master in
/// [`crate::account::Account::derive`], from the root in
/// [`crate::account::Account::import`].
///
/// Position 0 cannot serve. A derived account's first key takes its public
/// components from the master's generator and an imported account's from its
/// stored `faddress`, so the two differ over one stream — which is the
/// aliasing this is meant to detect, not a name for it. Rotation 0 (this
/// crate's [`crate::account::WotsIndex`] 1) is the first key that is a pure
/// function of the seed, so it is the first one both sides can agree on.
///
/// Public rather than a commitment to the secret: the value is an address
/// hash, and a record that carried `H(seed)` instead would put key-derived
/// data into the derived record, which carries none today by decision.
///
/// **Cost, stated because it is paid on every account construction:** one
/// WOTS+ generation (`wots::pkgen`, ~3,000 SHA-256 invocations). Group F
/// records the answer for two seeds — `F-address-widths` and
/// `F-high-byte-seed` carry it as the second twenty bytes of `wots_address`
/// at `wots_index: 0` — so this is pinned against the TypeScript rather than
/// against itself (`tests/derive.rs`).
#[must_use]
pub fn stream_id(seed: &Secret<SEED_LEN>) -> StreamId {
    StreamId::from_bytes(derive_wots_key(seed, 0).tag())
}

/// What `MasterSeed.deriveAccount` returns (`MasterSeed.ts:115-137`): the tag,
/// the account seed, and the first key.
pub struct DerivedAccount {
    tag: Tag,
    seed: Secret<SEED_LEN>,
    first: WotsKey,
}

impl DerivedAccount {
    /// The 20-byte account tag.
    #[must_use]
    pub fn tag(&self) -> Tag {
        self.tag
    }

    /// The account seed: the root every rotation derives from.
    #[must_use]
    pub fn seed(&self) -> &Secret<SEED_LEN> {
        &self.seed
    }

    /// The first key — the account's `faddress`, whose secret
    /// is the account seed itself.
    #[must_use]
    pub fn first_key(&self) -> &WotsKey {
        &self.first
    }

    /// Take the three apart.
    #[must_use]
    pub fn into_parts(self) -> (Tag, Secret<SEED_LEN>, WotsKey) {
        (self.tag, self.seed, self.first)
    }
}

impl fmt::Debug for DerivedAccount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DerivedAccount")
            .field("tag", &TagHex(self.tag))
            .field("seed", &self.seed)
            .field("first", &self.first)
            .finish()
    }
}

/// `MasterSeed.deriveAccount(account_index)` (`MasterSeed.ts:115-137`).
///
/// The shipped method derives twice — `deriveAccountTag` and then `deriveSeed`
/// again for the address — and both derivations start the same generator from
/// the same seed material, so they draw the same bytes and build the same
/// public key. One derivation here; the KAT asserts the recorded `tag` and
/// the recorded 2208-byte address against the one key.
#[must_use]
pub fn derive_account(master: &Secret<SEED_LEN>, account_index: u32) -> DerivedAccount {
    let derived = derive_seed(master.expose(), account_index);
    let seed = derived.secret().clone();
    let first = first_key(derived);
    DerivedAccount {
        tag: first.tag(),
        seed,
        first,
    }
}

/// Lowercase hex for a tag in Debug output. Tags are public.
struct TagHex(Tag);

impl fmt::Debug for TagHex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Not under Miri: its time is the key generation inside `derive_account`
    /// (408 s measured at S11), and `tests/derive.rs` replays that whole
    /// composition under the interpreter over group F's embedded subset --
    /// `F-address-widths` among them -- while what this test asserts is the
    /// text a `Debug` impl writes.
    #[cfg(not(miri))]
    #[test]
    fn debug_never_reveals_generator_state_or_secrets() {
        // Distinguishing, non-zero material.
        let mut g = DigestRandomGenerator::new();
        g.add_seed_material(&[0xA5u8; 32]);
        let mut out = [0u8; 64];
        g.fill(&mut out);
        let rendered = format!("{g:?}");
        assert_eq!(
            rendered,
            "DigestRandomGenerator { states_generated: 1, seed_cycles: 0, \
             state: \"<redacted>\", seed: \"<redacted>\" }"
        );
        let hex_out: String = out.iter().map(|b| format!("{b:02x}")).collect();
        assert!(!rendered.contains(&hex_out[..8]));

        let d = derive_seed(&[0xA5u8; 32], 7);
        let secret_hex: String = d.secret().expose().iter().map(|b| format!("{b:02x}")).collect();
        let rendered = format!("{d:?}");
        assert!(rendered.starts_with("DerivedSeed { secret: Secret<32>(<redacted>), prng: "));
        assert!(!rendered.contains(&secret_hex[..8]));

        let key = first_key(d);
        let rendered = format!("{key:?}");
        assert!(rendered.starts_with("WotsKey { secret: Secret<32>(<redacted>), pub_seed: \"<redacted>\""));
        assert!(!rendered.contains(&secret_hex[..8]));
        let ps: String = key.pub_seed().iter().map(|b| format!("{b:02x}")).collect();
        assert!(!rendered.contains(&ps[..8]));

        let acct = derive_account(&Secret::new([0xA5u8; 32]), 0);
        let rendered = format!("{acct:?}");
        assert!(rendered.starts_with("DerivedAccount { tag: "));
        assert!(rendered.contains("seed: Secret<32>(<redacted>)"));
    }

    #[test]
    fn fill_of_zero_bytes_generates_no_state() {
        let mut g = DigestRandomGenerator::new();
        g.fill(&mut []);
        assert_eq!(g.states_generated(), 0);
        let mut one = [0u8; 1];
        g.fill(&mut one);
        assert_eq!(g.states_generated(), 1);
    }
}
