//! WOTS+ key generation, signing, and public-key recovery.

use crate::backend::selected as backend;
use zeroize::Zeroizing;

use crate::consts::{PK_LEN, SEED_LEN, SIG_LEN, WOTSLEN};
use crate::secret::Secret;

/// The XMSS hash address, `word32 addr[8]` in the reference.
///
/// This is a newtype over an array, not a generated struct: the C parameter
/// really is an array of eight words, so there is no layout to get wrong.
///
/// The reference mutates it in place, which is why every operation here takes
/// `&mut Adrs` — the terminal state is itself a fixture-checked value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Adrs(pub [u32; 8]);

impl Adrs {
    pub const ZERO: Adrs = Adrs([0; 8]);

    pub fn words(&self) -> &[u32; 8] {
        &self.0
    }

    /// The big-endian serialization the reference feeds to `prf`.
    pub fn to_bytes(&self) -> [u8; 32] {
        backend::addr_to_bytes(&self.0)
    }

    /// The **memory image** of the eight words — the byte-versus-word
    /// conversion this crate normalizes to little-endian by decision
    /// (`docs/specification.md`, *Big-endian serialization versus the
    /// little-endian image*): the form the reference's own `rndbytes((word8 *)addr, 32)`
    /// leaves in a `word32[8]` and the form the TypeScript's `addr:
    /// ByteArray` parameter takes (the TypeScript wraps it
    /// `LITTLE_ENDIAN`; `kat.rs::ts_pkgen_to_addr` is the executed second
    /// implementation agreeing). **Not** [`Adrs::to_bytes`], which is the
    /// big-endian serialization `addr_to_bytes` feeds to `prf`; the two are
    /// different byte images of one value.
    ///
    /// Added for the derivation, whose generator hands over 32 bytes
    /// that the extension reads this way (`derive::first_key`).
    pub fn from_le_image(image: &[u8; 32]) -> Adrs {
        let mut words = [0u32; 8];
        for (w, chunk) in words.iter_mut().zip(image.as_chunks::<4>().0) {
            *w = u32::from_le_bytes(*chunk);
        }
        Adrs(words)
    }

    /// The inverse of [`Adrs::from_le_image`].
    pub fn le_image(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (chunk, w) in out.as_chunks_mut::<4>().0.iter_mut().zip(self.0.iter()) {
            *chunk = w.to_le_bytes();
        }
        out
    }
}

impl From<[u32; 8]> for Adrs {
    fn from(words: [u32; 8]) -> Self {
        Adrs(words)
    }
}

pub type PublicKey = Box<[u8; PK_LEN]>;
pub type Signature = Box<[u8; SIG_LEN]>;

pub fn pkgen(secret: &Secret<SEED_LEN>, pub_seed: &[u8; SEED_LEN], adrs: &mut Adrs) -> PublicKey {
    backend::wots_pkgen(secret.expose(), pub_seed, &mut adrs.0)
}

/// The raw WOTS+ signer. **Crate-private**: a WOTS+
/// key signs at most once, ever (I1), and the only public path to a
/// signature is `Keystore::sign_spend`, which demands an `AdvanceReceipt` --
/// the keystore's evidence that the key's index advanced and is durable --
/// before it derives the key and calls this. The test tree reaches the raw
/// primitive through `backend::selected::wots_sign` under `raw-backend`;
/// `ui/fail/signing_raw_signer_is_not_reachable.rs` pins that this function
/// is not nameable from outside, and the downstream probe pins the backend
/// route in a build without the feature.
///
/// # Native, not `selected`, by decision
///
/// This is the one primitive in the file that does not go through
/// [`backend::selected`]. The wallet's own key material is signed by
/// [`crate::backend::native::wots_sign`] directly, the way the keystore's
/// trailer hash is computed by the native sha3: under the
/// foreign-function backend the expanded private key would otherwise have
/// transited C stack memory nothing zeroizes. The per-call-site evidence for
/// the direct call is `tests/kat.rs::sign`, which replays every group B
/// signing vector through this path, and `tests/spend.rs`, which reproduces
/// the validated group D signatures. `selected` is now an alias of `native`,
/// so the distinction no longer moves any bytes; the direct call stays so
/// that a second backend could not be selected under the wallet's key
/// material by an alias flip alone. Residue, stated: the derivation's `pkgen`
/// upstream of every signing key routes through `selected`, so a second
/// backend there would see the seed; flipping that call site changes the group F
/// KAT's claim and is recorded as a lead, not done here. `tests/signing.rs`
/// recovers this signature with `wots::pk_from_sig` on every run and says
/// which backend that resolved to -- `native`, the only one.
///
/// Gated on `native` because the only caller is, and because the signer this
/// routes to is.
#[cfg(feature = "native")]
pub(crate) fn sign(
    msg: &[u8; SEED_LEN],
    secret: &Secret<SEED_LEN>,
    pub_seed: &[u8; SEED_LEN],
    adrs: &mut Adrs,
) -> Signature {
    crate::backend::native::wots_sign(msg, secret.expose(), pub_seed, &mut adrs.0)
}

/// Recovers the public key implied by a signature.
///
/// This always produces 2144 bytes; it does not verify. Verification is
/// comparing the result against a known public key, which is the caller's job.
pub fn pk_from_sig(
    sig: &[u8; SIG_LEN],
    msg: &[u8; SEED_LEN],
    pub_seed: &[u8; SEED_LEN],
    adrs: &mut Adrs,
) -> PublicKey {
    backend::wots_pk_from_sig(sig, msg, pub_seed, &mut adrs.0)
}

/// The file-local helpers inside `wots.c`.
///
/// These are not the wallet API. They exist because groups A and B pin them
/// individually, which turns "our WOTS+ is wrong somewhere" into "our `base_w`
/// is wrong". **Crate-private**, with [`sign`]: `prf` keyed with
/// the secret *is* `expand_seed`, and with `thash_f` and `chain_lengths` a
/// caller has a complete signer by composition, so demoting `sign` alone
/// would have been decorative. `tests/kat.rs` reaches the same four through
/// `backend::selected` under `raw-backend`, which is where the raw surface
/// now lives. Nothing in the crate calls these today; they stay
/// so that the delegation the KATs exercise has one spelling in `src/`.
#[allow(dead_code)]
pub(crate) mod internals {
    use super::*;

    pub fn prf(input: &[u8; 32], key: &[u8; SEED_LEN]) -> [u8; 32] {
        backend::prf(input, key)
    }

    pub fn thash_f(input: &[u8; 32], pub_seed: &[u8; SEED_LEN], adrs: &mut Adrs) -> [u8; 32] {
        backend::thash_f(input, pub_seed, &mut adrs.0)
    }

    pub fn expand_seed(inseed: &Secret<SEED_LEN>) -> Box<Zeroizing<[u8; PK_LEN]>> {
        backend::expand_seed(inseed.expose())
    }

    /// The WOTSLEN1 base-w message digits followed by the WOTSLEN2 checksum
    /// digits.
    pub fn chain_lengths(msg: &[u8; SEED_LEN]) -> [i32; WOTSLEN] {
        backend::chain_lengths(msg)
    }
}
