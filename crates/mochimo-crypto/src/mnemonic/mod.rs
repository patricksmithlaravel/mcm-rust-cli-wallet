//! BIP39, as the shipped extension's restore path uses it
//! (`reference/mochimo-wallet/src/core/MasterSeed.ts:43-67` over
//! `@scure/bip39` 1.5.0, read on disk).
//!
//! # Which value is the master seed
//!
//! `fromPhrase` runs `mnemonicToSeed` — PBKDF2-HMAC-SHA512 over the NFKD
//! phrase with salt `"mnemonic" ‖ passphrase`, 2048 rounds, 64 bytes
//! (`@scure/bip39/index.js:116` for the salt for the call) — and
//! keeps **the first 32 bytes** as the
//! master seed. It stores the mnemonic's entropy
//! separately. The two are different values and only the first is
//! the seed every account derives from; `F-from-phrase` pins both, and
//! `F-create-not-inverse` pins that a seed constructed directly and then
//! exported as a phrase does **not** come back as itself — what comes back
//! as the seed is the PBKDF2 of the phrase that was made *from* it.
//!
//! So [`master_seed_from_phrase`] is the live master seed source, and a
//! port that took the 64-byte BIP39 seed, or the entropy, or the full 64
//! bytes' second half, derives accounts nobody holds.
//!
//! # Scope, stated
//!
//! English wordlist only ([`english::WORDLIST`], checked against the pinned
//! package's file by `tests/derive.rs`). Input is required to be ASCII and
//! single-space separated; non-ASCII input is refused rather than
//! NFKD-normalised — for an English phrase normalisation is the identity, and
//! a normaliser is a dependency nothing here can check.
//!
//! **What group F pins.** At first both BIP39 vectors were 24-word,
//! empty-passphrase captures, so the partial-byte checksum path that 12–21-word
//! phrases take was exercised only by this module agreeing with itself, and the
//! passphrase reached the salt on the word of a unit test. The corpus then captured both
//! from the library the extension uses: `F-bip39-passphrase`
//! (`mnemonicToSeed` with a non-empty passphrase), `F-bip39-entropy-16/20/24/28`
//! (the entropy widths below 32 bytes, round-tripped) and `F-bip39-bad-checksum`
//! (the refusal). `tests/support/derivation_walk.rs` replays them.
//!
//! # Where PBKDF2 and HMAC come from
//!
//! RustCrypto `pbkdf2` with its `hmac` feature, on the same `digest` 0.10
//! line as the crate's `sha2` — the standing choice (see `Cargo.toml`'s note
//! on `sha2`), so the derivation puts no hand-rolled MAC inside the diff.
//! **The project does not itself verify HMAC or PBKDF2**: both are
//! RustCrypto's, a dependency choice and not evidence, and the two BIP39
//! vectors check only that the composition agrees with the library the
//! extension uses. If a hand-rolled fallback ever replaces the crate, those
//! same two vectors become the only evidence for the primitive, and this
//! paragraph must change with the artifact.

pub mod english;

use core::fmt;

use pbkdf2::pbkdf2_hmac;
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroizing;

use crate::consts::SEED_LEN;
use crate::error::{Error, Result};
use crate::secret::Secret;

/// `mnemonicToSeed`'s round count (`@scure/bip39/index.js:128`, `c: 2048`).
pub const PBKDF2_ROUNDS: u32 = 2048;
/// `mnemonicToSeed`'s output width (`dkLen: 64`); the master seed is the
/// first [`SEED_LEN`] bytes of it.
pub const BIP39_SEED_LEN: usize = 64;
/// The salt prefix (`@scure/bip39/index.js:116`).
const SALT_PREFIX: &str = "mnemonic";

/// A phrase, zeroized on drop: it names the master seed as surely as the
/// seed does. `Debug` redacts it.
pub struct Phrase(Zeroizing<String>);

impl Phrase {
    /// The words, space-separated.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Phrase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Phrase(<redacted>)")
    }
}

/// `entropyToMnemonic(entropy, english)`: 16, 20, 24, 28 or 32 bytes of
/// entropy → 12, 15, 18, 21 or 24 words. The checksum is the first
/// `len / 4` bits of `SHA-256(entropy)`; entropy bits then checksum bits are
/// read in 11-bit groups as wordlist indices.
pub fn phrase_from_entropy(entropy: &[u8]) -> Result<Phrase> {
    let len = entropy.len();
    if !((16..=32).contains(&len) && len.is_multiple_of(4)) {
        return Err(Error::Mnemonic {
            what: "entropy is not 16, 20, 24, 28 or 32 bytes",
        });
    }
    let checksum_bits = len / 4;
    let digest = Sha256::digest(entropy);

    // Bit string: entropy, then the checksum's leading bits. The phrase is
    // built straight into its zeroizing home: an intermediate list of word
    // references would name the entropy just as surely and die unzeroized.
    let total_bits = len * 8 + checksum_bits;
    let mut phrase = Zeroizing::new(String::with_capacity(total_bits / 11 * 9));
    let bit_at = |i: usize| -> u16 {
        let byte = if i < len * 8 { entropy[i / 8] } else { digest[(i - len * 8) / 8] };
        u16::from((byte >> (7 - (i % 8))) & 1)
    };
    let mut i = 0;
    while i + 11 <= total_bits {
        let mut idx: u16 = 0;
        for k in 0..11 {
            idx = (idx << 1) | bit_at(i + k);
        }
        if !phrase.is_empty() {
            phrase.push(' ');
        }
        phrase.push_str(english::WORDLIST[usize::from(idx)]);
        i += 11;
    }
    Ok(Phrase(phrase))
}

/// `mnemonicToEntropy(phrase, english)`: the inverse of
/// [`phrase_from_entropy`], refusing a word count outside {12, 15, 18, 21,
/// 24}, a word not in the list, or a checksum that does not match.
pub fn entropy_from_phrase(phrase: &str) -> Result<Zeroizing<Vec<u8>>> {
    if !phrase.is_ascii() {
        return Err(Error::Mnemonic {
            what: "phrase is not ASCII",
        });
    }
    let words: Vec<&str> = phrase.split(' ').collect();
    let count = words.len();
    if !((12..=24).contains(&count) && count.is_multiple_of(3)) {
        return Err(Error::Mnemonic {
            what: "word count is not 12, 15, 18, 21 or 24",
        });
    }
    let entropy_len = count * 11 * 32 / 33 / 8;
    let checksum_bits = entropy_len / 4;

    // One bit per byte, the whole entropy plus checksum: zeroized like the
    // entropy it spells.
    let mut bits: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(count * 11));
    for w in &words {
        let Ok(idx) = english::WORDLIST.binary_search(w) else {
            return Err(Error::Mnemonic {
                what: "a word is not in the English wordlist",
            });
        };
        for k in (0..11).rev() {
            bits.push(((idx >> k) & 1) as u8);
        }
    }

    let mut entropy = Zeroizing::new(vec![0u8; entropy_len]);
    for (i, bit) in bits.iter().take(entropy_len * 8).enumerate() {
        entropy[i / 8] |= bit << (7 - (i % 8));
    }
    let digest = Sha256::digest(&*entropy);
    for (k, bit) in bits.iter().skip(entropy_len * 8).take(checksum_bits).enumerate() {
        let want = (digest[k / 8] >> (7 - (k % 8))) & 1;
        if *bit != want {
            return Err(Error::Mnemonic {
                what: "checksum mismatch",
            });
        }
    }
    Ok(entropy)
}

/// `mnemonicToSeed(phrase, passphrase)`: the full 64-byte BIP39 seed.
///
/// The phrase is validated first, as `fromPhrase` does,
/// so a phrase with a bad checksum is refused rather than stretched.
pub fn bip39_seed(phrase: &str, passphrase: &str) -> Result<Zeroizing<[u8; BIP39_SEED_LEN]>> {
    let _entropy = entropy_from_phrase(phrase)?;
    if !passphrase.is_ascii() {
        return Err(Error::Mnemonic {
            what: "passphrase is not ASCII",
        });
    }
    let salt = Zeroizing::new(format!("{SALT_PREFIX}{passphrase}"));
    let mut out = Zeroizing::new([0u8; BIP39_SEED_LEN]);
    pbkdf2_hmac::<Sha512>(phrase.as_bytes(), salt.as_bytes(), PBKDF2_ROUNDS, &mut *out);
    Ok(out)
}

/// The master seed `MasterSeed.fromPhrase` holds: the first [`SEED_LEN`]
/// bytes of [`bip39_seed`]. The extension passes no
/// passphrase; the parameter is here so the port cannot silently hardcode
/// the empty one where a caller meant otherwise.
///
/// # `passphrase` is NOT the store password, and this is where that breaks
///
/// The keystore has a password. **It must never reach this parameter**,
/// and this is the one place in the tree where putting it there would look
/// right: BIP39 has a passphrase slot, a wallet has a password, and joining
/// them is a one-word edit.
///
/// The consequence of that edit would be silent and unrecoverable. The seed
/// phrase is portable with the shipped Chrome extension by construction --
/// the derivation was pinned, then ported, and every group F vector
/// replays (ninety-six). The extension passes **no** passphrase. A phrase salted here with a
/// store password would produce a different master seed, therefore different
/// accounts, therefore a wallet whose recovery phrase restores *somebody
/// else's empty wallet* in any other client -- and nothing would say so until
/// an operator tried it, by which time the store the funds were in is the only
/// copy of the truth.
///
/// **Two secrets, two jobs.** The phrase is the wallet's identity and travels
/// between clients; the password encrypts one file on one disk and travels
/// nowhere. `derive::the_store_password_never_reaches_seed_derivation` asserts
/// the separation rather than leaving it to this comment: the same phrase
/// under two different store passwords must give the same master seed, the
/// same tag, and the same address.
pub fn master_seed_from_phrase(phrase: &str, passphrase: &str) -> Result<Secret<SEED_LEN>> {
    let full = bip39_seed(phrase, passphrase)?;
    let mut head = Zeroizing::new([0u8; SEED_LEN]);
    head.copy_from_slice(&full[..SEED_LEN]);
    Ok(Secret::new(*head))
}

/// `toPhrase` with **no stored entropy**: the seed's
/// 32 bytes are used **as** entropy. The other branch is
/// [`phrase_from_entropy`] over the stored entropy. Exposed because
/// `F-create-not-inverse` pins that this and [`master_seed_from_phrase`] are
/// not inverses.
pub fn phrase_from_seed_as_entropy(seed: &Secret<SEED_LEN>) -> Result<Phrase> {
    phrase_from_entropy(seed.expose())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wordlist_is_sorted_and_complete() {
        assert_eq!(english::WORDLIST.len(), 2048);
        assert!(english::WORDLIST.windows(2).all(|w| w[0] < w[1]));
    }

    #[test]
    fn debug_never_reveals_the_phrase() {
        let p = phrase_from_entropy(&[0xA5u8; 16]).unwrap_or_else(|e| panic!("{e}"));
        let rendered = format!("{p:?}");
        assert_eq!(rendered, "Phrase(<redacted>)");
        assert!(!rendered.contains(p.expose().split(' ').next().unwrap_or("")));
    }

    #[test]
    fn passphrase_reaches_the_salt() {
        // Nothing in group F passes a passphrase (the extension never does),
        // so this is the one place the parameter is shown to do anything: a
        // non-empty passphrase changes the seed, and the empty one is not
        // hardcoded behind the caller's back. What it cannot show is that the
        // salt is `"mnemonic" ‖ passphrase` rather than some other function
        // of the two -- that needs an executed capture (group F `pending`).
        let valid = phrase_from_entropy(&[0u8; 32]).unwrap_or_else(|e| panic!("{e}"));
        let empty = bip39_seed(valid.expose(), "").unwrap_or_else(|e| panic!("{e}"));
        let with = bip39_seed(valid.expose(), "x").unwrap_or_else(|e| panic!("{e}"));
        assert_ne!(empty[..], with[..], "the passphrase did not reach the salt");
        assert_eq!(
            bip39_seed(valid.expose(), "").unwrap_or_else(|e| panic!("{e}"))[..],
            empty[..],
            "the seed is not a pure function of (phrase, passphrase)"
        );
    }

    #[test]
    fn refusals_are_by_variant() {
        assert!(matches!(
            phrase_from_entropy(&[0u8; 15]),
            Err(Error::Mnemonic { what: "entropy is not 16, 20, 24, 28 or 32 bytes" })
        ));
        assert!(matches!(
            entropy_from_phrase("abandon abandon"),
            Err(Error::Mnemonic { what: "word count is not 12, 15, 18, 21 or 24" })
        ));
        let bad_word = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon zzzz";
        assert!(matches!(
            entropy_from_phrase(bad_word),
            Err(Error::Mnemonic { what: "a word is not in the English wordlist" })
        ));
        // Twelve valid words whose checksum is wrong: swap the last word of a
        // valid phrase for its neighbour.
        let valid = phrase_from_entropy(&[0u8; 16]).unwrap_or_else(|e| panic!("{e}"));
        let mut words: Vec<&str> = valid.expose().split(' ').collect();
        let last = words[11];
        let i = english::WORDLIST.binary_search(&last).unwrap_or(0);
        words[11] = english::WORDLIST[(i + 1) % 2048];
        assert!(matches!(
            entropy_from_phrase(&words.join(" ")),
            Err(Error::Mnemonic { what: "checksum mismatch" })
        ));
        assert!(matches!(
            entropy_from_phrase("abandón"),
            Err(Error::Mnemonic { what: "phrase is not ASCII" })
        ));
        assert!(matches!(
            bip39_seed(
                phrase_from_entropy(&[0u8; 16]).unwrap_or_else(|e| panic!("{e}")).expose(),
                "pässword"
            ),
            Err(Error::Mnemonic { what: "passphrase is not ASCII" })
        ));
        // Failure-path text is invisible to a passing suite:
        // render one refusal and read it.
        let rendered = format!("{}", Error::Mnemonic { what: "phrase is not ASCII" });
        assert_eq!(rendered, "bip39: phrase is not ASCII");
    }
}
