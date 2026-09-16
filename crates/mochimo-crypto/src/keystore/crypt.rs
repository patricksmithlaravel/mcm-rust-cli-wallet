//! The store's encryption at rest: an Argon2id KDF over an operator password
//! and a ChaCha20-Poly1305 AEAD over the record body.
//!
//! # What this changes about what the wallet rests on, stated first
//!
//! Before this, a stolen `accounts.mks` yielded **every imported account**:
//! the roots were in it in the clear, and a root is signing power. What it did
//! not yield was the derived accounts — the master seed was not in the file and
//! the recovery phrase lived on paper. After this, the seed IS in it, and the
//! file yields **everything** to whoever knows the password and **nothing** to
//! whoever does not.
//!
//! So this is a trade in both directions, not a loss in one: the imported roots
//! moved from readable to sealed, the master seed moved from absent to sealed,
//! and what used to be a property of the file alone is now a property of the
//! password. The first draft of this paragraph said a stolen store had yielded
//! *nothing* — flattering the old state, and contradicted by the same
//! change's `sign.rs`, which said in as many words that possession of the directory was
//! signing power for imported accounts.
//!
//! That is a real transfer of what the security rests on, not a pure gain, and
//! it is the trade every wallet makes for the right reason: the alternative
//! was twenty-four words typed for every balance check, which is an interface
//! nobody uses, and an unused wallet protects nothing. But password strength
//! is now part of the threat model in a way it was not, and
//! [`Kdf::RECOMMENDED`]'s parameters are the only thing making a guess
//! expensive. Said here because a reader meeting this module should meet the
//! cost with the mechanism.
//!
//! # No C, by the same rule as the trailer
//!
//! The keystore was designed under the rule that a plaintext image never
//! transit the C's stack -- which is why `format::encode`'s trailer called
//! `backend::native::sha3_256` directly rather than through the backend
//! wrapper. Both crates here are pure Rust, so that rule holds by
//! construction rather than by a call-site convention. Nothing in this module
//! touches `backend::selected`.
//!
//! # No RNG, by the same rule as `create`
//!
//! There is no `rand` and no `getrandom` in this crate's graph, and
//! `cli::create` already established what to do about it: **the caller
//! supplies the entropy** and the binary reads it from `/dev/urandom` through
//! `std::fs`. The salt and the nonce seed are parameters here for exactly that
//! reason -- and the consequence is worth naming, because it is what saved
//! three proofs. A test that supplies fixed entropy gets a **deterministic
//! image**, so the format KAT, `records_are_addressed_by_tag_not_position` and
//! the I3 crash proof keep the byte-level observables the decision deferring
//! the AEAD predicted it would delete. The nondeterminism is a parameter, not an ambient fact.

use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// Salt width. Sixteen bytes is RFC 9106's recommendation for password
/// hashing; it is stored in the header because the reader needs it.
pub const SALT_LEN: usize = 16;
/// ChaCha20-Poly1305's nonce is 96 bits.
pub const NONCE_LEN: usize = 12;
/// Poly1305's tag.
pub const TAG_LEN: usize = 16;
/// The derived key, and ChaCha20's key width.
pub const KEY_LEN: usize = 32;
/// The per-open entropy the nonce is derived from. See [`nonce_for`].
pub const NONCE_SEED_LEN: usize = 32;

/// The KDF identifier written into the header.
///
/// A number rather than a name so the header stays fixed-width, and a number
/// **dispatched before use** so a file naming a KDF this build does not have
/// reports `UnsupportedVersion` rather than being fed to the wrong function.
pub(crate) const KDF_ARGON2ID_V13: u8 = 1;

/// The largest `m_cost` this build will honour from a file, in KiB.
///
/// **This is a bound before an allocation, and it is the same shape as
/// `format`'s cap on `count`.** `m_cost` comes out of a file that may have
/// been written by somebody else, and it is a direct instruction to allocate
/// that many kibibytes; a hostile store naming 64 GiB would otherwise be a
/// one-line denial of service against an operator who merely ran `balance`.
/// One gibibyte leaves room to raise [`Kdf::RECOMMENDED`] by a factor of
/// sixteen without a format change and still refuses the absurd.
pub(crate) const MAX_M_COST_KIB: u32 = 1024 * 1024;

/// The KDF parameters, as the header carries them.
///
/// **They live in the file rather than in this binary**, so raising them later
/// is a change a new store picks up while every existing store keeps opening.
/// Lowering them on somebody else's file to make cracking cheap is defeated
/// twice, and the two are worth distinguishing because they answer
/// differently:
///
/// * **out of bounds** -- above [`MAX_M_COST_KIB`] -- is refused by
///   [`Kdf::checked`] before anything allocates or derives, as `Range` naming
///   the field. It never reaches the AEAD.
/// * **in bounds** -- say `m_cost` driven down to 8 KiB, which is what an
///   attacker actually wants -- derives a different key, so the tag fails and
///   the operator sees *wrong password*.
///
/// An earlier draft of this note said only the second, which was wrong about
/// the case that matters: `parser_refuses_each_malformation_with_the_right_variant`
/// asserts both.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Kdf {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Kdf {
    /// What a new store is created with, **measured rather than copied**.
    ///
    /// RFC 9106's second recommended option is `m = 64 MiB, t = 3, p = 4`.
    /// The memory and the passes are taken as written; the parallelism is
    /// **one**, and that is a decision rather than an omission:
    ///
    /// * this crate builds `argon2` without threads, so `p = 4` would compute
    ///   four lanes sequentially -- the defender pays the same wall clock and
    ///   an attacker with four cores takes the speedup we declined. `p = 1`
    ///   maximises the sequential dependency for the same memory, which is
    ///   exactly the shape a single-threaded verifier wants.
    ///
    /// **Cost, measured on the machine this was written on** (Apple Silicon,
    /// release profile): 19 MiB/t=2 was 20 ms, 64 MiB/t=2 was 38 ms, **64
    /// MiB/t=3 was 70 ms**, 128 MiB/t=2 was 83 ms, 256 MiB/t=3 was 265 ms.
    /// Seventy milliseconds is paid once per command and is below what an
    /// operator notices; 256 MiB is not, and buying four times the attacker
    /// cost for four times a latency that has become perceptible is the wrong
    /// end of that curve for a wallet somebody uses.
    ///
    /// This figure is the *default for new stores only*. An existing store
    /// opens with whatever its own header says.
    pub const RECOMMENDED: Kdf = Kdf {
        m_cost_kib: 65536,
        t_cost: 3,
        p_cost: 1,
    };

    /// The cheapest parameters Argon2 accepts, **for tests only**.
    ///
    /// Not a fallback and never reached by the binary: `cli::create` passes
    /// [`Kdf::RECOMMENDED`]. This exists because the suite creates hundreds of
    /// stores and a KDF chosen to make one guess expensive makes that
    /// impractical — see `keystore::Init`'s `kdf` field for what it cost when
    /// the two were the same number.
    pub const CHEAP_FOR_TESTS: Kdf = Kdf {
        m_cost_kib: 8,
        t_cost: 1,
        p_cost: 1,
    };

    /// Refuse parameters this build will not honour, **before** anything is
    /// allocated or derived.
    ///
    /// Two gates, and the range each reports is the one the two enforce
    /// together: this branch holds the ceiling (`MAX_M_COST_KIB`, the
    /// format's own), and `argon2::Params::new` below holds the floor
    /// (`Params::MIN_M_COST`, 8 KiB, Argon2's own) and every other bound.
    /// Argon2's refusal is mapped to the parameter it names -- memory,
    /// passes or lanes -- with that parameter's value as `got`; it was
    /// always reported as an `m_cost` problem for a time, so a `t_cost` of
    /// 0 read as a memory error (AGENT.md, Known-open 12, closed at S6).
    pub fn checked(self) -> Result<Kdf> {
        use argon2::Params;
        if self.m_cost_kib > MAX_M_COST_KIB {
            return Err(Error::Range {
                what: "keystore kdf m_cost",
                min: u64::from(Params::MIN_M_COST),
                max: u64::from(MAX_M_COST_KIB),
                got: u64::from(self.m_cost_kib),
            });
        }
        Params::new(self.m_cost_kib, self.t_cost, self.p_cost, Some(KEY_LEN)).map_err(|e| match e {
            argon2::Error::MemoryTooLittle | argon2::Error::MemoryTooMuch => Error::Range {
                what: "keystore kdf m_cost",
                min: u64::from(Params::MIN_M_COST),
                max: u64::from(MAX_M_COST_KIB),
                got: u64::from(self.m_cost_kib),
            },
            argon2::Error::TimeTooSmall => Error::Range {
                what: "keystore kdf t_cost",
                min: u64::from(Params::MIN_T_COST),
                max: u64::from(Params::MAX_T_COST),
                got: u64::from(self.t_cost),
            },
            argon2::Error::ThreadsTooFew | argon2::Error::ThreadsTooMany => Error::Range {
                what: "keystore kdf p_cost",
                min: u64::from(Params::MIN_P_COST),
                max: u64::from(Params::MAX_P_COST),
                got: u64::from(self.p_cost),
            },
            _ => Error::Range {
                what: "keystore kdf parameters",
                min: 0,
                max: u64::from(MAX_M_COST_KIB),
                got: u64::from(self.m_cost_kib),
            },
        })?;
        Ok(self)
    }
}

/// The algorithm and the version the store's KDF is, named once.
///
/// **The Argon2 variant and version are written here and nowhere else in
/// this crate.** `argon2id_v13` is the only constructor call, and it is one
/// straight-line path with no branch, so the vector RFC 9106 §5.3 records
/// (`format::tests::argon2id_v13_matches_the_rfc9106_vector`) and every
/// store's key derivation run through the same lines and differ only in
/// argument values. The first draft of the anchor had two constructor arms -- one
/// for a secret, one without -- and the design panel showed that the arm
/// production took was anchored by nothing, because the RFC's vector carries
/// a secret and took the other one. The branch was removed
/// rather than covered.
const ALGORITHM: argon2::Algorithm = argon2::Algorithm::Argon2id;
const VERSION: argon2::Version = argon2::Version::V0x13;

/// The one site where a [`Kdf`] becomes the parameters Argon2 *hashes with*,
/// and where the algorithm and the version are named ([`ALGORITHM`],
/// [`VERSION`]). [`Kdf::checked`] maps the same three fields into
/// `argon2::Params::new` as well, but only to refuse them before anything is
/// allocated; nothing it builds reaches a hash. If the role order changes
/// here it must change there.
///
/// **Two callers, one path.** [`derive_key`] is this with an empty secret and
/// no associated data -- the only shape a v3 header can express.
/// `format::tests::argon2id_v13_matches_the_rfc9106_vector` is this with an
/// eight-byte secret and twelve bytes of associated data, because RFC 9106
/// §5.3's published vector carries both, and a test that built its own
/// `Argon2` to drive them would pin the crate and not the wallet's call. So
/// the two parameters exist for that test and for nothing the wallet does,
/// and they are passed through unconditionally: an empty secret is hashed
/// as `LE32(0)` and empty associated data as `LE32(0)` too, which is what
/// the crate wrote for the old `Argon2::new` path. That identity is not
/// argued here -- a pre/post probe measured byte-identical store images
/// across the change.
///
/// The policy bound comes first: [`Kdf::checked`] refuses an `m_cost` above
/// [`MAX_M_COST_KIB`] before the block buffer that `m_cost` sizes is
/// allocated, so a caller cannot reach the allocation around the bound.
///
/// The working memory is allocated here, sized by the crate's own
/// `block_count`, and is `Zeroizing`, so Argon2's blocks -- a function of the
/// password -- clear on drop rather than being handed back to the allocator
/// warm. `hash_password_into_with_memory` is the entry point because the
/// allocating one is behind the `alloc` feature this crate does not enable.
/// `output_len` is a bound the crate checks `out` against, not
/// an input to the hash -- the hash takes the length from `out` itself -- so
/// no test can distinguish it and none claims to.
pub(crate) fn argon2id_v13(
    kdf: Kdf,
    secret: &[u8],
    associated_data: &[u8],
    password: &[u8],
    salt: &[u8],
    out: &mut [u8],
) -> Result<()> {
    let kdf = kdf.checked()?;
    let data = argon2::AssociatedData::new(associated_data).map_err(|_| Error::Range {
        what: "keystore kdf associated data",
        min: 0,
        max: argon2::Params::MAX_DATA_LEN as u64,
        got: associated_data.len() as u64,
    })?;
    let mut builder = argon2::ParamsBuilder::new();
    builder
        .m_cost(kdf.m_cost_kib)
        .t_cost(kdf.t_cost)
        .p_cost(kdf.p_cost)
        .output_len(out.len())
        .data(data);
    // `checked` has already run `Params::new` over m, t and p, so the only
    // thing left for `build` to refuse is the output length.
    let params = builder.build().map_err(|_| Error::Range {
        what: "keystore kdf output length",
        min: argon2::Params::MIN_OUTPUT_LEN as u64,
        max: argon2::Params::MAX_OUTPUT_LEN as u64,
        got: out.len() as u64,
    })?;
    let mut blocks: Zeroizing<Vec<argon2::Block>> =
        Zeroizing::new(vec![argon2::Block::default(); params.block_count()]);
    // One constructor for both callers. `new_with_secret(&[], ..)` hashes the
    // same bytes `Argon2::new` did (`LE32(0)` for the secret's length) -- the
    // pre/post probe measured that -- and having no second arm
    // is what lets the RFC vector speak for the wallet's own call.
    let hasher = argon2::Argon2::new_with_secret(secret, ALGORITHM, VERSION, params).map_err(|_| {
        Error::Range {
            what: "keystore kdf secret",
            min: 0,
            max: argon2::MAX_SECRET_LEN as u64,
            got: secret.len() as u64,
        }
    })?;
    hasher
        .hash_password_into_with_memory(password, salt, out, &mut blocks)
        .map_err(|_| Error::Corrupt {
            what: "key derivation",
            offset: 0,
        })
}

/// Derive the store key from a password and the header's salt.
///
/// **Called once per open and the result held in `Zeroizing`** -- the marker's
/// prescribed shape, and the reason is cost rather than tidiness: a wallet
/// that re-derived per commit would pay seventy milliseconds on every write
/// and tempt somebody to lower the parameters.
///
/// This is [`argon2id_v13`] with an empty secret and no associated data. The
/// algorithm, the version, the parameter roles, the policy bound and the
/// `Zeroizing` working memory are all that function's; RFC 9106's vector is
/// replayed through it
/// (`format::tests::argon2id_v13_matches_the_rfc9106_vector`), and that this
/// path agrees with it is
/// `derive_key_agrees_with_the_anchored_argon2id_at_cheap_parameters`'s claim
/// -- the call structure, not the mapping.
pub(crate) fn derive_key(
    password: &[u8],
    salt: &[u8; SALT_LEN],
    kdf: Kdf,
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let mut key: Zeroizing<[u8; KEY_LEN]> = Zeroizing::new([0u8; KEY_LEN]);
    argon2id_v13(kdf, &[], &[], password, salt, key.as_mut())?;
    Ok(key)
}

/// The nonce for one commit, from the per-open seed and the generation.
///
/// # Why not a counter, and why not fresh randomness per write
///
/// ChaCha20-Poly1305 is catastrophic on nonce reuse -- two messages under one
/// key and nonce leak their XOR and hand an attacker the Poly1305 key -- so
/// this is the one place in the format where getting it wrong is worse than
/// having no encryption at all.
///
/// **The generation counter alone will not do.** It is monotonic within a
/// store, which is enough right up until somebody copies the directory: two
/// copies share a salt, therefore a key, and both advance from generation *N*
/// with different contents. A restored backup is an ordinary thing to have,
/// so that is a reachable reuse and not a theoretical one. The kernel lock
/// prevents two writers on one directory; it says nothing about two
/// directories.
///
/// **Fresh randomness per write would do, and there is no RNG here to give
/// it** -- and adding one would put `getrandom` in a crate that has
/// deliberately never had one (`cli::create`'s note).
///
/// So: **thirty-two bytes of entropy supplied once per open**, and the nonce
/// is `sha3_256(seed || generation)` truncated to twelve bytes. Two copies of
/// a store opened by two processes get different seeds, so equal generations
/// no longer mean equal nonces; within one open the generation is strictly
/// increasing, so the input never repeats. The hash is the **native** sha3,
/// for the trailer's reason (module doc, *No C*).
///
/// A caller that supplies a constant seed gets a deterministic nonce, which is
/// what the tests want and what keeps the byte-level proofs alive. That is a
/// property of the parameter, and the binary's parameter is `/dev/urandom`.
pub(crate) fn nonce_for(seed: &[u8; NONCE_SEED_LEN], generation: u64) -> [u8; NONCE_LEN] {
    let mut input = [0u8; NONCE_SEED_LEN + 8];
    let (head, tail) = input.split_at_mut(NONCE_SEED_LEN);
    head.copy_from_slice(seed);
    tail.copy_from_slice(&generation.to_le_bytes());
    let digest = crate::backend::native::sha3_256(&input);
    let mut nonce = [0u8; NONCE_LEN];
    // sha3_256 is 32 bytes and NONCE_LEN is 12, so this always matches. It is
    // an `if let` and not an `expect` because the panic census is right that a
    // wallet which panics on an internal invariant is a wallet that panics;
    // the unreachable else leaves a zero nonce, which every round-trip test
    // would catch.
    if let Some((head, _)) = digest.split_first_chunk::<NONCE_LEN>() {
        nonce.copy_from_slice(head);
    }
    nonce
}

/// Encrypt `plaintext` in place and return the tag. `aad` is the header.
pub(crate) fn seal(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &mut [u8],
) -> Result<[u8; TAG_LEN]> {
    use chacha20poly1305::aead::AeadInPlace;
    use chacha20poly1305::KeyInit;
    let cipher = chacha20poly1305::ChaCha20Poly1305::new(key.into());
    let tag = cipher
        .encrypt_in_place_detached(nonce.into(), aad, plaintext)
        .map_err(|_| Error::Corrupt {
            what: "keystore encryption",
            offset: 0,
        })?;
    let mut out = [0u8; TAG_LEN];
    out.copy_from_slice(&tag);
    Ok(out)
}

/// Decrypt `ciphertext` in place. **Failure is one error whatever the cause.**
///
/// A wrong password, a flipped bit and a tampered header all arrive here as
/// the same tag mismatch, and they leave as the same [`Error::WrongPassword`].
/// Distinguishing them would be a decryption oracle: an attacker who could
/// tell *wrong password* from *damaged file* learns which of his guesses moved
/// him closer. The CLI's message therefore names both possibilities and
/// neither is a lie.
pub(crate) fn open(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &mut [u8],
    tag: &[u8; TAG_LEN],
) -> Result<()> {
    use chacha20poly1305::aead::AeadInPlace;
    use chacha20poly1305::KeyInit;
    let cipher = chacha20poly1305::ChaCha20Poly1305::new(key.into());
    cipher
        .decrypt_in_place_detached(nonce.into(), aad, ciphertext, tag.into())
        .map_err(|_| Error::WrongPassword)
}
