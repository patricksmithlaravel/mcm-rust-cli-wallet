use core::fmt;

use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// Key material. Zeroed on drop, and never printable.
///
/// There is no `Display`, no `AsRef<[u8]>`, and no derived `Debug` anywhere in
/// this type's neighbourhood: a `#[derive(Debug)]` on any struct that happens
/// to hold one of these is how seeds end up in log files. Reading the bytes is
/// deliberately a named method, so it shows up in review.
///
/// `PartialEq` is deliberately absent. A derived comparison over key material
/// is variable-time and short-circuits on the first differing byte. If
/// comparing secrets ever becomes necessary it goes through
/// `subtle::ConstantTimeEq`, never `==`.
#[derive(Clone)]
pub struct Secret<const N: usize>(Zeroizing<[u8; N]>);

impl<const N: usize> Secret<N> {
    pub fn new(bytes: [u8; N]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let arr: [u8; N] = bytes.try_into().map_err(|_| Error::Length {
            what: "secret",
            expected: N,
            got: bytes.len(),
        })?;
        Ok(Self::new(arr))
    }

    /// Borrow the raw bytes. Named to be conspicuous at the call site.
    pub fn expose(&self) -> &[u8; N] {
        &self.0
    }

    pub const fn len(&self) -> usize {
        N
    }

    pub const fn is_empty(&self) -> bool {
        N == 0
    }

    /// Constant-time equality, crate-private. The one comparison of key
    /// material this crate makes: `Keystore::add` refuses an imported root
    /// already stored, and `sign_spend` refuses a derived seed that is also
    /// stored as an imported root -- two accounts over one key stream let
    /// one key sign twice. Through `subtle::ConstantTimeEq` over
    /// the slices, exactly as the type doc above prescribes; never `==`.
    pub(crate) fn ct_eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        self.0[..].ct_eq(&other.0[..]).into()
    }
}

impl<const N: usize> fmt::Debug for Secret<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secret<{N}>(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::Secret;

    #[test]
    fn debug_never_reveals_bytes() {
        let s = Secret::new([0xABu8; 4]);
        let rendered = format!("{s:?}");
        assert_eq!(rendered, "Secret<4>(<redacted>)");
        assert!(!rendered.contains("ab") && !rendered.contains("AB"));
    }
}
