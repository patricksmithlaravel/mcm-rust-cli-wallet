//! Unix creation modes and permission checks on held directory handles.

use std::fs::File;
use std::os::unix::fs::MetadataExt;

use crate::error::{Error, Result};

/// Owner read/write for each new store file.
pub(crate) const FILE_MODE: rustix::fs::Mode = rustix::fs::Mode::from_bits_retain(0o600);
/// Owner-only access for a new store directory.
pub(crate) const DIR_MODE: rustix::fs::Mode = rustix::fs::Mode::from_bits_retain(0o700);

/// Check the opened directory, never a path that may name another inode.
pub(crate) fn refuse_unsafe_dir(dir: &File) -> Result<()> {
    let meta = dir.metadata().map_err(|e| Error::Io { op: "stat directory", kind: e.kind() })?;
    if !meta.is_dir() {
        return Err(Error::Io { op: "stat directory", kind: std::io::ErrorKind::NotADirectory });
    }
    if meta.uid() != rustix::process::geteuid().as_raw() {
        return Err(Error::Io { op: "directory owner", kind: std::io::ErrorKind::PermissionDenied });
    }
    let mode = meta.mode() & 0o777;
    if mode & 0o022 != 0 {
        return Err(Error::UnsafePermissions { mode });
    }
    Ok(())
}
