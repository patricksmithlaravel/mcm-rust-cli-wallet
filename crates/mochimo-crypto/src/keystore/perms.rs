//! The Unix permission model, in one module.
//!
//! Every mode bit this crate sets or reads is here: the `0600` the lock file
//! and the temp snapshot are created with, the `0700` the store directory is
//! created with when this crate creates it, and the group- and other-writable
//! bits whose presence on that directory is a refusal rather than a warning.
//!
//! # Why they are in one place
//!
//! `lib.rs`'s platform statement names three interfaces this crate cannot do
//! without, and the first of them is this one: the store is created `0600` and
//! its directory `0700`, and a store whose directory is group- or
//! world-writable is refused, which is a check against another local user
//! rather than a convenience.
//!
//! That sentence is a claim about the whole crate. While the sites it
//! describes were spread across `keystore/mod.rs` and `keystore/medium.rs` --
//! six of them, behind three separate `std::os::unix::fs` imports -- it was
//! prose checked against nothing: a mode loosened at one of the six, or a
//! seventh site added beside them, and the statement went on reading exactly
//! the same. Concentrated, the claim has one module to be read against and one
//! module to be wrong in.
//!
//! This is [`crate::cli::destination`]'s argument about a tag aimed at a
//! permission instead of a string: four separate call sites of the formatter
//! would be four chances to print a form no other wallet takes, and six
//! separate call sites of a mode are six chances to create a file this
//! crate's own platform statement does not describe.
//!
//! # What this module is not
//!
//! **It is not a portability layer.** There is no second implementation behind
//! it, no `cfg`, and no trait. A non-unix build fails at `lib.rs`'s
//! `compile_error!` and again at [`crate::keystore`]'s, exactly as it did
//! before this module existed, and nothing here is a step toward changing
//! that. What it changes is that the Unix surface is locatable rather than
//! scattered, which is worth having whether or not anything is ever built on
//! it.
//!
//! # The shape of the public error, stated because it is not obvious
//!
//! [`Error::UnsafePermissions`] carries `mode: u32` -- a Unix mode, in this
//! crate's public error type, rendered as octal by its `Display`. The
//! refusal is therefore not merely *implemented* in terms of mode bits; it
//! *reports* in them, and a caller that matches on the variant reads an octal
//! number out of it.
//!
//! That is the right shape for a crate whose platform statement is the one
//! above, and it is written down here rather than left in `error.rs` to be
//! inferred, because it is the part of the permission model that is visible
//! from outside the crate and the only part a dependent can come to depend on.

use std::fs::{self, File, OpenOptions};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::Path;

use crate::error::{Error, Result};

/// The mode every file this crate creates is created with: owner read and
/// write, nothing for anyone else.
///
/// Both files it names are covered. The snapshot's temp holds a plaintext
/// header over a sealed body, so a partial one leaks KDF parameters rather
/// than a root; the lock file holds no bytes at all. Neither is key material
/// and both are still nobody else's, which is the same standard the directory
/// check below applies and the reason one constant serves both.
pub(crate) const FILE_MODE: u32 = 0o600;

/// The mode the store directory is created with **when this crate creates
/// it**: owner only, no group and no other.
///
/// A directory this crate did not create keeps whatever mode it has, and is
/// then held to [`refuse_unsafe_dir`] instead. The two are not the same
/// standard and deliberately so: this is what we make, that is what we accept.
pub(crate) const DIR_MODE: u32 = 0o700;

/// The bits whose presence on the store directory is a refusal: group-write
/// (`0o020`) and other-write (`0o002`).
///
/// **Write, and not read.** A group- or world-*readable* directory discloses
/// that a store exists and what its files are called, which is metadata; a
/// group- or world-*writable* one lets another local user rename the snapshot
/// out from under a live handle, which defeats the commit's atomicity
/// directly. The check is aimed at the second and says nothing about the
/// first, and widening it to `0o077` would refuse the mode a great many
/// home directories already carry for a property this crate does not rest on.
const REFUSED_WRITE_BITS: u32 = 0o022;

/// Refuse a store directory another local user could write to.
///
/// Asked by both [`crate::keystore::Keystore::create_with`] and
/// [`crate::keystore::Keystore::open_with`], before either takes the lock.
///
/// A path that is not a directory is refused as `NotADirectory` under the
/// same `op` as the stat that found it, rather than as a permission problem:
/// the caller named something that cannot hold a store, which is a different
/// mistake from naming a directory that should not.
pub(crate) fn refuse_unsafe_dir(dir: &Path) -> Result<()> {
    let meta = fs::metadata(dir).map_err(|e| Error::Io {
        op: "stat directory",
        kind: e.kind(),
    })?;
    if !meta.is_dir() {
        return Err(Error::Io {
            op: "stat directory",
            kind: std::io::ErrorKind::NotADirectory,
        });
    }
    let mode = meta.mode() & 0o777;
    if mode & REFUSED_WRITE_BITS != 0 {
        return Err(Error::UnsafePermissions { mode });
    }
    Ok(())
}

/// Create the store directory at [`DIR_MODE`].
///
/// The mode passed to `DirBuilder` applies only on creation, which is why the
/// caller asks this **only when the directory is absent** and asks
/// [`refuse_unsafe_dir`] of it either way.
///
/// `std::io::Result`, not this crate's: the one caller already names the `op`
/// this failure is reported under, and moving that name in here would put
/// half of one error's vocabulary in a second file.
pub(crate) fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    fs::DirBuilder::new().mode(DIR_MODE).create(dir)
}

/// Create a file at [`FILE_MODE`], failing if it already exists.
///
/// `create_new`, so a leftover cannot be opened in place: a mode passed to
/// `open` applies only when the file is created, and a truncated leftover
/// carries its own permissions through to whatever is written into it. The
/// caller that needs the leftover gone unlinks it first.
pub(crate) fn create_private_file(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(FILE_MODE)
        .open(path)
}

/// Open the lock file at [`FILE_MODE`], creating it if absent and **never**
/// truncating it.
///
/// Read and write are both asked for because the caller locks the descriptor
/// afterwards; truncation is refused because the file is a lock and not a
/// store, and a `create(true).truncate(true)` here would rewrite a file
/// another process may hold at exactly the moment this one is finding out
/// whether it does.
pub(crate) fn open_private_lock(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(FILE_MODE)
        .open(path)
}
