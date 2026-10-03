//! The four durable steps as primitives, and the typestate that fixes their
//! order.
//!
//! # Why a trait, and why it is sealed
//!
//! The keystore's commit is four syscall-level steps: write the temp, fsync
//! it, rename it over the target, fsync the directory. The steps are
//! primitives supplied by a [`Medium`]; the **order** is crate-owned code in
//! `Keystore::commit` and is not something an implementor can change. The
//! trait is `pub` only so that `tests/` — an external crate — can drive the
//! instrumented medium; it is sealed so nothing outside this crate can
//! implement it, which is what makes "the durability contract is I2's clause"
//! a property rather than a promise.
//!
//! # One primitive outside the commit
//!
//! [`Medium::fsync_parent`] flushes the directory that holds the store
//! directory -- where the store directory's own entry lives, which none of
//! the four steps reaches. `Keystore::create` calls it once, before its first
//! commit, and no commit calls it; it takes and returns no token, because it
//! has no place in the commit's order to hold. [`Instrumented`] records it
//! with the parent's path, so a flush aimed at the store directory instead --
//! a wrong path that would leave every count green -- shows in the recorded
//! sequence. The keystore's module doc says what the flush does and does not
//! reach.
//!
//! # The typestate
//!
//! Each step returns a token the next step consumes: `write_temp -> Written`,
//! `fsync_file(Written) -> Synced`, `rename(Synced) -> Renamed`,
//! `fsync_dir(Renamed)`. A reorder is a type error (E0308), not a review
//! finding — `ui/fail/medium_steps_are_not_reorderable.rs` pins it. The
//! tokens have private fields, so they cannot be forged outside the crate.
//!
//! # What the instrumented medium models, and what it cannot
//!
//! [`Instrumented`] records every call **with its arguments** and can be told
//! to stop after call `k`: it performs the primitive and then returns an
//! error, modelling a process that died after the syscall completed and
//! before it consumed the return. Everything a completed syscall left behind
//! is visible afterwards; that is a kill at a syscall boundary. It is **not**
//! power loss: it cannot drop the page cache or truncate a journal, and it
//! cannot make `fsync` lie. Those residues are stated at the proof tests.
//! Recording arguments is what makes the recorder non-decorative: an fsync on
//! the wrong path keeps every count and every byte assertion green and is
//! visible only here (the proof test's sequence assertion, and the paired
//! injection that shows it).

use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

use super::Directory;
use crate::error::{Error, Result};

pub(crate) const SNAPSHOT_NAME: &str = "accounts.mks";
pub(crate) const TEMP_NAME: &str = "accounts.mks.tmp";

mod sealed {
    pub trait Sealed {}
}

/// The temp file has been written in full (not yet flushed).
pub struct Written {
    file: File,
    path: PathBuf,
}

/// The temp file's bytes and metadata have reached the device (`sync_all`,
/// not `sync_data`: a new inode's size and block map are metadata, which
/// `fdatasync` may omit).
pub struct Synced {
    path: PathBuf,
}

/// The temp has been renamed over the target; the directory entry may still
/// be in an uncommitted journal transaction until `fsync_dir`.
pub struct Renamed {
    _private: (),
}

/// The primitives. See the module doc for why the order is not here.
pub trait Medium: sealed::Sealed {
    fn write_temp(&mut self, dir: &Directory, image: &[u8]) -> Result<Written>;
    fn fsync_file(&mut self, written: Written) -> Result<Synced>;
    fn rename(&mut self, synced: Synced, dir: &Directory) -> Result<Renamed>;
    fn fsync_dir(&mut self, renamed: Renamed, dir: &Directory) -> Result<()>;
    /// Flush the directory holding `dir`, which is where `dir`'s own entry
    /// lives. Not a commit step; see the module doc.
    fn fsync_parent(&mut self, dir: &Directory) -> Result<()>;
}

fn io(op: &'static str) -> impl Fn(std::io::Error) -> Error {
    move |e| Error::Io { op, kind: e.kind() }
}

/// The directory holding `dir`: its parent, `.` for a bare relative name, and
/// `dir` itself for a root, which has no parent to hold its entry.
///
/// `Path::parent` answers `Some("")` for `wallet` and for `wallet/` -- the
/// second is what shell completion types -- and opening the empty path
/// fails, so that answer is read as the working directory it means. Without
/// the mapping, `create --dir wallet` would be refused at its flush.
pub(crate) fn parent_of(dir: &Path) -> &Path {
    match dir.parent() {
        Some(p) if p.as_os_str().is_empty() => Path::new("."),
        Some(p) => p,
        None => dir,
    }
}

/// The real filesystem.
pub struct Disk;

impl sealed::Sealed for Disk {}

impl Medium for Disk {
    fn write_temp(&mut self, dir: &Directory, image: &[u8]) -> Result<Written> {
        let path = dir.path().join(TEMP_NAME);
        dir.remove_temp(TEMP_NAME).map_err(io("write_temp unlink stale temp"))?;
        let mut file = dir.create_temp(TEMP_NAME).map_err(io("write_temp open"))?;
        file.write_all(image).map_err(io("write_temp write"))?;
        Ok(Written { file, path })
    }

    fn fsync_file(&mut self, written: Written) -> Result<Synced> {
        written.file.sync_all().map_err(io("fsync_file"))?;
        Ok(Synced { path: written.path })
    }

    fn rename(&mut self, synced: Synced, dir: &Directory) -> Result<Renamed> {
        let _ = synced;
        dir.replace(TEMP_NAME, SNAPSHOT_NAME).map_err(io("rename"))?;
        Ok(Renamed { _private: () })
    }

    fn fsync_dir(&mut self, _renamed: Renamed, dir: &Directory) -> Result<()> {
        // Retain File::sync_all, including Apple's full-flush behavior.
        dir.sync_all().map_err(io("fsync_dir"))
    }

    fn fsync_parent(&mut self, dir: &Directory) -> Result<()> {
        dir.sync_parent().map_err(io("fsync_parent"))
    }
}

/// One recorded primitive call, with the arguments that matter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Call {
    WriteTemp { path: PathBuf, len: usize },
    FsyncFile { path: PathBuf },
    Rename { from: PathBuf, to: PathBuf },
    FsyncDir { dir: PathBuf },
    /// The directory flushed, which is the store directory's parent.
    FsyncParent { dir: PathBuf },
}

/// A recording, optionally interrupting decorator over any medium.
pub struct Instrumented<M: Medium> {
    inner: M,
    calls: Vec<Call>,
    /// `(k, calls.len() when armed)`: the interruption fires on the k-th call
    /// **after arming**, so seeding calls recorded earlier do not shift it.
    stop_after: Option<(usize, usize)>,
}

impl<M: Medium> Instrumented<M> {
    pub fn new(inner: M) -> Self {
        Instrumented {
            inner,
            calls: Vec::new(),
            stop_after: None,
        }
    }

    /// After the `k`-th call (1-based, counted from this arming) performs its
    /// primitive, return an error instead of its result. `None` disarms.
    pub fn stop_after(&mut self, k: Option<usize>) {
        self.stop_after = k.map(|k| (k, self.calls.len()));
    }

    pub fn calls(&self) -> &[Call] {
        &self.calls
    }

    pub fn reset_calls(&mut self) {
        self.calls.clear();
    }

    fn interrupt_here(&self, op: &'static str) -> Result<()> {
        match self.stop_after {
            Some((k, armed_at)) if self.calls.len() == armed_at + k => Err(Error::Io {
                op,
                kind: std::io::ErrorKind::Interrupted,
            }),
            _ => Ok(()),
        }
    }
}

impl<M: Medium> sealed::Sealed for Instrumented<M> {}

impl<M: Medium> Medium for Instrumented<M> {
    fn write_temp(&mut self, dir: &Directory, image: &[u8]) -> Result<Written> {
        self.calls.push(Call::WriteTemp {
            path: dir.path().join(TEMP_NAME),
            len: image.len(),
        });
        let out = self.inner.write_temp(dir, image)?;
        self.interrupt_here("write_temp")?;
        Ok(out)
    }

    fn fsync_file(&mut self, written: Written) -> Result<Synced> {
        self.calls.push(Call::FsyncFile {
            path: written.path.clone(),
        });
        let out = self.inner.fsync_file(written)?;
        self.interrupt_here("fsync_file")?;
        Ok(out)
    }

    fn rename(&mut self, synced: Synced, dir: &Directory) -> Result<Renamed> {
        self.calls.push(Call::Rename {
            from: synced.path.clone(),
            to: dir.path().join(SNAPSHOT_NAME),
        });
        let out = self.inner.rename(synced, dir)?;
        self.interrupt_here("rename")?;
        Ok(out)
    }

    fn fsync_dir(&mut self, renamed: Renamed, dir: &Directory) -> Result<()> {
        self.calls.push(Call::FsyncDir {
            dir: dir.path().to_path_buf(),
        });
        self.inner.fsync_dir(renamed, dir)?;
        self.interrupt_here("fsync_dir")
    }

    fn fsync_parent(&mut self, dir: &Directory) -> Result<()> {
        self.calls.push(Call::FsyncParent {
            dir: dir.parent_path().to_path_buf(),
        });
        self.inner.fsync_parent(dir)?;
        self.interrupt_here("fsync_parent")
    }
}

#[cfg(test)]
mod tests {
    use super::parent_of;
    use std::path::Path;

    /// The directory `create` flushes, for every shape `--dir` arrives in.
    /// The bare name, with or without the slash shell completion adds, is the
    /// case that matters: without its mapping to `.`, `create --dir wallet`
    /// would be refused at the flush.
    #[test]
    fn parent_of_names_the_directory_holding_the_store_in_every_shape() {
        assert_eq!(parent_of(Path::new("wallet")), Path::new("."));
        assert_eq!(parent_of(Path::new("wallet/")), Path::new("."));
        assert_eq!(parent_of(Path::new("./wallet")), Path::new("."));
        assert_eq!(parent_of(Path::new("stores/wallet")), Path::new("stores"));
        assert_eq!(parent_of(Path::new("/home/op/wallet")), Path::new("/home/op"));
        assert_eq!(parent_of(Path::new("/")), Path::new("/"));
    }
}
