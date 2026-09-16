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

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

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
    fn write_temp(&mut self, dir: &Path, image: &[u8]) -> Result<Written>;
    fn fsync_file(&mut self, written: Written) -> Result<Synced>;
    fn rename(&mut self, synced: Synced, dir: &Path) -> Result<Renamed>;
    fn fsync_dir(&mut self, renamed: Renamed, dir: &Path) -> Result<()>;
}

fn io(op: &'static str) -> impl Fn(std::io::Error) -> Error {
    move |e| Error::Io { op, kind: e.kind() }
}

/// The real filesystem.
pub struct Disk;

impl sealed::Sealed for Disk {}

impl Medium for Disk {
    fn write_temp(&mut self, dir: &Path, image: &[u8]) -> Result<Written> {
        let path = dir.join(TEMP_NAME);
        // A leftover temp is UNLINKED first, then the temp is created new.
        // The unlink is what keeps a temp left by an earlier crash from
        // blocking every future commit; creating new rather than truncating
        // is what keeps that leftover's mode out of the snapshot, since a
        // mode passed to `open` applies only when the file is created and a
        // truncated leftover carries its own permissions through the rename.
        // `open` already unlinks a stale temp after taking the lock; doing it
        // here too is what keeps `create`'s first commit, and every other,
        // from depending on the caller remembering. Mode 0600: since format
        // v3 the temp is a 51-byte plaintext header over a sealed body, so a
        // partial one leaks the KDF parameters, the salt and the nonce rather
        // than a root -- metadata, not key material, and still nobody else's.
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(io("write_temp unlink stale temp")(e)),
        }
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&path)
            .map_err(io("write_temp open"))?;
        file.write_all(image).map_err(io("write_temp write"))?;
        Ok(Written { file, path })
    }

    fn fsync_file(&mut self, written: Written) -> Result<Synced> {
        written.file.sync_all().map_err(io("fsync_file"))?;
        Ok(Synced { path: written.path })
    }

    fn rename(&mut self, synced: Synced, dir: &Path) -> Result<Renamed> {
        fs::rename(&synced.path, dir.join(SNAPSHOT_NAME)).map_err(io("rename"))?;
        Ok(Renamed { _private: () })
    }

    fn fsync_dir(&mut self, _renamed: Renamed, dir: &Path) -> Result<()> {
        // On Apple targets std's sync_all is fcntl(F_FULLFSYNC) with no
        // fallback; it was measured succeeding on a directory fd on APFS.
        File::open(dir)
            .map_err(io("fsync_dir open"))?
            .sync_all()
            .map_err(io("fsync_dir"))
    }
}

/// One recorded primitive call, with the arguments that matter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Call {
    WriteTemp { path: PathBuf, len: usize },
    FsyncFile { path: PathBuf },
    Rename { from: PathBuf, to: PathBuf },
    FsyncDir { dir: PathBuf },
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
    fn write_temp(&mut self, dir: &Path, image: &[u8]) -> Result<Written> {
        self.calls.push(Call::WriteTemp {
            path: dir.join(TEMP_NAME),
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

    fn rename(&mut self, synced: Synced, dir: &Path) -> Result<Renamed> {
        self.calls.push(Call::Rename {
            from: synced.path.clone(),
            to: dir.join(SNAPSHOT_NAME),
        });
        let out = self.inner.rename(synced, dir)?;
        self.interrupt_here("rename")?;
        Ok(out)
    }

    fn fsync_dir(&mut self, renamed: Renamed, dir: &Path) -> Result<()> {
        self.calls.push(Call::FsyncDir {
            dir: dir.to_path_buf(),
        });
        self.inner.fsync_dir(renamed, dir)?;
        self.interrupt_here("fsync_dir")
    }
}
