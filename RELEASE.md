# Release checklist

This is the manual replacement for automated verification: weaker than
automation, because it runs only when a person remembers to run it and reports
only what that person writes down, and stronger than memory, because the run
is named, the platform is recorded, and an unticked box is visible where an
unasked question is not.

Work down it before a tag. Nothing here is new verification -- every gate is
one the repository already has. What this document adds is that they were all
run, on both platforms, at the commit being tagged.

## The gates

- [ ] The working tree is clean and the commit to be tagged is the one in hand.
      `git status --short` prints nothing.
- [ ] `./board verify` is **green on Linux**. Record the run below.
- [ ] `./board verify` is **green on macOS**. Record the run below.
- [ ] The board's figures in `AGENT.md` match the run that just happened --
      the per-target counts and the wall time, re-derived from the run being
      reported. AGENT.md's own rule governs: the total is summed from that
      run's result lines, never carried forward from a previous one, and a
      figure that moved is re-read rather than adjusted.
- [ ] `AGENT.md`'s board section names the commit being tagged.
- [ ] The version in `crates/mochimo-crypto/Cargo.toml` is the version being
      tagged.
- [ ] **The declared MSRV still builds.** `rust-toolchain.toml` pins the board
      to one compiler, so no board row ever compiles this tree on the
      `rust-version` the workspace declares. This is the only thing that
      checks it, and both must exit 0:

          cargo +1.89.0 check --workspace
          cargo +1.89.0 check -p mochimo-crypto --features mesh-https

      The version is written out twice here and once in `Cargo.toml`. If
      either moves, this line moves with it -- a version number in a checklist
      is a value that drifts, and nothing holds this one to the manifest.

`./board verify` is `./board check` -- the eight commands under *Build and
test* in `AGENT.md` -- followed by `cargo deny check` and the Miri run. It
takes hours, most of it Miri. `./board check` alone is the pre-commit gate and
takes minutes; it is not sufficient here.

## Why both platforms, and not as a formality

The wallet claims Linux and macOS. The keystore's durability and exclusion
rest on syscalls whose behaviour is not the same on the two, and the
divergence is documented in the code rather than assumed away:

- **The directory fsync.** `keystore/medium.rs`'s `fsync_dir` carries the
  note that on Apple targets `std`'s `sync_all` is `fcntl(F_FULLFSYNC)` with
  no fallback, and that it was *measured* succeeding on a directory fd on
  APFS. That is a different syscall from the `fsync(2)` the same line makes on
  Linux, and the measurement behind it was taken on one platform. I3 -- spend
  state moves atomically through temp-write, fsync, rename, fsync -- rests on
  that step on both.
- **The lock.** `keystore.lock` is held with `File::try_lock` (`flock(2)`),
  and the module's own note records the residue: local filesystems only, with
  NFS lock emulation able to make it silently meaningless. Whether a given
  host's filesystem is one where the lock means what I1 needs it to mean is a
  property of that host, not of this source.
- **The mode bits.** `Keystore::create_with` makes the store directory with
  `DirBuilderExt::mode(0o700)`, and the lock file and every temp file a
  snapshot is written through are opened with `OpenOptionsExt::mode(0o600)`.
  `refuse_unsafe_dir` then stats that directory and **refuses to open the store
  at all** when `mode & 0o022` is set -- group- or other-writable. Whether that
  refusal fires is settled by the host's umask and by whatever the filesystem
  and any ACL layer above it do to a mode, which is a property of the platform
  and not of this source.

A green board on one platform is evidence about that platform. Running it on
the other is not duplication; it is the only thing that makes the second claim
true.

## What this checklist does not reach

Stated here for the same reason `AGENT.md` states it of the board: a gate that
is believed to cover more than it does is worse than a gate known to be
narrow.

- The three conditions `AGENT.md` deliberately declines to carry as board rows
  -- a live node for group E's framing, a capture at submit time for Mesh
  authorship, and an upstream header for `valid_op` -- are not reached by any
  gate here either. They live outside any repository, and tagging does not
  change that.
- `cargo deny check` catches a policy violation introduced by a change. It
  cannot catch a new advisory filed against a dependency whose version did not
  move; `deny.toml`'s own comments say so at length.
- `./board check`'s `cargo doc` row does not fail on a warning -- rustdoc
  warns and exits 0. It does catch a broken intra-doc link, because `lib.rs`
  denies that lint. Read the row's output rather than trusting its status.
- A green board means every row that runs passes. `AGENT.md`'s rule holds
  here: check by name, not by count.

## The record

The one thing this document does that memory cannot: it says which platform
the last verification actually ran on.

**Append a row; never edit one.** A record adjusted after the fact certifies
nothing -- the same reason the fixture corpus is never edited. If a run was
red, the row says red and a later row says green.

| date | commit | platform | OS / kernel | toolchain | `./board verify` | by |
| --- | --- | --- | --- | --- | --- | --- |
| _(no verification recorded yet)_ | | | | | | |

`platform` is `linux` or `macos`. `toolchain` is the stable version the board
ran on and the nightly Miri ran on, since the `compile_fail` target pins
rustc's exact diagnostic wording and a toolchain bump can turn it red with no
change to the property it checks. The stable half should now equal the channel
in `rust-toolchain.toml`; recording it anyway is what would show that someone
had overridden the pin, which a row reading only "pinned" never could.

A tag needs one green `linux` row and one green `macos` row at the commit
being tagged. Two rows at different commits are two half-verifications.
