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
- [ ] `./board verify` is **green on Linux**, in its three parts, each at
      the commit being tagged. Only the first has to run on Linux, so the
      three may come from three runs rather than one -- `./board verify`
      run whole on an x86_64 Linux host is all three at once. Record them
      in one row below, each with where it ran:

      - `./board check`, green on Linux: on a Linux host, or the workflow's
        Linux job (below). It is the one part that runs anything on Linux
        -- the keystore's lock, flushes and mode bits on a Linux kernel and
        filesystem, the binary under util-linux `script(1)`, and `ring`'s C
        and assembly built for the target -- and so the one part no other
        host can stand in for.
      - `cargo deny check`, green on any host. `deny.toml` leaves `targets`
        unset and sets `all-features`, so the graph whose licences,
        advisories, bans and sources it judges is the whole lockfile's and
        not a host's; the `macos` row's own run at this commit is this part
        too.
      - Miri for the Linux target, green on any host, with MIRIFLAGS
        unset as the board leaves it:

            cargo +nightly miri test -p mochimo-crypto --target x86_64-unknown-linux-gnu

        On an x86_64 Linux host that is `./board verify`'s Miri row;
        anywhere else the target has to be named. Miri interprets the
        target it is given whatever the host -- its README calls this
        cross-interpretation -- and with MIRIFLAGS unset its isolation is
        on, which the README says replaces entropy, environment variables
        and clocks with deterministic fakes, and which refuses the file
        system. The same README says isolation is not a sandbox, and that
        a gap in it is a Miri bug.

      The third part reaches less than its name suggests: *What this
      checklist does not reach* says what.
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

      On both platforms, and not once: a dependency's code for one target
      compiles only for that target -- `sha2`'s backends, and `ring`'s C and
      assembly, among it -- so one host's check says nothing about the
      other's. The workflow's `msrv` job runs both commands on Linux and
      macOS, reading the version from `Cargo.toml`; a green run of it is
      evidence for this box, and a person still ticks it.

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

## Hosts this repository does not have

The gates above ask for two platforms, and this tree is developed on one,
macOS. `.github/workflows/board.yml` runs `./board check` on GitHub's Linux
and macOS runners at one commit, and in a job of its own the MSRV check
above, when a person pushes a branch whose name begins `board/`, on its own
-- the workflow's head says why alone -- or, once the workflow is on the
default branch, dispatches it. Its runs are listed at the end of this
section. It is a way to reach a platform, and it changes nothing above:

- **It gates nothing.** No pull request waits on it and no check is required
  of one.
- **It runs `check`, not `verify`.** A green run is evidence about the board
  on that platform, and the record below is for `verify`. A green Linux job
  is the first of the three parts the `linux` row is assembled from, and the
  gate says why the other two need no Linux host. A green macOS job is no
  part of the `macos` row, which is `./board verify` run whole on a macOS
  host. Whether the Miri run finishes inside a hosted job's six hours has not
  been measured.
- **It writes nothing here.** The run's log is the transcript, GitHub deletes
  it when its retention period ends, and the record is what a person copies
  out of it before then.
- **A runner is one host.** The section above calls the lock's meaning and
  the mode-bit refusal properties of a host -- its filesystem and its umask
  -- and not of this source, and a runner measures its own. The workflow
  prints each job's image and kernel before the board, so a reader can tell
  which host a result is about.

The workflow's head carries the rest of its argument: why it clones under the
user's profile rather than into the runner's workspace, why it uses no
actions, and why its images are `-latest`. The Windows fork's copy of it came
first; this one is its Linux and macOS half.

**Its runs.** Each figure is summed from that job's own seventeen result
lines, read with `gh run view --repo patricksmithlaravel/mcm-rust-cli-wallet
--job <job> --log`, and each host is the one that job printed. Append a run;
like the record below, a row is never edited.

| run | commit | Linux `check` | macOS `check` | `msrv`, Linux and macOS |
| --- | --- | --- | --- | --- |
| _(no run recorded yet)_ | | | | |

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
- **Miri for the Linux target runs the tests a macOS host's run does.**
  Measured at `c2b08ce` on this repository's arm64 macOS host,
  `cargo +nightly miri test -p mochimo-crypto -- --list` and the same
  command with `--target x86_64-unknown-linux-gnu` name the same 54 tests,
  counted by their `: test` lines and compared by name: the library's 35,
  `derive`'s 7, `mesh`'s 4, `net`'s 3, `txwire`'s 3 and `miri`'s 2. The
  other ten targets list none -- `cli`, `keystore` and `invariants` among
  them -- and isolation refuses the file system, so none of the keystore's
  locking, flushing or renaming is under either target. What the Linux
  target adds is Linux's `std` beneath the same tests, on x86_64, with Miri
  itself answering the calls `std` makes to the system: no Linux kernel is
  beneath it, and the keystore's calls to one are the `check` part's. Nor is
  there `unsafe` of the library's own to reach: `src/` has none, and
  `unsafe_is_confined_to_declared_files` holds it to none with an empty
  allow-list. This tree's own `unsafe` is the test tree's -- three blocks in
  the drop witness, `tests/support/drop_witness.rs`, which
  `secret_drop_witness_is_sound_under_miri` runs under Miri for either
  target -- and every other `unsafe` Miri walks is `std`'s or a
  dependency's.
- The TLS graph is built on each platform's own host. `ring` compiles C and
  assembly for its target, and `mesh-https` is in no configuration Miri
  interprets, so a platform's `mesh-https` rows -- `clippy: mesh-https`,
  `build: shipped`, and the binary the pty harness builds -- are its
  `check` part's and nothing else's.

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

A `linux` row may be assembled, as its gate says. Its `OS / kernel` is then
the Linux host `./board check` ran on, and its `./board verify` cell names
each part and where it ran: the check by its host or its workflow run,
`cargo deny` by its host, and Miri by its host and target.

A tag needs one green `linux` row and one green `macos` row at the commit
being tagged. Two rows at different commits are two half-verifications.
