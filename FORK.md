# Forking this wallet into a graphical one

Three repositories, in a line. This document says what each is for, what has
to be true before each fork is cut, and -- where a claim here was measured
rather than reasoned about -- what was measured and what the measurement does
not cover.

| | what it is | platform |
| --- | --- | --- |
| **Rep-0** | this repository: the command-line wallet | Unix. Linux and macOS, as `RELEASE.md` requires |
| **Rep-1** | a command-line wallet that also runs on Windows | Linux, macOS **and** Windows |
| **Rep-2** | a graphical wallet | all three |

**Rep-1 keeps Unix and adds Windows.** It is not a Windows port in the sense of
a Windows-only tree: Rep-2 descends from the tri-platform result, and a Rep-1
that dropped Linux and macOS would leave Rep-2 merging them back from Rep-0
forever.

---

## The organizing principle

Every structural change made downstream instead of here becomes permanent
friction on every later fix, because every Rep-0 fix has to cross two fork
points to reach the graphical wallet. **Phase 0's job is to shape the seams so
both deltas are thin**, and the measure of whether it succeeded is the size of
the Rep-0-to-Rep-1 diff, not the size of Phase 0 itself.

Phase 0 changes no behaviour. Every item in it is justified on this
repository's own terms, and where an item's larger beneficiary is downstream
that is said at the item rather than left to be inferred.

---

## Phase 0 -- work in Rep-0

### P0-1 -- concentrate the Unix surface **(done, 2026-09-20)**

`src/keystore/perms.rs` now holds every mode bit this crate sets or reads. It
was six call sites across `keystore/mod.rs` and `keystore/medium.rs` behind
three separate `std::os::unix::fs` imports; it is one module behind one import,
and the module's own doc carries the argument.

The reason is in `lib.rs`'s platform statement: it claims the crate needs a
permission model of a particular shape, and while the sites it described were
scattered that claim was prose checked against nothing. It now has one module
to be read against.

Measured rather than asserted: `cargo build --workspace`, `cargo test
--workspace --no-fail-fast` (385 tests, 17 targets), all four clippy rows at
`-D warnings`, and `cargo doc` are green at the commit that introduced it. The
error `op` strings at every moved site are unchanged, which is what keeps the
extraction invisible to `tests/keystore.rs`.

**What it is not.** It is not a portability layer. There is no second
implementation behind it, no `cfg` and no trait, and a non-unix build still
fails at `lib.rs`'s `compile_error!` and again at `keystore`'s.

### P0-2 -- cooperative cancellation, and the signal gap **(the restore walk done, 2026-09-20)**

Two parts. The second is the reason the first is worth having here rather than
downstream.

**The gap, which is a defect of this wallet on Unix today.** Nothing in this
tree addresses signals -- not the source, not the documents, not `Cargo.toml`.
A `restore` walks up to `recon::RECOVERY_CEILING` key positions with `master:
&Secret<SEED_LEN>` live across the whole walk, and `SIGINT` terminates the
process without unwinding, so **no destructor runs and the seed is not
overwritten.** That is the argument the root `Cargo.toml` makes against
`panic = "abort"`, reaching a signal that argument does not mention.

**The mechanism, done for the restore walk.** `recon::Cancel` is asked once
per position; a cancel is `Error::Cancelled`, which is deliberately not the
`Ok(None)` an exhausted bound returns, because those two say opposite things.
The check sits in the derivation closure `restore_account_index_with` already
builds, so neither `walk` nor `scan_for_address` grew a parameter. `README.md`
records the open half in its limits section.

**Still open, and both deliberately.**

* **The diagnostic walk.** `reconcile_account_with` reaches the same ceiling
  through `locate` and is not cancellable. It cannot be without reshaping
  `ChainPosition`: `Unlocated` records a stopped walk in `failed_at` and its
  `Display` says the walk stopped *on a derivation error*, which of a cancel is
  false. That is a public enum whose every variant carries an argument, and the
  reshape belongs in a commit whose subject is the reshape. The two walks also
  differ in kind -- cancel a restore and nothing happened; cancel a diagnostic
  and the divergence is still reported, with its position uncharacterised -- so
  the right answer may differ too.
* **A signal handler.** Nothing installs one and the binary passes
  `Cancel::NEVER`, so at the command line the gap is open. A wallet that
  catches a signal is a wallet with a new path through its own shutdown, and
  that path owes the fault injection every other path here owes.

### P0-3 -- separate the decision from its rendering

`cli/mod.rs` is 2,090 lines carrying 96 `Report` constructions and 135 format
sites. Split each `cmd_*` into a typed outcome and a renderer over it.

**On this repository's own terms:** the decisions become assertable as values.
Today a test that means to check a gating decision can only check that a
sentence came out, and `tests/cli.rs` is 7,042 lines of largely that. The same
suite is what holds the split honest -- the rendered text and the exit codes
must come out byte-identical.

**Stated plainly: the larger beneficiary is downstream.** A graphical wallet
cannot parse those strings responsibly, so without this it re-derives the
orchestration that carries I1 and I4, and two copies of that reasoning drift
with nothing holding them together. The `board` script's own header names that
failure class. If Rep-0 is to stay strictly self-justifying, this item moves to
Rep-1 -- at the cost of diverging the largest file in the tree at a fork point.

### P0-4 -- decide the trust store

`webpki-roots` or the platform verifier. It changes what this wallet trusts, so
it is a decision here, and making it once is cheaper than making it three
times.

### P0-5 -- fork hygiene

Tag the fork point. Write down what Rep-1 is permitted to change and how Rep-0
changes flow down. Cheap now; the alternative is discovering the policy at the
third merge.

---

## Fork point 1 -- Rep-0 to Rep-1

**The delta to expect after Phase 0: two `cfg` arms and a durability
statement.** If it is larger than that, P0-1 did not do its job and the
difference should be understood before the fork is cut rather than after.

## Phase 1 -- work in Rep-1

### What was measured

`cargo check --workspace --target x86_64-pc-windows-msvc`, run against this
tree, reports **eight errors**. Two are the deliberate `compile_error!` gates
(`lib.rs`, `keystore/mod.rs`). The other six are **mode bits and nothing else**
-- the sites P0-1 has since gathered into `keystore::perms`.

Patching only those six, the same command reports **no errors and no
warnings**. WOTS+, the address path, the transaction wire form, BIP39 and
derivation, the Mesh codec, the spend builder, reconciliation, `Wallet` and the
whole command layer compile for Windows unchanged.

**What that measurement does not cover.** It is a `cargo check`. It compiles
and it type-checks; it runs nothing, links nothing, and says nothing about
behaviour. Three of the items below are behavioural and the check is blind to
every one of them.

### R1-1 -- the gates

Replace both `compile_error!`s with a per-platform statement. The Unix half of
what they say stays true and stays said.

### R1-2 -- the Windows permission model

A second arm in `keystore::perms`: a DACL check where the mode check is, and
restricted creation where the mode-carrying creation is.

`windows-sys` is **already in `Cargo.lock`** (two versions, through the
transport's graph), and `deny.toml` leaves `targets` unset deliberately so the
licence walk already reaches it. A direct dependency on it adds no crate and no
licence to this workspace's policy.

Note what `perms.rs` records about the public surface: `Error::UnsafePermissions`
carries `mode: u32` and renders it as octal. A second implementation either
reports a Unix mode it did not measure or changes a public variant.

### R1-3 -- `fsync_dir`, which is the one that matters

`medium.rs`'s fourth durable step opens the directory and `sync_all`s it. On
Windows that **compiles and fails at runtime**: `File::open` on a directory is
refused there, so every commit fails at its last step. It is the only item in
this document that the compile gate is actively hiding, and it is the reason
the gate should not simply be deleted.

There is no directory `fsync` on NTFS to substitute. **I3's crash proof does
not transfer**, and the honest form is a per-platform durability claim that
says so, in the idiom the rest of this tree uses for what it cannot establish.

### R1-4 -- rename under a sharing violation

`fs::rename` over an existing file maps to a replacing move on Windows, which
fails while another process holds the target open without delete sharing --
scanners, indexers, backup agents. The commit fails cleanly and the store is
unchanged, so this is an availability problem and not a correctness one, but it
needs a named error rather than an anonymous `Io`.

### R1-5 -- the binary

`/dev/tty`, `stty` and `/dev/urandom` are the binary's, not the library's --
the library takes entropy as a parameter and `cli::create::Terminal` is already
the seam for the prompts. The Windows equivalents are the console device, the
console mode flags, and the platform generator.

### R1-6 -- the board

`./board` is a POSIX shell script. `RELEASE.md` asks for green on two platforms
at one commit; it becomes three.

**Record the coverage that does not come with it.** `tests/cli.rs`'s
pseudo-terminal harness drives the binary through `script(1)` and has no
Windows equivalent, so the binary's remainder -- argv, the prompts, the real
transport -- is exercised on two platforms and not on the third.

---

## Fork point 2 -- Rep-2

**Rep-2 forks from Rep-0, not from Rep-1**, as soon as Phase 0 lands, and takes
Rep-1's Windows delta as a merge when it is ready.

The reason is scheduling and nothing deeper: Phase 0 gives a graphical wallet
everything it needs, so forking from Rep-0 lets Phase 1 and Phase 2 run at the
same time instead of end to end. The merge is small for exactly the reason
Phase 0 exists.

It does not make Windows arrive sooner. It makes the Unix builds arrive sooner.

## Phase 2 -- work in Rep-2

### R2-1 -- where the graphical code lives

**Outside `crates/`.** Several checks in `tests/invariants.rs` walk
`crates/*/src` by glob -- the route scan, the panic census, the `Debug`-holder
scan, the zeroization scan, the name-citation scan. A crate under `crates/` is
adopted by all of them. A sibling workspace is not, and it follows the
precedent `crates/mochimo-crypto/ui/downstream` already sets. It also lets the
graphical workspace carry its own toolchain pin, which is what makes
`rust-toolchain.toml`'s pin -- held there by the `trybuild` expectations -- a
non-issue rather than a conflict.

### R2-2 -- the toolkit

Measured against this workspace's own `deny.toml` policy, on macOS/aarch64:

| | crates | new licences needed | trips `unmaintained = "all"` | webview |
| --- | --- | --- | --- | --- |
| egui/eframe | 166 | BSD-2-Clause, BSL-1.0, Zlib, **OFL-1.1 + Ubuntu-font-1.0** | 1 | no |
| iced | 150 | BSD-2-Clause, BSL-1.0, Zlib, CC0-1.0 | 2 | no |
| Tauri | 215 | Zlib, **MPL-2.0**, Apache-2.0 WITH LLVM-exception | 6 | **yes** |
| this wallet today | 55 | -- | 0 | -- |

No security advisories in any of them; the failures are maintenance status and
allow-list coverage. Windows backends will shift the counts.

**egui, with `default_fonts` off.** Turning it off drops
`epaint_default_fonts` and with it both font licences -- an `AND` of `OFL-1.1`
and the non-standard `Ubuntu-font-1.0` -- leaving the smallest licence delta of
the three. Immediate mode is also a direct fit for a worker thread that owns
the wallet and a frame that renders a snapshot of it.

**Against Tauri for a wallet:** a JavaScript runtime and an IPC bridge inside
the process that holds the master seed, safety-bearing refusal text rendered
through HTML, and the largest trusted computing base of the three -- of which
the webview is outside anything `cargo deny` can see.

### R2-3 -- the dependency debt stays quarantined

Any toolkit forces the first entries in `deny.toml`'s `ignore` list, which that
file describes as a decision that belongs in a commit message with a reason.
**Rep-0 and Rep-1 never take them.** They are taken in the graphical
workspace's own `deny.toml`, which is a second reason to put that workspace
outside `crates/`: the policy over the code that holds keys stays exactly as it
is today.

### R2-4 -- architecture

A worker thread owns the `Keystore` and the `Wallet`; the interface sends
commands and receives values. Nothing calls the library on the drawing thread:
the transport is synchronous, `Wallet::open` reconciles over the network, and
the KDF is 64 MiB over three passes at `Kdf::RECOMMENDED`. Progress and
cancellation come from P0-2.

### R2-5 -- the threat model changes, and must be restated

This wallet's memory argument is that it retains nothing between calls, because
a command is one process that exits. A graphical wallet holds the seed for
hours. No code follows from that by itself; a corrected paragraph does, and
writing it down is this tree's standard.

An idle timer that drops the `Keystore` drops the `Secret` and releases the
lock in one move, which is the cheapest thing that makes the restatement a
smaller one.

### R2-6 -- one writer, still

The lock is held for the handle's life. A running graphical wallet gives the
command line `Error::Locked`, and so does a second window. That is the correct
behaviour and it needs a sentence in the interface, not a workaround.

### R2-7 -- failing closed, in front of a person

I4 refuses an account whose stored index and the chain disagree, and refuses a
store in which nothing reconciled. `README.md` warns against deleting the store
and restoring the seed elsewhere, because those are the paths back to key
reuse.

**A graphical wallet turns that reflex into a button-shaped affordance**, and
the refusal text is the only thing standing against it. I4's message-quality
clause governs here exactly as it governs `Wallet::open`: a message that
satisfies the letter and produces a workaround is the failure the invariant
exists to prevent.

The states that need designing, and not one of them is a dialog with an OK
button: diverged; reserved and unsettled; a reservation that can no longer be
accepted; the emptied-account window; a spend between submission and
settlement.

This is the item with no estimate. It is also the item that decides whether the
result is worth shipping.

### R2-8 -- three residues, still owed

`cli/mod.rs` renders three things a graphical wallet inherits and must not
soften: submit is a socket write and not a verdict; `tx_val` has never run
offline; the retry artifact is losable. The third is the one place a graphical
wallet can do better than the command line -- the artifact can be a file the
operator saves rather than hex they must notice.

### R2-9 -- notices, generated

BSD-2-Clause requires its notice in binary distributions, and MIT and
Apache-2.0 run throughout the graph. Generate the aggregate in CI rather than
maintaining it, for the reason `board` gives about two copies not held to each
other. `BSL-1.0` and `Zlib` contribute nothing to it -- both exempt binary
distribution.

### R2-10 -- packaging

Installer, signed application bundle with notarisation, and a Linux package.
Certificates have lead time; notarisation especially. Start that before the
code is ready for it.

---

## Licence

*This section is an engineering reading of the licence, not advice, and the two
questions at the end are the ones worth putting to counsel.*

A graphical wallet is squarely inside the Field: the licence's own preface
names tools and wallets that work with the cryptocurrency. Section 3.3 permits
a Larger Work under terms of your choice provided the Covered Software's
obligations are met, which is the MPL lineage doing what it is for -- the
licence attaches to files, not to everything in a binary.

**The toolkit licences raise nothing.** BSD-2-Clause, BSL-1.0, Zlib, CC0-1.0,
MIT and Apache-2.0 are permissive: notice preservation and a warranty
disclaimer, no reciprocal clause, and nothing that reaches across into
`mochimo-crypto` or dictates the combined work's licence. GPL is the licence
that would fail here, and it fails on the field-of-use restriction being a
further restriction it forbids -- which is why a GPL-licensed toolkit is out
and these are not.

**The one real interaction is with the licence itself.** The grant-back at
3.2(a)(ii)(1) fires only if the executable is sublicensed under *different*
terms. Distribute Rep-2's executable under this licence -- the first option the
same clause offers -- and it never triggers. The source-availability obligation
is owed either way.

Over permissive dependencies the grant-back would be a no-op in any case, since
those rights are already available upstream. Over `MPL-2.0` dependencies it is
not, which is a fourth reason the toolkit table above matters.

No trademark rights are granted, so Rep-2 cannot be branded as an official
product of the cryptocurrency it serves.

**For counsel, two questions:**

1. Is `mochimo-crypto` *Original Software* or *Covered Software* under section
   1? It is a reimplementation this workspace's own `Cargo.toml` describes as a
   derivative work. The answer decides whether 3.2(a), which carries the
   grant-back, or 3.2(b), which does not, governs distributing an executable.
2. Does distributing under this licence rather than sublicensing leave
   3.2(a)(ii)(1) untriggered, as its text reads?

---

## What this document does not establish

It is a plan. Nothing in it is verified by anything that runs, and no check
reads it -- if an item here stops matching the tree, nothing goes red. The
figures in it were measured on one host on one day and are quoted with the
command that produced them so they can be taken again; take them again rather
than carrying them forward.

The estimates are absent on purpose for R2-7 and approximate everywhere else.
