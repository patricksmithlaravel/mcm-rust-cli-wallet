# mcm-wallet

A Rust wallet for Mochimo v3: WOTS+ one-time signatures, 40-byte `tag || hash`
addresses, an encrypted keystore whose key index only ever moves forward, and
a client for the Mesh API. One crate, `crates/mochimo-crypto`, and one binary,
`mcm-wallet`. Pure Rust; no C toolchain is needed to build or test it.

**How the wallet works is written down once, in `docs/specification.md`.** Read
it before changing anything that touches a wire format, a key, or the store.
The numbers in it are pinned by the fixture corpus under `fixtures/`, which is
the executable form of the same specification.

This repository was forked from `mochimo-rs`, where the code was ported from a
vendored C reference under differential testing. That history is not here and
is not needed: the corpus carries the facts. The old repository's errata
document, which the comments once cited by entry number, is not here either
and is not needed: every reason a comment needs is written at the site, in the
specification or in this file, and three checks in `tests/invariants.rs` hold
the comments and the string literals under `src/` and `tests/` to that (S3
rewrote the comments under `src/`; S4 rewrote the rest and widened the
checks). A `tx.c:NN`, `types.h:NN`, `wots.c:NN`
or `reference/.../file:NN` citation in a comment refers to the C reference at
the commit named under *The fixture corpus* below (or to the TypeScript at its
pin there); those sources are public and are read there. When a question
arises that the specification and the corpus do not answer, the old repository
is the place to ask it -- it is the only place the corpus can be regenerated.

## Build and test

```sh
export PATH="$HOME/.cargo/bin:$PATH"       # cargo is not on the default PATH on this machine

cargo build --workspace
cargo test --workspace --no-fail-fast     # the board; see "The board" below
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy --workspace -- -D warnings                                              # what a dependent compiles
cargo clippy -p mochimo-crypto --features mesh-https --all-targets -- -D warnings    # the binary's graph
cargo clippy --manifest-path crates/mochimo-crypto/ui/downstream/Cargo.toml --bin pass -- -D warnings
cargo build --features mesh-https --bin mcm-wallet                                   # the shipped binary (TLS)
cargo +nightly miri test -p mochimo-crypto      # not part of the board; MIRIFLAGS unset; green in 2 h 57 m 16 s on 2026-09-14 (S11, see "Miri" below)
```

`cargo fmt` is not a gate; do not reformat unrelated code.

### Features

| feature | default | what |
| --- | --- | --- |
| `native` | yes | the whole crate: primitives, keystore, derivation, mesh codec, CLI |
| `mesh-http` | no | the HTTP transport (`ureq`, no TLS); on for every test target through the dev-dependency on the crate itself |
| `mesh-https` | no | TLS (rustls, `ring`); required by the `mcm-wallet` binary and the `mesh_probe` example |
| `raw-backend` | no | makes the primitive layer nameable; on for the test targets only, never for a dependent |

A fifth feature, `ffi-oracle`, once routed every primitive through a vendored C
reference. It was declared and dead from the plant until S2, which stripped
it whole: the feature line, the foreign-function backend, the TXENTRY handle,
and every `cfg` site. `tests/invariants.rs::documented_counts_match_the_artifacts`
holds that no `cfg` sites under `crates/` name it, and that no count of such
sites reappears in this file or in `Cargo.toml`.

## The fixture corpus

`fixtures/` holds 5,364 vectors in 15 groups (`fixtures/manifest.toml`
lists them; `tests/kat.rs::manifest_and_disk_agree` and
`manifest_counts_match_the_files` hold the manifest to the directory in both
directions). Every value was produced by executing an implementation that is
not this crate -- the Mochimo C reference at commit
`bbbaceabe5c21b5d8a094cf34c050d28e4ae93f4` (v3.1.0-beta), the `mochimo-wots`
TypeScript at `b583580bffcbe51dbcfd4e30aa711d0d2703b851`, the shipped browser
extension `mochimo-wallet` at `f4694cefd3fc4f15a9922db0bb2ca1c0f27ecb60` with
its lockfile from `mochiwallet` at `af20bfccdde1b0dd75ac1a98f7c83b82ccf359a2`,
or the live Mesh API at one block. Each file's header says which.

| group | file | subject | vectors | oracle |
| --- | --- | --- | --- | --- |
| A | `group_a_keygen.json` | WOTS+ key generation, curated | 11 | C |
| AK | `group_ak_keygen_bulk.json` | WOTS+ key generation, bulk (digests) | 1512 | C |
| AKX | `group_akx_keygen_bulk_crosscheck.json` | the AK keys recomputed by the TypeScript | 1000 | TypeScript, executed crosscheck |
| B | `group_b_sign.json` | WOTS+ signing and recovery, curated | 33 | C |
| BK | `group_bk_sign_bulk.json` | WOTS+ signing and recovery, bulk (digests) | 1128 | C |
| C | `group_c_addr.json` | addresses, Base58, CRC-16 (+ a 1000-entry tag corpus) | 29 | C |
| CX | `group_c_crosscheck.json` | group C recomputed by the TypeScript | 29 | TypeScript, executed crosscheck |
| CK | `group_ck_tag_crosscheck.json` | the 1000-entry tag corpus recomputed by the TypeScript | 1000 | TypeScript, executed crosscheck |
| D | `group_d_tx.json` | transaction layout, hashing, offline validation verdicts | 72 | C |
| E | `group_e_net.json` | network constants; framing is a recorded gap | 10 | C |
| F | `group_f_derivation.json` | the extension's seed derivation and BIP39 | 96 | TypeScript, specification capture |
| HS | `group_hs_hash_sweep.json` | sha256, sha3-512, ripemd160 at every length across two blocks | 390 | C |
| RX | `group_rx_ripemd.json` | RIPEMD-160 where the C cannot compute it | 26 | `@noble/hashes`, no reference side |
| M | `group_m_mesh_client.json` | the shipped mesh client under a recording double | 6 | TypeScript, specification capture |
| N | `group_n_mesh_live.json` | the Mesh API, live, at one block | 22 | api.mochimo.org |

**Three rules about the corpus.**

1. **A fixture is never edited.** Not a value, not a count, not a file list.
   An expectation moved to fit an observation certifies the observation. The
   only hand-written text under `fixtures/` is the `reason` prose in
   `manifest.toml`.
2. **It cannot be regenerated here.** The generators and the reference they
   call live in the old repository. If a vector looks wrong, that is a finding
   about this crate or about the reading of the reference, and the old
   repository is where to check it.
3. **Bulk groups record digests; curated groups record bytes.** AK and BK
   carry sha256 of any value wider than 64 bytes and never a sidecar; every
   other group carries the bytes (`*.bin` sidecars over 64 bytes).
   `tests/kat.rs::artifact_policy_is_declared_by_the_generator_and_enforced_here`
   holds the split.

**How it is replayed.** `tests/kat.rs` dispatches every vector on its `source`
string to a handler, reads every field the vector carries (an unread field is
a failure, not a skip), and compares this crate's answer with the recorded
one. `tests/derive.rs` replays group F, `tests/mesh.rs` groups M and N,
`tests/txwire.rs` round-trips every group D wire image through the native
serializer. In this repository the group D handlers that called the C validators are compiled out; `reference_verdicts_native` round-trips every group D wire image through the native serializer, asserts the layout offsets the vector records, recomputes the two transaction digests, and marks the validator verdicts *not called* -- the crate has no transaction validator, and those recorded verdicts are what a node does. `derived_inputs_are_exactly_as_expected` holds the not-called set to exactly the five named vectors plus the group D vectors under the reference-only sources: 74 of 5,364.

## Invariants

Each is a property the code holds today and a test that would go red if it
stopped. Details, and what each mechanism does and does not reach, are in the
specification.

- **I1 -- a key signs once per store.** The raw signer is crate-private. The
  two public routes to a signature are `Keystore::sign_spend`, which consumes
  an `AdvanceReceipt` minted only after the advanced index is durable, and
  `Keystore::resign_reserved`, which takes no receipt and no digest -- both
  come from the pending record, so it can only reproduce the signature already
  released. WOTS+ is deterministic, so those bytes are identical.
- **I2 -- the index is durable before the signature is released.**
- **I3 -- spend state moves atomically:** index, generation, pending record and
  the retained settled block change in one temp-write, fsync, rename, fsync.
- **I4 -- startup reconciles against the chain and fails closed.** `Wallet::open`
  is the only constructor.
- **I5 -- restore derives the index from the chain, never from zero.**
- **I6 -- key material never leaves the process readable:** zeroized on drop,
  redacted `Debug`, encrypted at rest under Argon2id + ChaCha20-Poly1305.
- **I7 -- no self-referential C transaction struct is ever a Rust value.** In
  this crate the transaction is `tx::wire::Transaction`, plain Rust with a
  serializer at the boundary; I7 is satisfied by construction.
- **I8 -- an imported account keeps a path back to its key material** and its
  first key is verified against the root.

### What holds this document to the code

`tests/invariants.rs::documented_counts_match_the_artifacts` reads this file
and `crates/mochimo-crypto/Cargo.toml` and refuses a figure that disagrees
with the artifact it describes: the vector totals against `fixtures/`, the
corpus table row by row, and -- the arm with no artifact behind it -- any
number written in front of the phrase `cfg` sites. There are none to count,
so a count appearing there would be a claim about a feature this crate does
not have.

That phrase is written out here deliberately, and this paragraph is its
anchor. The check refuses to pass if the phrase occurs nowhere in either
file, because a needle that matches nothing is a tripwire that has been
stepped over rather than one that holds; keeping the phrase in a sentence
*about the check* means no edit to the prose elsewhere can quietly retire the
arm. Leave the phrase in place when rewriting around it.

## The board

`cargo test --workspace --no-fail-fast` is **green** in this repository since
S6, and it is green by name: every row that runs passes, and the one row that
was red from the S1 re-gate to S5 -- `invariants::group_e_constants_stay_anchored`,
the census that demands every group E constant be compared by a checker
that runs -- carries a declared exclusion for the 33rd constant, `sizeof_TX`,
as the check's own data. That constant is the size of the node's network
packet container (65,664 bytes); this wallet never builds or reads such a
packet -- it speaks to the Mesh over HTTP, and the node's own framing is the
specification's open item -- and the two ways to pin the number here, a
literal transcribed from the fixture or an expression transcribed from the
reference's `types.h`, both compare the fixture to itself. The operator
decided on 2026-09-14 that the packet size is not this wallet's to pin; the
row names the constant and carries that reason, the failure message prints
it, and two guards hold the row honest (a name the fixture does not carry is
refused as a permit for nothing; a name the checker compares after all is
refused as a lie). `kat::group_e_constants_match_the_reference` is unchanged:
it compares the 32 it can.

The three debt markers the old repository carried red (a live node for group
E's framing, a capture at submit time for Mesh authorship, an upstream header
for `valid_op`) are still not carried, because their conditions live outside
any repository and a permanently red row destroys the exit code as a signal.
Their home is this section and the specification's *Open items* table. Green
on a row means the check that runs passes; it does not mean those conditions
were met. **Check by name, not by count.**

And **the total is summed, never carried.** Where this section writes one it is
the sum of that run's own result lines -- seventeen of them today, one per
target -- added up from the run being reported. It is never the previous
session's figure with this session's deltas added to it, and that arithmetic is
why the number has been wrong three times: S15 wrote 367 where the board said
369, S16 corrected it, and S17 wrote 372 where the board said 374, corrected at
S18. Each time the per-target line in the same paragraph was right in every
figure, and each time the total was short by exactly two. **No check reads the
total** -- `documented_counts_match_the_artifacts` walks this file for vector
counts and `cfg` site counts and never for the board, and nothing else in the
tree names it -- so a person adding the line up is the only check there will
ever be. S16 wrote that last observation in its commit message, where no later
session looks; it is here now for the reason it recurred.

The board on commit `7b7d1a7`, cargo's exit read from its own process: exit 0,
**374 passed** -- summed from its own seventeen result lines -- 0 failed, 0
ignored, 17 result lines, 4 m 44 s on a warm `target/`. **The commit is named
by its hash rather than pointed at, because a commit cannot contain its own
hash**: every version of this sentence that said *this commit* was true when it
was written and false at the next commit, and correcting anything in this
paragraph is always a documents-only commit, so the pointer broke itself twice
-- S16 left S15's stale, S17 rewrote it, S18 falsified it again over one digit.
A reader further along runs `git diff 7b7d1a7` and, if nothing outside the
documents moved, these figures are still theirs. S17's own commit `da9b789`
boarded the same seventeen, at S17 and again at S18, and the 5 m 04 s S17's
paragraph recorded belongs to the run immediately before that one, on the same
content with these figures not yet written in. The figure to compare
across sessions is the per-target one either way: HEAD `bbf8731` -- S16's
documents-only commit, whose board S15's paragraph still described -- was 369
in 4 m 42 s, re-derived at the start of this session, against S15's own
5 m 00 s for the same content. Per target: lib 43, cli 105, compile_fail 1,
derive 10, invariants 65, kat 18, keystore 33, mesh 12, mesh_http 10, miri 2,
net 3, recon 29, signing 17, spend 19, txwire 3, wots_internals 4,
doc-tests 0.
`lib` reports 43, not 41: S17's two parser tests over `discover`'s `--to`,
one per arm of a refusal that had been one string (Known-open 46). Each pins
its own arm's reason and the ABSENCE of the other's, which is the defect:
the S15 test asserted that the refusal happened, never that its prose fitted
the value, and passed while `--to 2000` was told about account index 0.
`cli` reports 105, not 103: S17's two. The first drives `resign` over a
reservation the chain has already moved past -- the state a mainnet run
reached by running `resign` after a `send` that worked -- and holds the page
that replaced I4's divergence there: it names `settle`, names both
positions, says what the observation did NOT establish, and carries none of
the three needles quoted from the page it replaced (Known-open 45). The
second is its pair: `send` over the same chain state, which must still refuse
as a divergence and must never reach the landed page.
`spend` reports 19, not 18: S17's one -- the planner still calls a chain
standing at the change address `ChainAddressMismatch`, which is the test that
goes red if the landed-spend refusal is ever moved down into `SpendPlan::new`
where `send` would inherit it. It is also the only one of the three that
catches that move, `send` being refused by the wallet gate before the planner
is reached; the fault matrix says so by name.
`lib` reported 41 at S15, not 40: S15's parser test over `discover`'s `--to`.
`cli` reported 103 at S15, not 99: S15's four -- three `discover` pages in process
(the sweep with its extent and its held marker, a clean sweep finding
nothing beside an unreachable node, and a masterless store refused before
any call) and one pty test driving the verb through the shipped binary.
`recon` reports 29, not 27: S15's two. The first pins the recovery
ceiling at the extension's 10,000, and that the divergence window did not
move with it, walking no positions at all -- the value and the sentences a
failure at that value prints, the latter from a constructed failure rather
than a provoked one. The second is the test that can tell which way hazard
2 went (Known-open 43): it walks 72 derivations to find index 71 under a
local of 50, which the default diagnostic reaches and a ceiling of 20 does
not.
`lib` reported 40 at S13, not 33: S12's four parser tests over the destination list
(Known-open 37 and 38) and S13's three over the explorer verbs' arguments.
`spend` reported 18 at S15, not 12: S12's six, driven through `cli::run` over the
scripted chain. `cli` reported 99 at S13: S12's one pty test shipping three
destinations, and S13's six -- four pages in process, the empty and
no-indexer pair, and a pty test that drives `recent-transactions` through
the binary with the store directory absent. `mesh` reports 12, not 8:
S13's four over the explorer endpoints (the captured request bodies, the
two endpoints' two renderings, the captured block, and the cap and
field-by-field refusals).
`wots_internals` is the 17th result line, added at S8: four oracle-free
property tests over the native WOTS+ internals (Known-open 22), each
printing the count of inputs it tried in its evidence line and flooring
it. `lib` reported 33 at S10, not 29:
the unit tests for Known-open 15 and 14 (S6), the parser's three (S7) and
its `--ref` case (S10). `cli` reported 92 at S10, not 81: the `submit` verb's three
(S5); S7's -- three pty tests for item C, one for `address --account`, two
in-process tests for `address --account`, and the zero-reference pin for
the then-deferred 19(a); and S10's four for the reference flag -- the
offset twin of that pin, the parse-time refusals, `resign --ref`'s
reproduction and refusal, and one pty test shipping `--ref` through the
binary.
`keystore` reports 33, not 26: the five tests S6 added and the two message
pins of 19(b) and 19(c). `spend` reports 12, not 8: the two
key-access-per-account tests (S5, Known-open 28) and the reference rule's
table and corpus test (S10). `invariants` reports 65,
`group_e_constants_stay_anchored` among them with its exclusion printed in
its evidence line (S6, Known-open 23); the three checks S3
added and S4 widened (`no_comment_or_string_under_the_crate_cites_an_errata_entry_by_number`,
`no_comment_or_string_under_the_crate_cites_a_document_that_is_not_in_this_repository`
and `no_comment_or_string_under_the_crate_carries_a_phase_tag_or_a_row_name`)
walk the comment text and the string literals of every `.rs` file under
`src/`, `tests/`, `ui/` and `examples/` -- 83 files, about 17,400 comment
lines and 12,700 string lines at S8, floored; never `fixtures/`, never the pinned
`.stderr` files -- and hold the narrative to this repository;
`names_cited_in_src_resolve_to_a_fn_or_are_declared_matched_by_shape_not_by_path`,
red at S1, is green with its 24 dead citations corrected. `kat` reports 18,
not 16: `group_e_constants_match_the_reference` and
`constants_match_the_reference` were both gated on the dead feature although
neither body needed the C, and both are un-gated. The `cli` target's eighteen
`pty::` tests (this file said eight until S8 and twenty-one at S8, both
stale, and fifteen until S15; the count is what `cargo test -q -p mochimo-crypto --test cli --
--list | grep -c 'pty::'` prints, read at S9, at S10 and again at S15) build the shipped binary with `--features mesh-https` and drive
it under BSD `script(1)`; they need `cargo` on the path and a host whose
`script` accepts `-q /dev/null cmd args`, and they ran on this machine. The
`invariants` target's census spawns `cargo test --workspace --no-run` and the
sibling binaries, so it needs to be run by `cargo test`, never by invoking the
binary. `kat.rs` replays all 5,364 vectors twice in about 110 s in a debug
build; the whole board takes about five minutes. The shipped binary
builds with `--features mesh-https`, and the four clippy gates above exit 0 --
and since S2 those gates are what proves the strip is whole: a `cfg` site
naming the dead feature is an `unexpected_cfgs` error under `-D warnings`.

Ten fault-injection rows were declared and run against the replay at the plant
(a flipped wire byte, a moved recorded offset, a moved `tx_sz`, a flipped
transaction digest, a flipped RIPEMD-160 digest, a moved Base58 probe, a moved
return code, a removed verdict key, a stray key, and an unmutated control).
Twenty-two more were declared and run against the re-gated invariants at S1,
eleven declared at S2 (one withdrawn, named in place), eleven at S3
against the three comment walks and the comments-only proof that guarded the
rewrite (none withdrawn), ten at S4 against the widened walks, the
masked-token proof and its string audit (none withdrawn), and thirteen at S5
in three matrices, one per part -- the walks widened to `ui/` and
`examples/`, the per-account key-access fix reverted, the `submit` verb's
two checks dropped or reordered -- none withdrawn, and twenty-three at S6 in
eight matrices, one per part and item (the exclusion row removed and a
lying row added; each fix reverted; the captured image and the I3 recorder
unchanged), none withdrawn, and twenty-five at S7 in nine matrices, one
per item (each fix reverted, the two decided pages reverted, the
derivation index off by one and the write path made reachable for
`address --account`, the zero reference pinned), none withdrawn, and
seventeen at S8 in three matrices, one per part (each WOTS+ internal
mutated against the property that pins it, with the corpus replayed while
the checksum's add was made checked -- green, because the corpus never
leaves the domain -- and after every restore; the `create` change
reverted against both arms; the TLS binary built and the tree grepped
after the version bump), none withdrawn, and four at S9 in one matrix (a one-past-the-end read through `get_unchecked` reported as undefined behaviour; a signed overflow planted in `wots_checksum` firing the overflow check; the ordinary board unchanged after the two gates; the stated command green as the control), none withdrawn, and seven at
S10 in two matrices (the machine's UPPER_DASH made to accept an uppercase
letter and its ZERO state made to accept any byte, against the table; the
reference written one byte off in the serializer against the layout test;
`resign` ignoring the flag against the reproduction test; the unmutated
control; S7's zero pin; the corpus's two vectors through the
transcription), none withdrawn, and eight at S17 in three matrices, one per
part (the landed-spend refusal reverted, made to fire on a reservation that
has NOT landed, moved down into `SpendPlan::new` where `send` would inherit
it, stripped of the sentence saying what the observation did not establish,
and made to name `reconcile` again; the comparison-only scan scope widened to
the diagnostic one, declared GREEN in advance as a cost change nothing in this
tree times, and green; the two `--to` arms collapsed back to the one string;
the unmutated control over fourteen tests), none withdrawn; each matrix and
its verdicts are in that session's commit message. S17's guard carries S15's
`DID-NOT-RUN` verdict and two more: an empty observed set fails the row, and
the restore after every row is by content and digest-verified against the
pristine file.

**Miri, measured at S9 and re-measured at S11 (2026-09-14).** `cargo +nightly
miri test -p mochimo-crypto`, with `MIRIFLAGS` unset -- isolation on, no flag
recorded anywhere and none needed -- ran green in 2 h 57 m 16 s on this machine
(18:56:58 to 21:54:14, the control run; miri 0.1.0 (fd7ed57dfd 2026-08-29) on
nightly-aarch64-apple-darwin, 14 cores), exit 0 read from the process, inside
a declared three-hour budget by 2 m 44 s. The interpreter time it needs is
about 1 h 57 m: `derive` lost about an hour to CPU starvation on a desktop
that was doing other work, spending 1 h 43 m of wall on about 43 m of CPU,
sampled rather than assumed (its process gained 60.0 s of CPU in 60 s of wall
when measured directly, and `pmset -g therm` records no warning). `mesh`,
`miri`, `txwire` and `net` all came in within about 7 % of S9's figures, so
the machine is the one S9 measured on; the wall clock is what an operator on a
busy machine gets, and the CPU figure is what compares across sessions. The
same command took 4 h 40 m 39 s at S9 with its `lib` at 3 h 28 m; S11 gated
nine lib unit tests whose whole cost was WOTS+ key generation, and the next
paragraph says what that did and did not take away. What it covers, by target: `lib` (23 of the 33
unit tests -- ten gated, S9's one that writes a store and S11's nine --
40 m 54 s, against 3 h 28 m at S9); `derive` (7 tests: the embedded subset its file states, 11 vectors
with `F-address-widths`' three generations among them, and six in-memory
tests; 1 h 43 m 14 s of wall on about 43 m of CPU, against 41 m at S9); `mesh` (4 tests: the hex codec, the two parser totality
runs over the embedded group N capture, the request-body serialisation;
20 m 25 s); `miri` (2 tests: the native walk over every covered backend
function and the drop witness; 11 m 55 s); `net` (3 tests, the opcode range;
under a second); `txwire` (3 tests over the embedded group D subset; 45 s).
Gated `#[cfg(not(miri))]` whole, each with its reason in the file: `cli`,
`keystore`, `recon`, `spend` and `signing` write stores or drive the binary;
`invariants` and `compile_fail` read the tree and spawn cargo; `mesh_http`
opens sockets; `kat` reads the corpus from disk; `wots_internals` for
interpreter time alone. Libtest's "finished in" figure under Miri is the
interpreter's isolated virtual clock, not wall time -- a test that took 385 s
by `date` reported 1,442 s -- so every clock here is `date`'s. A WOTS+ key
generation costs about three minutes under the interpreter on this machine,
which is what made the lib the long pole and keeps the corpus unreachable.

**S11's nine gates, and the three slow tests it did not gate.** S11 timed all
32 lib tests that then compiled under Miri, each as its own `--exact` run: 32
of 32 green, 32 m 31 s wall at up to eight concurrent, 11,926 s summed. The
split has no middle -- every test that generates a WOTS+ key cost between 372
and 1,951 s, every test that does not cost between 0 and 63 s -- and
`Account::import` is two generations, `Account::derive` two, `two_accounts()`
four. The nine, with the seconds each cost alone: in `account`,
`debug_never_reveals_key_material` 372,
`advance_is_monotonic_and_overflow_is_an_error_not_a_wrap` 386,
`import_refuses_a_first_address_the_root_does_not_reproduce` 1,123,
`records_round_trip_both_kinds_in_crate` 1,127 and
`restore_refuses_a_record_that_disagrees_with_its_own_root` 1,323; in
`derive`, `debug_never_reveals_generator_state_or_secrets` 408; in
`keystore::format`, `encode_refuses_both_an_open_and_a_settled_block_in_one_record`
385, `known_answer_image_for_two_accounts` 1,515 and
`encode_refuses_the_pending_relation_the_parser_refuses` 1,906. Each carries
its reason at the test, naming what still covers it under the interpreter.
Three slow tests are **not** gated, and that is the rule's second clause:
`an_older_format_reports_unsupported_version_before_anything_else` (761 s) is
the sole payer of `good_image()`'s `OnceLock`, and so the only ungated route
by which `Account::import`, `Account::derive`, the encoder's happy path and
`Account::restore_from_record` stay interpreted at all;
`parser_refuses_each_malformation_with_the_right_variant` (1,951 s alone,
about 1,190 s once that `OnceLock` is filled) walks the largest byte-slicing
table in the crate and the truncation sweep; and
`mnemonic::passphrase_reaches_the_salt` (487 s) generates no key at all, its
time being three PBKDF2-HMAC-SHA512 runs at 2048 iterations -- a search for
key generation would never have found it, only the timed run did -- and it is
the one place under Miri where a non-empty passphrase reaches the salt, since
`tests/derive.rs`'s `F-from-phrase` passes the empty one and
`F-bip39-passphrase` is outside that file's Miri subset. The gates orphaned thirteen
test-module items under `cfg(miri)`; S14 gated all of them, and two imports
they orphaned in turn, so that build now emits **no** warning at all and no
summary line either -- cargo prints "generated N warnings" only when there
are some. `cargo miri` never printed them: the count is taken from a plain
nightly with the cfg forced, in a fresh target directory, which is the only
form that makes them visible:
`RUSTFLAGS="--cfg miri" CARGO_TARGET_DIR=/tmp/cfgmiri cargo +nightly test -p
mochimo-crypto --lib --no-run 2>&1 | grep -c '^warning'` -- 14 before S14
(thirteen and the summary), 0 after.

What Miri buys here, said plainly now that `src/` holds no `unsafe` (S2):
the `unsafe` inside the dependencies as this crate drives them -- `sha2`,
`sha3`, `ripemd`, `argon2`, `chacha20poly1305`, `zeroize`, `subtle` -- and
the crate's own arithmetic and indexing under the interpreter's overflow
and uninitialised-memory checks. That is a property of the paths walked,
not of the crate, which is why this was one measurement session and is not
a gate; `tests/miri.rs`'s header says the same in its own words. Two fault
rows at S9 showed the interpreter looking at the code that ran: a
one-past-the-end read through `get_unchecked`, on a slice whose stated
length lied by one so the debug precondition could not see it, was reported
as undefined behaviour; and a signed overflow planted in `wots_checksum`
fired the overflow check. Both reports are quoted in S9's commit message.

## Known-open

Recorded here rather than fixed; each is a session of its own. None is a
blocker for building or running the wallet.

**From the fork itself (Stage 1 stopped here; Stage 2 -- S1 and S2 -- closed items 1 to 6).**

1. **Closed at S2.** The dead `ffi-oracle` feature is stripped whole: the
   feature line, `backend/ffi.rs` (774 lines), `backend/unported.rs`, the
   TXENTRY handle and its `Debug`, `Drop` and hash selector in `tx.rs`, the
   C diagnostic-string bodies in `error.rs`, the bindings half of `consts`
   and its `CROSSCHECK` table, and every `cfg` attribute and `cfg!()` read
   that named it (41 in `src/`, 35 in `tests/`, 4 reads). Everything behind
   `cfg(not(...))` was the live code and is un-gated; three items behind
   `cfg(feature)` needed nothing the C provided and are un-gated rather than
   deleted (`kat.rs`'s `constants_match_the_reference` and
   `group_e_constants_match_the_reference`; see 20). `unsafe` occurs nowhere
   under `src/`, and the confinement scan's allow-list is empty.
2. **Closed at S1.** `tests/invariants.rs` runs under `#[cfg(not(miri))]`: 62
   tests. Of the 84 it carried, 37 were kept unchanged, 24 ported to a
   subject that exists here (a document in place of a submodule, a census in
   place of a text scan, a floor re-derived, an anchor on a vendored source
   dropped), and 23 deleted with the reference, the bindgen crate, the
   TXENTRY handle and the differential suite they were about; the drop
   witness `secret_bytes_are_gone_after_drop` moved in from `native.rs`. The three debt markers
   stay out (see The board). Two checks the re-gate brought back are red by
   finding: Known-open 20 and 21.
3. **Closed at S1.** `tests/native.rs`, `tests/layout.rs` and
   `tests/txentry.rs` are deleted. `tests/txentry_compile_fail.rs` was not
   what its name said -- 18 of its 22 cases are wallet properties (I1, I2,
   I3, I6, the account model, the keystore, the terminal) -- so it is renamed
   `tests/compile_fail.rs`, re-gated on `not(miri)`, and its four TXENTRY
   cases and their `ui/pass` twin are deleted. `proptest` left
   `[dev-dependencies]` with the differential suite.
4. **Closed at S1.** The pty module (8 tests, not 7) and the downstream probe
   run under `#[cfg(not(miri))]`; the `cli` target reports 78 and `signing`
   17.
5. **Closed at S2.** `src/backend/unported.rs` is deleted with item 1.
6. **Closed at S2**, two of three. `src/backend/mod.rs`'s module doc is
   rewritten (it described the seam between two backends); `src/cli/address.rs`
   says "the record's `first[64]`" rather than "format v2's". The third site,
   `src/mesh/http.rs:17-19`, was re-read and left: its sentence -- TLS is
   exercised by nothing in the board -- is still true (the pty tests build
   the TLS binary and never dial), and it describes no C configuration.

**In the wallet (found while the specification was written; verified, not fixed).**

7. **Closed at S7, by decision.** `address --account N` derives account N
   from the master the store holds and prints its destination and
   position-0 ledger address exactly as `address <tag>` does, says the
   account is NOT STORED, and writes nothing, reserves nothing and asks no
   node; a masterless store and an account the store already holds are
   refused. Funding that destination and then running `restore --account
   N` adds the account at the position the chain holds (0 for a first
   credit), under the same tag -- the loop the specification recorded as
   closed opens at that one place, read-only. Decided by the operator on
   2026-09-14 (the memo's option 3): no invariant moves, `Wallet::open`'s
   refusal on a never-funded account stays, and the route goes around it.
   The reason a store still cannot hold an unfunded second account is
   unchanged: the Mesh's not-found answer conflates never-funded with four
   other readings, and I4 fails closed on it. `tests/cli.rs` drives the
   loop end to end (derive, fund, restore, the tag equal) and the binary
   with the snapshot bytes identical across the call.
8. **Closed at S7, by decision.** A dead reservation has no route out, and
   this build offers none on purpose: the only route is a second signature
   under the reserved key, which I1 forbids, and its price would be the
   whole balance at that key. The page that reports a dead reservation now
   says so beside the price, in the specification's own words (the
   block-to-live subsection carries the same two sentences), where it said
   the route out was not decided. Decided by the operator on 2026-09-14
   (the memo's option 2); a `sweep` verb would be a second signer and needs
   a security argument this repository does not hold.
9. **Closed at S5.** `submit <artifact-hex>` writes a saved artifact -- the
   hex `send` printed -- to the socket as it is, through the same client path
   `send` and `resign` use, and prints the same `submitted:` block. It opens
   no store, asks no password, reserves and signs nothing and writes nothing
   to disk, so the emptied-account window (the Mesh reporting a just-emptied
   account as not found, `Wallet::open` refusing) no longer strands an
   operator holding a valid signed artifact. Layout is checked -- the bytes
   must parse and re-serialize byte for byte -- and nothing else is judged;
   the node validates. Two pty tests and one in-process test in
   `tests/cli.rs` hold it, the pty ones against the loopback ledger with the
   store locked or absent.
10. **The seed-derivation scheme is confirmed for one client only.** Five
    schemes exist across the reference clients and no two answer the same
    question; group F pins the browser extension's. A phrase created under
    another scheme restores nothing here and this program does not say so.
11. **Closed at S6.** `Keystore::add` recomputes a derived record's stream
    identity from the master seed the store holds -- it has held it since
    format version 3, which is what made the code's "add has no master
    seed" and the specification's "which the add path does not hold" stale
    -- and refuses a derived record whose tag or identity is not what its
    seed produces, by the names `sign_spend` uses, at the door. A store
    holding no master takes the stored value (nothing there can recompute
    it or sign for it) and `sign_spend`'s re-derivation, untouched, catches
    it the day a master is in hand. No signature changed: `add(account)`
    reads the master out of the store, so the two shipped callers and every
    test call site are as they were. The entry as it stood was wrong about
    the specification: I1's paragraph stated the asymmetry honestly; the
    code's doc bullet claimed recomputation for the incoming account
    without saying it held for one kind only. Both now say what the code
    does. Two tests in `tests/keystore.rs` hold both directions.
12. **Closed at S6.** `open`'s stat gate names the parser's range for
    `keystore image length` (112 to 12,779,632, not a minimum of 0);
    `Kdf::checked`'s ceiling refusal still reports a minimum of 8, now
    derived from Argon2's own `Params::MIN_M_COST` with the doc saying whose
    floor it is and which gate enforces it; and an `argon2::Params` refusal
    is mapped to the parameter it names -- `keystore kdf m_cost`, `t_cost`
    or `p_cost`, each with its own bounds and value -- so a `t_cost` of 0
    is no longer a memory error. Two tests in `tests/keystore.rs` pin the
    values the errors carry.
13. **Closed at S6.** `write_temp` unlinks an existing `accounts.mks.tmp`
    and creates its own (`create_new`, mode 0600) at the one place every
    write goes through, so a leftover's looser mode can no longer reach
    the snapshot through the rename, and neither `open` nor `create` has to
    remember. The recorded call sequence is unchanged. One test in
    `tests/keystore.rs` pre-creates a 0644 leftover, commits, and reads the
    snapshot back as 0600.
14. **Closed at S6.** Any error between `commit`'s `Ok` and the end of
    the in-memory application poisons the handle before it returns
    (`poison_on`, in `advance_committed` and `persist_settled`), the way
    `commit` poisons on its own errors; `persist_settled`'s silent
    `if let Some(slot)` became an error too. Unreachable from today's
    callers, so a unit test inside the module drives `advance_committed`
    with a target the encoder accepts and `advance_to` refuses: the next
    call answers Poisoned and a fresh open reads the generation the commit
    wrote. The I3 recorder's call sequence and the interruption proof are
    unchanged (fault rows R14, R15).
15. **Closed at S6.** `WotsIndex::advanced()`'s ceiling refusal names
    `u32::MAX` as the last position; a unit test pins the whole `Range` the
    error carries.
16. **Closed at S7.** `send`'s and `resign`'s block-to-live line and the
    reservation figures' line state the whole of the node's rule: it
    accepts the transaction only while the tip is at or below N and refuses
    it if N is below the tip when it arrives, or more than 256 blocks past
    it. The plan builder still takes no block number and no chain call was
    added to `send`; four `tests/cli.rs` needles moved with the text.
17. **Closed at S6.** `SpendAddresses::unverified` exists under
    `raw-backend` alone -- on for the test tree through the crate's
    dev-dependency on itself, never for a dependent, the way the raw
    signer is held -- and the wallet's one use (the resign path) goes
    through a crate-private constructor over addresses `address_at` just
    derived, so the type's doc is true for a wallet build. The compile-fail
    proof is in the downstream probe (`ui/downstream/src/fail.rs`, checked
    with default features by `tests/signing.rs`), which now pins three
    errors, not under `ui/fail`: trybuild inherits the test build's
    `raw-backend`, and a `ui/fail` case naming `unverified` compiles there
    (measured at S6 and deleted). The compile-fail census stays at 18.
18. **Closed at S6.** Every line it listed is corrected, the code being
    the authority: `sign.rs:1-2` and `keystore/mod.rs`'s "the one public
    route" name `resign_reserved` as the second; `format.rs`'s `Pending`
    doc says which commit writes each block and that `figures` is `None`
    for the version-3 read arm alone, carried forward by a settle;
    `AccountView::settled` says the encoder holds "never `Some` beside
    `pending`"; the Behind page says the reservation was written before
    format version 4 recorded figures; `mesh/mod.rs` says the middleware
    writes to a set of nodes; `mesh/spend.rs`'s sequence marks
    `check_spend` optional and skipped by the shipped path; `tx/wire.rs`
    says four 64-bit header fields and cites nothing for byte order;
    `recon.rs`'s restore doc lists the five failures; `wallet.rs`'s
    duplicated doc line is one; `tests/spend.rs`'s doc says an imported
    account spends from position 0 through its stored components.
19. **Closed at S10.** (b) `Error::Exists { what: "snapshot" }` and
    `create`'s pre-check page name the next step -- a different `--dir` for
    a new store, `restore --account N` to add an account to this one -- and
    say nothing was changed. (c) `WrongPassword` says it cannot tell a wrong
    password from a damaged file, by design, and what to try in order (the
    password, a backup, the phrase through `create --from-phrase` and
    `restore`); the variant is one on purpose and unchanged. (a) **closed
    at S10.** `--ref <text>` on `send` and `resign` sets `MDST::ref`, the
    destination's 16-byte reference field. The grammar is
    `mesh::spend::reference_is_valid`: the node's `mdst_val__reference`
    (`tx.c:510-573` at the corpus's pinned commit
    `bbbaceabe5c21b5d8a094cf34c050d28e4ae93f4`, the rules at
    `types.h:407-418`, refused as `EMCM_XTXREF` at `tx.c:626`) transcribed
    state for state, both files re-fetched from the public repository at
    that commit before it was written -- restating became admissible once
    the reference could be read at its pinned commit and the transcription
    pinned there without a node: at the function's own eight stated
    examples and two byte arrays, at seventeen more shapes those leave
    open, and at the corpus's two recorded values through the same function
    (`tests/spend.rs::the_reference_rule_is_the_references_own`,
    `the_corpus_reference_verdicts_are_the_transcriptions`). `SpendPlan::new`
    applies it as refusal 6, at the C's arm position, with
    `Error::InvalidReference { index }`; the parser applies it before any
    prompt and refuses as a usage error carrying the rule's words. Without
    the flag the field is sixteen zero bytes, and S7's pin still holds it
    byte for byte; `resign` needs the same `--ref`, and without it is
    refused as a different transaction by the digest check that already
    existed, the page naming the reference. Four tests in `tests/cli.rs`,
    one of them on a pty against the loopback ledger, and one in the lib.

**Found by the S1 re-gate; closed by the S2 strip.**

20. **Closed at S2.** `tests/kat.rs::group_e_constants_match_the_reference`
    is un-gated and runs; 32 of the 33 integers in group E's `constants`
    block are compared to the crate's literals. The 33rd is Known-open 23,
    closed at S6 by decision: `invariants::group_e_constants_stay_anchored`
    excludes it by name with the reason (see The board).
21. **Closed at S2.** Every one of the 24 dead citations under `src/` is
    corrected to the handler in `tests/kat.rs` that now holds the claim, or
    the sentence is removed where no test does; five went with
    `backend/ffi.rs`. Four of the removals name Known-open 22, because the
    claim has no holder.

**Found by the S2 strip (verified, not fixed).**

22. **Closed at S8.** `tests/wots_internals.rs` pins the four shapes with
    no oracle behind them, over inputs drawn from splitmix64 under constant
    seeds, each evidence line printing and flooring its count: that
    `gen_chain_counted` produces the bytes, the `adrs` and the count
    `gen_chain`'s loop does, over every `(start, steps)` in `0..18`
    squared, the edges where the `u32` sum wraps and pairs from the whole
    range (18,432 pairs over 48 seeds); that `wots_checksum` is total over
    `[i32; 64]` and its three digits are, on every input, the base-16
    digits of `Σ (15 − d[i]) mod 4096` taken over the integers -- the wrap
    is modulo 2^32, which 2^12 divides, so it never shows in the output,
    and what the wrapping buys is totality (20,010 inputs, 12,006 on which
    checked arithmetic would have panicked; the doc's claim that a `u32`
    accumulator would silently diverge was false and is withdrawn); that
    `wots_sign_counted`'s 67 counts equal `chain_lengths(msg)` chain by
    chain (320 messages, 21,440 chains); and that `chain_lengths` never
    yields a digit outside `0..=15` (200,517 messages, every single-byte
    fill and every one-bit message among them, 13,434,639 digits). No
    code in `native.rs` changed; its five doc sites name the test that
    pins each. The corpus replayed green while the checksum's add was made
    checked (S8's fault row 4), which is exactly the gap this entry
    recorded.
23. **Closed at S6, by decision.** `sizeof_TX`, the network packet
    container's size (65,664), is compared to nothing, and the census
    `invariants::group_e_constants_stay_anchored` now says so by name: a
    declared exclusion row carries the constant and the reason -- this wallet
    never builds or reads such a packet, it speaks to the Mesh over HTTP,
    the node's own framing is the specification's open item, and a literal
    transcribed from the fixture or an expression transcribed from the
    reference's `types.h` would compare the fixture to itself. The row is
    the check's own data, its reason is printed by the failure message and
    the evidence line, and two guards refuse a stale row (a name the fixture
    does not carry) and a lying row (a name the checker compares after all);
    a fault matrix drove both. The operator decided it on 2026-09-14. `kat::group_e_constants_match_the_reference`
    still compares 32 of 33, unchanged. The board is green by name from this
    commit on.

**Found by the S3 rewrite of the narrative under `src/`; 24 and 25 closed by
the S4 rewrite of the rest, 27 found by it and closed at S5.**

24. **Closed at S4.** `tests/` no longer carries the old repository's
    narrative: the 558 errata-entry citations by number (539 lines, 17
    files), the phase tags and bare `PN` labels, the review-round labels,
    and the three citations of `docs/errata.md` are gone. Per site the
    number was dropped where the sentence stands, the reason restated where
    it did not, or the sentence pointed at the specification or at this
    file; no entry was found to disagree with the code. `tests/cli.rs`'s
    child-process protocol markers are renamed `<<<CHILD ...>>>` on both
    sides. The three checks are widened: they walk comments *and* string
    literals under `src/` and `tests/` (never `fixtures/`, never `ui/`),
    the tag needle matches the wider `PN`, `PN-M`, `W1-N`, `H1`/`L1`/`V1`
    and `Q1-a` forms, and a fourth needle catches an old fault-matrix row
    name in a comment run that also says *matrix* or *row*. That widening
    is the one code change of S4 and is confined to the checks' block at
    the end of `tests/invariants.rs`; the masked-token proof holds every
    other changed file, and everything before that block, to S3's code.
25. **Closed at S4.** Every string literal under `src/` that cited an
    errata entry, `docs/errata.md`, a phase tag or `super::ffi` is reworded
    in place: the operator pages in `cli/mod.rs`, the messages in
    `error.rs` and `recon.rs`, the test messages in `keystore/format.rs`,
    and `backend/native.rs:105`, which now points at the function's own doc
    comment. One test needle moved with its message
    (`tests/keystore.rs`, on the message that says a store is never
    rewritten in place); the page prefixes `tests/cli.rs` asserts on were
    left intact by the rewording. The widened walks see string literals,
    so the class cannot come back unseen.
26. **Closed at S6.** `src/account.rs`'s sentence says the trailer is an
    AEAD tag under the store key -- authenticity for whoever holds the
    password and nothing for whoever does not -- so a party that could
    forge the fields could already replace the root, and the re-checks at
    `add` and at signing time are what stop a forged record from being
    acted on. The `Cargo.toml` comment that described the `mesh_probe`
    example now sits above `[[example]]`, and a true comment about the
    shipped binary sits above `[[bin]]`.
27. **Closed at S5.** The 35 comment lines under `crates/mochimo-crypto/ui/`
    and `examples/` that cited the old repository (23 errata entries by
    number, 11 phase labels, 3 citations of `docs/invariants.md`, in 20 of
    the 24 `.rs` files) are rewritten line for line, so no file's line count
    moved and no pinned `.stderr` changed; the compile-fail partition is
    green as pinned. The three walks take `ui/**/*.rs` and `examples/` as
    their third and fourth root -- never the `.stderr` files, which are
    compiler output, and never `ui/downstream/target` -- with the floors
    re-derived from the measurement (82 files, 16,799 comment lines in 2,550
    runs, 11,955 string lines; the files floor sits above the 58 the two
    old roots hold, so a walk that lost the new roots is red).

**Closed at S5, never in this list before: item B of the specification's
limits, and Known-open 9.**

28. **Closed at S5.** Key access was chosen per store, not per account:
    `src/cli/mod.rs`'s `key_access` took the master alone and answered one
    question -- does the store hold a master seed -- at its five call sites
    (`address`, `settle`, `send` twice, `resign`), so in a store holding
    both a master and an imported account the imported account was routed
    down the master path and refused with a key-access mismatch. Fail-closed,
    unreachable from the command line (there is no import verb), reachable
    by a library caller, and recorded in the specification under *Key access
    is chosen per store*. The helper now takes the store and the tag and
    asks `recon::access_for` -- the per-account choice `Wallet::open`,
    `status` and `reconcile` already made -- mapping its two refusals to the
    errors the pages already render. `tests/spend.rs` holds both directions
    on a store built with both kinds: the imported account signs from its
    stored root and the derived account still signs from the master; the
    first is red with the store-wide choice restored. `KeyAccess`, the
    `sign_spend` gate and every commit path are unchanged.

**Closed at S6, never in this list before: item D of the specification's
review.**

29. **Closed at S6.** `src/keystore/format.rs` said two WOTS+ generations
    cost "~1,070 s each under Miri (measured)" and, elsewhere, "roughly
    three hundred seconds" for one; the first figure was known wrong when
    written (the old repository measured about 1,429 s for the pair) and
    Miri has not been run in this repository. Both comments now say the
    cost is minutes, measured in the old repository and not re-derived
    here. Re-measured at S9: about three minutes per WOTS+ generation
    under the interpreter on this machine, and the two comments' "not
    re-derived here" is now the stale half (Known-open 34).

**Closed at S7, never in this list before: item C of the specification's
review, the argv and prompt defects.**

30. **Closed at S7.** Three defects of the command line's parsing and
    prompting: `-h`, `--help` or `help` anywhere in argv won over the
    command, so a help spelling in a tag or amount position printed the help
    and exited 0 (help is now recognised where a verb or a global flag is
    and is an unexpected token anywhere else); a repeated global flag was
    accepted silently with the last one winning while the tail flags took
    the first (a flag given twice, global or tail, is now a usage error
    naming it); and Ctrl-D at a prompt read as an empty answer, so end of
    input at the password prompt was reported as a wrong password (zero
    bytes read is now refused in the prompt's own words before anything is
    compared: exit 2 at the password prompt, exit 3 inside `create`). The
    parser has its own unit tests since S7 (`cli::args::tests`), and three
    pty tests drive the binary; the end-of-file test delivers one 0x04
    byte into the pty and reads the refusal back.
31. **Closed at S8.** Every refusal `create` returns before the store is
    written ends "Nothing was created.": one appender in `src/cli/create.rs`
    (`nothing_was_created`) sits behind every arm of `orchestrate` that
    returns before the write and behind the two terminal reads inside
    `read_new_password`, and the binary's `acquire_terminal` no longer
    appends the sentence itself, so no caller can drop it and none can
    double it. The occupied-directory page still says nothing was shown
    and nothing was changed, and then the sentence; the floor and the
    mismatch texts are as they were. The pty end-of-input test's `create`
    arm asserts the sentence beside the absent directory, the in-process
    no-terminal test asserts it through the seam, and the specification's
    prompt section says "every one of them ends" where it said "most of
    them say".

**Reduced or recorded at S8, never in this list before: item E of the
specification's review, decided, and item F, the standing condition for a
tag.**

32. **Item E: the version done, the license decided, the README present;
    the tag waits for F.** The crate is `version = "0.1.0"` with `publish =
    false` kept, since S8; the one reader of the version is the transport's
    user agent (`mochimo-rs/0.1.0`), the binary reports none, and no test
    carried the literal. The license is the **Mochimo Cryptocurrency Engine
    License Agreement, version 1.0**, decided by the operator on 2026-09-14
    for a derivative work of Mochimo and present since S10b: its text is
    the root `LICENSE.md`, copied byte for byte from the supplied file
    (sha256 `f958e87e09453252d1eedecd3da93c0d89140ab0420635ac56817442f39dbd17`,
    26,325 bytes), Exhibit B not attached; the workspace declares
    `license-file = "LICENSE.md"` and the crate inherits it, and the `MIT`
    declaration that stood from the fork to S10 is gone. The README's
    *License* section names it and carries the Exhibit A notice. No check
    reads the license field or the root file list. A `README.md` exists
    since pull request #1 (`a6c4772`, Jared Stone, merged by the operator
    as `945e402` after S9): the operator's document at its own level of
    detail, not the specification's, held to HEAD at S10 sentence by
    sentence. No check walks it -- the three narrative walks are
    crate-scoped and the README is at the root -- and nothing in this file
    claims otherwise. What remains of E: **nothing**. `v0.1.0` waited for
    item F, item F was met on 2026-09-15, and the tag is placed at S17 on
    the commit that carries the two defects that run found.
33. **Closed on 2026-09-15.** Item F's condition was *`restore` has
    reproduced a funded account from the phrase alone, and `reconcile` has
    caught a store up after a spend it did not make*. Both halves were run
    on mainnet by the operator at a terminal that day, between blocks
    **1,086,967 and 1,086,987**, and both pages were read at the
    terminal and recorded verbatim as they were printed. `restore --account 0` against a store built by
    `create --from-phrase` reproduced the funded account's destination
    character for character and reported `index 0 (from the chain, never
    assumed)` with its balance; `reconcile <tag> --advance-to 1`, after a
    second store on the same seed had spent, printed the whole store's
    divergence report and advanced only after re-deriving index 1 and
    comparing it to the chain. **Six commands ran live for the first time**
    -- `restore`, `discover`, `transaction`, `recent-transactions`, `block`
    and `blocks` -- and every other verb ran beside them.

    Three results no fixture could have produced. **A transaction this
    crate built was accepted by mainnet** -- three of them, in blocks
    1086977, 1086984 and 1086986 -- and **the id the crate computed locally
    is the id the chain holds**. **`resign` reproduced 2,408 byte-identical
    bytes across two processes**, identical sha256, zero differing
    positions, the 2,144-byte signature region included: I1's second route
    witnessed rather than argued from determinism. **The key chain walked
    one position per spend**, each spend's source being its predecessor's
    change, read out of the three artifacts' own wire bytes.

    The run also found the two defects this session fixes (Known-open 45
    and 46) and one observation the specification now carries (the two
    endpoints disagree on timestamp as well). `address --account N` (S7,
    Known-open 7) is what made the exercise possible: it derives a
    destination for an account the store does not hold, and
    `restore --account N` adds the account once the chain has credited it.

**Found by the S9 Miri measurement (recorded, not fixed).**

34. **Closed at S10.** `src/keystore/format.rs`'s two comments on the cost
    of a WOTS+ generation under Miri said it was "not re-derived here";
    since S9 it is, about three minutes a generation under the interpreter
    on this machine (the `miri` target's two walks, four
    generation-equivalents, in 11 m 28 s; the unit tests that build
    accounts at 6 to 30 minutes each), and both comments now say so. They
    were outside S9's scope by its own list; S10 corrected them with its
    documents.
35. **Closed at S11.** The stated command was a 4 h 40 m run, more than two
    hours of it WOTS+ key generation inside lib unit tests, over primitives
    `tests/miri.rs` walks once and a derivation composition `tests/derive.rs`
    walks once. S11 measured every lib test that compiled under Miri -- 32 of
    them, one `--exact` run each, 32 green in 32 m 31 s at up to eight
    concurrent -- and gated the nine whose whole cost was that generation,
    each with its reason at the test naming what still covers it. The `lib`
    target is 40 m 54 s, against 3 h 28 m at S9, which is the whole of what this entry asked for. The
    command end to end measured 2 h 57 m 16 s rather than the under-two-hours the
    entry projected, and the difference is not the gates: `derive` was starved
    of CPU on a busy desktop and spent 1 h 43 m of wall on about 43 m of CPU,
    while every target S11 did not touch came in within about 7 % of S9's
    figures. The interpreter time the command needs is about 1 h 57 m. Three slow tests were left ungated
    because what they drive nothing else walks under the interpreter, and one
    of those is a test this entry did not know existed:
    `mnemonic::passphrase_reaches_the_salt` generates no key at all and spends
    487 s in three PBKDF2-HMAC-SHA512 runs, which is why the session measured
    instead of grepping. The board is unchanged, a `not(miri)` gate being
    invisible to `cargo test`; the per-target figures, the nine names and the
    three exceptions are in *The board*'s Miri paragraphs above.

**Found while the README was held to HEAD at S10 (recorded, not fixed).**

36. **Closed at S11, and not as this entry proposed.** Reading all three
    sentences together with the program that renders them settles it: they do
    not count the same thing, and both counts are right. Three is the number
    of states the endpoint has -- no ledger entry for the tag, a zero balance
    the quorum discards, a failed lookup. Five is the number of readings an
    operator has to rule out, because never funded, the wrong chain and the
    wrong seed all reach the first of those states. `recon.rs`'s two reports
    say exactly that already: each prints the three, then tells the operator
    that a tag which should have funds means the wallet is pointed at the
    wrong chain or the seed is not the one that made it. So keeping the five,
    as this entry recommended, would have put the specification at odds with
    its own program and with the Mesh section's other "all three". Each of
    the three sentences now says which it counts and points at the other, and
    the README's sentence carries the two readings its list did not.

**Added at S12 (the operator's feature decisions of 2026-09-14), both closed.**

37. **Closed at S12.** `send` and `resign` take **1 to 256 destinations**.
    The planner always did (`SpendPlan::new` takes a list and charges
    `MFEE x count`); the command line built a one-element list at one site.
    Two exclusive forms: positional `<to> <amount>` pairs, and
    `--destinations <path>`, a file whose non-empty lines are
    `<to> <amount> [<ref>]` with `#` starting a comment. Pairs rather than a
    repeated `--to`, because a repeated flag is a usage error everywhere else
    in this parser. `--ref` names one destination's reference and is taken
    only with a single destination; with several the file's third column
    gives one per line. `--fee` stays a **total** and defaults to `MFEE x N`,
    the node's own floor, so one destination is unchanged at 500. Two
    destinations sharing a tag are a usage error before any prompt -- the
    node accepts them, and the specification says byte-identical duplicates
    are legal, so the refusal is deliberately **not** in `SpendPlan`, whose
    rules are the node's and nothing else; one tag twice in one spend is
    almost always a mistyped payee and the money does not come back. The page
    lists every destination with its amount and reference, the count, the fee
    beside the floor it clears, the change and the block-to-live, read off
    the plan rather than off argv so it cannot disagree with the bytes.
    `resign` takes the same syntax and reproduces byte for byte; a list
    retyped in another ORDER also reproduces, because the planner sorts by
    the 44-byte image before laying out (`EMCM_TXMDSTSORT`'s own order), so
    the bytes are identical and it is the same transaction -- the session's
    prescribed "reorder refused" test was not built and the reproduction is
    pinned instead. Six tests in `tests/spend.rs`, one pty test in
    `tests/cli.rs`, four parser tests in the lib.
38. **Closed at S12.** `send <tag> <to> all` sends the whole balance less the
    fee. The amount is read from the **same** ledger observation the plan is
    built against -- `cmd_send` unrolls `Wallet::plan`'s own three public
    calls rather than calling it, so there is one `resolve_tag` and no more,
    and a balance that moved between two reads cannot leave a non-zero change
    where the operator asked for none. One destination only; `all` with pairs
    or a file is a usage error. The page says the account will be emptied,
    that the change is zero, and what that costs in the specification's own
    words: the Mesh reports a tag at zero balance as *account not found*, so
    the gated verbs refuse until it is paid again and `submit` is the route
    to the socket meanwhile. That notice is printed for **any** zero change,
    not only the keyword, since an operator who typed `balance - fee` by hand
    reaches the same state. `resign ... all` reproduces while the balance
    stands and is refused as a different transaction if it moved, which is
    correct: the reserved bytes encode the old amount.

**Added at S13 (the operator's feature decisions of 2026-09-14), all four closed.**

39. **Closed at S13.** `transaction <hash>` reads `/search/transactions` by
    hash and prints the block it sits in, the timestamp, every operation with
    its type, address, amount in nanoMCM and MCM and memo, then the metadata
    in the endpoint's own spelling. It opens no store and asks no password.
40. **Closed at S13.** `recent-transactions <tag> [--count N]` reads
    `/search/transactions` by account. No `offset` is sent: the rows come
    back `ORDER BY bm.block_height DESC, tm.id DESC` (`indexer/search.go:70`
    at the Mesh commit the corpus pins), so offset 0 already names the
    newest. The address sent is the 20-byte tag, which is what the indexer
    matches (`:44-57`). One row per transaction with the direction as the tag
    sees it; a tag with no history is an empty table and exit 0, and a
    deployment with no indexer is exit 3 carrying the endpoint's own internal
    error (`search_handler.go:114-118`).
41. **Closed at S13.** `block <number | hash>` reads `/block`. Its "moved"
    figure is every `DESTINATION_TRANSFER` of every non-reward transaction --
    on this endpoint a source is debited its net and the change is not an
    operation, so that is exactly value delivered to payees. The reward is
    excluded and printed on its own line, being newly minted rather than
    moved, and the fee likewise. **`block 0` is refused**: `getBlock` routes
    by number only when `Index != 0` (`block_handler.go:56-80`), so index 0
    is served as the *current* block and genesis is unreachable by number
    through this endpoint at all.
42. **Closed at S13.** `blocks [--count N]` reads the tip from
    `/network/status` and then one `/block` per row. `--count` runs
    `1..=100` for both verbs that take it and defaults to 5; the ceiling is
    the endpoint's, not a taste: `searchTransactionsHandler` takes a limit
    only inside that window and otherwise leaves its own default of ten
    **without clamping and without saying so** (`search_handler.go:71-74`),
    so a count it would ignore is refused before any socket is opened.

    The four share one rule the pages state: **each names the endpoint it
    read**. `/block` re-parses the wire and shows a source's NET debit with
    no change operation; `/search/transactions` replays indexer rows and
    shows the GROSS debit with the change as its own destination, and its
    metadata values are JSON numbers where `/block`'s are decimal strings.
    Both are correct and nothing reconciles them. Two of the five request
    shapes have no group N vector -- a search by account, and a block by
    hash -- and are pinned only by that Go source; no fixture was added.

    Two false positives the invariants caught, both fixed by renaming rather
    than by allow-listing, because the scans are name-based by design and an
    exemption would have hidden a real one: a `Command::Transaction` variant
    put `tx::wire::Transaction`'s identifier into `Command`'s token stream
    and made `args::parse` read as returning a signature-bearing type (it is
    `LookupTransaction` now), and a local named `sign` in an amount
    formatter put it in the I1 taint set, whose fixpoint includes
    `wots.rs::sign` (it is `minus` now). Each carries its reason at the site.

**Added at S15 (the operator's decisions of 2026-09-15), both closed.**

43. **Closed at S15.** `recon::RECOVERY_CEILING` is **10,000**, not BIP-44's
    20. The two are not the same quantity: BIP-44's 20 is a gap limit over
    *unused addresses*, and this bounds *how many spends an account has
    already made* before a phrase alone cannot recover it -- a quantity
    BIP-44 does not have, so the inheritance was of a number and not of a
    subject. 10,000 is taken from the only other implementation of this
    protocol, whose users' funds a phrase restored here has to reach: the
    shipped browser extension walks `0..10000` over the same key positions
    in `MasterSeed.deriveWotsIndexFromWotsAddrHash` (`MasterSeed.ts:161-187`
    at the extension commit pinned above). At 20, an account spent from 25
    times restored as `NoIndexReproducesTheAddress`, which names three
    causes and prefers none -- correct, and it meant the operator was never
    told the ceiling was the likely one.

    `DIVERGENCE_WINDOW` keeps its 20, which is the borrowing that fits: a
    window is a neighbourhood to look past, which is BIP-44's shape. The two
    constants no longer coincide, so the module doc's claim that they are
    two quantities is now observable rather than asserted, and a test pins
    that they differ.

    **The diagnostic's ceiling follows the recovery ceiling**, decided
    rather than inherited: pinning it at 20 would have `Wallet::open` report
    `Unlocated` -- three causes, a foreign seed and a foreign chain among
    them -- for an account this wallet's own `restore` had just placed at
    5,000, and would describe I4's two-instance case, a second wallet
    hundreds of keys ahead, as three causes with the true one missing rather
    than as `Ahead { gap }`. It is a change on the startup path and it is
    confined to the failing half: an account that reconciles walks nothing,
    a disagreement inside the window is found in at most 41 derivations
    wherever the account sits, and only a divergence larger than the window
    pays -- up to a full exhaustion, about 16 s in a release build, per
    diverged account, on a startup that refuses either way.

    **The cost is a debug-build number and it governed the whole session.**
    One derivation is 1.58 ms in a release build and **44.4 ms** in the
    debug profile `cargo test` builds (measured at S15 on this machine, 300
    and 60 samples), so one exhausted walk is 15.8 s for an operator and
    **7 m 24 s** on the board, and the one-restore-per-position loops are
    `n(n+1)/2` of them -- 616 hours at 10,000. **No test in this tree walks
    the default ceiling.** Seven sites that did were given explicit
    ceilings, each with its reason at the site: `tests/recon.rs`'s
    stop-on-match loop, its never-zero case (3), its boundary test, its
    far-along-ceiling test, and the alien arm of
    `the_wallet_refuses_to_open_on_every_unreconcilable_account`;
    `tests/invariants.rs`'s I5 proof and the alien arm of its I4 proof. Two
    of those -- the two alien arms -- go through `reconcile_account_with`
    rather than `Wallet::open`, which takes no scope: the classification is
    driven where a ceiling can be named, `open`'s refusal is driven by the
    four and five other arms beside them, and **the composition, `open`
    reaching an `Unlocated` end to end, is no longer driven anywhere**.
    That, and the absence of any ten-thousand-position walk (a silent clamp
    inside the walk would pass), are the two stated costs.

    Four tests changed *meaning* rather than cost, all of them the raise
    working: `status <tag>` and `restore --account 0` with no `--scan-to`
    against a chain at index 30 now find it where they reported it out of
    reach, on the pty as in process, and the startup page names
    `--advance-to 30` where it named the wider search. Each keeps its old
    rendering at `--scan-to 19` -- a ceiling of 20, which is what the
    default was -- and gains a case pinning the new one.
44. **Closed at S15.** `discover [--to <N>]` derives the tags of accounts
    `0..=N` from the master the store holds, resolves each against the node
    at one `/call` per index, and prints what the node said for every index
    **and the extent it searched**, every time. `N` defaults to 64 and runs
    1 to 1,024. It opens the store (the master is in it) and constructs no
    wallet, so it runs where `Wallet::open` refuses; it writes nothing, and
    the store is borrowed immutably so a write is a compile error as well as
    a test failure.

    **It never asserts that an account does not exist**, which is the whole
    verb. Code 4 conflates three states the endpoint does not distinguish,
    and the first has three readings of its own, so the page reports *the
    node did not resolve these indices* and stops there; a test asserts the
    page carries the extent and does not carry `does not exist`. That is
    also why 64 is defensible -- not as the right number of accounts to look
    for, but because the number searched is printed and `--to` changes it.
    Accounts the store already holds are shown and marked, including one the
    node does not resolve, which is the emptied-account window and the one
    row an operator most needs. A sweep that resolves nothing is exit 0; a
    node that cannot be reached is exit 3 and the page then reports **no**
    extent for what it never asked about, because a partial sweep printed as
    a whole one asserts absence by omission. The 1,024 ceiling is this
    program's own and the refusal says so: each index is one call, and an
    unbounded `--to` puts thousands of round trips behind a typo. Three
    in-process tests and one pty test in `tests/cli.rs`, one parser test in
    the lib. No fixture was added and `fixtures/` was not touched: the verb
    composes `derive_account_tag` with `resolve_tag`, both already covered.

    The pty loopback now splices the asked-for tag into the address it
    answers. `discover` is the first verb to ask about more than one tag and
    the codec checks that a resolved address begins with the tag asked
    about, so a fixed answer made every index after the first a parse
    failure; the splice changes nothing for the tests that came before,
    which ask about one tag whose address already begins with it.

**Found by the live mainnet run of 2026-09-15 (item F); both closed at S17. Neither was
reachable by any test on the board, and the reason is the same for both: the
board scripts the states a verb is *for*, and these are the states an operator
walks into by mistake.**

45. **Closed at S17.** `resign` misdiagnosed a spend that had already
    settled. `Wallet::resign_pending` rebuilds the reserved plan through
    `SpendPlan::new`, whose opening guard refuses when the chain's address
    is not the source being laid out against; on this path the source is
    the **reserved** key, so once the reserved spend lands the chain
    necessarily stands at the change key and the guard necessarily fires.
    What the operator got was `ChainAddressMismatch`'s page -- I4's
    divergence, three causes with three remedies, *do not advance the index
    by hand; reconcile*. **None of the three applied**: the spend had
    settled, and the right verb was `settle`, which handled the identical
    state one command later in a single line. It fires on what is probably
    the commonest mistaken route to the verb, running it after a `send`
    that worked, and it is a wrong page on a recovery path -- diagnostic,
    never fund-losing, since nothing was reserved, signed or written.

    The guard is **right for `send` and is untouched there**: the planner's
    rules are the node's and nothing else, which is the argument S12 used
    when it put the duplicate-destination refusal in the parser rather than
    beside them. A refusal about this wallet's reservation state is not the
    node's rule. So the fix is in `resign`'s own path: when the guard
    refuses, the state is put to `recon::reconcile_account_with` -- the
    classifier `settle_if_landed` already acts on, so the crate holds one
    definition of a landed spend and not two -- under a scope that walks
    **nothing**, because the comparison that decides *landed* is scope-free
    and a divergence's report is not rendered here. Its `SpendLanded` becomes
    `Error::ReservationLanded { spent_index, settled_index }`; every other
    answer keeps the guard's own page.

    **The page does not trade one over-confident answer for another.** A
    change address follows the POSITION and not the transaction, so a chain
    standing at the reservation's change key is equally what a *different*
    spend from the same reserved key looks like. The page reports what was
    observed, names `settle` (which re-reads the chain and confirms), and
    says in its own words that the observation does not name which
    transaction put the chain there -- `transaction <hash>` on the id the
    original `send` printed is what does. That discipline is the one
    `recon`'s module doc records this module getting wrong once before.
    Two tests in `tests/cli.rs` (the landed page, and `send` unchanged over
    the same chain state) and one in `tests/spend.rs` (the planner still
    calls the change address a divergence -- the test that goes red if the
    refusal is ever moved down there).
46. **Closed at S17.** `discover --to` printed zero-specific advice for an
    above-ceiling value. One format string served both ends of the range,
    so `--to 2000` was told *"A sweep bounded at 0 searches only account
    index 0, which a store with a master already holds"* -- true of zero,
    nonsense about 2000, and read by an operator who had mistyped 2000 for
    200. Cosmetic: the refusal is correct, exits 1, and happens before any
    socket opens; only the tail was wrong. The arm is split in two. Zero
    keeps zero's reason (it searches the one index a store with a master
    already holds, and it is what an unexpanded shell variable produces);
    an above-ceiling value gets the ceiling's (every index is one call to
    the node) and is told to name a bound at or below 1,024. Both arms name
    the bounds and echo the value. The S15 parser test asserted that the
    refusal *happened*, never that its prose fitted the value, which is why
    it passed; there are two tests now, one per arm, each pinning its own
    reason and the absence of the other's.

**In the corpus (not editable; recorded).** Group C's `C7`-`C10` cite
`tx.c:268-270` where the composing statements are at 269-271; `C-base58-degenerate`'s
two prose halves name lines 144 and 145 for one fault; group F's
`F-ascii-control` note calls a round trip "not a simple high-bit drop" that its
own recorded probe shows is exactly one; `F-high-byte-seed`'s citation is off by
one; group N's `N-network-options` note says code 9 is never returned (two Mesh
handlers this wallet never calls return it); `group_hs_hash_sweep.json` declares
`artifacts: "whole"` explicitly while the other whole-artifact groups rely on the
default.

