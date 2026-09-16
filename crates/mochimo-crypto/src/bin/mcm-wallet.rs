//! `mcm-wallet` — the binary.
//!
//! Thin on purpose: parse argv, get the seed if the store needs one, build the
//! transport, hand off to [`mochimo_crypto::cli::run`], print, exit. Every
//! decision the program makes is in `src/cli/`, where the tests can drive it
//! against a scriptable chain.
//!
//! # Why this lives under `src/` and not in a crate of its own
//!
//! `crates/mochimo-crypto/src/bin/` is inside `crates/*/src`, which is **every
//! existing scan's domain**: the route scan, the panic census, the
//! Debug-holder scan and the endian scan all cover this file with no change to
//! any of them. A separate crate would sit outside several of them, and this
//! is the precedent for choosing a module over a crate.
//!
//! `required-features = ["mesh-https"]` follows the `[[example]] mesh_probe`
//! precedent: no test target links this binary's graph, because building it
//! drags in rustls and `ring`'s C, which the test and Miri configurations
//! keep out. The command layer is under `native` alone and the tests run
//! there. **The default board does build and execute this binary** --
//! `tests/cli.rs`'s pty harness spawns `cargo build --features mesh-https
//! --bin mcm-wallet` as a subprocess and drives the result under a
//! pseudo-terminal -- in the one configuration that compiles any C, `ring`'s,
//! and in a subprocess. This sentence said "the board never builds this
//! target" for a time, and the conclusion drawn from it was that what
//! the target adds over the tested code did not need testing. Both defects
//! found in this file were in that remainder.
//!
//! # Where the master seed comes from, and what that exposes
//!
//! **Out of the encrypted store, unlocked by a password prompt on the
//! controlling terminal**. Until then it was twenty-four words typed
//! on every invocation -- a decision working exactly as argued and
//! producing an interface nobody would use. The words are now what they are in
//! every other wallet: shown once at creation, written down, and the way back
//! in if the store is lost. They are not the login.
//!
//! **What that transfers, stated because it is a transfer and not a gain.**
//! Before this a stolen store file yielded every *imported* account outright --
//! the roots were in it in the clear -- and no derived account, the seed not
//! being in it. It now yields everything to whoever knows the password and
//! nothing to whoever does not, so password strength is part of the threat
//! model in a way it was not, which is why `cli::create::MIN_PASSWORD_LEN`
//! refuses rather than warns. This paragraph said the old file yielded
//! *nothing* for a session. The full argument is at
//! `keystore::crypt`'s head.
//!
//! The mnemonic prompt's rule survives almost intact: the crate still retains nothing
//! between calls, and the seed lives exactly as long as the handle that
//! decrypted it. What changed is where it comes from.
//!
//! The prompt itself was argued against the alternatives, all of which
//! leave the secret somewhere, and every one of those arguments applies to a
//! password unchanged:
//!
//! * **argv** — `ps` and `/proc/pid/cmdline` show it to the same user, and the
//!   shell writes it to history. At rest, and readable.
//! * **an environment variable** — `/proc/pid/environ`, every child process,
//!   and crash handlers; and it is normally set from a plaintext rc file, so
//!   it is at rest anyway.
//! * **a file** — plaintext at rest. This bullet argued, before encryption
//!   at rest, that such a path would create exactly the debt encryption
//!   existed to remove; encryption landed and the argument survives it
//!   **inverted**, which is why
//!   it is restated rather than struck. The store is now sealed under this
//!   password, so putting the password in a plaintext file hands back the
//!   whole of what the encryption bought — and it buys more than sealing
//!   the roots alone would have,
//!   because the body holds the master seed and the master derives *every*
//!   derived account, where an imported root is one account.
//!
//! What the prompt still exposes, stated rather than implied: the terminal
//! driver's input buffer, and this process's memory until the `Secret`
//! zeroizes — a core dump or an attached debugger inside that window sees it.
//! Neither is fixable here.
//!
//! **What exists before it becomes a `Secret`.**
//! `mnemonic::master_seed_from_phrase` takes a `&str`, so the read buffer is
//! this program's problem. It is a `Zeroizing<String>` with its capacity
//! reserved up front, because a `String` that grows reallocates and leaves the
//! old allocation holding the phrase, unzeroed, for the allocator to hand to
//! someone else.
//!
//! **Read from `/dev/tty`, not stdin**, so that a pipe or a redirect cannot
//! supply the seed silently — the point of choosing a prompt is that the seed
//! never comes from something that can be recorded.
//!
//! **The cost, accepted rather than overlooked:** not scriptable. `balance`
//! prompts, because `Wallet::open` refuses a derived account with no master —
//! "a refusal, not a skip" — so there is no read-only mode to exempt. Testnet
//! is where scripting demand appears, and it runs on a
//! throwaway seed by the ordering condition already recorded.

use std::io::{BufRead, BufReader, Write};

use mochimo_crypto::cli::create::{self as create_cmd, Terminal as _, ENTROPY_LEN};
use mochimo_crypto::cli::{self, args, Code};
use mochimo_crypto::keystore::Keystore;
use mochimo_crypto::mesh::http::UreqTransport;
use mochimo_crypto::mesh::{MeshClient, Transport};
use mochimo_crypto::{Error, TransportKind};
use zeroize::Zeroizing;

/// A 24-word BIP39 phrase is 24 × 8 + 23 ≈ 215 bytes; 512 covers every length
/// with room to spare, so the buffer never grows and never leaves a copy
/// behind.
const PHRASE_CAPACITY: usize = 512;

/// What a prompt says when the terminal reports end-of-file before a line
/// was typed. Zero bytes read is end of input, not an empty answer: it was
/// trimmed to an empty line and compared for a time, so Ctrl-D at the
/// password prompt was reported as a wrong password by the store rather than
/// as the input it was (AGENT.md, Known-open 30, closed at S7). Refused
/// here, before anything is compared, in the same class as "no terminal".
const END_OF_INPUT: &str =
    "end of input at the prompt: the terminal reported end-of-file (Ctrl-D) before a line was \
     typed, so nothing was read and nothing was compared. Type the answer and press Enter, or \
     run the command again.";

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let report = match run_from_argv(&argv) {
        Ok(r) => r,
        Err(usage) => {
            eprintln!("{usage}");
            std::process::exit(Code::Usage as i32);
        }
    };
    if report.code == Code::Ok {
        println!("{}", report.text);
    } else {
        eprintln!("{}", report.text);
    }
    std::process::exit(report.code as i32);
}

fn run_from_argv(argv: &[String]) -> Result<cli::Report, args::Usage> {
    let inv = match args::parse(argv)? {
        // Help is an outcome, not an error: it prints and exits 0.
        args::ParsedArgv::Help => {
            return Ok(cli::Report {
                text: args::HELP.to_string(),
                code: Code::Ok,
            })
        }
        args::ParsedArgv::Run(inv) => inv,
    };

    // **A supplied node is validated first, whatever the command**.
    // `UreqTransport::new` opens no socket -- it checks the scheme and the
    // authority and builds an agent -- so a URL this program cannot use is
    // refused before the password prompt and the key derivation, for all ten
    // verbs alike. Until this moved, `create --node <bad>` was accepted
    // silently (dispatched before the transport existed) and `address --node
    // <bad>` was refused AFTER Argon2id, for a command the help says needs no
    // node. The parser has already refused a reconciling command
    // with no `--node`, so `None` arrives only for the two that never dial and
    // becomes the refusing transport below; there is no command-awareness
    // here.
    let node = match &inv.node {
        Some(url) => match UreqTransport::new(url) {
            Ok(t) => Node::Named(t),
            Err(e) => {
                return Ok(cli::Report {
                    text: format!("cannot use node {url}: {e}"),
                    code: Code::StartupRefused,
                })
            }
        },
        None => Node::Absent,
    };

    // `create` is the one command with no store to open -- making one is the
    // point of it -- so it is dispatched before the open below.
    if let args::Command::Create { from_phrase } = inv.command {
        return Ok(run_create(&inv.dir, from_phrase));
    }
    // `submit` is the other command with no store to open: the artifact is
    // its input and the socket its only output, so it is dispatched before
    // the password prompt and the open below (AGENT.md, Known-open 9). The
    // parser still requires `--dir`, as it does for every verb; the
    // directory is not read, not created and not locked here.
    if let args::Command::Submit { artifact } = &inv.command {
        return Ok(cli::run_submit(&MeshClient::new(node), artifact));
    }

    // The four read-only verbs, on the same route and for the same reason:
    // the node is the whole input, so there is nothing to unlock. `--dir` is
    // parsed and not touched.
    if inv.command.opens_no_store() {
        return Ok(cli::run_explorer(&MeshClient::new(node), &inv.command));
    }

    // **The password, every command that opens a store**. It is not a
    // per-command decision beyond that: the file is encrypted, so nothing
    // -- not even the account list -- can be read without it. That is the
    // whole of the change, and the trade it rests on is at
    // `keystore::crypt`'s head.
    let password = match read_secret_line("password: ") {
        Ok(p) => p,
        Err(e) => {
            return Ok(cli::Report {
                text: e,
                code: Code::StartupRefused,
            })
        }
    };
    let nonce_seed = match os_bytes::<{ mochimo_crypto::keystore::NONCE_SEED_LEN }>() {
        Ok(b) => *b,
        Err(e) => {
            return Ok(cli::Report {
                text: e,
                code: Code::StartupRefused,
            })
        }
    };
    let store = match Keystore::open(
        std::path::Path::new(&inv.dir),
        &mochimo_crypto::keystore::Unlock {
            password: password.as_bytes(),
            nonce_seed,
        },
    ) {
        Ok(s) => s,
        Err(e) => {
            return Ok(cli::Report {
                text: format!("cannot open the keystore at {}: {e}", inv.dir),
                code: Code::StartupRefused,
            })
        }
    };

    Ok(cli::run(store, MeshClient::new(node), &inv.command))
}

/// The transport `cli::run` gets: a real one when `--node` was given, and
/// one that refuses every request when it was not.
///
/// `cli::run` takes a `MeshClient` for every command, including the two that
/// never use it, so an invocation with no node still has to hand one in.
/// This arm is what it hands in, and its `post` is unreachable for the two
/// commands allowed to omit the flag: `create` by construction (dispatched
/// before this exists, and `orchestrate` takes no client) and `address` by
/// measurement (`address_makes_no_request_at_all` counts the transport's
/// calls through a wrapper and finds none). That the arm itself never runs
/// is knowledge rather than a marker: a `[[bin]]`'s items are
/// not importable by any test target, so the pty subprocess is the only
/// thing that executes this type at all. If a later change made either
/// command dial, the operator meets a refusal naming the missing flag rather
/// than a request sent to nowhere -- the fail-closed direction, and the
/// reason this is an enum rather than a placeholder URL.
enum Node {
    Named(UreqTransport),
    Absent,
}

impl Transport for Node {
    fn post(&self, path: &str, body: &[u8]) -> mochimo_crypto::Result<Vec<u8>> {
        match self {
            Node::Named(t) => t.post(path, body),
            Node::Absent => Err(Error::Transport {
                op: "post with no --node given",
                kind: TransportKind::Other,
            }),
        }
    }
}

// `read_master` is gone. It prompted for twenty-four words and turned
// them into a `Secret` on EVERY command; the seed now comes out of the
// encrypted store, so nothing after `create` asks for a mnemonic. That
// closed with encryption at rest -- the two were one mechanism.
// `mnemonic::master_seed_from_phrase` is still reached, once, from
// `cli::create` on the `--from-phrase` path, which is the one place an
// operator genuinely has a phrase and no store.

/// The password prompt of the eight commands that open a store: one line
/// from the controlling terminal, echo off, the prompt on that terminal.
///
/// **The refusal comes before the read.** This once turned echo off,
/// prompted, read the line, and only then refused if echo had not actually
/// been disabled -- so in the one path built to keep the phrase off the screen,
/// the phrase was on the screen by the time the refusal printed. Refusing first
/// costs nothing and is the whole point of the path; [`open_terminal`] holds
/// that order through `?` on the guard.
///
/// # One impl, two callers
///
/// This was once its own copy of the read: `/dev/tty` opened
/// read-only, the prompt written with `eprint!`, the newline with `eprintln!`.
/// So `mcm-wallet ... balance 2>/dev/null` printed nothing and waited
/// silently -- the shape of the read-only-descriptor defect (an invisible
/// prompt) reached by a different route, redirection rather than a dead
/// descriptor. `create` had already argued the case exactly: its prompts were moved onto the
/// acquired descriptor *so that a shell redirect could not separate a prompt
/// from what it asks about*. The argument was applied to the one impl it was
/// written beside and not to the function below it, and the containment
/// scan's print ban was scoped to that impl, so the `eprint!` here sat one
/// function outside its domain and stayed green.
///
/// A second thing the move removed, stated because it is the strongest
/// argument for the widened ban: `eprint!` and `eprintln!` panic when stderr
/// cannot be written, so `balance 2>&-` panicked out of this function in a
/// binary whose parser argues that panic-freedom is structural. The three
/// print sites left are `main`'s, on the report and the usage.
///
/// It is now [`Tty`]'s own `read_secret_line`, the one made to write and
/// check, on a terminal from the same [`open_terminal`] that `create` uses.
/// What establishes that the prompt reaches the screen is
/// `tests/cli.rs::pty::address_on_a_real_pty_needs_no_node_and_its_prompt_survives_a_redirected_stderr`,
/// which runs this path with stderr redirected inside a pty and finds the
/// prompt on the screen and not in the file; the scan's widened ban (no print
/// macro outside `main`) is the cheap early signal, not the proof.
fn read_secret_line(prompt: &str) -> Result<Zeroizing<String>, String> {
    let mut tty = open_terminal()?;
    tty.read_secret_line(prompt)
}

/// Terminal echo, off for as long as the guard lives.
///
/// Existing at all is the point: it makes *echo is off* a precondition the
/// caller cannot skip, and restores on drop so an early return cannot leave a
/// terminal silent. Done by `stty` rather than a `termios` dependency — the
/// only place the binary needs it, and a crate for one call is the shape
/// declined for `tempfile`.
struct EchoGuard(std::fs::File);

fn echo_off(tty: &std::fs::File) -> Result<EchoGuard, String> {
    let dup = tty
        .try_clone()
        .map_err(|e| format!("cannot duplicate /dev/tty: {e}"))?;
    let off = std::process::Command::new("stty")
        .arg("-echo")
        .stdin(std::process::Stdio::from(
            tty.try_clone()
                .map_err(|e| format!("cannot duplicate /dev/tty: {e}"))?,
        ))
        .status();
    if !matches!(off, Ok(s) if s.success()) {
        return Err(
            "refusing to read a secret with terminal echo on: the words would be visible and \
             may be kept in the terminal's scrollback. Nothing was read."
                .into(),
        );
    }
    Ok(EchoGuard(dup))
}

impl EchoGuard {
    /// Turn echo back on **and say whether it worked**.
    ///
    /// `echo_off` refuses when `stty -echo` fails, so the direction that
    /// protects the *secret* is checked. The restore was not: `Drop` runs
    /// `stty echo` and discards the result, and its `if let Ok(dup)` arm skips
    /// the call entirely when the descriptor cannot be duplicated. That
    /// asymmetry is invisible until it bites, and when it bites it reproduces
    /// exactly the failure the first live run recorded -- an operator typing
    /// three words into a terminal that shows nothing, and an `exit 3`.
    ///
    /// So the one caller that *depends* on echo being back — the confirmation
    /// — calls this through `?` and refuses **before** prompting. `Drop` stays
    /// as the best-effort backstop for every other path, where nothing is
    /// waiting to be read and a silent terminal is an annoyance rather than a
    /// lost store.
    fn restore(&self) -> Result<(), String> {
        let dup = self
            .0
            .try_clone()
            .map_err(|e| format!("cannot duplicate /dev/tty to restore terminal echo: {e}"))?;
        let on = std::process::Command::new("stty")
            .arg("echo")
            .stdin(std::process::Stdio::from(dup))
            .status();
        if !matches!(on, Ok(s) if s.success()) {
            return Err(
                "cannot turn terminal echo back on, so the confirmation would be typed blind. \
                 That is how the words get mistyped. Nothing further was read; run `stty echo` \
                 to restore your terminal."
                    .into(),
            );
        }
        Ok(())
    }
}

impl Drop for EchoGuard {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

/// `N` bytes from the OS CSPRNG.
///
/// `/dev/urandom` through `std::fs` rather than a crate: there is no RNG in
/// this crate's graph, the command layer is under `native` alone so `ring` is
/// not reachable, and the binary already opens `/dev/tty` by path. This is the
/// operating system's generator, not a hand-rolled one.
///
/// **Generic over the width**, because the store now needs three
/// separate draws rather than one: the phrase entropy, the KDF salt and the
/// per-open nonce seed. They are separate draws and not one split three ways --
/// see `cli::create::CreateEntropy`.
fn os_bytes<const N: usize>() -> Result<Zeroizing<[u8; N]>, String> {
    use std::io::Read;
    let mut buf = Zeroizing::new([0u8; N]);
    std::fs::File::open("/dev/urandom")
        .map_err(|e| format!("cannot open /dev/urandom: {e}"))?
        .read_exact(&mut buf[..])
        .map_err(|e| format!("cannot read /dev/urandom: {e}"))?;
    Ok(buf)
}

/// Everything `create` draws from the OS, in one value.
fn os_create_entropy() -> Result<Zeroizing<create_cmd::CreateEntropy>, String> {
    Ok(Zeroizing::new(create_cmd::CreateEntropy {
        phrase: *os_bytes::<{ ENTROPY_LEN }>()?,
        salt: *os_bytes::<{ mochimo_crypto::keystore::SALT_LEN }>()?,
        nonce_seed: *os_bytes::<{ mochimo_crypto::keystore::NONCE_SEED_LEN }>()?,
    }))
}

/// `create`: acquire the terminal, then hand off.
///
/// **Everything that decides is in `cli::create::run`.** This function exists
/// to supply two things the library cannot have — a real `/dev/tty` and the OS
/// generator — and its whole contribution to the ordering is that `acquire`
/// is passed rather than called late. See that function's note for why the
/// acquisition is first and what holding the guard longer costs.
fn run_create(dir: &str, from_phrase: bool) -> cli::Report {
    create_cmd::orchestrate(
        std::path::Path::new(dir),
        from_phrase,
        os_create_entropy,
        acquire_terminal,
    )
}

/// The controlling terminal, with echo already off.
///
/// Holds the echo guard for its whole life, so a `Tty` that exists is a
/// terminal that is both present and silent. The guard carries its own
/// duplicated descriptor, so field drop order here is not load-bearing.
struct Tty {
    file: std::fs::File,
    _echo: EchoGuard,
}

/// **Read AND write**. `File::open` is `O_RDONLY`, and for a time
/// that is how this descriptor was opened -- so all three of the impl
/// below's writes to it failed with `EBADF` (measured: `write_all` returned
/// `Err(Os { code: 9, "Bad file descriptor" })` from a `dbg` placed on the
/// discarded result), every one discarded by `let _ =`, and `create` showed
/// the operator nothing: no password prompt, no phrase, no question. It then
/// exited 3 on a confirmation nobody had been asked, having written a store
/// whose only backup nobody had seen. Six sessions, because nobody ran
/// `create` in a terminal again. `tests/cli.rs`'s pty harness now does, on
/// every board.
///
/// **The one place the terminal is opened**. `create` acquires it through
/// [`acquire_terminal`] and every other command through [`read_secret_line`],
/// and both are this function, so there is no second open for the next
/// read-only `File::open` to hide in.
fn open_terminal() -> Result<Tty, String> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|e| {
            format!(
                "cannot open /dev/tty: {e}. This program reads secrets from the controlling \
                 terminal and there is none here -- it cannot be driven from a pipe, a cron job \
                 or a harness without one."
            )
        })?;
    let _echo = echo_off(&file)?;
    Ok(Tty { file, _echo })
}

/// `create`'s acquisition: [`open_terminal`], in its own words. The promise
/// every refusal from `create` keeps -- "Nothing was created." -- is appended
/// by `orchestrate` at the one seam every refusal goes through, so this no
/// longer appends it. It did for a time, while the seam rendered the text
/// verbatim, which left the sentence to the caller and let the seam's other
/// arms drop it (AGENT.md, Known-open 31, closed at S8).
fn acquire_terminal() -> Result<Tty, String> {
    open_terminal()
}

impl create_cmd::Terminal for Tty {
    /// **To the terminal this `Tty` acquired, not to stdout**.
    ///
    /// It was `println!` once, and that quietly falsified two things at
    /// once. `/dev/tty` was acquired precisely so a phrase could not reach
    /// *"whatever captured stdout"* (in as many words) — and then the
    /// display went to stdout anyway, so `mcm-wallet ... create > seed.txt`
    /// wrote the twenty-four words into a plaintext file, which is the exact
    /// exposure `create`'s module doc enumerates. And the confirmation prompt
    /// goes to stderr, so under any redirection the operator was asked to read
    /// back words from a screen that had never shown them: an `exit 3` by
    /// construction, and the argument for echoing the confirmation —
    /// *the phrase is three lines above in the same scrollback* — was an
    /// argument about a screen the phrase might never have reached.
    ///
    /// Writing to `self.file` makes that premise true by construction: the
    /// phrase and the question now travel on the same descriptor, the one the
    /// operator is sitting in front of, and no shell redirection separates
    /// them.
    ///
    /// **The write's result is returned, not discarded**. This method
    /// once argued that a failed write need not be reported because *"the
    /// confirmation immediately afterwards is what establishes the operator
    /// actually read it, which is a stronger check than an `io::Result` on
    /// the write would be."* That reasoning is what failed: the confirmation
    /// is asked on the **same descriptor**, by design, so a descriptor that
    /// cannot be written fails both the display and the question together and
    /// the confirmation cannot see the failure it was supposed to catch. The
    /// two checks are complementary, not ordered by strength -- the `Result`
    /// catches the descriptor class (`EBADF`, `EIO`, a pty that went away),
    /// the confirmation catches the human class (present, could read it) --
    /// and `orchestrate` refuses on this `Err` before anything is written.
    fn show(&mut self, text: &str) -> Result<(), String> {
        use std::io::Write as _;
        let mut out = self
            .file
            .try_clone()
            .map_err(|e| format!("cannot write to /dev/tty: {e}"))?;
        out.write_all(text.as_bytes())
            .and_then(|()| out.write_all(b"\n"))
            .and_then(|()| out.flush())
            .map_err(|e| format!("cannot write to /dev/tty: {e}"))
    }

    /// The confirmation, **visible** — see the trait method's note for why
    /// echoing three words of a phrase that is three lines above costs
    /// nothing, and why consuming `self` is what keeps the acquisition's property.
    ///
    /// The implementation is the natural one rather than a careful one, and
    /// that is the design working: **releasing the echo guard is the whole
    /// mechanism.** `EchoGuard::drop` restores echo, which it was going to do
    /// when this `Tty` fell out of scope a few lines later; the only thing
    /// that changed is that the one caller who wants the answer visible drops
    /// it first. Nothing turns echo on by hand, so there is no second place
    /// for the two states to disagree, and no window a secret read could be
    /// added into later -- `self` is gone.
    fn read_visible_line(self, prompt: &str) -> Result<Zeroizing<String>, String> {
        let Tty { file, _echo } = self;
        // Restore echo, CHECKED, and refuse before prompting if it did not
        // work -- the whole contract of this method is that the answer is
        // visible, so an unverifiable restore is a precondition failure and
        // not a detail. `_echo` still drops afterwards, best-effort, which is
        // what every other path relies on.
        _echo.restore()?;
        drop(_echo);
        let mut term = file
            .try_clone()
            .map_err(|e| format!("cannot write to /dev/tty: {e}"))?;
        // The prompt's write is checked: a question that could not be
        // asked is a precondition failure of a method whose contract is that
        // the operator answers it, not a detail to read past.
        term.write_all(prompt.as_bytes())
            .and_then(|()| term.flush())
            .map_err(|e| format!("cannot write to /dev/tty: {e}"))?;
        let mut line = Zeroizing::new(String::with_capacity(PHRASE_CAPACITY));
        let read = BufReader::new(
            file.try_clone()
                .map_err(|e| format!("cannot read /dev/tty: {e}"))?,
        )
        .read_line(&mut line);
        match read {
            Ok(0) => return Err(END_OF_INPUT.into()),
            Ok(_) => {}
            Err(e) => return Err(format!("cannot read from /dev/tty: {e}")),
        }
        Ok(Zeroizing::new(line.trim().to_string()))
    }

    /// The prompt goes to the acquired terminal too.
    ///
    /// It went to stderr, which is a process-wide stream and can be
    /// redirected: `create --from-phrase 2>log` asked for twenty-four words
    /// with nothing on screen. Same defect as `show`'s, on the other stream,
    /// and the containment scan now forbids both spellings inside this impl.
    fn read_secret_line(&mut self, prompt: &str) -> Result<Zeroizing<String>, String> {
        let mut term = self
            .file
            .try_clone()
            .map_err(|e| format!("cannot write to /dev/tty: {e}"))?;
        // Checked, as in `read_visible_line`. A password prompt that
        // never appeared reads a password typed blind, or waits forever on
        // an operator who was never asked.
        term.write_all(prompt.as_bytes())
            .and_then(|()| term.flush())
            .map_err(|e| format!("cannot write to /dev/tty: {e}"))?;
        let mut line = Zeroizing::new(String::with_capacity(PHRASE_CAPACITY));
        let read = BufReader::new(
            self.file
                .try_clone()
                .map_err(|e| format!("cannot read /dev/tty: {e}"))?,
        )
        .read_line(&mut line);
        // The newline after an echo-off read is cosmetic -- the operator's
        // Enter was not echoed -- so this one is the one write here whose
        // failure changes nothing that matters, and it stays best-effort.
        let _ = term.write_all(b"\n");
        match read {
            Ok(0) => return Err(END_OF_INPUT.into()),
            Ok(_) => {}
            Err(e) => return Err(format!("cannot read from /dev/tty: {e}")),
        }
        Ok(Zeroizing::new(line.trim().to_string()))
    }
}
