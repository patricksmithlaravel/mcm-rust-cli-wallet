//! Fixture loading and failure reporting for the KAT suite.
//!
//! Nothing in here computes a protocol value. It reads JSON, reads `.bin`
//! sidecars, compares bytes, and formats a failure so that it names the
//! reference `file:line` the vector came from.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use serde_json::Value;

// --- corpus location ----------------------------------------------------

/// The fixture directory. `MOCHIMO_FIXTURES` overrides it, which is how the
/// deliberate-failure demonstration points the suite at a scratch copy without
/// ever touching the committed corpus.
pub fn fixtures_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("MOCHIMO_FIXTURES") {
        return PathBuf::from(dir);
    }
    repo_root().join("fixtures")
}

pub fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crate lives at <repo>/crates/mochimo-crypto")
        .to_path_buf()
}

// --- manifest -----------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    pub id: String,
    pub file: String,
    pub name: String,
    pub status: String,
    pub vectors: usize,
    pub sources: usize,
    pub reason: Option<String>,
    /// Known fixture debt the generator owes. Not a skip list — the group's
    /// vectors all still run.
    pub pending: Vec<String>,
    /// Vector ids inside a `deferred` group that are nevertheless replayed.
    ///
    /// A group splits across sessions when part of it is blocked on something
    /// the rest is not. Group-level `status` cannot say that, and a third
    /// status value would say it badly: "partial" reads as "mostly done" and
    /// the remaining count stops being loud. So the group stays `deferred` and
    /// names the replayable ids explicitly. Listing ids rather than a count
    /// makes the set auditable — a typo is a hard failure instead of an
    /// off-by-one nobody sees.
    pub activated: Vec<String>,
    /// Vectors in this group that nothing replays.
    ///
    /// Read from the manifest rather than computed as `vectors -
    /// activated.len()`. Deriving it makes every agreement check a tautology:
    /// dropping an id from `activated` moves both sides together, so the vector
    /// stops being replayed while all three counts still add up. That was
    /// demonstrated, not theorised — the check was written the derived way
    /// first and a deliberate deletion stayed green.
    pub still_deferred: usize,
}

impl Group {
    pub fn is_active(&self) -> bool {
        self.status == "active"
    }
}

pub fn load_manifest() -> Vec<Group> {
    let path = fixtures_dir().join("manifest.toml");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    let doc: toml::Value = text
        .parse()
        .unwrap_or_else(|e| panic!("{} is not valid TOML: {e}", path.display()));

    let groups = doc
        .get("group")
        .and_then(|g| g.as_array())
        .unwrap_or_else(|| panic!("{} has no [[group]] entries", path.display()));

    let out: Vec<Group> = groups
        .iter()
        .map(|g| {
            let s = |k: &str| -> String {
                g.get(k)
                    .and_then(|v| v.as_str())
                    .unwrap_or_else(|| panic!("manifest group missing string field `{k}`"))
                    .to_string()
            };
            let n = |k: &str| -> usize {
                g.get(k)
                    .and_then(|v| v.as_integer())
                    .unwrap_or_else(|| panic!("manifest group missing integer field `{k}`"))
                    as usize
            };
            // An optional array-of-strings field. Absent is empty; present but
            // the wrong shape is a hard failure, because a silently-ignored
            // malformed `activated` would defer vectors nobody notices.
            let strings = |k: &str| -> Vec<String> {
                g.get(k)
                    .map(|v| {
                        v.as_array()
                            .unwrap_or_else(|| panic!("group `{}`: {k} must be an array", s("id")))
                            .iter()
                            .map(|e| {
                                e.as_str()
                                    .unwrap_or_else(|| {
                                        panic!("group `{}`: {k} entries must be strings", s("id"))
                                    })
                                    .to_string()
                            })
                            .collect()
                    })
                    .unwrap_or_default()
            };

            let status = s("status");
            assert!(
                status == "active" || status == "deferred",
                "manifest group `{}` has status `{status}`; expected \"active\" or \"deferred\"",
                s("id")
            );
            if status == "deferred" {
                assert!(
                    g.get("reason").and_then(|v| v.as_str()).is_some(),
                    "deferred group `{}` must carry a `reason`",
                    s("id")
                );
            }

            let activated = strings("activated");
            assert!(
                status == "deferred" || activated.is_empty(),
                "group `{}` is `{status}` and carries `activated`. Only a deferred \
                 group may: in an active group every vector runs already, so the \
                 list would be a second, weaker statement of the same thing and \
                 the two could drift apart.",
                s("id")
            );
            assert!(
                activated.len() <= n("vectors"),
                "group `{}`: {} activated ids but only {} vectors",
                s("id"),
                activated.len(),
                n("vectors")
            );
            // `still_deferred` is honoured whenever it is written, not only
            // when the group is split.
            //
            // It used to be read only if `activated` was non-empty, and derived
            // as `vectors` otherwise. That made a stated `still_deferred = 15`
            // on a wholly-deferred group *silently ignored* — the number would
            // sit in the file agreeing with nothing, and a later edit that
            // changed the vector count would leave it stale with no test
            // noticing. Ignoring a field a human wrote down is the same failure
            // as a fixture field nothing reads; the fix is the
            // same, which is to consume it.
            let stated = g
                .get("still_deferred")
                .and_then(|v| v.as_integer())
                .map(|n| n as usize);
            assert!(
                status == "deferred" || stated.is_none(),
                "group `{}` is active and carries `still_deferred`. An active \
                 group defers nothing, so the field could only ever be 0 and \
                 would be a second, weaker statement of `status`.",
                s("id")
            );
            let still_deferred = match stated {
                Some(stated) => {
                    assert_eq!(
                        activated.len() + stated,
                        n("vectors"),
                        "group `{}`: {} activated + {stated} still deferred != {} vectors",
                        s("id"),
                        activated.len(),
                        n("vectors")
                    );
                    stated
                }
                None if !activated.is_empty() => panic!(
                    "group `{}` carries `activated` but no `still_deferred`. \
                     The remainder must be written down, not computed from \
                     the list: a derived count moves with the list and an id \
                     deleted from it would defer a vector with every total \
                     still agreeing.",
                    s("id")
                ),
                // No split and nothing stated: everything the group has is
                // deferred, or it is active and nothing is.
                None => {
                    if status == "active" {
                        0
                    } else {
                        n("vectors")
                    }
                }
            };

            {
                let mut seen = std::collections::BTreeSet::new();
                for id in &activated {
                    assert!(
                        seen.insert(id.clone()),
                        "group `{}`: `{id}` appears twice in `activated`. A duplicate \
                         inflates the activated count and silently hides a vector in \
                         the deferred remainder.",
                        s("id")
                    );
                }
            }

            Group {
                id: s("id"),
                file: s("file"),
                name: s("name"),
                status,
                vectors: n("vectors"),
                sources: n("sources"),
                reason: g
                    .get("reason")
                    .and_then(|v| v.as_str())
                    .map(str::to_string),
                pending: strings("pending"),
                activated,
                still_deferred,
            }
        })
        .collect();

    assert!(!out.is_empty(), "{} lists no groups", path.display());
    out
}

/// Every `*.json` actually present in the fixture directory.
pub fn json_files_on_disk() -> Vec<String> {
    let dir = fixtures_dir();
    let entries = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("cannot read fixture directory {}: {e}", dir.display()));
    let mut names: Vec<String> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".json"))
        .collect();
    names.sort();
    names
}

// --- fixture files ------------------------------------------------------

pub struct Fixture {
    pub file: String,
    pub root: Value,
}

impl Fixture {
    pub fn load(file: &str) -> Fixture {
        let path = fixtures_dir().join(file);
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("cannot read fixture {}: {e}", path.display()));
        assert!(
            !text.trim().is_empty(),
            "fixture {} is empty; a KAT suite that iterates nothing is worse than no suite",
            path.display()
        );
        let root: Value = serde_json::from_str(&text)
            .unwrap_or_else(|e| panic!("{} is not valid JSON: {e}", path.display()));
        Fixture {
            file: file.to_string(),
            root,
        }
    }

    pub fn vectors(&self) -> Vec<&Value> {
        let vs = self
            .root
            .get("vectors")
            .and_then(|v| v.as_array())
            .unwrap_or_else(|| panic!("{} has no `vectors` array", self.file));
        assert!(
            !vs.is_empty(),
            "{} has an empty `vectors` array; a KAT run must never pass by iterating nothing",
            self.file
        );
        vs.iter().collect()
    }

    /// Every vector's `id`, in file order.
    pub fn vector_ids(&self) -> Vec<String> {
        self.vectors()
            .iter()
            .map(|v| field_str(v, "id", &self.file).to_string())
            .collect()
    }

    /// The vector with this `id`. A miss is a hard failure: the only caller is
    /// the `activated` replay, and a typo there must not quietly run nothing.
    pub fn vector_by_id(&self, id: &str) -> &Value {
        self.vectors()
            .into_iter()
            .find(|v| field_str(v, "id", &self.file) == id)
            .unwrap_or_else(|| {
                panic!(
                    "{}: no vector with id `{id}`.\n  \
                     manifest.toml lists it under this group's `activated`, so either \
                     the id is a typo or the vector was renamed upstream. Either way \
                     nothing would have replayed it.",
                    self.file
                )
            })
    }

    pub fn sources(&self) -> Vec<String> {
        let mut set: BTreeMap<String, ()> = BTreeMap::new();
        for v in self.vectors() {
            set.insert(field_str(v, "source", &self.file).to_string(), ());
        }
        set.into_keys().collect()
    }
}

fn field_str<'a>(v: &'a Value, key: &str, file: &str) -> &'a str {
    v.get(key)
        .and_then(|x| x.as_str())
        .unwrap_or_else(|| panic!("{file}: a vector is missing the required `{key}` field"))
}

// --- hex ----------------------------------------------------------------

pub fn from_hex(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err(format!("odd-length hex string ({} chars)", s.len()));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| format!("not hex: {:?}", &s[i..i + 2]))
        })
        .collect()
}

pub fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Renders a possibly-huge blob around the first byte that differs, so a
/// 2144-byte mismatch stays readable.
fn render(bytes: &[u8], focus: Option<usize>) -> String {
    const WINDOW: usize = 16;
    if bytes.len() <= 48 {
        return to_hex(bytes);
    }
    match focus {
        None => format!("{}… ({} bytes)", to_hex(&bytes[..48]), bytes.len()),
        Some(at) => {
            let start = at.saturating_sub(WINDOW);
            let end = (at + WINDOW).min(bytes.len());
            format!(
                "{}[{}]{} (bytes {}..{} of {})",
                if start > 0 { "…" } else { "" },
                to_hex(&bytes[start..end]),
                if end < bytes.len() { "…" } else { "" },
                start,
                end,
                bytes.len()
            )
        }
    }
}

// --- the per-vector checker --------------------------------------------

/// How much of the reference a vector's replay actually exercised.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Disposition {
    /// Every input came from a machine-readable fixture field.
    Replayed,
    /// At least one input was reconstructed by a rule in the harness rather
    /// than read from a field, because the fixture records it only in prose.
    ///
    /// Session 2b emptied this: no handler constructs it any more, which is
    /// why it needs `allow(dead_code)`. It stays because
    /// `no_input_is_reconstructed_from_prose` only catches a handler that
    /// reads the `note` string, and the reconstruction 2b removed did not --
    /// it mapped `B6-2` to `B2` from a hardcoded table. A future handler doing
    /// the same must have somewhere to declare it, and
    /// `derived_inputs_are_exactly_as_expected` asserts the declared set is
    /// still empty.
    #[allow(dead_code)]
    DerivedInput,
    /// The reference was not called. Either the fixture itself records that
    /// (the base58 fault class), or the input does not exist on disk.
    NotCalled,
}

pub struct Ctx<'a> {
    pub file: &'a str,
    pub id: String,
    pub source: String,
    pub v: &'a Value,
    /// The whole fixture file, for the file-level `constants` block that some
    /// vectors reference by name instead of repeating.
    pub root: &'a Value,
    pub disposition: Disposition,
    failures: Vec<String>,
    /// Every key this vector's handler asked the fixture for.
    ///
    /// `RefCell` because the value accessors take `&self` -- `hex`, `str_`,
    /// `arr` and `u64_` are called from expression position all over the
    /// handlers, and widening them to `&mut self` would fight the borrow
    /// checker at every call site to buy nothing.
    read: RefCell<BTreeSet<String>>,
    /// Every nested key the handler descended into with [`Ctx::cases`].
    ///
    /// Separate from `read` on purpose, and it is the whole point of the
    /// distinction: reading a nested key marks one entry in `read` and would
    /// mark an entire subtree covered while covering none of it. Nothing but
    /// an actual descent, over every element, with a child `Ctx` that runs its
    /// own coverage, may put a key in here. There is no accessor that touches
    /// this set and returns a value.
    ///
    /// Not a `RefCell`: `cases` is the only writer and it takes `&mut self`.
    descended: BTreeSet<String>,
    /// Fields read by child `Ctx`es, which the suite-level vacuity floor must
    /// see. They cannot go in `read` -- that set is this vector's key space,
    /// and a sub-key name landing in it would mark a same-named parent key
    /// covered.
    nested_fields_read: usize,
}

/// The four keys every vector carries and none of which is an assertable
/// value: `id` and `source` locate the vector, `note` and `falsifies` are
/// prose.
///
/// Verified rather than assumed -- these are exactly the universal keys across
/// all five fixture files, computed from the corpus rather than recalled. `note`
/// is prose that `no_input_is_reconstructed_from_prose` already forbids reading
/// as an input, so that test and this list agree rather than overlap.
///
/// `i` is the fifth and is argued for separately, as any entry on a list that
/// cannot be derived must be: it is the positional identifier of a
/// `crc16_base58_corpus` entry, which is exactly what `id` is for a vector.
/// `Ctx::labelled` exists precisely because corpus entries identify themselves
/// by index instead of by id, and the index is consumed to build that label
/// before the `Ctx` exists. It locates an entry; it pins no protocol value.
const METADATA_KEYS: [&str; 5] = ["id", "note", "falsifies", "source", "i"];

/// Fields that are English rather than data, and so can be covered but never
/// asserted.
///
/// Kept separate from `METADATA_KEYS` because the reason differs and blurring
/// the two would let a future entry inherit an argument made for something
/// else: metadata *locates* a vector, prose *explains* one. Both are
/// unassertable; only the second is a place a protocol value could plausibly
/// hide, which is why every entry is named individually and argued here.
///
/// `no_input_is_reconstructed_from_prose` forbids reading any of these as an
/// input. This list does not weaken that -- it records that the field was seen
/// and deliberately not asserted, which is the state coverage otherwise cannot
/// distinguish from an oversight.
///
/// - `crosscheck_source` -- a `file:line` locator for the second
///   implementation, the same kind of thing as `source`.
/// - `decode_not_called_reason` -- why the reference was not invoked. The
///   machine-readable half is `decode_not_called`, which *is* asserted.
/// - `correct_out_expected` -- states a requirement the C cannot be asked for,
///   because calling it faults. There is no value to compare against.
/// - `reference_behaviour_with_out` -- the crash the reference exhibits
///   (`SIGBUS` in `_platform_memmove`). Not reproducible as an assertion
///   without crashing the test process on purpose.
/// - `rule_not_evaluated` -- names the validator the vectors carrying it do
///   *not* reach and why (`tx_val`, which needs an open ledger). Its
///   machine-readable half is an absence rather than a value: no vector
///   anywhere in the corpus may claim `tx_val` as its source, because one that
///   did would mean the generator found a way to call it and these vectors are
///   stale. `kat.rs::tx_val_is_absent_from_the_corpus` asserts exactly that.
///   The sentence itself is a `jw_str` literal identical in all **four** of
///   them, so an `eq_str` against a Rust copy of it would assert that two
///   copies of one sentence match -- which is why the absence is the assertion
///   instead.
///
///   Three are the `D9` vectors, whose unreached rule is the block-to-live
///   range. The fourth is `D17`, whose unreached rule is the src/chg
///   address relationship -- `addr_tag_equal` true and `addr_hash_equal` false.
///   Different rules, the same absence and the same reason, so the same
///   sentence: `tx_val` is what would adjudicate both and it needs a ledger.
///   `D17` records the two predicates as booleans the reference itself
///   computed, which is the machine-readable half specific to it.
/// - `literal_absent_reason` -- why a crosscheck vector carries no transcribed
///   literal. The machine-readable half is `literal_absent`, which *is*
///   asserted, and the assertion is fail-closed against group C in both
///   directions.
/// - `crc16_derivation` -- how the CRC16 was recovered from `addrTagToBase58`'s
///   own output, `crc()` not being exported from the package. The value it
///   describes, `crc16_typescript_executed`, is asserted against group C.
/// - `reference_cannot_compute_reason` -- why group RX has no reference side.
///   The machine-readable half is `reference_can_compute`, which *is* asserted.
///
/// # `ref` and `case` are deliberately NOT on this list
///
/// `D10`/`D11`'s `ref` and `D15`'s `case` are case labels, and exempting them
/// here was the obvious move. They are not exempted, for two reasons that
/// point the same way. This list is global, and `ref` is a real protocol field
/// name -- `MDST::ref`, `ADDR_REF_LEN` -- so exempting it would blind coverage
/// to a data field some later group can plausibly carry. And they do not need
/// exempting: the `cases` handlers in `kat.rs` read both and assert that the
/// labels within a vector are pairwise distinct. That is weak, and it is real:
/// it fails when a generator loop stops varying its label, which is the one
/// way a label can be wrong. An assertion that has to gate on content --
/// `ref` is the input text for eight of the nine cases and a description of
/// unwritable bytes for the ninth -- would be the thing this suite spends the
/// most effort not writing.
const PROSE_KEYS: [&str; 8] = [
    "crosscheck_source",
    "decode_not_called_reason",
    "correct_out_expected",
    "reference_behaviour_with_out",
    "rule_not_evaluated",
    "literal_absent_reason",
    "crc16_derivation",
    "reference_cannot_compute_reason",
];

impl<'a> Ctx<'a> {
    pub fn new(file: &'a str, root: &'a Value, v: &'a Value) -> Ctx<'a> {
        Ctx {
            file,
            id: field_str(v, "id", file).to_string(),
            source: field_str(v, "source", file).to_string(),
            v,
            root,
            disposition: Disposition::Replayed,
            failures: Vec::new(),
            read: RefCell::new(BTreeSet::new()),
            descended: BTreeSet::new(),
            nested_fields_read: 0,
        }
    }

    /// For the corpus entries, which carry an index rather than an `id` and
    /// take their `source` from the enclosing block.
    pub fn labelled(file: &'a str, root: &'a Value, v: &'a Value, id: String, source: String) -> Ctx<'a> {
        Ctx {
            file,
            id,
            source,
            v,
            root,
            disposition: Disposition::Replayed,
            failures: Vec::new(),
            read: RefCell::new(BTreeSet::new()),
            descended: BTreeSet::new(),
            nested_fields_read: 0,
        }
    }

    pub fn mark(&mut self, d: Disposition) {
        self.disposition = d;
    }

    /// A named integer from the fixture's file-level `constants` block.
    pub fn constant(&self, path: &[&str]) -> u64 {
        let mut node = self
            .root
            .get("constants")
            .unwrap_or_else(|| panic!("{}: no file-level `constants` block", self.file));
        for key in path {
            node = node
                .get(key)
                .unwrap_or_else(|| panic!("{}: constants has no `{key}`", self.file));
        }
        node.as_u64()
            .unwrap_or_else(|| panic!("{}: constant {path:?} is not an integer", self.file))
    }

    pub fn into_failures(mut self) -> Vec<String> {
        self.check_coverage();
        self.failures
    }

    /// How many distinct fields this vector's handler asked for. Feeds the
    /// suite-level vacuity floor.
    pub fn fields_read(&self) -> usize {
        self.read.borrow().len() + self.nested_fields_read
    }

    /// Descend into an array of case objects, one child [`Ctx`] each.
    ///
    /// # What this closes
    ///
    /// `check_coverage` is a flat walk. Reading a key that holds an array of
    /// objects would mark the whole subtree covered while covering none of it,
    /// so nested keys were reported as uncoverable **whether or not they were
    /// read** — self-clearing debt, deliberately not built earlier because
    /// there was no vector to test it against. `D10`, `D11` and
    /// `D15` are that vector, three times over: twelve case objects across
    /// three shapes. This is the recursion they were waiting for.
    ///
    /// # Why a child `Ctx` rather than a prefix scheme
    ///
    /// A case object is a vector in every respect that matters here — it has
    /// keys, a handler reads some of them, and the ones it does not read are a
    /// silent hole. Giving it a real `Ctx` means it gets the *same* coverage
    /// walk, not a second implementation of one that could drift from it. The
    /// child's failures are folded into this one, so an unread sub-key is
    /// reported against `<id>[n]` and names the case rather than the vector.
    ///
    /// [`Ctx::labelled`] is reused unchanged: it exists for exactly this shape
    /// already, objects that identify themselves by position instead of by
    /// `id`, which is what `crc16_base58_corpus`'s entries are.
    ///
    /// # The three guards, and what each is for
    ///
    /// * The key must exist and hold an array — a `cases` key that changed
    ///   shape is a fixture change, not something to skip.
    /// * The array must be **non-empty**. An empty one would descend over
    ///   nothing, mark the key covered, and read as coverage. The exact count
    ///   is not asserted here because it is a fact about one vector; the
    ///   per-arm censuses in `kat.rs` state it.
    /// * Every element must be an object. `check_coverage` returns early on a
    ///   non-object, so a scalar in the array would be covered by nobody and
    ///   reported by nobody.
    pub fn cases<F>(&mut self, key: &str, mut each: F)
    where
        F: FnMut(&mut Ctx<'a>),
    {
        let node = self.v.get(key).unwrap_or_else(|| {
            panic!(
                "{}: vector {} has no `{key}` field.\n  source: {}\n  \
                 Either the fixture changed shape or the replay is descending \
                 into the wrong key.",
                self.file, self.id, self.source
            )
        });
        let arr = node.as_array().unwrap_or_else(|| {
            panic!(
                "{}: vector {} -- `{key}` is not an array, so there is nothing \
                 to descend into.",
                self.file, self.id
            )
        });
        assert!(
            !arr.is_empty(),
            "{}: vector {} -- `{key}` is an empty array. Descending over it \
             would mark the key covered while covering nothing, which is the \
             exact state this recursion exists to make impossible.",
            self.file,
            self.id
        );

        // Recorded before the loop so that a panic inside a case handler still
        // leaves the descent visible; recorded at all only here, because this
        // is the sole writer.
        self.descended.insert(key.to_string());

        for (n, case) in arr.iter().enumerate() {
            assert!(
                case.is_object(),
                "{}: vector {} -- `{key}[{n}]` is not an object. Coverage \
                 returns early on a non-object, so this element would be \
                 checked by nothing.",
                self.file,
                self.id
            );
            let mut child = Ctx::labelled(
                self.file,
                self.root,
                case,
                format!("{}[{n}]", self.id),
                self.source.clone(),
            );
            each(&mut child);
            self.nested_fields_read += child.fields_read();
            self.failures.extend(child.into_failures());
        }
    }

    /// Read a field without asserting it. For vectors whose values are the
    /// reference's verdicts and this crate has nothing to compare them with:
    /// the field is seen, so coverage does not report it, and the caller marks
    /// the vector `NotCalled` so the census says what happened.
    pub fn touch(&self, key: &str) -> &'a Value {
        match self.get(key) {
            Some(v) => v,
            None => self.missing(key),
        }
    }

    /// The one place a field is fetched from a vector, so that asking for a
    /// field and recording that it was asked for cannot come apart.
    fn get(&self, key: &str) -> Option<&'a Value> {
        self.read.borrow_mut().insert(key.to_string());
        self.v.get(key)
    }

    /// Every field a vector carries is either read by an assertion or named on
    /// `METADATA_KEYS`. There is no third state in which a field is simply
    /// never looked at.
    ///
    /// # What this is for
    ///
    /// The harness dispatches on `source`, and three of group D's dispatch arms
    /// receive vectors of differing shape, so a handler is forced to span
    /// shapes with `has()`. `Ds3`/`Ds4` carry `hash_unchanged` while `Ds5`
    /// carries `hash_changed` -- so a handler gating on `has("hash_unchanged")`
    /// replays `Ds5` with its only substantive assertion unexecuted, and `Ds5`
    /// exists solely as the control proving `Ds3`/`Ds4` measure exclusion. The
    /// control stops controlling and the suite still reports success.
    ///
    /// # Answering the domain's two questions
    ///
    /// *What makes this domain complete?* It is derived from the artifact: the
    /// keys come from the vector itself, not from a list anybody maintains. A
    /// field added to a fixture is owed an assertion the moment it appears.
    ///
    /// *What would expand the domain without expanding the check?* Nesting.
    /// A field holding an object, or an array of objects, has sub-keys this
    /// flat walk cannot see, and reading the parent once would mark the whole
    /// subtree covered while covering none of it.
    ///
    /// **The recursion this used to defer was built with the vectors that need it.** Until then a nested
    /// field failed *whether or not it was read*, self-clearing, on the
    /// argument that per-entry coverage built against no vector would be
    /// tested against nothing. Group D's `D10`, `D11` and `D15`
    /// are that vector — twelve case objects across three shapes — and the
    /// recursion arrived with them, not before them.
    ///
    /// So the rule is now: a nested field is covered **iff the handler
    /// descended into it with [`Ctx::cases`]**, which is the only writer of
    /// `descended` and gives every element its own `Ctx` and its own run of
    /// this walk. A nested field that was merely *read* is still reported,
    /// exactly as before — reading the parent is what the recursion replaces,
    /// not what satisfies it.
    fn check_coverage(&mut self) {
        let Some(obj) = self.v.as_object() else {
            return;
        };
        let read = self.read.borrow().clone();

        let mut unread: Vec<&str> = Vec::new();
        let mut nested: Vec<&str> = Vec::new();
        for (k, val) in obj {
            if METADATA_KEYS.contains(&k.as_str()) || PROSE_KEYS.contains(&k.as_str()) {
                continue;
            }
            let is_nested = val.is_object()
                || val.as_array().is_some_and(|a| a.iter().any(Value::is_object));
            if is_nested {
                // `descended`, not `read`. An accessor that returned the node
                // would satisfy `read` while covering nothing inside it, which
                // is the whole failure mode; there is deliberately no such
                // accessor, and `cases` returns nothing.
                if !self.descended.contains(k.as_str()) {
                    nested.push(k);
                }
            } else if !read.contains(k.as_str()) {
                unread.push(k);
            }
        }

        if !unread.is_empty() {
            self.failures.push(format!(
                "FIELD NOT COVERED\n  \
                 fixture : {}\n  \
                 vector  : {}\n  \
                 source  : {}\n  \
                 fields  : {}\n  \
                 The vector records these and the handler never read them, so \
                 whatever they pin is not being checked. Either assert them or \
                 argue them onto METADATA_KEYS -- a field that is present and \
                 unread is a green vector with an unexecuted assertion.",
                self.file,
                self.id,
                self.source,
                unread.join(", ")
            ));
        }

        if !nested.is_empty() {
            self.failures.push(format!(
                "NESTED FIELD NOT COVERABLE\n  \
                 fixture : {}\n  \
                 vector  : {}\n  \
                 source  : {}\n  \
                 fields  : {}\n  \
                 Coverage is a flat walk, so reading the parent key once would \
                 mark every sub-key covered while covering none. Descend with \
                 Ctx::cases, which gives every element its own Ctx and its own \
                 coverage walk -- reading the key is not a substitute and does \
                 not clear this.",
                self.file,
                self.id,
                self.source,
                nested.join(", ")
            ));
        }
    }

    // --- required-field accessors. A missing field is a harness bug or a
    // --- fixture change, and either way must stop the run.

    fn missing(&self, key: &str) -> ! {
        panic!(
            "{}: vector {} has no `{}` field.\n  source: {}\n  \
             Either the fixture changed shape or the replay is reading the wrong key.",
            self.file, self.id, key, self.source
        )
    }

    /// Deliberately does **not** record `key` as read.
    ///
    /// Recording here would make `if ctx.has("x") { /* nothing */ }` satisfy
    /// coverage for `x` -- the field would count as covered because someone
    /// asked whether it existed, not because anything compared it. Since the
    /// branch that finds the field present goes on to read it through a real
    /// accessor, which does record, leaving `has` silent costs nothing and
    /// keeps the check fail-closed.
    pub fn has(&self, key: &str) -> bool {
        self.v.get(key).is_some()
    }

    pub fn str_(&self, key: &str) -> &'a str {
        match self.get(key).and_then(|x| x.as_str()) {
            Some(s) => s,
            None => self.missing(key),
        }
    }

    pub fn hex(&self, key: &str) -> Vec<u8> {
        let raw = self.str_(key);
        from_hex(raw).unwrap_or_else(|e| {
            panic!(
                "{}: vector {} field `{}` is not hex ({e}): {:?}\n  source: {}",
                self.file, self.id, key, raw, self.source
            )
        })
    }

    pub fn arr<const N: usize>(&self, key: &str) -> [u8; N] {
        let v = self.hex(key);
        v.clone().try_into().unwrap_or_else(|_| {
            panic!(
                "{}: vector {} field `{}` is {} bytes, expected {N}\n  source: {}",
                self.file,
                self.id,
                key,
                v.len(),
                self.source
            )
        })
    }

    pub fn words(&self, key: &str) -> [u32; 8] {
        let a = match self.get(key).and_then(|x| x.as_array()) {
            Some(a) => a,
            None => self.missing(key),
        };
        assert_eq!(
            a.len(),
            8,
            "{}: vector {} field `{}` has {} words, expected 8",
            self.file,
            self.id,
            key,
            a.len()
        );
        let mut out = [0u32; 8];
        for (i, w) in a.iter().enumerate() {
            out[i] = w
                .as_u64()
                .unwrap_or_else(|| panic!("{}: {} `{key}`[{i}] is not an integer", self.file, self.id))
                as u32;
        }
        out
    }

    pub fn ints(&self, key: &str) -> Vec<i32> {
        let a = match self.get(key).and_then(|x| x.as_array()) {
            Some(a) => a,
            None => self.missing(key),
        };
        a.iter()
            .enumerate()
            .map(|(i, x)| {
                x.as_i64()
                    .unwrap_or_else(|| {
                        panic!("{}: {} `{key}`[{i}] is not an integer", self.file, self.id)
                    }) as i32
            })
            .collect()
    }

    pub fn u64_(&self, key: &str) -> u64 {
        match self.get(key).and_then(|x| x.as_u64()) {
            Some(n) => n,
            None => self.missing(key),
        }
    }

    pub fn bool_(&self, key: &str) -> bool {
        match self.get(key).and_then(|x| x.as_bool()) {
            Some(b) => b,
            None => self.missing(key),
        }
    }

    /// Loads a `.bin` sidecar named by `<key>_file`, checking `<key>_len`.
    pub fn blob(&self, key: &str) -> Vec<u8> {
        let name = self.str_(&format!("{key}_file"));
        let want = self.u64_(&format!("{key}_len")) as usize;
        let bytes = read_sidecar(name, self.file, &self.id);
        assert_eq!(
            bytes.len(),
            want,
            "{}: vector {} sidecar {} is {} bytes but `{}_len` says {}",
            self.file,
            self.id,
            name,
            bytes.len(),
            key,
            want
        );
        bytes
    }

    // --- assertions -----------------------------------------------------

    pub fn eq_bytes(&mut self, key: &str, actual: &[u8]) {
        let expected = self.hex(key);
        self.compare(key, None, &expected, actual);
    }

    pub fn eq_blob(&mut self, key: &str, actual: &[u8]) {
        let name = self.str_(&format!("{key}_file")).to_string();
        let expected = self.blob(key);
        self.compare(key, Some(&name), &expected, actual);
    }

    pub fn eq_u64(&mut self, key: &str, actual: u64) {
        let expected = self.u64_(key);
        if expected != actual {
            self.record(key, None, &expected.to_string(), &actual.to_string(), None);
        }
    }

    pub fn eq_i64(&mut self, key: &str, actual: i64) {
        let expected = match self.get(key).and_then(|x| x.as_i64()) {
            Some(n) => n,
            None => self.missing(key),
        };
        if expected != actual {
            self.record(key, None, &expected.to_string(), &actual.to_string(), None);
        }
    }

    pub fn eq_bool(&mut self, key: &str, actual: bool) {
        let expected = self.bool_(key);
        if expected != actual {
            self.record(key, None, &expected.to_string(), &actual.to_string(), None);
        }
    }

    /// A field that may be JSON `null`, recorded as read either way.
    ///
    /// `has()` deliberately does not record a read (see its comment), and
    /// `str_()` panics on a null. Between them there was no way to cover a
    /// field whose *value* is the absence -- and group CX now carries several,
    /// because "this input is rejected" is an answer worth recording. Without
    /// this accessor the only ways to satisfy coverage for such a field would
    /// be to assert something false about it or to put it on an allow-list,
    /// and both lose the check.
    pub fn opt_str(&self, key: &str) -> Option<&'a str> {
        match self.get(key) {
            None => self.missing(key),
            Some(Value::Null) => None,
            Some(v) => Some(v.as_str().unwrap_or_else(|| {
                panic!(
                    "{}: vector {} field `{}` is neither a string nor null.\n  source: {}",
                    self.file, self.id, key, self.source
                )
            })),
        }
    }

    /// `opt_str` plus the comparison, so the two cannot drift apart.
    pub fn eq_opt_str(&mut self, key: &str, actual: Option<&str>) {
        let expected = self.opt_str(key).map(str::to_string);
        if expected.as_deref() != actual {
            self.record(
                key,
                None,
                expected.as_deref().unwrap_or("<null>"),
                actual.unwrap_or("<null>"),
                None,
            );
        }
    }

    pub fn eq_str(&mut self, key: &str, actual: &str) {
        let expected = self.str_(key).to_string();
        if expected != actual {
            self.record(key, None, &expected, actual, None);
        }
    }

    pub fn eq_words(&mut self, key: &str, actual: &[u32; 8]) {
        let expected = self.words(key);
        if &expected != actual {
            self.record(
                key,
                None,
                &format!("{expected:?}"),
                &format!("{actual:?}"),
                None,
            );
        }
    }

    pub fn eq_ints(&mut self, key: &str, actual: &[i32]) {
        let expected = self.ints(key);
        if expected != actual {
            let at = expected
                .iter()
                .zip(actual.iter())
                .position(|(a, b)| a != b)
                .map(|i| format!("first differing element: index {i}"));
            self.record(
                key,
                None,
                &format!("{expected:?}"),
                &format!("{actual:?}"),
                at,
            );
        }
    }

    fn compare(&mut self, key: &str, sidecar: Option<&str>, expected: &[u8], actual: &[u8]) {
        if expected == actual {
            return;
        }
        let at = expected
            .iter()
            .zip(actual.iter())
            .position(|(a, b)| a != b);
        let detail = match at {
            Some(i) => Some(format!(
                "first differing byte: offset {i} — expected 0x{:02x}, actual 0x{:02x}",
                expected[i], actual[i]
            )),
            None => Some(format!(
                "lengths differ: expected {} bytes, actual {} bytes",
                expected.len(),
                actual.len()
            )),
        };
        self.record(
            key,
            sidecar,
            &render(expected, at),
            &render(actual, at),
            detail,
        );
    }

    fn record(
        &mut self,
        key: &str,
        sidecar: Option<&str>,
        expected: &str,
        actual: &str,
        detail: Option<String>,
    ) {
        let field = match sidecar {
            Some(f) => format!("{key} ({f})"),
            None => key.to_string(),
        };
        let mut msg = String::new();
        let _ = write!(
            msg,
            "FIXTURE MISMATCH\n  \
             fixture : {}\n  \
             vector  : {}\n  \
             field   : {}\n  \
             source  : {}\n  \
             expected: {}\n  \
             actual  : {}",
            self.file, self.id, field, self.source, expected, actual
        );
        if let Some(d) = detail {
            let _ = write!(msg, "\n  {d}");
        }
        self.failures.push(msg);
    }
}

pub fn read_sidecar(name: &str, file: &str, id: &str) -> Vec<u8> {
    let path = fixtures_dir().join(name);
    std::fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "{file}: vector {id} references sidecar {} which cannot be read: {e}",
            path.display()
        )
    })
}
