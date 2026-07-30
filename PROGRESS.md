# Vigilance-Core — Progress & Handoff

Working notes for continuing this project. Last updated after the walk-performance pass
(`325d9df`), which cut the carve from 87 minutes to roughly 18.

Repo: `holialli/Vigilance-Core` (branch `main`). 122 tests passing (`python -m pytest tests/ -q`).

**Goal:** conversational forensics — an investigator asks questions in natural language
instead of manually hunting through artifacts. Not trying to match Autopsy's parser
coverage; competing on the AI/triage layer Autopsy doesn't have.

> Push with a transient auth header built from `GITHUB_TOKEN` in `src/.env`
> (`git -c http.extraheader=...`); never write it to git config.

---

## Start here

**State:** clean. `main` at `325d9df`, working tree clean, 122 tests passing,
NIST re-validated 11/11 through a full carve. Nothing is half-finished.

**In flight:** nothing. The last session ended on a committed, verified change.

**Next, in the order I'd do it:**

1. **Profile the extractor phase.** ~1,070s and never profiled. The shared walk
   turned out to be 79% of a carve and 99% of *that* was one bad line
   (`fs.open_dir(path_string)`); the extractors call into the same API and very
   likely repeat it. Grep the extractors for `open_dir(` and `open(` taking a
   path, and time one extractor before assuming. Highest expected value.
2. **Then re-decide `CARVE_MAX_WORKERS`** (item 1 below). Do this *after* (1) —
   (1) changes the numbers the decision rests on, exactly as it already did once.
3. **Fix the FAISS/OpenMP segfault** (item 3 below). Root-caused; needs a choice
   between `OMP_NUM_THREADS=1` and subprocess encoding. It is the only known
   issue that can take down the whole server.
4. **Promote the verified carve into the cache** (item 2 below) — cheap to
   describe, ~50 min of re-embed, so pair it with something else.

**Method note that paid off twice this session:** when a rewrite changes a count,
reproduce the old implementation and diff the actual sets rather than reasoning
about whether the delta is benign. Doing that cost ~2.7h of background runtime
and caught 67 silently-lost paths, including real evidence in the suspect's temp
directory, that "looks equivalent to me" would have shipped.

---

## External validation (NIST CFReDS "Hacking Case")

The strongest evidence the tool works, because the ground truth is not ours.
`https://cfreds-archive.nist.gov/Hacking_Case.html` publishes a Windows XP
image **and an answer key** (`TestAnswers.pdf`, 31 questions). Both segments
(`.E01` + `.E02`, 4.87 GB decoded) sit gitignored in the repo root.

| Q | NIST answer | Result |
|---|---|---|
| 1 / 1b | MD5 `AEE4FCD9301C03B3B054623CA261959A` | **PASS** — exact, and matches the hash stored in the E01 |
| 2 | Windows XP | **PASS** — `OS: Microsoft Windows XP` |
| 6 | `N-1A9ODN6ZXK4LQ` | **PASS** — surfaced as `HOST:` |
| 9 | 5 accounts | **PASS** — incl. `Mr. Evil` |
| 10 / 11 | Mr. Evil | **PASS** |
| 16 | 6 hacking tools | **PASS** — 7/7 found (Ethereal and NetStumbler via prefetch) |
| 28 | 4 executables in recycle bin | **PASS** — after implementing INFO2 parsing |
| 3, 5, 7 | install date, owner, domain | pass, but *recoverable by search* rather than surfaced |
| 30 | 3 files deleted | **not scored** — NIST counts what the recycle bin reports; `DELETED` counts unallocated MFT + `$OrphanFiles`. Different measures. |
| 12-15, 17-27, 29, 31 | mail/IRC config, packet capture, AV | **out of scope** — capabilities this tool does not claim |

Re-run with the harness in the session scratchpad (`validate_nist.py`).

**Re-validated end-to-end after the recycle-bin fixes: 11/11.** That run carved
the image from scratch rather than loading a pickle, so Q28 is confirmed through
a full carve and not just a direct parser test.

**Three bugs this image found that the local Windows 7 image never could:**
- Multi-segment E01 sets were **entirely unopenable** (`8a62634`).
- `.E02` was not gitignored (`ed8be04`).
- XP's `INFO2` recycle bin was never parsed (`92a5b16`).

**Write the checks strictly.** The first version of this harness scored Q28 and
Q30 as `len(...) > 0`, which passes on any non-zero result — it reported 12/12
while Q28 was really 2-vs-4 and Q30 was 27-vs-3. A validator that grades itself
leniently is worse than none.

---

## Verification setup

Real evidence used throughout (both gitignored, sitting in the repo root):

- `Image.E01` — ~300 MB IACIS training image, Windows 7, host `IACIS-HDD-2014`.
  **This is the good test image.**
- `C5W04_02.E01` — split image **missing its `.E02`+ segments**, so it cannot be
  opened. Errors out correctly via the existing "Split E01 Image Detected" guard.
  Not a bug; get the remaining segments if you want to use it.

Carve is slow. Background it and redirect output. Timings: see 'Concurrency' below.
Scratch scripts used this session (re-create as needed): a carve-and-pickle
runner, an EVTX-only runner, and a citation end-to-end harness.

**Always redirect carve output to a file and read it with `-u`** — Python buffers
stdout when redirected, and a crash loses everything you needed to see.

---

## Done

### Bug fixes (`b1a5566`, `5f23b99`)
- `requirements.txt` was UTF-16 → unusable by pip. Rewrote as UTF-8.
- Swapped unused `fpdf2` → `reportlab` (what `generate_pdf_report` imports).
- `.gitignore`: training CSVs now committed, so `isolation_model.py` is
  reproducible from a clean clone.
- SAM logon counts silently dropped: regex looked for `Logons:` but the extractor
  emits `Login Count:`.
- ML train/serve skew: `EventsPerMinute` used a 50-row lookback at inference vs
  100 at training. Aligned to 100.
- Blank Event IDs defaulted to `0`, colliding with the real heuristic threat ID
  "Kernel Critical Event" → every such row falsely flagged. Now `-1`.
- PDF download button wired with a pre-Gradio-6 API; silently did nothing.
- Cache-hit uploads never populated `artifact_counts`.

### Session isolation (`8802cb8`)
Per-case state moved off module globals onto a `CaseSession` in `gr.State`.
Two investigators were previously overwriting each other's evidence.

### Package split + tests (`c1b8e4c`)
3200-line monolith → `src/forensics/` package. `chatbot_app.py` is now just UI.
ML model and LLM clients load lazily, so tests import cleanly without keys.

```
src/forensics/
  config.py       paths, HEURISTIC_THREAT_IDS, hashset paths
  session.py      CaseSession
  parsers.py      EVTX, registry hive, SHA-256, EWFImgInfo
  extractors.py   all extract_*, walk_filesystem, carve orchestrator  (~1780 lines)
  ml.py           engineer_features, lazy model load
  rag.py          hybrid retrieval + citations
  context.py      extract_system_context
  llm.py          Ollama → Groq → Gemini → offline chain
  reporting.py    PDF
  analysis.py     search, timeline, triage
  correlation.py  entity extraction + pivoting
  cases.py        save/load/list cases
  shimcache.py    AppCompatCache parser
  hashsets.py     hashing + known-good/bad matching
  recyclebin.py   INFO2 (XP) and $I (Vista+) record parsers
```

### Evidence citations + RAG overhaul (`42d95b6`)
- The prompt used to *forbid* citations. Now it requires inline `[E1]` tags and
  the UI appends a resolved evidence appendix.
- **Retrieval was badly broken.** USB/BROWSER/PREFETCH/RECYCLE/ACTIVITY/RECENT/
  COMMUNICATION artifacts were *never indexed at all*. Rewrote as hybrid
  retrieval: semantic (FAISS) + lexical + query→artifact-type routing.

### Triage / Timeline / Search tabs (`8d09a1e`)
- **Triage** runs on upload, severity-ranked, channel-scoped rules.
- **Timeline** — daily/hourly/weekly buckets, filterable.
- **Search** — substring/regex over all artifacts.

### Extraction depth (`fb2cf06`)
- **ShimCache**: was a permanent no-op stub; now a real AppCompatCache parser
  recovering **492 execution records** (Win7 x64 pads 4 bytes after the length
  WORDs — without that the parser returns 0).
- **Deleted/orphaned files**: recovered via TSK unalloc flags + `$OrphanFiles`.
  Originally reported as "1,334 recovered" — **that was wrong**, see the
  double-counting fix below. The true figure on this image is **663**.
- **Hash sets** (`hashsets.py`): MD5+SHA-256 in one pass, NSRL-style loader.
  Skipped when no sets configured — it added ~22 min for zero benefit.
- **Correlation engine** + **Leads** tab; **Case management** + **Cases** tab.

### LLM provider + citation resolution (`238942d`) — verified live
The citation prompt had **never actually run against a model** before this session.
- Gemini was pinned to `gemini-2.0-flash`, which now returns 429 `limit: 0` on
  free-tier keys (`gemini-2.5-flash` 404s for new users). Every query had been
  silently falling through to the offline summary. Now tracks the `-latest`
  aliases with a fallback list, overridable via `GEMINI_MODEL`.
- **Groq's key is genuinely expired** — confirmed 401 `expired_api_key`. Replace it
  or accept Gemini-only.
- With Gemini answering, a second bug surfaced: models write `[E3, E4, E6]` as
  readily as `[E3]`, and the single-tag regex dropped grouped citations from the
  appendix — evidence the answer relied on became unverifiable. `cited_tags()`
  now parses both forms.

Verified end-to-end on `Image.E01` against `gemini-flash-latest`: USB, user-account
and log-clearing questions all emit tags, resolve to real evidence, invent none.

### Correlation engine (`e367efb`)
Driving Leads end-to-end for the first time found three defects:
- `build_correlations` capped input at 60k rows. Artifacts are concatenated one
  extractor at a time, so a `head()` cap removes **whole artifact types** rather
  than thinning evenly — all FILESYSTEM, DELETED, ACTIVITY, RECENT and most USB
  rows were never indexed. Now indexes everything.
- `top_entities` required 2 artifact types. USB serials only ever appear in USB
  rows, so `usb_serial` **could never return anything**. The 2-source rule now
  applies only to the unfiltered "All" view.
- USB serials were split in two — USBSTOR writes `I145291811100&0`, the
  device-attach record writes `I145291811100`. Normalized.

Real image: 0 → **4 USB serials**, 0 → **9 domains**, and users now surface the
actual case subjects (`jimmy wilson`, `billybob`) instead of `svchost.exe`.
Pivot rows are also deduped (was 200 byte-identical registry writes).

### Autostart in grounding facts (`86e0674`)
`Run` keys were collected then thrown away (`run_str` computed, never used).
Now reported in GLOBAL SYSTEM FACTS — a first-order persistence indicator.

### Directory-iteration truncation (`6594994`) — the big one
**A pytsk3 directory listing is invalidated by any other access through the same
handle.** Open a file, or descend into a subdirectory, while the listing is being
iterated and it silently stops early. Nothing raises; entries just never appear.

Four extractors did exactly that:

| Extractor | What was lost |
|---|---|
| `extract_all_evtx` | `System.evtx` (5,523) and `Application.evtx` (1,616) — the two largest logs |
| `extract_all_ntuser` | every profile after the first |
| `extract_user_activity` | same shape at both loop levels |
| `heuristic_discover_files`, `walk_filesystem` | siblings listed after the first subdirectory (this is the discovery path for recycle bin / browser / email) |

Full serial carve, before vs after (same image, `CARVE_MAX_WORKERS=1`):

| ArtifactType | before | after | delta |
|---|---:|---:|---:|
| REGISTRY | 54,395 | 56,869 | +2,474 |
| EVTX | 15,620 (39 channels) | **17,336 (42 channels)** | +1,716 |
| FILESYSTEM | 9,109 | **13,009** | +3,900 |
| EXECUTION | 0 | 492 | +492 |
| **BROWSER** | 0 | **73** | **+73** |
| COMMUNICATION | 0 | 28 | +28 |
| PREFETCH / RECYCLE | 0 | 5 / 4 | +9 |
| **TOTAL** | 80,554 | **89,247** | **+8,693** |

**The browser recovery is the headline.** An earlier note in this doc claimed
BROWSER was 0 because the image only has IE-era `index.dat` and the parser is
SQLite-only. **That was wrong.** The truncated discovery walk was hiding a
Firefox profile buried deep in the tree —
`AppData/Roaming/Mozilla/Firefox/Profiles/8pp14cbi.default/places.sqlite`.
With the walk completing, browser targets went 2 → 6 and Firefox parsed fine,
recovering the actual investigative payload of this training image (searches
for "identity theft jail time", "how to steal identities", "handguns").

A truncating filesystem walk does not fail loudly — it just makes the most
deeply nested evidence, which is often the most incriminating, disappear.

Also removed the bare `except: continue` that hid all of this — an unreadable
channel is a gap in the evidence and the examiner has to know which one.
Duplicate directory entries (unallocated entry sharing a name with the live one)
are now collapsed instead of double-counted.

`tests/test_extractors.py` uses a fake filesystem reproducing the truncation
semantics; **4 of its 5 tests fail against the previous code.**

### Path resolution by inode (`325d9df`) — 1,109x on the shared walk

**Never ask TSK a question by path string inside a walk.** Both walks decided
"is this entry a directory?" with `fs.open_dir(path_string)`. TSK answers that by
scanning each parent directory's entries in turn, so cost tracks **parent size,
not depth** — and a probe that *fails* scans the parent to the end before
concluding. Failing is the normal case, because the caller is usually asking
about a file.

Measured on the NIST image:

| operation | cost |
|---|---:|
| `open_dir(path)` on `/WINDOWS/system32/notepad.exe` (1,794-entry parent) | 196 ms |
| `open_dir(path)` on `/WINDOWS/system32/config/SAM` | 148 ms |
| `open_dir(inode=)` | ~0 ms |
| entries that are type-UNDEF and need the probe | 26% |

`/WINDOWS/system32` alone cost ~84s. Whole shared index: **4,145.6s → 3.7s.**
`walk_filesystem` hid the same bug only because it skips `system32` and
`program files` outright — which is also why FILESYSTEM misses those files.

**Verified byte-exact**, not just "looks right": the previous implementation was
re-run on the same image (9,691s) and the two path sets diffed — 12,614 both
ways, zero added, zero lost, zero dir/file disagreements. That diff was worth
the runtime; a naive inode swap silently lost 67 paths in two distinct ways:

- A name can list **twice under one dedup key**, with `meta_addr` 0 on the copy
  dedup keeps. `wizdata.dat` and `~DF99EB.tmp` both do. Both were filed as plain
  files, discarding an ARJ archiver toolset in the suspect's temp directory.
  Dedup now takes the inode from whichever copy has one.
- A name can list **twice under different keys** (differing `meta_type`), so both
  survive dedup and the stale copy has no inode at all. It now borrows its live
  twin's, instead of one path being reported as a directory and then as a file.

`entry.as_directory()` answers from the entry object already in hand, with no
lookup of any kind — it is the reason this lands at 3.7s instead of 302s. The
path lookup survives only as a last resort for a filesystem exposing no inodes
(the test fakes); it is unreachable on a real image. **If you remove it, 10 tests
fail** — `FakeFS` has no `as_directory()`.

### CI
`.github/workflows/tests.yml` exists **locally but is NOT pushed** — the PAT lacks
`workflow` scope. `.github/` is gitignored to stop it being re-staged.

---

## Left to do

### 0. Corrections to figures previously reported here

Three numbers in earlier versions of this document were wrong. They are
corrected in place above; recorded here so the same mistakes are not repeated.

- **"1,334 deleted files recovered" → 663.** `walk_filesystem` walked `/Users`,
  `/USERS`, `/` and `/$OrphanFiles` as overlapping roots — TSK resolves the case
  variants to one directory and `/` covers the rest — recording the same file up
  to four times. FILESYSTEM was inflated 2.8x, DELETED 2.0x. A row count was
  reported as an artifact count without ever checking distinctness.
- **"recycle bin 4 → 32" → 4 → 29.** Three of the 32 were `$Reparse`,
  `$RmMetadata` and `$Repair` — NTFS metafiles caught by a loose `^\$R` pattern,
  presented as deleted user data.
- **"BROWSER is 0 because the image is IE-era index.dat"** — wrong; it was the
  truncated discovery walk hiding a Firefox profile. Already corrected above.

The pattern in all three: a number was quoted from a row count or a single
observation without a second, independent check. Prefer distinct counts, and
prefer an external reference image over self-assessment.

### 1. Concurrency still corrupts libtsk (highest priority)
Per-task FS handles (`open_fs()` / `isolated()` in `extractors.py`) fixed the
*worst* of it — BROWSER, COMMUNICATION, PREFETCH and RECYCLE all come back, and
EXECUTION (492) / DELETED (663 distinct) are stable. **But it is not fully fixed.**

With error reporting now in place, a 14-worker carve visibly fails with
`$IDX_ROOT not found` on `System.evtx`, `GroupPolicy`, `WindowsUpdateClient` and
`Firewall` — files that parse perfectly when run serially. EVTX came out at
**7,808 and 9,023 on two threaded runs vs 17,423 serial**: roughly half the
event-log evidence, lost nondeterministically.

`CARVE_MAX_WORKERS` was added so a carve can be made reproducible (`1` = serial).

**Step 1 is done** (`693ac74`). `heuristic_discover_files` used to walk the whole
image per call, with four extractors calling it. `build_path_index()` now walks
once and every caller filters:

    per-caller walks  4,053.7s   ->   shared index  1,157.6s   (3.5x)

**Step 2 is done, and it reversed the conclusion twice.** A full serial carve of
the NIST image (`CARVE_MAX_WORKERS=1`) came in at **5,215.4s (87 min)**, split:

| phase | time | share |
|---|---:|---:|
| shared path index (single-threaded) | 4,145.6s | **79%** |
| all 16 extractors, serial | ~1,070s | 21% |

That first said "extractor concurrency cannot matter — ship serial and the
corruption problem disappears." But 12,614 paths in 4,146s is 329 ms per path,
which is not what a directory walk costs. It was the path-string probe; see
'Path resolution by inode' above. The index is now 3.7s.

**So the decision is open again, and the arithmetic is inverted:** extraction is
now ~99% of a carve of roughly 18 minutes, so worker count matters and serial no
longer gets the corruption fix for free. **Re-measure threaded vs serial on the
fixed walk before choosing a default.** Note the extractor phase has never been
profiled — it very likely contains more path-string resolution of the same kind,
and fixing that may make serial shippable on its own.

If threading is still needed and `$IDX_ROOT` corruption persists, move to
`ProcessPoolExecutor` for true isolation (libtsk keeps process-global state,
which is why per-thread handles could not fix it). The task closures
(`isolated(fn)`) aren't picklable, so this needs module-level workers taking
`(task_name, image_path, offset)`.

### 2. Promote the good carve into the cache
`src/cache/<sha256>/artifacts.pkl` still holds the **old racy carve** (80,554
rows, no BROWSER/EXECUTION/COMMUNICATION). The verified serial carve (89,247
rows) was never promoted, because replacing it changes `embed_df` size and
invalidates the cached FAISS index — forcing a ~50-minute re-embed. Do it
deliberately, and delete the stale `faiss.index` at the same time.

Scratchpad pickles from past sessions (`recarve2.pkl`, `nist_carve.pkl`) are
**gone** — scratchpads are per-session. Re-carve to regenerate; with the walk
fixed that is now ~18 min rather than ~2h, so this is much cheaper than the note
above previously implied.

### 3. Segfault during FAISS index build — root cause found, no fix applied
The citation harness segfaulted **3 times in a row** inside torch's BERT forward
(`transformers/activations.py`) while encoding ~2.3k texts, always during index
*build*. `OMP_NUM_THREADS=1` made it pass.

**Cause: three separate OpenMP runtimes loaded into one process.** Enumerated
with `EnumProcessModules` at each import step:

| runtime | loaded by |
|---|---|
| `vcomp140-55aba23c….dll` (MSVC) | `faiss_cpu.libs` — via `import faiss` at `rag.py:8`, **first** |
| `libiomp5md.dll` (Intel) | `torch/lib` |
| `vcomp140.dll` (MSVC, second copy) | `sklearn/.libs` |

Mixing OpenMP runtimes is a documented cause of nondeterministic native crashes
inside parallel regions, and it accounts for every observation on record: the
crash lands in GELU (an OMP-parallel op), only during *encode* (the only heavy
OMP workload), `OMP_NUM_THREADS=1` fixes it (no parallel region left to race in),
and **isolated encoding does not reproduce it — because that test never imported
faiss first.** `rag.py` imports faiss at module scope and `sentence_transformers`
lazily inside the function, so faiss always wins the load order in the real app.

Reproduce with `omp_check.py` (session scratchpad; note a substring match on
"omp" also catches `_dec`**`omp`**`_*.pyd` and `_middle_term_c`**`omp`**`uter.pyd`
— those are false positives, not runtimes).

**No fix applied — it needs a call:**
- `OMP_NUM_THREADS=1` before any import — known to work, costs ~4x on encode.
- **Encode in a subprocess — recommended.** A native crash then cannot take the
  Gradio server down, which is the actual risk given background index builds plus
  concurrent investigators.
- Import ordering alone — cheap, but does not remove the duplicate runtimes;
  don't trust it by itself.

### 5. The ML model is close to useless as-is
`AnomalyScore == -1` fires on **30.1%** of artifacts (23,068 / 76,693) on the
real image. Trained on synthetic CSVs that look nothing like real registry data.
`anomaly_overview()` reports the flag rate and warns, but the real fix is
retraining on features from actual carved images — or dropping the statistical
model and keeping only the heuristic Event-ID rules, which *do* work.

### 6. Not a bug: missing NTUSER hives
`BillyBob`, `Fred Flintstone`, `James Russell` and `Joe Nameless` report
"NTUSER.DAT not found" **even in a fully serial carve** — those profiles genuinely
have no hive. Only `Jimmy Wilson` does. Don't chase this.

### 7. Smaller items
- `extractors.py` is ~1780 lines — split per artifact family.
- Prefetch parsing reads only filenames/timestamps — no run counts from the `.pf` body.
- **EVTX extraction is Vista+ only.** Windows XP writes `.evt` (not `.evtx`) to
  `%SystemRoot%\system32\config\`, so the NIST XP image yields 0 event-log rows.
  Registry, SAM, prefetch and recycle bin all work on XP; only the event log
  does not. Add a `.evt` parser if XP support matters.
- `$R` recycle files carry no metadata of their own — the paired `$I` record
  names them. They are still listed individually, so a deleted item can appear
  twice (once named from `$I`, once as a bare `$R`). Consider pairing them.
- Leads ranking still puts `svchost.exe` on top; ubiquitous system binaries
  satisfy the 2-source rule trivially. Ranking is a judgement call, left alone.
- No hash sets shipped; consider documenting where to get NSRL.

---

## Gotchas

- **A truncating walk is silent.** It doesn't error — it just makes the most
  deeply nested evidence vanish, and deeply nested is often the most
  incriminating (the Firefox history here was 6 levels down). If an extractor
  returns suspiciously few artifacts, suspect the traversal before the parser.
- **Validate against someone else's ground truth.** Every self-assessment in
  this project has been too generous. The NIST image found three bugs in one
  evening that months of testing against `Image.E01` never surfaced, because a
  single test image only exercises the paths that image happens to use.
- **Count distinct things, not rows.** Two inflated figures shipped here because
  `len(df)` was reported as an artifact count.
- **Don't trust a clean run.** Nearly every bug here only appeared against the
  real E01 — ShimCache padding, mixed timezones, triage false positives, the
  thread race, the iteration truncation. Unit tests passed the whole time.
  Always re-carve the real image after touching extraction, and **read the log**.
- **Never `except: continue` in an extractor.** Two separate multi-hour
  investigations this project traced back to swallowed exceptions. A silently
  empty extractor looks exactly like an image with no such artifact.
- **Don't read through a handle that is mid-iteration.** Collect names first,
  then read. This is the single most expensive bug class here.
- Widening `EMBED_TYPES` in `rag.py` invalidates the cached FAISS index and forces
  a ~50-minute re-embed. Use `LEXICAL_TYPES` for low-volume artifact types.
- Windows security Event IDs only mean what they're documented to mean **in the
  Security channel** — always constrain with `sources`.
- Test scripts must encode output as ASCII before printing; the Windows console
  (cp1252) crashes on emoji and some artifact text.
- The GitHub token lives in `src/.env` as `GITHUB_TOKEN` (gitignored).
