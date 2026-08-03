# Vigilance-Core — Progress & Handoff

Working notes for continuing this project. Last updated after finding out why
the FAISS index build had never once completed: **the machine has no page file,
and the encode batch size was asking for more memory than it could commit.**
The index is now built (60,414 vectors) and retrieval is verified against it.

Repo: `holialli/Vigilance-Core` (branch `main`). 142 tests passing (`python -m pytest tests/ -q`).

**Goal:** conversational forensics — an investigator asks questions in natural language
instead of manually hunting through artifacts. Not trying to match Autopsy's parser
coverage; competing on the AI/triage layer Autopsy doesn't have.

> Push with a transient auth header built from `GITHUB_TOKEN` in `src/.env`
> (`git -c http.extraheader=...`); never write it to git config.

---

## Start here

**State:** clean. `main` at `b12f998`, working tree clean, 142 tests passing,
NIST re-validated 11/11 through a full carve. Nothing is half-finished.

**In flight:** nothing. The IACIS case (`6c18f662…`) now has a complete
`faiss.index` — 60,414 vectors — and three test queries return real evidence off
it. That had been the outstanding blocker for three sessions.

**Next, in the order I'd do it:**

1. **Turn on a page file** (item 3 below). This is the one that matters and it
   is a Windows setting, not code: System → About → Advanced system settings →
   Performance → Advanced → Virtual memory. Right now `ullTotalPageFile ==
   ullTotalPhys`, so the commit limit *is* RAM and the app runs with 400–2,600 MB
   of headroom. Every workaround in `embedding.py` exists to fit inside that.
   **Not done here deliberately** — it needs admin, affects the whole machine,
   and is the owner's call.
2. **Retrain or retire the anomaly model** (item 5 below). Still fires on 30% of
   artifacts; the biggest *quality* gap left, now that the index builds.
3. **Sweep `FORENSICS_EMBED_BATCH` upward** once a page file exists. 32 was
   chosen to fit today's headroom; 64 was 1.2x faster in the sweep and 256 only
   lost because it thrashed. This is pure throughput, worth little until (1).
4. **Parallelise EVTX with a process pool** (item 1 below). 83% of a carve, and
   the only thing left that is slow. Optional: nobody is complaining about 107s.
   Note it will want memory too — see (1) before starting.

**Method note that has now paid off three times:** when a rewrite changes a
count — or when you believe it changes nothing — diff the actual sets rather
than reasoning about whether the delta is benign. It caught 67 silently-lost
paths last session, and this session it is the only reason the `walk_filesystem`
change could be shipped as byte-identical rather than hoped to be.

**And a second one, new:** re-measure after a fix instead of carrying the old
number forward. Two of this session's three findings were just *stale figures* —
the extractor phase was recorded at ~1,070s when it was really 67s, and the
concurrency decision had been made against those wrong numbers.

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

Carve is ~107s (Win7) / ~22s (NIST) warm; background it anyway and redirect
output. Timings: see 'Extractor profile' and 'Concurrency' below.
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
  embedding.py    sentence embedding; bulk encode isolated in a subprocess
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
  double-counting fix below. The true figure on this image is **666** (see item 2).
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

### Extractor profile + the last two path probes (`8d1ec36`)

The extractor phase had never been profiled. `profile_extractors.py` (session
scratchpad) runs all 16 extractors serially, each against its own TSK handle
wrapped in a proxy that counts every `open_dir`/`open` **split by how it
resolves** — path string vs inode. Call counts are the useful output; they are
cache-independent, which wall-clock here is emphatically not.

Serial, cold, whole phase: **NIST 67.3s, Win7 333.1s.**

| phase | Win7 | NIST | note |
|---|---:|---:|---|
| EVTX | **277.6s** | 1.8s | 83% of Win7; only 0.3s of it is TSK |
| FILESYSTEM | 27.1s | 30.7s | 17.4s of Win7 was 34 path probes |
| SYSTEM | 11.1s | 5.7s | |
| PATH_INDEX | 8.3s | 11.3s | already fixed in `325d9df` |
| SRUM | 0.1s | 5.8s | 7 failed path opens on XP |
| *other 12* | ≤3.2s | ≤1.7s | |

Two survivors of the `325d9df` path-string bug, both now fixed:

- `walk_filesystem` probed UNDEF-typed entries with `fs.open_dir(path)`. 34
  probes, 512ms each, **17.4s of a 27.1s walk** — and every one was a deleted
  `Content.IE5` cache file with no inode and no live twin, so every probe
  returned nothing. `build_path_index` had already solved this case
  (`as_directory()`, then a live twin's inode) and **never** resolves an UNDEF
  entry by path; `walk_filesystem` had simply never been aligned with it.
  A probe that cannot succeed is pure cost.
- `extract_srum_data` probed 7 hardcoded case variants of `SRUDB.dat` *before*
  consulting the path index it is already handed. All 7 fail on an image with no
  SRUM at ~800ms each. Index first now; 7 path opens → 0.

Verified by set diff, not by eye: walk output byte-identical on both images —
5,262 paths (Win7), 6,168 (NIST), zero added, zero lost, zero dir/file
reclassifications.

**Checked and *not* a bug:** `extract_recent_documents` (L1654) and
`extract_browser_history` (L1001) call `open_dir` while iterating `users_dir`,
which is the truncation pattern three other extractors were fixed for. Tested
directly on both images: 7/7 profile entries survive in each. Profile
directories are small enough to stay resident, so it does not reproduce. Left
alone deliberately — noted here so the next reader doesn't re-investigate it.

### CI
`.github/workflows/tests.yml` exists **locally but is NOT pushed** — the PAT lacks
`workflow` scope. `.github/` is gitignored to stop it being re-staged.

---

## Left to do

### 0. Corrections to figures previously reported here

Three numbers in earlier versions of this document were wrong. They are
corrected in place above; recorded here so the same mistakes are not repeated.

- **"1,334 deleted files recovered" → 666.** `walk_filesystem` walked `/Users`,
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

A fourth, and the most expensive so far:

- **"The index build crashes because four OpenMP runtimes are co-loaded"** —
  wrong, and it survived three sessions because the evidence *did* fit: the
  crash was a `0xC0000005` inside an OMP-parallel op, and `OMP_NUM_THREADS=1`
  made it go away. All true, all explained equally well by the actual cause —
  a machine with no page file and a child asking for 2.9 GB of a 2.5 GB budget.
  The runtime enumeration was careful and correct; it just wasn't the question.
  **A hypothesis that explains the evidence is not the same as the one that is
  true, and the cheap discriminating test here — "how much memory does this
  process actually ask for?" — was never run.** Three sessions of work went into
  containing a symptom. When a fix keeps *nearly* working, suspect the diagnosis
  rather than reaching for a bigger version of the same fix.

### 1. Concurrency — DECIDED: the carve is serial (`CARVE_MAX_WORKERS=1`)

**Resolved.** The default is now `1`. Threading was measured against serial on
both reference images, through `carve_evidence_from_image` rather than a
harness, and it loses on both axes:

| | Win7 `Image.E01` | | NIST XP | |
|---|---:|---:|---:|---:|
| | **serial** | 14 workers | **serial** | 14 workers |
| wall | **106.5s** | 112.8s | 21.8s | **20.0s** |
| total rows | **80,191** | 79,853 | **30,017** | 29,935 |
| EVTX | **17,336** | 17,001 | 0 (XP) | 0 |
| PREFETCH | **81**† | 81 | **81** | **0** |

† Win7 prefetch is 5; the 81 figure is the NIST column.

Threading is **slower on the image that matters** and loses evidence on both.
On Win7 it dropped 6 EVTX channels to `$IDX_ROOT not found`
(`Diagnosis-PLA`, `Diagnosis-Scheduled`, `Winlogon`, `Kernel-WHEA`,
`Diagnosis-DPS`, `RestartManager`) plus 2 ACTIVITY and 1 COMMUNICATION row. On
NIST it lost **all 81 prefetch rows** — which is not an abstract loss:
**NIST Q16 is answered through prefetch** (Ethereal and NetStumbler are found
nowhere else), so a threaded carve regresses the external validation from 11/11.

It loses on speed because the phase is **83% EVTX parsing**, and that is pure
Python under the GIL — `python-evtx` builds an XML string per record and
re-parses it with ElementTree (~16ms × 17,336 records). Threads cannot overlap
that with anything but libtsk's C calls, while still paying for 16 extra image
handles and the contention that corrupts libtsk in the first place.

**The way to actually parallelise a carve is a process pool over the 65 EVTX
files**, not over the 16 extractors. That is real work — the task closures
(`isolated(fn)`) aren't picklable, so it needs module-level workers taking
`(task_name, image_path, offset)` — but it is the only remaining speedup worth
having, and it sidesteps libtsk's process-global state instead of fighting it.

Everything below is the original analysis, kept because the reasoning is the
reusable part.

### 1a. Concurrency corrupts libtsk (historical)
Per-task FS handles (`open_fs()` / `isolated()` in `extractors.py`) fixed the
*worst* of it — BROWSER, COMMUNICATION, PREFETCH and RECYCLE all come back, and
EXECUTION (492) / DELETED (666 distinct) are stable. **But it is not fully fixed.**

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

That reopened the decision, on the reading that extraction was now ~99% of a
roughly 18-minute carve. **That reading was wrong, and for an avoidable reason:
the ~1,070s extractor figure was measured *before* `325d9df`, and nobody
re-measured it after.** `walk_filesystem` got the inode fix in that same commit,
so the extractors had already sped up along with the walk. Profiled properly
(`profile_extractors.py`, session scratchpad — wraps the TSK handle and counts
every call by how it resolves), the phase is **67.3s on NIST and 333.1s on
Win7**, not 1,070s. See 'Extractor profile' under Done.

The lesson is cheap to state and was expensive to learn twice: **a figure
measured before a fix is not evidence about the code after it.**

### 2. Promote the good carve into the cache — DONE

`src/cache/6c18f662…/artifacts.pkl` (the IACIS Win7 case) held the **old racy
carve**, and a cache hit served it straight to the investigator. Promoted a
fresh serial carve through the app's own path — `carve_evidence_from_image` →
`engineer_features` → `save_case` — so the file is exactly what the app would
have written on a miss. Carve took 163s.

| ArtifactType | cached | fresh | |
|---|---:|---:|---|
| BROWSER | 0 | **73** | was missing entirely |
| EXECUTION | 0 | **492** | was missing entirely |
| RECYCLE | 0 | **29** | was missing entirely |
| COMMUNICATION | 0 | **28** | was missing entirely |
| PREFETCH | 0 | **5** | was missing entirely |
| EVTX | 15,620 | **17,336** | +1,716 (truncation fix) |
| REGISTRY | 54,395 | **56,869** | +2,474 (truncation fix) |
| ACTIVITY | 13 | 14 | |
| FILESYSTEM | 9,109 | 4,596 | −4,513, expected: 2.8x dedup |
| DELETED | 1,334 | 666 | −668, expected: 2.0x dedup |
| **TOTAL** | 80,554 | **80,191** | |

The total barely moves while five artifact types go from *nothing* to real
evidence — which is exactly why a row count is a bad health check.

Old file kept as `artifacts.pkl.racy-<timestamp>`; stale `faiss.index` (89 MB,
built from the old embed set) deleted.

**Correction:** this document said the true DELETED figure was 663. It is
**666** on a current serial carve, stable across three runs.

Note `artifacts.pkl.bak` in the same directory is a *different* older carve
(71,900 rows — has BROWSER/COMMUNICATION but no FILESYSTEM/DELETED/EXECUTION).
Neither backup is worth keeping once the promoted carve is confirmed good.

### 3. The index build "segfault" — SOLVED. It was memory, and the box has no page file.

**The index now builds.** 60,414 vectors, zero stalls, and retrieval verified
against it. Three sessions attributed this to mixed OpenMP runtimes. That was
wrong, and the correct answer is embarrassingly ordinary.

**This machine has no page file.** `GlobalMemoryStatusEx` reports
`ullTotalPageFile == ullTotalPhys` (16,242 MB both), `Win32_PageFileUsage`
returns nothing, and `AutomaticManagedPagefile` is `False`. So the **system
commit limit is physical RAM**. Measured while the app holds a case:

| moment | avail commit | avail *physical* |
|---|---:|---:|
| idle, case loaded | 2,060 MB | 5,213 MB |
| FAISS index loaded | 1,063 MB | 5,115 MB |
| during an index build | **369 MB** | 3,702 MB |

**That second column is why nobody found this.** Free RAM never drops below
~3.7 GB, so every casual look at memory said "plenty free" while the number that
actually governs allocation was down to 369 MB.

**And the child was sized for a machine with room.** Peak memory per encode
child is set by `batch_size` — texts per forward pass — not by chunk size, which
only decides how long a process lives. Chunk size is what three sessions tuned.
`batch_size` sat at **256**, pinned in `rag.py`, overriding the module default.
Same 500 real artifact texts, three interleaved rounds, one child per row:

| batch | peak commit | encode time |
|---:|---:|---:|
| 256 | **2,871 MB** | 15.4s |
| 64 | 1,490 MB | 6.7s |
| 32 | 1,228 MB | 5.5s |
| 8 | 1,041 MB | 4.7s |

A child asking for 2,871 MB on a box with ~2,500 MB of free commit does not get
it. **256 was also the slowest setting** — it thrashes on the way to failing —
so dropping to 32 made the encode 2.8x faster *and* halved its memory. The
loaded model alone is ~1,040 MB of that floor.

**Why it looked like a segfault.** An allocation Windows cannot commit returns
NULL, and native code that does not check dereferences it: `0xC0000005`, no
traceback, indistinguishable from the OpenMP fault this project went looking
for. It is not always silent, though, and the loud version names itself:

    OSError: The paging file is too small for this operation to complete.
             (os error 1455)

That is `ERROR_COMMITMENT_LIMIT`. **Treat any `0xC0000005` from an encode child
as an allocation failure until proven otherwise** — check
`GlobalMemoryStatusEx().ullAvailPageFile` before opening a debugger.

**The natural experiment that settles it.** Chunk 115 of this build killed five
consecutive children, including the serialised-OpenMP last resort. Minutes
later, the *same* chunk encoded cleanly 12 times out of 12 across four batch
sizes — from a parent process holding nothing. Same data, same child code, same
machine, same hour. The variable was memory, and nothing else. That also
explains the "`import faiss` in the parent makes children die 5/5" result
recorded below without needing any mechanism: faiss in the parent is ~1 GB of
commit the child then cannot have.

**Fixed in `90ff10a` and `b12f998`:**
- Default `batch_size` 256 → **32** (`FORENSICS_EMBED_BATCH`), and `rag.py` no
  longer pins it.
- A stalled chunk is retried at **half the batch**, down to a floor of 8, and
  the ladder resets on progress. Retrying an allocation the machine cannot
  satisfy with the identical allocation was never going to work.
- `encode_query` falls back to a child process on a memory failure instead of
  raising. It loads ~1,040 MB *into the server*, at the worst possible moment —
  the first question after an index build. That is what died with error 1455.
- The model loads with `local_files_only=True` first. Every child spawn had
  been re-resolving it over the network; one build lost two of its five stall
  slots to `RuntimeError: Cannot send a request, as the client has been closed`
  from httpx. Model load: 22.2s → 13.5s per process.

**The real fix is one Windows setting: enable a page file.** Everything above is
the code fitting into a commit limit that should not be this small. Left undone
deliberately — admin rights, machine-wide effect, owner's call.

---

Everything below is the original OpenMP investigation, kept because the runtime
enumeration is accurate and the probe lessons are the reusable part. **Its
conclusion is superseded**: four OpenMP runtimes really are co-loaded, but that
is not what was crashing the encode.

The citation harness segfaulted **3 times in a row** inside torch's BERT forward
(`transformers/activations.py`) while encoding ~2.3k texts, always during index
*build*. `OMP_NUM_THREADS=1` made it pass — which fits memory too: fewer threads
means fewer per-thread workspaces, so it pulls the same lever, less efficiently.

**Four OpenMP runtimes are loaded into one process.** Re-enumerated with
`EnumProcessModules` at each import step. **There are four, not three** — the
earlier count missed one of torch's:

| runtime | loaded by |
|---|---|
| `vcomp140-55aba23c….dll` (MSVC) | `faiss_cpu.libs` — via `import faiss` at `rag.py:8`, **first** |
| `libiomp5md.dll` (Intel) | `torch/lib` |
| `libiompstubs5md.dll` (Intel) | `torch/lib` |
| `vcomp140.dll` (MSVC, second copy) | `sklearn/.libs` |

Mixing OpenMP runtimes is a documented cause of nondeterministic native crashes
inside parallel regions, and it accounts for every observation on record: the
crash lands in GELU (an OMP-parallel op), only during *encode* (the only heavy
OMP workload), and `OMP_NUM_THREADS=1` fixes it (no parallel region left to race
in).

**Correction to the earlier note:** it said isolated encoding "does not
reproduce it — because that test never imported faiss first." That is wrong. A
faiss-free child process reproduces the crash roughly half the time. Dropping
faiss removes one runtime of four; the remaining three still conflict. Measured
on 2,000 real artifact texts:

| where | result |
|---|---|
| in-process, faiss loaded (the old path) | **segfault 3 / 3 runs** |
| child process, no faiss | segfault ~1 / 2 runs |

**Watch the probe itself.** The first enumeration reported *zero* runtimes
everywhere, which looks like a clean bill of health and is really a broken
measurement: `ctypes` truncates the 64-bit `HANDLE` from `GetCurrentProcess`
unless you set `restype`/`argtypes`, so `EnumProcessModules` quietly returns
nothing. Make the probe raise when it enumerates nothing. (Also note a substring
match on "omp" catches `_dec`**`omp`**`_*.pyd` and
`_middle_term_c`**`omp`**`uter.pyd` — false positives, not runtimes.)

**Fixed in `f89313e`:** bulk encoding moved into a child process
(`src/forensics/embedding.py`). This **contains** the crash rather than
preventing it — the child still crashes, but it exits with a status the parent
catches instead of killing the Gradio server. It never falls back to encoding in
the parent. Verified bit-identical to in-process encoding (max abs diff 0.0, min
cosine 1.0 over 400 real texts), so retrieval is unchanged.

**Then the first full-scale run showed retrying the whole job is useless.**
Crash probability scales with how much work one process does:

| texts in one encode call | result |
|---|---|
| 400 | never observed crashing |
| 2,000 | crashed 1 run in 3 (`OMP_NUM_THREADS=1`: 2/2 OK) |
| 60,414 (the real embed set) | **crashed 5 runs out of 5, including with `OMP_NUM_THREADS=1`** |

So `OMP_NUM_THREADS=1`, recorded here as "known to work", **works at 2k and not
at 60k**. Any fix that reruns the whole encode is dead on arrival at real scale.

> Read this table again knowing the cause is memory and it says something
> simpler: more texts held at once, more memory, less headroom. It is a memory
> curve, not a crash-probability curve. `OMP_NUM_THREADS=1` shifted it a little
> because each OpenMP thread carries its own workspace — it was never a fix.

**So the encoder is chunked and resumable.** Each chunk (default 500, via
`FORENSICS_EMBED_CHUNK`) is written out before the next starts, a dying child
costs only the chunk in flight, and its replacement resumes there. The give-up
rule counts **stalls, not attempts** — consecutive children that complete zero
chunks — because under a fixed retry budget a 60-chunk job could never finish.
The child walks the remaining chunks itself so the model is loaded once per
crash rather than once per chunk. Chunk files are written to a temp name and
renamed, so a crash mid-write cannot leave a truncated file that reads as done.

**Chunk size is not about the crash rate, it is about finishing before the
crash.** The first chunked build still failed, stalling at chunk 0 five times:
with 1,000-text chunks the child died *before completing one*, so resumption had
nothing to resume from. What matters is that a chunk lands.

> **Superseded.** Chunk size never had much to do with it. Peak memory is set by
> `batch_size`, which is per *forward pass* and was 256 throughout all of this
> tuning; chunk size only changes how many batches a process runs. Smaller
> chunks helped by ending processes sooner, not by making any one of them fit.
> Resumability is still worth having, so the chunking stays — but 500 is a
> resumption granularity now, not a crash mitigation.

**Finished chunks are kept in the case directory, not a temp dir.** The first
run that got this far stalled at chunk 55 of 121 — and `TemporaryDirectory`
deleted an hour of encoding on the way out. `encode_bulk(work_dir=...)` now
writes chunks to `src/cache/<sha256>/embed_chunks/`, so a build that gives up
can simply be re-run and picks up where it stopped. The directory carries a
fingerprint of the text set and chunk size; if either changes the old chunks are
discarded, because chunk 12 of a different text set is not chunk 12 of this one
and reusing it would corrupt the index silently rather than fail.

**It is memory, not OpenMP** — this was written as a hypothesis and is now the
confirmed cause; see the top of this section. The same child on the same payload
behaves very differently depending on what the *parent* has loaded, because
parent and child compete for one system-wide commit limit:

| parent holds | child outcome (chunk=1000) |
|---|---|
| nothing | 2 chunks+, survived past 100s (3 runs; 1 crash after 1 chunk) |
| the 80k-row DataFrame | same — 1 crash after 1 chunk, 1 survived |
| **`import faiss`** | **0 chunks, crashed in ~30s, 5 runs out of 5** |

These are separate processes, so this looked inexplicable at first. It is not
the inherited environment (`import faiss` changes nothing in `os.environ` —
checked) and not the CPU affinity mask (`0xff` before and after — checked, but
see the redirector-stub gotcha below: if that check was aimed at `Popen.pid` it
was reading the launcher, not the interpreter. It no longer matters — the answer
is that both processes draw on one system-wide commit limit).

Then a test run launched *while a build was already running* failed with
`OpenBLAS error: Memory allocation still failed after 10 retries, giving up.`
— an explicit allocation failure, not a segfault. That is the first direct
evidence of what is actually going on: **this box has 16 GB, an encode child
wanted ~2.9 GB at the batch size then in use, and every extra thing the parent
holds (faiss, the DataFrame, another encode process) eats the headroom.** It
fits everything: crash probability rising with texts per process, the `import
faiss` parent being worst, and my own concurrent measurements making things
worse. What this still missed is that the 16 GB was never the ceiling — with no
page file the *commit* limit is what binds, and free commit ran to a few
hundred MB.

That was recorded as a leading hypothesis, hedged because the failures are
usually 0xC0000005 rather than a clean allocation error. **The hedge was
unnecessary** — on Windows an uncommittable allocation *is* a 0xC0000005 as soon
as the caller skips the NULL check, so the two are the same observation. It
still means **don't run anything heavy while an index build is going**.

`rag.py` now also imports faiss **lazily**, after `encode_bulk` returns, so a
fresh index build encodes before faiss is loaded in that process. Once loaded it
stays, so this helps the first build in a process — the expensive one.

**Two broken probes this session, same root cause.** Both the OpenMP enumeration
and the CPU-affinity check returned confident, clean-looking answers — "zero
runtimes loaded", "affinity 0x0" — because `ctypes` truncates the 64-bit
`HANDLE` from `GetCurrentProcess` without explicit `restype`/`argtypes`. A
zeroed affinity mask is impossible and should have been obviously wrong. Always
sanity-check a Win32 probe against a value you already know.

**"Query embedding stays in-process, never observed crashing" — it crashed.**
That note reasoned about the *encode* (one short string, trivial) and missed
that the cost is the **model load**, which is ~1,040 MB whether the string is
one word or ten thousand. It failed with error 1455 on the first query after an
index build. It now falls back to a child on a memory error.
`FORENSICS_EMBED_IN_PROCESS=1` still disables subprocessing entirely.

**The durable fix is environmental, but not the one recorded here.** It is not
about getting faiss/torch/sklearn onto one OpenMP runtime — it is
**enable a page file**. Until then the code is fitting into a commit limit that
happens to equal RAM.

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
- **Time a carve cold, or count calls instead.** The OS caches the decoded E01,
  so a second run of the same walk is 2-3x faster for no reason of yours —
  `walk_filesystem` measured 27.1s cold and 8.8s warm on the same code. When
  comparing implementations, either compare warm-to-warm, or measure something
  cache-independent: the number of `open_dir(path)` calls is the honest metric
  here, since each one is a directory scan whether or not the blocks are cached.
- **A figure measured before a fix is not evidence about the code after it.**
  The extractor phase sat in this document at ~1,070s while it was really 67s;
  the same commit that fixed the walk had sped the extractors up too. A whole
  decision (`CARVE_MAX_WORKERS`) was made twice against that stale number.
- **On Windows, watch available *commit*, not available RAM.** They differed by
  3 GB here and only one of them governs whether an allocation succeeds. This
  box has no page file, so its commit limit *is* physical RAM
  (`ullTotalPageFile == ullTotalPhys` — that equality is the test). Free RAM
  read 3.7 GB while free commit was 369 MB, which is why three sessions looked
  at memory and saw nothing wrong.
- **A `0xC0000005` with no traceback is an out-of-memory until proven
  otherwise.** An allocation Windows cannot commit returns NULL and unchecked
  native code dereferences it, which is byte-for-byte what a wild pointer looks
  like. This project spent three sessions attributing those to mixed OpenMP
  runtimes. The runtimes really were mixed; they just weren't the problem.
  When the same failure surfaces cleanly it says so — `OSError: The paging file
  is too small for this operation to complete. (os error 1455)`.
- **Match OS error messages, not just codes, across a Rust boundary.**
  `safetensors` raises its `std::io::Error` as a bare Python `OSError` with no
  `.winerror`. `"[WinError 1455]"` means Python raised it and the code is
  available; `"(os error 1455)"` means Rust did and only the string is.
- **`.venv/Scripts/python.exe` is a redirector stub, not the interpreter.** It
  spawns the real python as a *separate process*, so `Popen.pid` names something
  that allocates about 1 MB. A child holding 700 MB measured as 0.8 MB. Any
  per-process probe (memory, affinity, handles) aimed at that pid is measuring
  the wrong process — have the child report its own numbers instead.
- **Tune the dial the resource is actually on.** Three sessions tuned
  `FORENSICS_EMBED_CHUNK` (texts per *process*) while peak memory was set by
  `batch_size` (texts per *forward pass*), which sat at 256 the whole time —
  and was pinned by the caller, so the module default never applied. Check that
  a default is reachable before concluding it is wrong.
- **Don't run anything heavy while an index build is going.** Encode children
  want ~1.2 GB each on this box, and a second Python process tipped one build
  from steady progress into its stall limit — my own measurement run caused the
  only stall-out this design has had. It also invalidates whatever you were
  measuring: an `OpenBLAS` allocation failure is what finally revealed the
  memory angle, but everything timed under that load was noise.
- **Don't edit `embedding.py` while an index build is running.** The child
  re-executes that file from disk on *every* spawn, so an edit lands mid-run and
  changes the behaviour of an operation already in flight. A missing `import re`
  added during a build turned retries 3-5 of a 5-attempt run into `NameError`s
  that looked exactly like more crashes, and destroyed the measurement. It is
  the one real downside of running the encoder as a script rather than a module.
- **Make a probe fail loudly when it measures nothing.** The OpenMP enumeration
  reported zero runtimes in every process — indistinguishable from "no problem
  here", and actually a truncated Win32 handle returning an empty list. A
  diagnostic that can return a clean-looking null result is worse than none; it
  now raises if it enumerates nothing.
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
  a full re-embed of ~60k texts. Use `LEXICAL_TYPES` for low-volume artifact
  types. The old "~50 minutes" here predates the batch-size fix; extrapolating
  from the tail of the completed build it should now be ~15 min, but nobody has
  timed a rebuild from zero — say so rather than quoting the estimate as fact.
- Windows security Event IDs only mean what they're documented to mean **in the
  Security channel** — always constrain with `sources`.
- Test scripts must encode output as ASCII before printing; the Windows console
  (cp1252) crashes on emoji and some artifact text.
- The GitHub token lives in `src/.env` as `GITHUB_TOKEN` (gitignored).
