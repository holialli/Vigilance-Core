"""Sentence embedding, with the bulk index build isolated in a subprocess.

Four separate OpenMP runtimes end up loaded in the app process, measured with
EnumProcessModules at each import step:

    vcomp140-<hash>.dll   MSVC     faiss_cpu.libs   (via `import faiss`, first)
    libiomp5md.dll        Intel    torch/lib
    libiompstubs5md.dll   Intel    torch/lib
    vcomp140.dll          MSVC     sklearn/.libs    (a second MSVC copy)

Mixing OpenMP runtimes is a documented cause of nondeterministic native crashes
inside parallel regions, and it accounts for every observation on record: the
crash lands in GELU (an OMP-parallel op), only while encoding, and setting
OMP_NUM_THREADS=1 makes it go away because no parallel region is left to race
in.

A segfault is not an exception. `_background_index_build` in `chatbot_app.py`
runs the index build on a daemon thread inside a `try/except Exception`, which
cannot catch a native crash — the whole Gradio server dies, taking every
concurrent investigator's session with it. That is the risk worth removing.

So the bulk encode runs in a child process. **This contains the crash rather
than preventing it**, and the distinction matters: dropping `faiss` removes only
one of the four runtimes, and the child was measured still loading three (torch's
two plus sklearn's, pulled in transitively by sentence-transformers). A child has
in fact been observed dying with 0xC0000005 on 2,000 real artifact texts.

What the child buys is that the failure is now a non-zero exit status the parent
can catch. Measured on real artifact text:

    in-process, faiss loaded (the old path)   segfault 3 / 3 runs at 2,000 texts
    child process, no faiss                   segfault 1 / 3 runs at 2,000 texts
    child process, no faiss                   segfault 5 / 5 runs at 60,414 texts

So the child is not safe, it is *survivable* — and that is the whole difference,
because the old path took the server with it every time.

Retrying the whole job does not scale, though: crash probability rises with how
much work one process does, and at 60,414 texts every attempt died, including
with OMP_NUM_THREADS=1 (which this project had recorded as "known to work" — it
works at 2k, not at 60k). So the encode is **chunked and resumable**: each chunk
is written out before the next begins, a dying child costs only the chunk it was
on, and the replacement resumes from there. Progress, not attempts, is what the
give-up rule counts.

The durable fix is environmental rather than code: get faiss, torch and sklearn
onto a single OpenMP runtime (matching wheels, or a conda-forge stack). Until
then this contains the damage.

Query embedding stays in-process: it is a single short string rather than
thousands, the crash has never been observed there, and a subprocess per query
would add a model load to every question. That leaves a small residual exposure;
set FORENSICS_EMBED_IN_PROCESS=1 to disable subprocessing entirely, or
OMP_NUM_THREADS=1 for the whole app to remove the race at the cost of speed.
"""

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import threading

import numpy as np

MODEL_NAME = "all-MiniLM-L6-v2"
DEFAULT_BATCH_SIZE = 256

_model = None
_model_lock = threading.Lock()


def _load_model():
    """Load the sentence transformer into *this* process, once."""
    global _model
    with _model_lock:
        if _model is None:
            from sentence_transformers import SentenceTransformer
            _model = SentenceTransformer(MODEL_NAME)
    return _model


def encode_in_process(texts, batch_size=DEFAULT_BATCH_SIZE):
    """Encode in the calling process. A crash here kills the process."""
    model = _load_model()
    return model.encode(
        list(texts),
        batch_size=batch_size,
        show_progress_bar=False,
        convert_to_numpy=True,
    )


def encode_query(text):
    """Embed a single query string, in-process. See the module docstring."""
    return encode_in_process([text], batch_size=1)


def _subprocess_enabled():
    return os.getenv("FORENSICS_EMBED_IN_PROCESS", "").strip() not in ("1", "true", "True")


# Crash probability scales with how much work one process does, so the encode is
# split into chunks and each finished chunk is persisted. Measured on real
# artifact text:
#
#     400 texts       never observed crashing
#   2,000 texts       crashed 1 run in 3
#  60,414 texts       crashed 5 runs out of 5 — including with OMP_NUM_THREADS=1
#
# That last line matters: retrying the whole job is useless at real scale, and
# the OMP_NUM_THREADS=1 escape hatch this project had recorded as "known to
# work" does not work either once the job is big enough. Only bounding the work
# per process does.
# 500 rather than 1,000 because what matters is not the crash rate but whether a
# chunk *finishes before the crash*. Driven from a parent holding faiss, a child
# given 1,000-text chunks died having completed nothing, 5 runs out of 5 — the
# encode could never start. The same child on 250-text chunks banked a chunk
# every time, which is all resumption needs.
CHUNK_SIZE = int(os.getenv("FORENSICS_EMBED_CHUNK", "500"))

# Consecutive child spawns that finish *zero* new chunks before giving up. This
# is a stall counter, not an attempt counter: as long as a child completes at
# least one chunk before dying, the encode is still making progress and gets
# another process. Otherwise a 60-chunk job could never finish under a fixed
# retry budget.
MAX_STALLS = 5


def encode_bulk(texts, batch_size=DEFAULT_BATCH_SIZE, chunk_size=None,
                max_stalls=MAX_STALLS, work_dir=None):
    """Embed many texts in child processes, resuming across crashes.

    Work is split into chunks and every finished chunk is written to disk, so a
    child that dies costs only the chunk it was on. Returns a float32 array of
    shape (len(texts), dim). Raises RuntimeError once the encode stops making
    progress — deliberately never falling back to encoding in the parent, since
    running a known-crashy workload in the server process is precisely the
    outcome this exists to prevent.

    `work_dir` keeps finished chunks somewhere durable, so a build that gives up
    resumes from where it stopped instead of starting over. Without it the
    chunks live in a temp directory that is deleted on the way out — which threw
    away 55 of 121 finished chunks the first time this hit its stall limit.
    """
    texts = list(texts)
    if not texts:
        return np.empty((0, 0), dtype="float32")

    if not _subprocess_enabled():
        return encode_in_process(texts, batch_size=batch_size)

    chunk_size = chunk_size or CHUNK_SIZE
    n_chunks = (len(texts) + chunk_size - 1) // chunk_size

    if work_dir:
        os.makedirs(work_dir, exist_ok=True)
        return _encode_into(texts, batch_size, chunk_size, n_chunks,
                            max_stalls, work_dir)
    with tempfile.TemporaryDirectory(prefix="forensics_embed_") as tmp:
        return _encode_into(texts, batch_size, chunk_size, n_chunks,
                            max_stalls, tmp)


def _encode_into(texts, batch_size, chunk_size, n_chunks, max_stalls, work):
    in_path = os.path.join(work, "texts.json")
    payload = {"texts": texts, "batch_size": batch_size,
               "model": MODEL_NAME, "chunk_size": chunk_size}

    # A resumed run must be encoding the same texts, or chunk N from the old run
    # means something different from chunk N now — which would corrupt the
    # index silently rather than fail. Drop stale chunks if anything changed.
    fingerprint = _fingerprint(texts, chunk_size)
    fp_path = os.path.join(work, "fingerprint.txt")
    prior = None
    if os.path.exists(fp_path):
        with open(fp_path, encoding="utf-8") as fh:
            prior = fh.read().strip()
    if prior and prior != fingerprint:
        stale = [f for f in os.listdir(work) if f.startswith("chunk_")]
        for f in stale:
            os.remove(os.path.join(work, f))
        print(f"  [EMBED] Text set changed since the last run; discarded "
              f"{len(stale)} stale chunk(s).")
    with open(fp_path, "w", encoding="utf-8") as fh:
        fh.write(fingerprint)

    with open(in_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh)

    def remaining():
        return [i for i in range(n_chunks)
                if not os.path.exists(os.path.join(work, f"chunk_{i}.npy"))]

    resumed = n_chunks - len(remaining())
    if resumed:
        print(f"  [EMBED] Resuming: {resumed}/{n_chunks} chunks already encoded.")

    failures, stalls = [], 0
    while True:
        todo = remaining()
        if not todo:
            break
        start, before = todo[0], n_chunks - len(todo)

        # Only once the fast path has stalled repeatedly is it worth paying
        # for serialised OpenMP — and note that is not a guaranteed fix at
        # scale, merely lower-risk for one chunk.
        env = dict(os.environ)
        if stalls >= max_stalls - 1:
            env["OMP_NUM_THREADS"] = "1"

        ok, detail = _run_child(in_path, work, start, env)
        gained = (n_chunks - len(remaining())) - before

        if ok and not remaining():
            break

        if gained > 0:
            stalls = 0
            print(f"  [EMBED] Encode child died after completing {gained} "
                  f"chunk(s); resuming at {n_chunks - len(remaining())}"
                  f"/{n_chunks}.")
        else:
            stalls += 1
            failures.append(f"chunk {start}: {detail}")
            print(f"  [EMBED] Encode child made no progress at chunk "
                  f"{start}/{n_chunks} ({detail}); "
                  f"stall {stalls}/{max_stalls}.")

        if stalls >= max_stalls:
            done = n_chunks - len(remaining())
            raise RuntimeError(
                f"Embedding stalled at chunk {start} of {n_chunks} while "
                f"encoding {len(texts)} texts — {max_stalls} consecutive child "
                f"processes completed nothing. {done}/{n_chunks} chunks are "
                f"encoded and kept; re-running resumes from there. "
                + " || ".join(failures[-3:])
            )

    parts = [np.load(os.path.join(work, f"chunk_{i}.npy"))
             for i in range(n_chunks)]
    return np.concatenate(parts, axis=0).astype("float32")


def _fingerprint(texts, chunk_size):
    """Identity of a chunk set: same texts, same boundaries, or start over."""
    h = hashlib.sha256()
    h.update(f"{len(texts)}:{chunk_size}:".encode())
    for t in texts:
        h.update(t.encode("utf-8", "replace"))
        h.update(b"\0")
    return h.hexdigest()


# Progress bars and HF download chatter, which otherwise fill the crash report
# and push the actual cause out of it. A segfault leaves no traceback at all, so
# what is left in stderr is usually pure noise — say so rather than quoting it.
_NOISE = re.compile(r"(\d+%\||it/s\]|Loading weights|HF Hub|huggingface|"
                    r"^\s*$)", re.IGNORECASE)


def _why(proc):
    """The useful part of a dead child's output, or an honest 'nothing'."""
    lines = [ln.strip()
             for ln in (proc.stderr or "").splitlines() + (proc.stdout or "").splitlines()
             if ln.strip() and not _NOISE.search(ln)]
    if not lines:
        return ("no diagnostic output — a native crash leaves no traceback, "
                "which is consistent with the OpenMP fault")
    return " | ".join(lines[-3:])


def _run_child(in_path, out_dir, start_chunk, env):
    """One child run, encoding from start_chunk on. Returns (ok, detail)."""
    # Run this file as a plain script, not as `-m forensics.embedding`: the
    # child then needs nothing on sys.path and imports no package __init__,
    # which is what keeps faiss out of it.
    proc = subprocess.run(
        [sys.executable, os.path.abspath(__file__), in_path, out_dir,
         str(start_chunk)],
        capture_output=True, text=True, env=env,
    )
    if proc.returncode != 0:
        return False, f"exit {proc.returncode}: {_why(proc)}"
    return True, ""


def _main(argv):
    """Child entry point. Imports sentence-transformers and nothing heavier.

    Encodes chunk by chunk from start_chunk, writing each one out before
    starting the next, so a crash costs at most the chunk in flight. The model
    is loaded once and reused across chunks — that load is the only per-process
    overhead chunking adds, and paying it once per *crash* rather than once per
    chunk is the reason the child walks the remaining chunks itself instead of
    the parent spawning one process each.
    """
    in_path, out_dir, start_chunk = argv[1], argv[2], int(argv[3])
    with open(in_path, encoding="utf-8") as fh:
        payload = json.load(fh)

    texts = payload["texts"]
    chunk_size = payload.get("chunk_size", CHUNK_SIZE)
    batch_size = payload.get("batch_size", DEFAULT_BATCH_SIZE)
    n_chunks = (len(texts) + chunk_size - 1) // chunk_size

    from sentence_transformers import SentenceTransformer

    model = SentenceTransformer(payload.get("model", MODEL_NAME))

    for i in range(start_chunk, n_chunks):
        out_path = os.path.join(out_dir, f"chunk_{i}.npy")
        if os.path.exists(out_path):
            continue
        part = texts[i * chunk_size:(i + 1) * chunk_size]
        vectors = model.encode(
            part,
            batch_size=batch_size,
            show_progress_bar=False,
            convert_to_numpy=True,
        )
        # Write to a temp name and rename into place, so a crash mid-write
        # cannot leave a truncated file that the parent counts as a finished
        # chunk. The name ends in .npy because np.save appends it otherwise.
        tmp_path = os.path.join(out_dir, f"chunk_{i}.part.npy")
        np.save(tmp_path, np.asarray(vectors, dtype="float32"))
        os.replace(tmp_path, out_path)
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv))
