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
can catch, and that a fresh process can simply be tried again. Measured on 2,000
real artifact texts:

    in-process, faiss loaded (the old path)   segfault 3 / 3 runs
    child process, no faiss                   segfault ~1 / 2 runs

So the child is not safe, it is *survivable* — and that is the whole difference,
because the old path took the server with it every time. Retries then do the
rest: the crash is intermittent, so a fresh process usually gets through, and
only the final attempt sets OMP_NUM_THREADS=1 to remove the race outright at
roughly 10x the encode cost. Slow, but it terminates, and it is far better paid
once on a rare fallback than on every index build.

The durable fix is environmental rather than code: get faiss, torch and sklearn
onto a single OpenMP runtime (matching wheels, or a conda-forge stack). Until
then this contains the damage.

Query embedding stays in-process: it is a single short string rather than
thousands, the crash has never been observed there, and a subprocess per query
would add a model load to every question. That leaves a small residual exposure;
set FORENSICS_EMBED_IN_PROCESS=1 to disable subprocessing entirely, or
OMP_NUM_THREADS=1 for the whole app to remove the race at the cost of speed.
"""

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


# Four fast attempts, then one serialised. Measured on 2,000 real artifact
# texts: encoding in the faiss-loaded parent crashed 3 out of 3 times, while a
# faiss-free child crashed roughly half the time — so a couple of retries are
# not enough, and a crashed attempt is cheap (a model load) next to the ~10x
# cost of the OMP_NUM_THREADS=1 fallback.
ATTEMPTS = 5


def encode_bulk(texts, batch_size=DEFAULT_BATCH_SIZE, attempts=ATTEMPTS):
    """Embed many texts in a child process, retrying if the child dies.

    Returns a float32 array of shape (len(texts), dim). Raises RuntimeError if
    every attempt fails — deliberately never falling back to encoding in the
    parent, since running a known-crashy workload in the server process is
    precisely the outcome this exists to prevent.
    """
    texts = list(texts)
    if not texts:
        return np.empty((0, 0), dtype="float32")

    if not _subprocess_enabled():
        return encode_in_process(texts, batch_size=batch_size)

    failures = []
    for attempt in range(1, attempts + 1):
        # Last attempt only: serialise OpenMP. This removes the race outright
        # (no parallel region left to corrupt) at ~4x the encode cost, so it is
        # a fallback rather than the default.
        last = attempt == attempts
        env = dict(os.environ)
        if last:
            env["OMP_NUM_THREADS"] = "1"

        ok, result, detail = _run_child(texts, batch_size, env)
        if ok:
            if attempt > 1:
                print(f"  [EMBED] Succeeded on attempt {attempt}/{attempts}"
                      f"{' with OMP_NUM_THREADS=1' if last else ''}.")
            return result

        failures.append(f"attempt {attempt}: {detail}")
        if not last:
            print(f"  [EMBED] Encode subprocess died ({detail}); "
                  f"retrying ({attempt + 1}/{attempts}).")

    raise RuntimeError(
        f"Embedding subprocess failed {attempts}x while encoding "
        f"{len(texts)} texts — " + " || ".join(failures)
    )


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


def _run_child(texts, batch_size, env):
    """One child run. Returns (ok, vectors_or_None, detail)."""
    with tempfile.TemporaryDirectory(prefix="forensics_embed_") as tmp:
        in_path = os.path.join(tmp, "texts.json")
        out_path = os.path.join(tmp, "vectors.npy")

        with open(in_path, "w", encoding="utf-8") as fh:
            json.dump({"texts": texts, "batch_size": batch_size,
                       "model": MODEL_NAME}, fh)

        # Run this file as a plain script, not as `-m forensics.embedding`: the
        # child then needs nothing on sys.path and imports no package __init__,
        # which is what keeps faiss out of it.
        proc = subprocess.run(
            [sys.executable, os.path.abspath(__file__), in_path, out_path],
            capture_output=True, text=True, env=env,
        )

        if proc.returncode != 0 or not os.path.exists(out_path):
            return False, None, f"exit {proc.returncode}: {_why(proc)}"

        return True, np.load(out_path), ""


def _main(argv):
    """Child entry point. Imports sentence-transformers and nothing heavier."""
    in_path, out_path = argv[1], argv[2]
    with open(in_path, encoding="utf-8") as fh:
        payload = json.load(fh)

    from sentence_transformers import SentenceTransformer

    model = SentenceTransformer(payload.get("model", MODEL_NAME))
    vectors = model.encode(
        payload["texts"],
        batch_size=payload.get("batch_size", DEFAULT_BATCH_SIZE),
        show_progress_bar=False,
        convert_to_numpy=True,
    )
    np.save(out_path, np.asarray(vectors, dtype="float32"))
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv))
