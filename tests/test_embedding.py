"""The bulk encode must stay out of the FAISS process, and survive its crashes.

The bug being guarded against is not a wrong answer, it is a native crash: four
OpenMP runtimes co-loaded, a segfault inside torch's GELU during a background
index build, and the whole Gradio server going down with it. A segfault cannot
be caught by `except Exception`, so the only defence is that the crash happens
somewhere other than the server process.

Crash probability rises with how much work one process does — 2,000 texts died
1 run in 3, 60,414 died 5 out of 5 even single-threaded — so the encode is
chunked and resumable, and these tests pin that contract.
"""

import os
import subprocess
import sys

import numpy as np
import pytest

from forensics import embedding


def test_child_script_does_not_import_faiss():
    """The child must not load faiss — that is the entire point of the split.

    faiss's OpenMP runtime loading first is what puts the process into the
    mixed-runtime state, so a child that imports faiss would isolate the crash
    from nothing.
    """
    # Run the file the same way the child does — as a standalone path, with
    # run_name set so the __main__ block stays dormant — then ask what loaded.
    script = (
        "import sys, runpy; "
        f"runpy.run_path({embedding.__file__!r}, run_name='_child_probe_'); "
        "print('faiss' in sys.modules)"
    )

    proc = subprocess.run([sys.executable, "-c", script],
                          capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "False", (
        f"child process imported faiss: {proc.stdout!r} {proc.stderr!r}")


class _Child:
    """Stands in for a child process, writing chunks until it 'dies'.

    `deaths` is how many chunks each spawn completes before failing; None means
    the spawn finishes everything it was asked for.
    """

    def __init__(self, deaths, dim=4):
        self.deaths = list(deaths)
        self.dim = dim
        self.calls = []

    def __call__(self, cmd, **kwargs):
        in_path, out_dir, start = cmd[2], cmd[3], int(cmd[4])
        self.calls.append({"start": start, "env": kwargs.get("env") or {},
                           "batch": int(cmd[5])})

        import json
        payload = json.load(open(in_path, encoding="utf-8"))
        texts = payload["texts"]
        chunk = payload["chunk_size"]
        n_chunks = (len(texts) + chunk - 1) // chunk

        budget = self.deaths.pop(0) if self.deaths else None
        written = 0
        for i in range(start, n_chunks):
            if budget is not None and written >= budget:
                return type("P", (), {"returncode": -1073741819, "stdout": "",
                                      "stderr": ""})()
            part = texts[i * chunk:(i + 1) * chunk]
            np.save(os.path.join(out_dir, f"chunk_{i}.npy"),
                    np.full((len(part), self.dim), float(i), dtype="float32"))
            written += 1
        return type("P", (), {"returncode": 0, "stdout": "", "stderr": ""})()


def test_chunks_are_concatenated_in_order(monkeypatch):
    """Order matters: row i of the result must be the vector for text i."""
    monkeypatch.setattr(embedding.subprocess, "run", _Child([]))

    out = embedding.encode_bulk([f"t{i}" for i in range(10)], chunk_size=4)

    assert out.shape == (10, 4)
    # _Child stamps each chunk with its index, so ordering is visible.
    assert [row[0] for row in out] == [0, 0, 0, 0, 1, 1, 1, 1, 2, 2]


def test_a_crashed_child_resumes_instead_of_restarting(monkeypatch):
    """A dead child must cost only its own chunk, not the whole job."""
    # First spawn completes 2 chunks then dies; second finishes the rest.
    child = _Child([2])
    monkeypatch.setattr(embedding.subprocess, "run", child)

    out = embedding.encode_bulk([f"t{i}" for i in range(10)], chunk_size=2)

    assert out.shape == (10, 4)
    assert len(child.calls) == 2
    assert child.calls[0]["start"] == 0
    assert child.calls[1]["start"] == 2, (
        f"restarted from {child.calls[1]['start']} instead of resuming at 2")


def test_progress_resets_the_stall_counter(monkeypatch):
    """Many crashes are fine as long as each one made progress first.

    Under a fixed retry budget a 60-chunk job could never finish; the give-up
    rule has to count stalls, not attempts.
    """
    # Ten spawns, each completing exactly one chunk before dying.
    child = _Child([1] * 10)
    monkeypatch.setattr(embedding.subprocess, "run", child)

    out = embedding.encode_bulk([f"t{i}" for i in range(10)],
                                chunk_size=1, max_stalls=2)

    assert out.shape == (10, 4)
    assert len(child.calls) > 2, "gave up despite steady progress"


def test_repeated_no_progress_raises(monkeypatch):
    """A chunk nothing can encode must fail loudly, not spin forever."""
    child = _Child([0] * 20)  # every spawn dies before writing anything
    monkeypatch.setattr(embedding.subprocess, "run", child)

    with pytest.raises(RuntimeError) as exc:
        embedding.encode_bulk([f"t{i}" for i in range(10)],
                              chunk_size=2, max_stalls=3)

    assert len(child.calls) == 3, "stall budget not honoured"
    assert "stalled at chunk 0" in str(exc.value)
    assert "10 texts" in str(exc.value)


def test_a_stalled_chunk_is_retried_with_a_smaller_batch(monkeypatch):
    """Batch size is what sets the child's peak memory, so it is what a retry
    has to change. Measured on 500 real texts: batch 256 peaks at 2,871 MB and
    batch 32 at 1,228 MB, against ~2,500 MB of free commit on a box with no page
    file. Retrying a failed chunk at the same batch just fails the same way."""
    child = _Child([0] * 20)
    monkeypatch.setattr(embedding.subprocess, "run", child)

    with pytest.raises(RuntimeError):
        embedding.encode_bulk(["a", "b"], chunk_size=1, batch_size=64,
                              max_stalls=4)

    tried = [c["batch"] for c in child.calls]
    assert tried == [64, 32, 16, 8], tried


def test_the_batch_ladder_has_a_floor(monkeypatch):
    """Below a handful of texts per pass the memory is all model weights, and
    shrinking further only costs throughput."""
    child = _Child([0] * 20)
    monkeypatch.setattr(embedding.subprocess, "run", child)

    with pytest.raises(RuntimeError):
        embedding.encode_bulk(["a"], chunk_size=1, batch_size=8, max_stalls=4)

    assert min(c["batch"] for c in child.calls) == embedding.MIN_BATCH_SIZE


def test_a_recovered_chunk_goes_back_to_full_speed(monkeypatch):
    """The ladder is per-stall, not sticky: one bad chunk must not leave the
    rest of a 121-chunk build crawling at the floor batch."""
    # Stall once, then the next spawn completes a chunk and dies, and so on.
    child = _Child([0, 1, 1])
    monkeypatch.setattr(embedding.subprocess, "run", child)

    embedding.encode_bulk([f"t{i}" for i in range(3)], chunk_size=1,
                          batch_size=64, max_stalls=3)

    tried = [c["batch"] for c in child.calls]
    assert tried[0] == 64 and tried[1] == 32, tried
    assert tried[2] == 64, f"stayed at a reduced batch after recovering: {tried}"


class _OomChild(_Child):
    """A child that dies the way a commit-exhausted one does: at model load."""

    def __call__(self, cmd, **kwargs):
        super().__call__(cmd, **kwargs)
        return type("P", (), {
            "returncode": 1, "stdout": "",
            "stderr": 'with safe_open(checkpoint_file, framework="pt") as f:\n'
                      'OSError: The paging file is too small for this '
                      'operation to complete. (os error 1455)'})()


def test_an_out_of_memory_gives_up_instead_of_shrinking_forever(monkeypatch):
    """The batch ladder is the wrong answer to a failure at model *load*: the
    weights are ~1,040 MB before a single text is encoded, and batch size does
    not control that. Descending to the floor and burning the rest of the stall
    budget only delays an honest answer."""
    child = _OomChild([0] * 20)
    monkeypatch.setattr(embedding.subprocess, "run", child)

    with pytest.raises(RuntimeError) as exc:
        embedding.encode_bulk(["a", "b"], chunk_size=1, batch_size=32,
                              max_stalls=5)

    msg = str(exc.value)
    assert "Not enough memory" in msg
    assert "smaller batch cannot help" in msg
    assert "page file" in msg
    # 32 -> 16 -> 8, then stop: the floor is reached and reaching it again
    # proves nothing.
    assert [c["batch"] for c in child.calls] == [32, 16, 8], \
        [c["batch"] for c in child.calls]


def test_a_non_memory_stall_still_uses_the_whole_budget(monkeypatch):
    """Only an explicit out-of-memory shortcuts the retries."""
    child = _Child([0] * 20)
    monkeypatch.setattr(embedding.subprocess, "run", child)

    with pytest.raises(RuntimeError) as exc:
        embedding.encode_bulk(["a", "b"], chunk_size=1, batch_size=32,
                              max_stalls=5)

    assert "Not enough memory" not in str(exc.value)
    assert len(child.calls) == 5


def test_last_stall_serialises_openmp(monkeypatch):
    """Before giving up, try the one setting known to lower the risk."""
    child = _Child([0] * 20)
    monkeypatch.setattr(embedding.subprocess, "run", child)

    with pytest.raises(RuntimeError):
        embedding.encode_bulk(["a", "b"], chunk_size=1, max_stalls=3)

    assert child.calls[0]["env"].get("OMP_NUM_THREADS") != "1"
    assert child.calls[-1]["env"].get("OMP_NUM_THREADS") == "1", (
        "never tried serialised OpenMP before giving up")


def test_encode_bulk_never_falls_back_to_the_parent(monkeypatch):
    """Running a known-crashy workload in the server is what this prevents."""
    monkeypatch.setattr(embedding.subprocess, "run", _Child([0] * 20))

    called = []
    monkeypatch.setattr(embedding, "encode_in_process",
                        lambda *a, **k: called.append(1))

    with pytest.raises(RuntimeError):
        embedding.encode_bulk(["one"], chunk_size=1, max_stalls=2)
    assert not called, "fell back to encoding in the parent process"


def test_the_model_loads_from_cache_before_reaching_for_the_network(monkeypatch):
    """A build spawns many children and each one re-resolved the model over the
    network. One run lost two of five stall slots to an httpx error doing it."""
    seen = []

    class _ST:
        def __init__(self, name, local_files_only=False):
            seen.append(local_files_only)

    monkeypatch.setitem(sys.modules, "sentence_transformers",
                        type(sys)("sentence_transformers"))
    sys.modules["sentence_transformers"].SentenceTransformer = _ST

    embedding._new_model("all-MiniLM-L6-v2")
    assert seen == [True], f"went to the network first: {seen}"


def test_an_uncached_model_still_downloads(monkeypatch):
    """The offline preference must not break a fresh checkout."""
    seen = []

    class _ST:
        def __init__(self, name, local_files_only=False):
            seen.append(local_files_only)
            if local_files_only:
                raise OSError("model not found in local cache")

    monkeypatch.setitem(sys.modules, "sentence_transformers",
                        type(sys)("sentence_transformers"))
    sys.modules["sentence_transformers"].SentenceTransformer = _ST

    embedding._new_model("all-MiniLM-L6-v2")
    assert seen == [True, False], f"never fell back to a download: {seen}"


def test_query_falls_back_to_a_child_when_memory_runs_out(monkeypatch):
    """The first question after an index build is the worst moment to ask for
    1 GB, and that is exactly when the model loads. A machine that cannot commit
    it must still answer, slowly, rather than put a stack trace where the
    evidence goes."""
    def _oom(*a, **k):
        # Rendered the way safetensors' Rust error reaches Python: no .winerror,
        # only the string. Matching on the code alone would miss this.
        raise OSError("The paging file is too small for this operation to "
                      "complete. (os error 1455)")

    monkeypatch.setattr(embedding, "encode_in_process", _oom)
    monkeypatch.setattr(embedding.subprocess, "run", _Child([]))

    out = embedding.encode_query("what USB devices were connected")
    assert out.shape[0] == 1


def test_query_does_not_swallow_a_real_error(monkeypatch):
    """Only memory exhaustion earns the slow path. Anything else is a bug and
    must surface as itself."""
    def _boom(*a, **k):
        raise OSError("model.safetensors is corrupt")

    monkeypatch.setattr(embedding, "encode_in_process", _boom)
    monkeypatch.setattr(embedding.subprocess, "run",
                        lambda *a, **k: pytest.fail("spawned a child for a "
                                                    "non-memory failure"))

    with pytest.raises(OSError, match="corrupt"):
        embedding.encode_query("anything")


def test_empty_input_needs_no_subprocess(monkeypatch):
    def _boom(*a, **k):
        raise AssertionError("spawned a process for nothing")

    monkeypatch.setattr(embedding.subprocess, "run", _boom)
    out = embedding.encode_bulk([])
    assert isinstance(out, np.ndarray)
    assert len(out) == 0


def test_in_process_escape_hatch_skips_the_subprocess(monkeypatch):
    monkeypatch.setenv("FORENSICS_EMBED_IN_PROCESS", "1")

    def _boom(*a, **k):
        raise AssertionError("subprocess used despite the escape hatch")

    monkeypatch.setattr(embedding.subprocess, "run", _boom)
    monkeypatch.setattr(embedding, "encode_in_process",
                        lambda texts, batch_size=None: np.zeros((len(texts), 4),
                                                                dtype="float32"))
    out = embedding.encode_bulk(["a", "b", "c"])
    assert out.shape == (3, 4)


def test_work_dir_chunks_survive_a_failed_build(tmp_path, monkeypatch):
    """A build that gives up must leave its finished chunks behind.

    The first full-scale run stalled at chunk 55 of 121 and the temp directory
    took an hour of encoding with it.
    """
    work = tmp_path / "embed_chunks"
    # Completes 2 chunks per spawn, then dies; stall budget runs out only after
    # it stops progressing, so some chunks land before the failure.
    child = _Child([2, 0, 0])
    monkeypatch.setattr(embedding.subprocess, "run", child)

    with pytest.raises(RuntimeError) as exc:
        embedding.encode_bulk([f"t{i}" for i in range(10)], chunk_size=1,
                              max_stalls=2, work_dir=str(work))

    kept = sorted(p.name for p in work.glob("chunk_*.npy"))
    assert kept == ["chunk_0.npy", "chunk_1.npy"], kept
    assert "2/10 chunks are encoded and kept" in str(exc.value)


def test_a_resumed_build_reuses_finished_chunks(tmp_path, monkeypatch):
    work = tmp_path / "embed_chunks"
    texts = [f"t{i}" for i in range(10)]

    monkeypatch.setattr(embedding.subprocess, "run", _Child([3, 0, 0]))
    with pytest.raises(RuntimeError):
        embedding.encode_bulk(texts, chunk_size=1, max_stalls=2,
                              work_dir=str(work))

    resumed = _Child([])          # this one finishes everything it is given
    monkeypatch.setattr(embedding.subprocess, "run", resumed)
    out = embedding.encode_bulk(texts, chunk_size=1, max_stalls=2,
                                work_dir=str(work))

    assert out.shape == (10, 4)
    assert resumed.calls[0]["start"] == 3, (
        f"restarted at {resumed.calls[0]['start']} instead of resuming at 3")


def test_changed_texts_discard_stale_chunks(tmp_path, monkeypatch):
    """Chunk N of an old run is not chunk N of a new one. Silence here would
    corrupt the index rather than fail it."""
    work = tmp_path / "embed_chunks"

    monkeypatch.setattr(embedding.subprocess, "run", _Child([]))
    embedding.encode_bulk([f"t{i}" for i in range(10)], chunk_size=5,
                          work_dir=str(work))
    assert len(list(work.glob("chunk_*.npy"))) == 2

    # A different text set of the same length must not reuse those chunks.
    child = _Child([])
    monkeypatch.setattr(embedding.subprocess, "run", child)
    out = embedding.encode_bulk([f"CHANGED{i}" for i in range(10)],
                                chunk_size=5, work_dir=str(work))
    assert out.shape == (10, 4)
    assert child.calls[0]["start"] == 0, "reused chunks from a different text set"
