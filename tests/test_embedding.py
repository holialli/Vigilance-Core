"""The bulk encode must stay out of the FAISS process, and fail catchably.

The bug being guarded against is not a wrong answer, it is a native crash: four
OpenMP runtimes co-loaded, a segfault inside torch's GELU during a background
index build, and the whole Gradio server going down with it. A segfault cannot
be caught by `except Exception`, so the only defence is that the crash happens
somewhere other than the server process — measured, encoding 2,000 real
artifact texts in the faiss-loaded process died 3 times out of 3.
"""

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
    """Stand-in for subprocess.run with a scripted outcome per call."""

    def __init__(self, outcomes):
        self.outcomes = list(outcomes)
        self.calls = []

    def __call__(self, cmd, **kwargs):
        self.calls.append(kwargs.get("env") or {})
        rc = self.outcomes.pop(0)
        if rc == 0:
            # Success means the child wrote the .npy the parent then loads.
            out_path = cmd[3]
            np.save(out_path, np.zeros((2, 4), dtype="float32"))
        return type("P", (), {"returncode": rc, "stdout": "",
                              "stderr": "Segmentation fault"})()


def test_encode_bulk_reports_total_failure_as_an_exception(monkeypatch):
    """A child that always dies must raise, not crash the parent."""
    # 0xC0000005 is an access violation on Windows.
    monkeypatch.setattr(embedding.subprocess, "run",
                        _Child([-1073741819] * 3))

    with pytest.raises(RuntimeError) as exc:
        embedding.encode_bulk(["one", "two"], attempts=3)

    # The examiner has to be able to tell what died and how.
    assert "1073741819" in str(exc.value)
    assert "2 texts" in str(exc.value)


def test_a_crashed_child_is_retried(monkeypatch):
    """The crash is intermittent, so a fresh process usually succeeds."""
    child = _Child([-1073741819, 0])
    monkeypatch.setattr(embedding.subprocess, "run", child)

    out = embedding.encode_bulk(["one", "two"], attempts=3)
    assert out.shape == (2, 4)
    assert len(child.calls) == 2, "did not retry after a crash"


def test_last_attempt_serialises_openmp(monkeypatch):
    """Final retry drops to OMP_NUM_THREADS=1, which removes the race."""
    child = _Child([-1073741819, -1073741819, 0])
    monkeypatch.setattr(embedding.subprocess, "run", child)

    embedding.encode_bulk(["one", "two"], attempts=3)

    assert len(child.calls) == 3
    assert child.calls[0].get("OMP_NUM_THREADS") != "1"
    assert child.calls[1].get("OMP_NUM_THREADS") != "1"
    assert child.calls[2].get("OMP_NUM_THREADS") == "1", (
        "last attempt did not serialise OpenMP")


def test_encode_bulk_never_falls_back_to_the_parent(monkeypatch):
    """Running a known-crashy workload in the server is what this prevents."""
    monkeypatch.setattr(embedding.subprocess, "run", _Child([1, 1, 1]))

    called = []
    monkeypatch.setattr(embedding, "encode_in_process",
                        lambda *a, **k: called.append(1))

    with pytest.raises(RuntimeError):
        embedding.encode_bulk(["one"], attempts=3)
    assert not called, "fell back to encoding in the parent process"


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
