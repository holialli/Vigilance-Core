import pandas as pd
import pytest

from forensics import cases


@pytest.fixture(autouse=True)
def isolated_cache(tmp_path, monkeypatch):
    monkeypatch.setattr(cases, "CACHE_DIR", str(tmp_path))
    return tmp_path


HASH_A = "a" * 64
HASH_B = "b" * 64


def test_save_and_reload_roundtrip(artifact_df):
    cases.save_case(HASH_A, artifact_df, case_name="Op Nightfall",
                    examiner="Det. Chen")
    loaded, manifest = cases.load_case(HASH_A)
    assert len(loaded) == len(artifact_df)
    assert manifest["case_name"] == "Op Nightfall"
    assert manifest["examiner"] == "Det. Chen"
    assert manifest["artifact_count"] == 4


def test_missing_case_returns_none():
    artifacts, manifest = cases.load_case("does-not-exist")
    assert artifacts is None and manifest is None


def test_list_cases_orders_most_recent_first(artifact_df):
    cases.save_case(HASH_A, artifact_df, case_name="Older")
    saved = cases.save_case(HASH_B, artifact_df, case_name="Newer")
    saved["updated"] = "2999-01-01 00:00:00 UTC"
    cases.save_case(HASH_B, artifact_df, case_name="Newer")

    listing = cases.list_cases()
    assert len(listing) == 2
    assert set(listing['Case']) == {"Older", "Newer"}


def test_list_cases_empty_cache():
    assert cases.list_cases().empty


def test_update_preserves_created_timestamp(artifact_df):
    first = cases.save_case(HASH_A, artifact_df, case_name="Initial")
    second = cases.save_case(HASH_A, artifact_df, case_name="Renamed")
    assert second["created"] == first["created"]
    assert second["case_name"] == "Renamed"


def test_notes_persist(artifact_df):
    cases.save_case(HASH_A, artifact_df, notes="suspect interviewed 3 Mar")
    _, manifest = cases.load_case(HASH_A)
    assert "suspect interviewed" in manifest["notes"]


def test_save_requires_hash(artifact_df):
    with pytest.raises(ValueError):
        cases.save_case("", artifact_df)


def test_directory_without_artifacts_is_not_listed(isolated_cache):
    (isolated_cache / "stray").mkdir()
    assert cases.list_cases().empty
