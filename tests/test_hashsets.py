import hashlib

from forensics.hashsets import (hash_stream, hash_summary, load_hashset,
                                match_hashsets)

MD5_EVIL = hashlib.md5(b"evil").hexdigest()
SHA_EVIL = hashlib.sha256(b"evil").hexdigest()


def test_hash_stream_matches_hashlib():
    md5, sha256 = hash_stream([b"ev", b"il"])
    assert md5 == MD5_EVIL
    assert sha256 == SHA_EVIL


def test_load_hashset_plain_list(tmp_path):
    f = tmp_path / "bad.txt"
    f.write_text(f"# comment\n{MD5_EVIL}\n{SHA_EVIL}\n")
    assert load_hashset(str(f)) == {MD5_EVIL, SHA_EVIL}


def test_load_hashset_csv_with_extra_columns(tmp_path):
    f = tmp_path / "nsrl.csv"
    f.write_text(f'"{SHA_EVIL}","{MD5_EVIL}","12345","evil.exe"\n')
    loaded = load_hashset(str(f))
    assert MD5_EVIL in loaded and SHA_EVIL in loaded


def test_load_hashset_missing_file():
    assert load_hashset("/nonexistent/path.txt") == set()


def test_known_bad_produces_artifact():
    rows = [{'_filepath': '/Users/x/evil.exe', '_md5': MD5_EVIL}]
    out = match_hashsets(rows, known_bad={MD5_EVIL})
    assert len(out) == 1
    assert "known-bad" in out.iloc[0]['Task Category']
    assert rows[0]['_known_bad'] is True


def test_known_good_is_tagged_but_not_reported():
    rows = [{'_filepath': '/Windows/notepad.exe', '_sha256': SHA_EVIL}]
    out = match_hashsets(rows, known_good={SHA_EVIL})
    assert out.empty
    assert rows[0]['_known_good'] is True


def test_hash_matching_is_case_insensitive():
    rows = [{'_filepath': '/x.exe', '_md5': MD5_EVIL.upper()}]
    assert len(match_hashsets(rows, known_bad={MD5_EVIL})) == 1


def test_summary_counts():
    rows = [
        {'_known_bad': True, '_known_good': False},
        {'_known_bad': False, '_known_good': True},
        {'_known_bad': False, '_known_good': False},
    ]
    assert hash_summary(rows) == {
        "hashed": 3, "known_bad": 1, "known_good": 1, "unknown": 1,
    }
