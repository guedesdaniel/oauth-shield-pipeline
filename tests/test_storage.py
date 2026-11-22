from pathlib import Path

import pytest

from oauth_shield.storage import Storage


def test_local_roundtrip(tmp_path, events):
    pytest.importorskip("pyarrow")
    store = Storage(backend="local", data_dir=str(tmp_path))
    path = store.write(events.head(100), "bronze", "oauth_events", "2026-11-20")
    # Path().as_posix() normalizes Windows backslashes so the check is OS-independent.
    assert Path(path).as_posix().endswith("bronze/oauth_events/dt=2026-11-20/part-0000.parquet")
    back = store.read("bronze", "oauth_events", "2026-11-20")
    assert len(back) == 100


def test_s3_requires_bucket(monkeypatch):
    monkeypatch.delenv("S3_BUCKET", raising=False)
    with pytest.raises(ValueError):
        Storage(backend="s3")


def test_rejects_unknown_backend():
    with pytest.raises(ValueError):
        Storage(backend="ftp")
