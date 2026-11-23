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


def test_read_many_skips_missing_local(tmp_path, events):
    store = Storage(backend="local", data_dir=str(tmp_path))
    store.write(events.head(10), "silver", "t", "2026-11-01")
    store.write(events.head(5), "silver", "t", "2026-11-03")
    df, n = store.read_many("silver", "t", ["2026-11-01", "2026-11-02", "2026-11-03"])
    assert n == 2 and len(df) == 15
    assert set(df["dt"]) == {"2026-11-01", "2026-11-03"}


def test_read_many_none_found(tmp_path):
    df, n = Storage(backend="local", data_dir=str(tmp_path)).read_many("silver", "t", ["2026-11-01"])
    assert n == 0 and df.empty


class _FakeS3:
    def __init__(self, code):
        self.code = code

    def get_object(self, Bucket, Key):  # noqa: N803 - mirrors the boto3 signature
        from botocore.exceptions import ClientError

        raise ClientError({"Error": {"Code": self.code}}, "GetObject")


def test_read_many_s3_skips_nosuchkey():
    store = Storage(backend="s3", bucket="b")
    store._s3 = _FakeS3("NoSuchKey")
    df, n = store.read_many("silver", "t", ["2026-11-01"])
    assert n == 0 and df.empty


def test_read_many_s3_reraises_other_errors():
    from botocore.exceptions import ClientError

    store = Storage(backend="s3", bucket="b")
    store._s3 = _FakeS3("AccessDenied")
    with pytest.raises(ClientError):
        store.read_many("silver", "t", ["2026-11-01"])
