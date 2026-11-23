"""Read/write Parquet partitions locally or on S3, with the same layout.

Layout: <layer>/<table>/dt=YYYY-MM-DD/part-0000.parquet
Backend is chosen by the STORAGE_BACKEND env var ("local" or "s3").
"""

from __future__ import annotations

import io
import os
from pathlib import Path

import pandas as pd

PARQUET_OPTS = {"index": False, "coerce_timestamps": "ms", "allow_truncated_timestamps": True}


class Storage:
    def __init__(
        self,
        backend: str | None = None,
        data_dir: str | None = None,
        bucket: str | None = None,
    ) -> None:
        self.backend = (backend or os.getenv("STORAGE_BACKEND", "local")).lower()
        self.data_dir = Path(data_dir or os.getenv("DATA_DIR", "./data"))
        self.bucket = bucket or os.getenv("S3_BUCKET")
        if self.backend not in {"local", "s3"}:
            raise ValueError(f"STORAGE_BACKEND must be 'local' or 's3', got {self.backend!r}")
        if self.backend == "s3" and not self.bucket:
            raise ValueError("S3_BUCKET is required when STORAGE_BACKEND=s3")
        self._s3 = None

    @staticmethod
    def key(layer: str, table: str, dt: str) -> str:
        return f"{layer}/{table}/dt={dt}/part-0000.parquet"

    @property
    def s3(self):
        if self._s3 is None:
            import boto3  # imported lazily so local runs and tests don't need it

            self._s3 = boto3.client("s3")
        return self._s3

    def write(self, df: pd.DataFrame, layer: str, table: str, dt: str) -> str:
        key = self.key(layer, table, dt)
        # An all-empty object column would be written as Parquet type `null` and break reading the
        # table as a whole (pandas/DuckDB/Athena); write it as string like the non-empty days.
        empty_obj = [c for c in df.columns if df[c].dtype == object and df[c].isna().all()]
        if empty_obj:
            df = df.astype(dict.fromkeys(empty_obj, "string"))
        if self.backend == "local":
            path = self.data_dir / key
            path.parent.mkdir(parents=True, exist_ok=True)
            df.to_parquet(path, **PARQUET_OPTS)
            return str(path)
        buf = io.BytesIO()
        df.to_parquet(buf, **PARQUET_OPTS)
        self.s3.put_object(Bucket=self.bucket, Key=key, Body=buf.getvalue())
        return f"s3://{self.bucket}/{key}"

    def read(self, layer: str, table: str, dt: str) -> pd.DataFrame:
        key = self.key(layer, table, dt)
        if self.backend == "local":
            return pd.read_parquet(self.data_dir / key)
        body = self.s3.get_object(Bucket=self.bucket, Key=key)["Body"].read()
        return pd.read_parquet(io.BytesIO(body))

    def _read_if_exists(self, layer: str, table: str, dt: str) -> pd.DataFrame | None:
        if self.backend == "local":
            path = self.data_dir / self.key(layer, table, dt)
            return pd.read_parquet(path) if path.exists() else None
        from botocore.exceptions import ClientError

        try:
            return self.read(layer, table, dt)
        except ClientError as err:
            if err.response.get("Error", {}).get("Code") in {"NoSuchKey", "404"}:
                return None
            raise

    def read_many(self, layer: str, table: str, dts: list[str]) -> tuple[pd.DataFrame, int]:
        """Concatenate the partitions that exist (missing days are skipped), adding a `dt` column.

        Returns (frame, number_of_partitions_found).
        """
        frames = []
        for dt in dts:
            df = self._read_if_exists(layer, table, dt)
            if df is not None:
                frames.append(df.assign(dt=dt))
        if not frames:
            return pd.DataFrame(), 0
        return pd.concat(frames, ignore_index=True), len(frames)
