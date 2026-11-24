"""Read-only queries for the local dashboard: DuckDB over the Parquet layers in DATA_DIR.

Nothing here re-scores or recomputes a metric. Every number comes from what the pipeline wrote:
"flagged" is risk_level = 'HIGH', "real attack" is a client in ground_truth on the same dt, and
precision/recall/baseline_ready come from detection_metrics. Dates are 'YYYY-MM-DD' strings and
ranges are inclusive.
"""

from __future__ import annotations

import glob
from pathlib import Path

import duckdb
import pandas as pd

from oauth_shield import risk

TABLES: dict[str, str] = {
    "oauth_events": "bronze",
    "client_profile": "bronze",
    "ground_truth": "bronze",
    "benign_events": "bronze",
    "client_daily": "silver",
    "ip_daily": "silver",
    "client_subnet_daily": "silver",
    "client_subnet_baseline": "silver",
    "risk_scores": "gold",
    "detection_metrics": "gold",
}
SIGNALS: list[str] = list(risk.WEIGHTS)


def connect(data_dir: str | Path) -> duckdb.DuckDBPyConnection:
    """In-memory DuckDB with one view per table that has at least one Parquet file on disk."""
    con = duckdb.connect()
    missing = []
    for table, layer in TABLES.items():
        pattern = (Path(data_dir) / layer / table / "*" / "*.parquet").as_posix()
        if not glob.glob(pattern):
            missing.append(table)
            continue
        con.execute(
            f"CREATE VIEW {table} AS SELECT * FROM read_parquet('{pattern.replace(chr(39), chr(39) * 2)}', "
            "hive_partitioning = true, hive_types = {'dt': DATE})"
        )
    con.execute("CREATE TEMP TABLE _missing (pos INTEGER, name VARCHAR)")
    if missing:
        order = list(TABLES)
        con.executemany("INSERT INTO _missing VALUES (?, ?)", [(order.index(t), t) for t in missing])
    return con


def missing_tables(con: duckdb.DuckDBPyConnection) -> list[str]:
    """Tables with no Parquet file yet, in TABLES order (the dashboard asks for a DAG run/backfill)."""
    return [r[0] for r in con.execute("SELECT name FROM _missing ORDER BY pos").fetchall()]


def available_dates(con: duckdb.DuckDBPyConnection) -> list[str]:
    rows = con.execute("SELECT DISTINCT strftime(dt, '%Y-%m-%d') FROM detection_metrics ORDER BY 1").fetchall()
    return [r[0] for r in rows]


def _df(con: duckdb.DuckDBPyConnection, sql: str, params: list | None = None) -> pd.DataFrame:
    return con.execute(sql, params or []).df()
