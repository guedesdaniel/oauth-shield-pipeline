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


_RANGE = "dt BETWEEN CAST(? AS DATE) AND CAST(? AS DATE)"
_DAY = "dt = CAST(? AS DATE)"
_IS_ATTACK = "EXISTS (SELECT 1 FROM ground_truth g WHERE g.dt = {t}.dt AND g.client_id = {t}.client_id)"


# ---------------------------------------------------------------- Visão geral
def day_summary(con: duckdb.DuckDBPyConnection, dt: str) -> dict:
    """Cards of one day. precision/recall/baseline_ready are read from detection_metrics as written."""
    high, medium = con.execute(
        f"SELECT count(*) FILTER (risk_level = 'HIGH'), count(*) FILTER (risk_level = 'MEDIUM') "
        f"FROM risk_scores WHERE {_DAY}",
        [dt],
    ).fetchone()
    (attacks,) = con.execute(f"SELECT count(*) FROM ground_truth WHERE {_DAY}", [dt]).fetchone()
    m = con.execute(f"SELECT precision, recall, baseline_ready FROM detection_metrics WHERE {_DAY}", [dt]).fetchone()
    precision, recall, ready = m if m else (None, None, False)
    return {
        "high": int(high),
        "medium": int(medium),
        "attacks": int(attacks),
        "precision": None if precision is None else float(precision),
        "recall": None if recall is None else float(recall),
        "baseline_ready": bool(ready),
    }


def daily_outcomes(con: duckdb.DuckDBPyConnection, start: str, end: str) -> pd.DataFrame:
    """HIGH apps per day split into real attacks and false positives (the bar heights add up to HIGH)."""
    return _df(
        con,
        f"""
        SELECT strftime(r.dt, '%Y-%m-%d') AS dt,
               CASE WHEN {_IS_ATTACK.format(t="r")} THEN 'ataque real' ELSE 'falso positivo' END AS outcome,
               count(*) AS n,
               coalesce(any_value(m.baseline_ready), false) AS baseline_ready
        FROM risk_scores r LEFT JOIN detection_metrics m ON m.dt = r.dt
        WHERE r.risk_level = 'HIGH' AND r.{_RANGE}
        GROUP BY 1, 2 ORDER BY 1, 2
        """,
        [start, end],
    )


def daily_signals(con: duckdb.DuckDBPyConnection, start: str, end: str) -> pd.DataFrame:
    """How many apps (any level) had each signal fire, per day. One app can count in several signals."""
    cols = ", ".join(SIGNALS)
    return _df(
        con,
        f"""
        SELECT strftime(dt, '%Y-%m-%d') AS dt, signal, count(*) AS n
        FROM (UNPIVOT (SELECT dt, {cols} FROM risk_scores WHERE {_RANGE}) ON {cols} INTO NAME signal VALUE fired)
        WHERE fired
        GROUP BY 1, 2 ORDER BY 1, 2
        """,
        [start, end],
    )


def attacks_by_type(con: duckdb.DuckDBPyConnection, start: str, end: str) -> pd.DataFrame:
    """Caught (HIGH) vs missed per attack type, on baseline-ready days only."""
    df = _df(
        con,
        f"""
        SELECT g.attack_type,
               count(*) FILTER (r.risk_level = 'HIGH') AS caught,
               count(*) FILTER (r.risk_level IS DISTINCT FROM 'HIGH') AS missed
        FROM ground_truth g
        JOIN detection_metrics m ON m.dt = g.dt AND m.baseline_ready
        LEFT JOIN risk_scores r ON r.dt = g.dt AND r.client_id = g.client_id
        WHERE g.{_RANGE}
        GROUP BY 1
        """,
        [start, end],
    )
    df["recall"] = (df["caught"] / (df["caught"] + df["missed"])).round(3)
    return df.sort_values(["recall", "attack_type"]).reset_index(drop=True)


def day_errors(con: duckdb.DuckDBPyConnection, dt: str) -> pd.DataFrame:
    """False positives (with the benign event that explains them) and missed attacks of one day."""
    return _df(
        con,
        f"""
        SELECT 'falso positivo' AS kind, r.client_id, r.risk_score, r.reasons,
               coalesce((SELECT string_agg(DISTINCT b.event_type, ', ' ORDER BY b.event_type)
                         FROM benign_events b WHERE b.dt = r.dt AND b.client_id = r.client_id),
                        'sem explicação') AS explanation
        FROM risk_scores r
        WHERE r.{_DAY} AND r.risk_level = 'HIGH' AND NOT {_IS_ATTACK.format(t="r")}
        UNION ALL
        SELECT 'ataque que escapou', g.client_id, r.risk_score, r.reasons, g.attack_type
        FROM ground_truth g LEFT JOIN risk_scores r ON r.dt = g.dt AND r.client_id = g.client_id
        WHERE g.{_DAY} AND r.risk_level IS DISTINCT FROM 'HIGH'
        ORDER BY kind, risk_score DESC
        """,
        [dt, dt],
    )
