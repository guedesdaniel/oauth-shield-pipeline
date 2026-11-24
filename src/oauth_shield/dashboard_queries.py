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
    # A regular (not TEMP) table, so per-session cursors (con.cursor()) see it too.
    con.execute("CREATE TABLE _missing (pos INTEGER, name VARCHAR)")
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


# ---------------------------------------------------------------- IPs suspeitos
def suspicious_ips(con: duckdb.DuckDBPyConnection, start: str, end: str, limit: int = 50) -> pd.DataFrame:
    """IPs with at least one failure in the range, the ones hitting the most apps first."""
    return _df(
        con,
        f"""
        WITH agg AS (
            SELECT source_ip, mode(country) AS country, count(DISTINCT dt) AS days_seen,
                   max(distinct_clients) AS max_clients,
                   CAST(sum(failed_requests) AS BIGINT) AS failed, CAST(sum(total_requests) AS BIGINT) AS total
            FROM ip_daily WHERE {_RANGE}
            GROUP BY 1 HAVING sum(failed_requests) > 0
        ), hit AS (
            SELECT DISTINCT e.source_ip
            FROM oauth_events e JOIN ground_truth g ON g.dt = e.dt AND g.client_id = e.client_id
            WHERE e.{_RANGE} AND e.source_ip IN (SELECT source_ip FROM agg)
        )
        SELECT agg.*, round(failed / total, 3) AS fail_ratio,
               source_ip IN (SELECT source_ip FROM hit) AS hit_real_attack
        FROM agg
        ORDER BY max_clients DESC, failed DESC, source_ip
        LIMIT ?
        """,
        [start, end, start, end, limit],
    )


def unusual_subnet_scope_errors(
    con: duckdb.DuckDBPyConnection, start: str, end: str, min_errors: int = 5
) -> pd.DataFrame:
    """Athena query 5, on baseline-ready days only: scope errors from a /24 the app does not usually use."""
    return _df(
        con,
        f"""
        SELECT strftime(d.dt, '%Y-%m-%d') AS dt, d.client_id, d.subnet, d.invalid_scope_count,
               d.success_count, d.total_requests, {_IS_ATTACK.format(t="d")} AS is_attack
        FROM client_subnet_daily d
        JOIN detection_metrics m ON m.dt = d.dt AND m.baseline_ready
        LEFT JOIN client_subnet_baseline b ON b.dt = d.dt AND b.client_id = d.client_id AND b.subnet = d.subnet
        WHERE d.{_RANGE} AND d.invalid_scope_count >= ? AND coalesce(b.is_usual, false) = false
        ORDER BY d.dt DESC, d.invalid_scope_count DESC, d.client_id
        """,
        [start, end, min_errors],
    )


def ip_activity(con: duckdb.DuckDBPyConnection, ip: str, start: str, end: str) -> pd.DataFrame:
    """What one IP did, per day and app, from the raw events."""
    return _df(
        con,
        f"""
        WITH a AS (
            SELECT dt, client_id, count(*) AS requests,
                   count(*) FILTER (status_code = 200) AS s200,
                   count(*) FILTER (status_code = 400) AS s400,
                   count(*) FILTER (status_code = 401) AS s401,
                   string_agg(DISTINCT country, ', ' ORDER BY country) AS countries,
                   string_agg(DISTINCT requested_scope, ', ' ORDER BY requested_scope) AS scopes
            FROM oauth_events WHERE source_ip = ? AND {_RANGE}
            GROUP BY 1, 2
        )
        SELECT strftime(a.dt, '%Y-%m-%d') AS dt, client_id, requests, s200, s400, s401, countries, scopes,
               {_IS_ATTACK.format(t="a")} AS is_attack
        FROM a ORDER BY a.dt, client_id
        """,
        [ip, start, end],
    )


# ---------------------------------------------------------------- Detalhe
def app_options(con: duckdb.DuckDBPyConnection, start: str, end: str) -> pd.DataFrame:
    """Apps for the selector, the riskiest in the range first."""
    return _df(
        con,
        f"SELECT client_id, max(risk_score) AS max_score FROM risk_scores WHERE {_RANGE} "
        "GROUP BY 1 ORDER BY max_score DESC, client_id",
        [start, end],
    )


def app_timeline(con: duckdb.DuckDBPyConnection, client_id: str, start: str, end: str) -> pd.DataFrame:
    """One app day by day: volume vs expected, score and reasons, and what it really was (truth)."""
    df = _df(
        con,
        f"""
        SELECT strftime(c.dt, '%Y-%m-%d') AS dt, c.total_requests, c.success_count, c.invalid_scope_count,
               c.expected_daily_volume, r.risk_score, r.risk_level, r.reasons,
               coalesce(g.attack_type,
                        (SELECT string_agg(DISTINCT b.event_type, ', ' ORDER BY b.event_type)
                         FROM benign_events b WHERE b.dt = c.dt AND b.client_id = c.client_id)) AS truth
        FROM client_daily c
        LEFT JOIN risk_scores r ON r.dt = c.dt AND r.client_id = c.client_id
        LEFT JOIN ground_truth g ON g.dt = c.dt AND g.client_id = c.client_id
        WHERE c.client_id = ? AND c.{_RANGE}
        ORDER BY c.dt
        """,
        [client_id, start, end],
    )
    df["truth"] = df["truth"].astype(object).where(df["truth"].notna(), None)
    return df


def app_subnets(con: duckdb.DuckDBPyConnection, client_id: str, dt: str) -> pd.DataFrame:
    """The app's /24s of the day against the learned baseline of that day (usual / fora do usual / nova)."""
    return _df(
        con,
        f"""
        SELECT d.subnet, d.total_requests, d.success_count, d.invalid_scope_count,
               CASE WHEN b.subnet IS NULL THEN 'nova' WHEN b.is_usual THEN 'usual' ELSE 'fora do usual' END
                   AS baseline_status,
               b.token_share, b.days_seen
        FROM client_subnet_daily d
        LEFT JOIN client_subnet_baseline b ON b.dt = d.dt AND b.client_id = d.client_id AND b.subnet = d.subnet
        WHERE d.client_id = ? AND d.{_DAY}
        ORDER BY d.total_requests DESC, d.subnet
        """,
        [client_id, dt],
    )
