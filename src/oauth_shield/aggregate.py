"""Silver layer: daily aggregates per client application and per source IP."""

from __future__ import annotations

import pandas as pd

from oauth_shield.generator import STATUS_INVALID_CLIENT, STATUS_INVALID_SCOPE, STATUS_OK
from oauth_shield.network import subnet_of

CLIENT_SUBNET_DAILY_COLUMNS = [
    "client_id",
    "subnet",
    "total_requests",
    "success_count",
    "invalid_scope_count",
    "distinct_ips",
]

CLIENT_DAILY_COLUMNS = [
    "client_id",
    "total_requests",
    "success_count",
    "error_count",
    "invalid_scope_count",
    "invalid_client_count",
    "distinct_ips",
    "distinct_scopes_requested",
    "off_baseline_ip_requests",
    "foreign_country_requests",
    "expected_daily_volume",
]


def _baseline_pairs(profiles: pd.DataFrame) -> pd.DataFrame:
    """(client_id, source_ip) pairs the registry considers usual."""
    pairs = profiles[["client_id", "usual_ips"]].copy()
    pairs["source_ip"] = pairs["usual_ips"].str.split()
    pairs = pairs.explode("source_ip")[["client_id", "source_ip"]]
    pairs["is_baseline_ip"] = True
    return pairs


def client_daily(events: pd.DataFrame, profiles: pd.DataFrame) -> pd.DataFrame:
    df = events.merge(_baseline_pairs(profiles), on=["client_id", "source_ip"], how="left")
    df = df.merge(profiles[["client_id", "home_country"]], on="client_id", how="left")
    df["is_ok"] = df["status_code"] == STATUS_OK
    df["is_invalid_scope"] = df["status_code"] == STATUS_INVALID_SCOPE
    df["is_invalid_client"] = df["status_code"] == STATUS_INVALID_CLIENT
    df["is_off_baseline"] = df["is_baseline_ip"].isna()
    df["is_foreign"] = df["country"] != df["home_country"]

    agg = df.groupby("client_id").agg(
        total_requests=("event_id", "size"),
        success_count=("is_ok", "sum"),
        invalid_scope_count=("is_invalid_scope", "sum"),
        invalid_client_count=("is_invalid_client", "sum"),
        distinct_ips=("source_ip", "nunique"),
        distinct_scopes_requested=("requested_scope", "nunique"),
        off_baseline_ip_requests=("is_off_baseline", "sum"),
        foreign_country_requests=("is_foreign", "sum"),
    )

    out = profiles[["client_id", "expected_daily_volume"]].merge(agg.reset_index(), on="client_id", how="left")
    count_cols = [c for c in CLIENT_DAILY_COLUMNS if c not in ("client_id", "expected_daily_volume")]
    out[count_cols] = out.reindex(columns=count_cols).fillna(0)
    out["error_count"] = out["total_requests"] - out["success_count"]
    out[count_cols] = out[count_cols].astype("int64")
    out["expected_daily_volume"] = out["expected_daily_volume"].astype("int64")
    return out[CLIENT_DAILY_COLUMNS]


def client_subnet_daily(events: pd.DataFrame) -> pd.DataFrame:
    """One row per (client, /24 subnet): the daily input of the learned subnet baseline."""
    df = events.assign(
        subnet=events["source_ip"].map(subnet_of),
        is_ok=events["status_code"] == STATUS_OK,
        is_invalid_scope=events["status_code"] == STATUS_INVALID_SCOPE,
    )
    out = (
        df.groupby(["client_id", "subnet"])
        .agg(
            total_requests=("event_id", "size"),
            success_count=("is_ok", "sum"),
            invalid_scope_count=("is_invalid_scope", "sum"),
            distinct_ips=("source_ip", "nunique"),
        )
        .reset_index()
    )
    for col in CLIENT_SUBNET_DAILY_COLUMNS[2:]:
        out[col] = out[col].astype("int64")
    return out[CLIENT_SUBNET_DAILY_COLUMNS]


def ip_daily(events: pd.DataFrame) -> pd.DataFrame:
    df = events.assign(is_failed=events["status_code"] != STATUS_OK)
    out = (
        df.groupby(["source_ip", "country"])
        .agg(
            total_requests=("event_id", "size"),
            failed_requests=("is_failed", "sum"),
            distinct_clients=("client_id", "nunique"),
        )
        .reset_index()
    )
    for col in ("total_requests", "failed_requests", "distinct_clients"):
        out[col] = out[col].astype("int64")
    return out
