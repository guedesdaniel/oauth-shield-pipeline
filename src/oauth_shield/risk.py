"""Gold layer: explainable, rule-based risk score per client application.

Each signal is a simple, auditable rule. The score is a weighted sum capped at
100, and every flagged client carries the list of reasons that fired, so an
analyst can act on it without reverse-engineering a model.
"""

from __future__ import annotations

from dataclasses import dataclass

import pandas as pd


@dataclass(frozen=True)
class Thresholds:
    scope_probing_min: int = 10
    scope_probing_ratio: float = 0.05
    off_baseline_min: int = 20
    off_baseline_ratio: float = 0.25
    foreign_min: int = 5
    burst_ratio: float = 3.0
    suspicious_ip_min_clients: int = 10
    suspicious_ip_fail_ratio: float = 0.5
    suspicious_ip_min_hits: int = 10
    new_subnet_scope_errors_min: int = 5


WEIGHTS = {
    "s_scope_probing": 40,
    "s_off_baseline_ip": 25,
    "s_foreign_geo": 40,
    "s_volume_burst": 25,
    "s_suspicious_ip": 40,
    "s_new_subnet_scope_errors": 40,
}
REASONS = {
    "s_scope_probing": "repeated requests for unauthorized scopes",
    "s_off_baseline_ip": "large share of traffic from unseen IPs",
    "s_foreign_geo": "token requests from outside the home country",
    "s_volume_burst": "volume far above the expected baseline",
    "s_suspicious_ip": "targeted by an IP that is attacking many clients",
    "s_new_subnet_scope_errors": "scope errors from a subnet not usual for this app",
}
HIGH, MEDIUM = 40, 20
HIGH_LABEL = "HIGH"

RISK_COLUMNS = ["client_id", "risk_score", "risk_level", "reasons", *WEIGHTS.keys()]
DETECTION_COLUMNS = [
    "run_date",
    "flagged",
    "true_positives",
    "false_positives",
    "false_negatives",
    "precision",
    "recall",
    "baseline_ready",
]


def suspicious_ips(ip_daily: pd.DataFrame, t: Thresholds = Thresholds()) -> pd.Series:
    fail_ratio = ip_daily["failed_requests"] / ip_daily["total_requests"]
    mask = (ip_daily["distinct_clients"] >= t.suspicious_ip_min_clients) & (fail_ratio >= t.suspicious_ip_fail_ratio)
    return ip_daily.loc[mask, "source_ip"]


def new_subnet_scope_error_clients(
    subnet_daily: pd.DataFrame, baseline: pd.DataFrame, t: Thresholds = Thresholds()
) -> set[str]:
    """Clients with >= N scope errors today from a /24 that is not usual for them.

    Counted per (client, subnet) and never divided by the client's total volume, so a big app
    cannot dilute a small, focused attack. A subnet absent from the baseline counts as not usual.
    """
    usual = baseline.loc[baseline["is_usual"], ["client_id", "subnet"]].assign(usual=True)
    df = subnet_daily.merge(usual, on=["client_id", "subnet"], how="left")
    hits = df[df["usual"].isna() & (df["invalid_scope_count"] >= t.new_subnet_scope_errors_min)]
    return set(hits["client_id"])


def score_clients(
    client_daily: pd.DataFrame,
    ip_daily: pd.DataFrame,
    events: pd.DataFrame,
    subnet_daily: pd.DataFrame | None = None,
    baseline: pd.DataFrame | None = None,
    baseline_ready: bool = False,
    t: Thresholds = Thresholds(),
) -> pd.DataFrame:
    bad_ips = set(suspicious_ips(ip_daily, t))
    hits = events[events["source_ip"].isin(bad_ips)].groupby("client_id").size().rename("suspicious_ip_hits")
    df = client_daily.merge(hits, on="client_id", how="left")
    df["suspicious_ip_hits"] = df["suspicious_ip_hits"].fillna(0)

    total = df["total_requests"].clip(lower=1)
    df["s_scope_probing"] = (df["invalid_scope_count"] >= t.scope_probing_min) & (
        df["invalid_scope_count"] / total >= t.scope_probing_ratio
    )
    df["s_off_baseline_ip"] = (df["off_baseline_ip_requests"] >= t.off_baseline_min) & (
        df["off_baseline_ip_requests"] / total >= t.off_baseline_ratio
    )
    df["s_foreign_geo"] = df["foreign_country_requests"] >= t.foreign_min
    df["s_volume_burst"] = df["total_requests"] / df["expected_daily_volume"].clip(lower=1) >= t.burst_ratio
    df["s_suspicious_ip"] = df["suspicious_ip_hits"] >= t.suspicious_ip_min_hits
    new_subnet = set()
    if baseline_ready and subnet_daily is not None and baseline is not None:
        new_subnet = new_subnet_scope_error_clients(subnet_daily, baseline, t)
    df["s_new_subnet_scope_errors"] = df["client_id"].isin(new_subnet)

    signals = list(WEIGHTS)
    df["risk_score"] = sum(df[s].astype("int64") * w for s, w in WEIGHTS.items()).clip(upper=100)
    df["risk_level"] = "LOW"
    df.loc[df["risk_score"] >= MEDIUM, "risk_level"] = "MEDIUM"
    df.loc[df["risk_score"] >= HIGH, "risk_level"] = "HIGH"
    df["reasons"] = df[signals].apply(lambda row: "; ".join(REASONS[s] for s in signals if row[s]), axis=1)
    df["risk_score"] = df["risk_score"].astype("int64")
    for s in signals:
        df[s] = df[s].astype(bool)
    return df[RISK_COLUMNS].sort_values("risk_score", ascending=False).reset_index(drop=True)


def detection_metrics(
    scores: pd.DataFrame, ground_truth: pd.DataFrame, dt: str, baseline_ready: bool = False
) -> pd.DataFrame:
    """Compare HIGH-risk clients with the injected attacks (synthetic ground truth)."""
    flagged = set(scores.loc[scores["risk_level"] == HIGH_LABEL, "client_id"])
    attacked = set(ground_truth["client_id"])
    tp = len(flagged & attacked)
    fp = len(flagged - attacked)
    fn = len(attacked - flagged)
    return pd.DataFrame(
        [
            {
                "run_date": dt,
                "flagged": len(flagged),
                "true_positives": tp,
                "false_positives": fp,
                "false_negatives": fn,
                "precision": tp / (tp + fp) if flagged else 0.0,
                "recall": tp / (tp + fn) if attacked else 0.0,
                "baseline_ready": bool(baseline_ready),
            }
        ],
        columns=DETECTION_COLUMNS,
    )
