"""Silver layer: the /24 subnets each client application usually issues tokens from.

Learned from the app's own history instead of a declared registry: for day D, look at the
`client_subnet_daily` partitions of D-14 .. D-1 (never D itself) and keep the subnets that,
together, issued 95% of the app's tokens. A fraudster who shows up once with a handful of
requests never gets near that share; a legitimate new host in the same /24 is usual from day one.
"""

from __future__ import annotations

from dataclasses import dataclass

import pandas as pd

BASELINE_COLUMNS = [
    "client_id",
    "subnet",
    "window_tokens",
    "token_share",
    "days_seen",
    "is_usual",
    "window_days_available",
]
_DTYPES = {
    "client_id": "object",
    "subnet": "object",
    "window_tokens": "int64",
    "token_share": "float64",
    "days_seen": "int64",
    "is_usual": "bool",
    "window_days_available": "int64",
}


@dataclass(frozen=True)
class BaselineConfig:
    window_days: int = 14
    coverage: float = 0.95
    min_days: int = 14


def window_dates(dt: str, days: int = BaselineConfig.window_days) -> list[str]:
    """The `days` calendar days before `dt` (D-days .. D-1), oldest first."""
    end = pd.Timestamp(dt) - pd.Timedelta(days=1)
    return [d.strftime("%Y-%m-%d") for d in pd.date_range(end=end, periods=days, freq="D")]


def is_ready(window_days_available: int, cfg: BaselineConfig = BaselineConfig()) -> bool:
    """The baseline is trusted only when the whole window exists (decided per day, not per app)."""
    return window_days_available >= cfg.min_days


def build_baseline(
    history: pd.DataFrame, window_days_available: int, cfg: BaselineConfig = BaselineConfig()
) -> pd.DataFrame:
    """`history`: client_subnet_daily rows of the window plus a `dt` column (Storage.read_many)."""
    if history.empty:
        return pd.DataFrame({c: pd.Series(dtype=t) for c, t in _DTYPES.items()})[BASELINE_COLUMNS]

    tokens = history[history["success_count"] > 0]
    out = (
        tokens.groupby(["client_id", "subnet"])
        .agg(window_tokens=("success_count", "sum"), days_seen=("dt", "nunique"))
        .reset_index()
        .sort_values(["client_id", "window_tokens", "subnet"], ascending=[True, False, True])
    )
    out["token_share"] = out["window_tokens"] / out.groupby("client_id")["window_tokens"].transform("sum")
    cumulative = out.groupby("client_id")["token_share"].cumsum()
    # Include subnets until the one that crosses the coverage target (inclusive).
    out["is_usual"] = (cumulative - out["token_share"]) < cfg.coverage
    out["window_days_available"] = window_days_available
    return out.astype(_DTYPES)[BASELINE_COLUMNS].reset_index(drop=True)
