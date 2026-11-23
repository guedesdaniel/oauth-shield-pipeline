"""Offline simulation of N consecutive days, in memory, for tuning the generator.

It chains exactly the same functions the Airflow DAG runs (generate -> silver -> 14-day baseline ->
risk -> metrics) but writes nothing. The official data still comes from the Airflow backfill;
this only exists so a parameter change can be evaluated in minutes instead of a 30-day backfill.

Usage:  python scripts/simulate.py --end 2026-11-22 --days 30
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from oauth_shield import aggregate, baseline, generator, risk  # noqa: E402


def simulate(end: str, days: int, cfg: generator.GeneratorConfig) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Return (one metrics row per day, one row per injected attack with whether it was caught)."""
    profiles = generator.build_client_profiles(cfg)
    subnet_history: dict[str, pd.DataFrame] = {}
    daily, attacks = [], []
    for dt in pd.date_range(end=end, periods=days, freq="D").strftime("%Y-%m-%d"):
        events, truth, benign = generator.generate_day(profiles, dt, cfg)
        registry = generator.registry_for_day(profiles, dt, cfg)
        subnet_daily = aggregate.client_subnet_daily(events)

        window = [d for d in baseline.window_dates(dt) if d in subnet_history]
        history = pd.concat([subnet_history[d].assign(dt=d) for d in window]) if window else pd.DataFrame()
        ready = baseline.is_ready(len(window))
        scores = risk.score_clients(
            aggregate.client_daily(events, registry),
            aggregate.ip_daily(events),
            events,
            subnet_daily=subnet_daily,
            baseline=baseline.build_baseline(history, len(window)),
            baseline_ready=ready,
        )
        subnet_history[dt] = subnet_daily

        metrics = risk.detection_metrics(scores, truth, dt, baseline_ready=ready).iloc[0].to_dict()
        high = set(scores.loc[scores["risk_level"] == "HIGH", "client_id"])
        false_pos = high - set(truth["client_id"])
        for kind in generator.BENIGN_EVENT_TYPES:
            explained = set(benign.loc[benign["event_type"] == kind, "client_id"])
            metrics[f"fp_{kind}"] = len(false_pos & explained)
        metrics["fp_new_subnet_signal"] = int(
            scores.loc[scores["client_id"].isin(false_pos), "s_new_subnet_scope_errors"].sum()
        )
        daily.append(metrics)
        attacks.append(truth.assign(dt=dt, caught=truth["client_id"].isin(high), baseline_ready=ready))
        print(f"{dt}  P={metrics['precision']:.2f}  R={metrics['recall']:.2f}  ready={ready}", file=sys.stderr)
    return pd.DataFrame(daily), pd.concat(attacks, ignore_index=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--end", required=True, help="last day, YYYY-MM-DD")
    parser.add_argument("--days", type=int, default=30)
    args = parser.parse_args()

    daily, attacks = simulate(args.end, args.days, generator.GeneratorConfig())
    print(daily.to_string(index=False))

    ready = daily[daily["baseline_ready"]]
    evaluated = attacks[attacks["baseline_ready"]]
    print(f"\nEvaluated days (baseline ready): {len(ready)}")
    for col in ("precision", "recall"):
        print(f"  {col:9s} mean={ready[col].mean():.3f}  min={ready[col].min():.3f}  max={ready[col].max():.3f}")
    print("\nRecall by attack type (evaluated days):")
    print(evaluated.groupby("attack_type")["caught"].agg(["mean", "sum", "count"]).round(3).to_string())
    print(f"\nFalse positives on evaluated days: {int(ready['false_positives'].sum())}")
    for kind in generator.BENIGN_EVENT_TYPES:
        print(f"  explained by benign {kind}: {int(ready[f'fp_{kind}'].sum())}")
    print(f"  of which raised by the new-subnet signal: {int(ready['fp_new_subnet_signal'].sum())}")


if __name__ == "__main__":
    main()
