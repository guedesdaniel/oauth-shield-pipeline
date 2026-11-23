"""Daily OAuth Shield pipeline: bronze -> quality checks -> silver -> gold.

bronze  oauth_events, client_profile, ground_truth, benign_events   (raw, synthetic)
silver  client_daily, ip_daily, client_subnet_daily                (daily aggregates)
silver  client_subnet_baseline   (usual /24 subnets learned from the previous 14 days)
gold    risk_scores, detection_metrics                              (explainable risk + evaluation)

Storage is local Parquet or S3 (STORAGE_BACKEND), same partition layout either way,
so Athena can query the S3 output through partition projection.
"""

from __future__ import annotations

import logging

import pendulum
from airflow.sdk import dag, get_current_context, task

log = logging.getLogger(__name__)


def _run_date() -> str:
    ctx = get_current_context()
    for key in ("logical_date", "data_interval_end", "run_after"):
        value = ctx.get(key)
        if value:
            return value.strftime("%Y-%m-%d")
    return pendulum.now("UTC").strftime("%Y-%m-%d")


@dag(
    dag_id="oauth_shield_daily",
    schedule="@daily",
    start_date=pendulum.datetime(2026, 10, 1, tz="UTC"),
    catchup=False,
    max_active_runs=1,
    default_args={"retries": 2, "retry_delay": pendulum.duration(minutes=2)},
    tags=["oauth", "fraud", "medallion"],
    doc_md=__doc__,
)
def oauth_shield_daily():
    @task
    def generate_events() -> str:
        from oauth_shield import generator
        from oauth_shield.storage import Storage

        dt = _run_date()
        store = Storage()
        cfg = generator.GeneratorConfig()
        profiles = generator.build_client_profiles(cfg)
        events, truth, benign = generator.generate_day(profiles, dt, cfg)
        # The registry as declared on dt: only migrations the client reported are reflected.
        store.write(generator.registry_for_day(profiles, dt, cfg), "bronze", "client_profile", dt)
        store.write(truth, "bronze", "ground_truth", dt)
        store.write(benign, "bronze", "benign_events", dt)
        uri = store.write(events, "bronze", "oauth_events", dt)
        log.info("dt=%s wrote %d events to %s", dt, len(events), uri)
        return dt

    @task
    def check_quality(dt: str) -> str:
        import pandas as pd

        from oauth_shield.generator import EVENT_COLUMNS, VALID_STATUSES
        from oauth_shield.storage import Storage

        events = Storage().read("bronze", "oauth_events", dt)
        day_start = pd.Timestamp(dt)
        checks = {
            "not empty": len(events) > 0,
            "expected columns": list(events.columns) == EVENT_COLUMNS,
            "unique event_id": events["event_id"].is_unique,
            "no null client_id": events["client_id"].notna().all(),
            "valid status codes": set(events["status_code"]).issubset(VALID_STATUSES),
            "events inside the day": events["event_ts"]
            .between(day_start, day_start + pd.Timedelta(days=1), inclusive="left")
            .all(),
        }
        failed = [name for name, ok in checks.items() if not ok]
        if failed:
            raise ValueError(f"data quality checks failed for dt={dt}: {failed}")
        log.info("dt=%s all %d quality checks passed", dt, len(checks))
        return dt

    @task
    def build_silver(dt: str) -> str:
        from oauth_shield import aggregate
        from oauth_shield.storage import Storage

        store = Storage()
        events = store.read("bronze", "oauth_events", dt)
        profiles = store.read("bronze", "client_profile", dt)
        store.write(aggregate.client_daily(events, profiles), "silver", "client_daily", dt)
        store.write(aggregate.ip_daily(events), "silver", "ip_daily", dt)
        store.write(aggregate.client_subnet_daily(events), "silver", "client_subnet_daily", dt)
        return dt

    @task
    def build_baseline(dt: str) -> str:
        from oauth_shield import baseline
        from oauth_shield.storage import Storage

        store = Storage()
        history, n_days = store.read_many("silver", "client_subnet_daily", baseline.window_dates(dt))
        store.write(baseline.build_baseline(history, n_days), "silver", "client_subnet_baseline", dt)
        log.info("dt=%s baseline window: %d of 14 days found, ready=%s", dt, n_days, baseline.is_ready(n_days))
        return dt

    @task
    def score_risk(dt: str) -> dict:
        from oauth_shield import baseline, risk
        from oauth_shield.storage import Storage

        store = Storage()
        subnet_baseline = store.read("silver", "client_subnet_baseline", dt)
        n_days = int(subnet_baseline["window_days_available"].max()) if len(subnet_baseline) else 0
        ready = baseline.is_ready(n_days)
        scores = risk.score_clients(
            store.read("silver", "client_daily", dt),
            store.read("silver", "ip_daily", dt),
            store.read("bronze", "oauth_events", dt),
            subnet_daily=store.read("silver", "client_subnet_daily", dt),
            baseline=subnet_baseline,
            baseline_ready=ready,
        )
        metrics = risk.detection_metrics(scores, store.read("bronze", "ground_truth", dt), dt, baseline_ready=ready)
        store.write(scores, "gold", "risk_scores", dt)
        store.write(metrics, "gold", "detection_metrics", dt)

        summary = metrics.iloc[0].to_dict()
        log.info("dt=%s risk levels: %s", dt, scores["risk_level"].value_counts().to_dict())
        log.info("dt=%s detection: %s", dt, summary)
        for _, row in scores[scores["risk_level"] == "HIGH"].head(10).iterrows():
            log.warning("HIGH risk %s (score %d): %s", row["client_id"], row["risk_score"], row["reasons"])
        # numpy scalars (np.int64, np.bool_) are not JSON-serializable for XCom: unwrap them.
        return {k: (v.item() if hasattr(v, "item") else v) for k, v in summary.items()}

    score_risk(build_baseline(build_silver(check_quality(generate_events()))))


oauth_shield_daily()
