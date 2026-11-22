import pandas as pd
import pytest

from oauth_shield import risk

from .conftest import DT


@pytest.fixture(scope="module")
def scores(client_daily, ip_daily, events):
    return risk.score_clients(client_daily, ip_daily, events)


def test_scores_shape(scores, client_daily):
    assert list(scores.columns) == risk.RISK_COLUMNS
    assert len(scores) == len(client_daily)
    assert scores["risk_score"].between(0, 100).all()


def test_every_flag_is_explained(scores):
    flagged = scores[scores["risk_level"] != "LOW"]
    assert (flagged["reasons"].str.len() > 0).all()


def test_detects_injected_attacks(scores, ground_truth):
    metrics = risk.detection_metrics(scores, ground_truth, DT).iloc[0]
    assert metrics["recall"] >= 0.9
    assert metrics["precision"] >= 0.8


def test_each_attack_triggers_its_signal(scores, ground_truth):
    expected = {
        "scope_probing": "s_scope_probing",
        "credential_stuffing": "s_suspicious_ip",
        "geo_anomaly": "s_foreign_geo",
        "volume_burst": "s_volume_burst",
    }
    merged = ground_truth.merge(scores, on="client_id")
    for _, row in merged.iterrows():
        assert row[expected[row["attack_type"]]], row["client_id"]


def test_quiet_client_scores_zero():
    client = pd.DataFrame(
        [
            {
                "client_id": "sw-quiet",
                "total_requests": 100,
                "success_count": 100,
                "error_count": 0,
                "invalid_scope_count": 0,
                "invalid_client_count": 0,
                "distinct_ips": 1,
                "distinct_scopes_requested": 2,
                "off_baseline_ip_requests": 0,
                "foreign_country_requests": 0,
                "expected_daily_volume": 100,
            }
        ]
    )
    ips = pd.DataFrame(columns=["source_ip", "country", "total_requests", "failed_requests", "distinct_clients"])
    events = pd.DataFrame(columns=["client_id", "source_ip"])
    out = risk.score_clients(client, ips, events)
    assert out.loc[0, "risk_score"] == 0
    assert out.loc[0, "risk_level"] == "LOW"
