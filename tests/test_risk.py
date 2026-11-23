import pandas as pd
import pytest

from oauth_shield import aggregate, baseline, risk

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


def test_metrics_reconcile(scores, ground_truth):
    m = risk.detection_metrics(scores, ground_truth, DT).iloc[0]
    assert m["true_positives"] + m["false_negatives"] == len(ground_truth)
    assert m["true_positives"] + m["false_positives"] == m["flagged"]
    assert 0.0 <= m["precision"] <= 1.0 and 0.0 <= m["recall"] <= 1.0


def test_detection_metrics_carries_baseline_ready(scores, ground_truth):
    m = risk.detection_metrics(scores, ground_truth, DT, baseline_ready=True)
    assert list(m.columns) == risk.DETECTION_COLUMNS
    assert bool(m.iloc[0]["baseline_ready"])


def _quiet(client_id, total=100):
    return {
        "client_id": client_id,
        "total_requests": total,
        "success_count": total,
        "error_count": 0,
        "invalid_scope_count": 0,
        "invalid_client_count": 0,
        "distinct_ips": 1,
        "distinct_scopes_requested": 2,
        "off_baseline_ip_requests": 0,
        "foreign_country_requests": 0,
        "expected_daily_volume": total,
    }


def _empty_ips():
    return pd.DataFrame(columns=["source_ip", "country", "total_requests", "failed_requests", "distinct_clients"])


def _score(subnet_rows, ready=True, extra_clients=(), total=100):
    """Client "a" usually issues tokens from 1.1.1.0/24. subnet_rows: (client, subnet, invalid_scope_count)."""
    cd = pd.DataFrame([_quiet("a", total), *(_quiet(c) for c in extra_clients)])
    sd = pd.DataFrame(
        [
            {
                "client_id": c,
                "subnet": s,
                "total_requests": n,
                "success_count": 0,
                "invalid_scope_count": n,
                "distinct_ips": 1,
            }
            for c, s, n in subnet_rows
        ],
        columns=aggregate.CLIENT_SUBNET_DAILY_COLUMNS,
    )
    hist = pd.DataFrame(
        [
            {
                "client_id": "a",
                "subnet": "1.1.1.0/24",
                "total_requests": 500,
                "success_count": 500,
                "invalid_scope_count": 0,
                "distinct_ips": 1,
                "dt": "2026-11-01",
            }
        ]
    )
    bl = baseline.build_baseline(hist, 14)
    events = pd.DataFrame(columns=["client_id", "source_ip"])
    out = risk.score_clients(cd, _empty_ips(), events, subnet_daily=sd, baseline=bl, baseline_ready=ready)
    return out.set_index("client_id")


def test_fires_on_unusual_subnet_at_threshold():
    assert _score([("a", "9.9.9.0/24", 5)]).loc["a", "s_new_subnet_scope_errors"]
    assert not _score([("a", "9.9.9.0/24", 4)]).loc["a", "s_new_subnet_scope_errors"]


def test_alone_is_high_with_reason():
    r = _score([("a", "9.9.9.0/24", 5)]).loc["a"]
    assert r["risk_level"] == "HIGH"
    assert "scope errors from a subnet not usual for this app" in r["reasons"]


def test_usual_subnet_never_fires():
    assert not _score([("a", "1.1.1.0/24", 50)]).loc["a", "s_new_subnet_scope_errors"]


def test_not_diluted_by_client_volume():
    assert _score([("a", "9.9.9.0/24", 5)], total=100_000).loc["a", "s_new_subnet_scope_errors"]


def test_off_when_baseline_not_ready():
    assert not _score([("a", "9.9.9.0/24", 50)], ready=False).loc["a", "s_new_subnet_scope_errors"]


def test_client_without_history_can_fire():
    r = _score([("z", "8.8.8.0/24", 6)], extra_clients=["z"])
    assert r.loc["z", "s_new_subnet_scope_errors"]


def test_client_without_events_today():
    r = _score([("a", "9.9.9.0/24", 5)], extra_clients=["b"])
    assert not r.loc["b", "s_new_subnet_scope_errors"]
    assert r.loc["b", "risk_score"] == 0


def test_quiet_client_scores_zero():
    no_events = pd.DataFrame(columns=["client_id", "source_ip"])
    out = risk.score_clients(pd.DataFrame([_quiet("sw-quiet")]), _empty_ips(), no_events)
    assert out.loc[0, "risk_score"] == 0
    assert out.loc[0, "risk_level"] == "LOW"
