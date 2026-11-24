import pandas as pd
import pytest

from oauth_shield import baseline, risk
from oauth_shield import dashboard_queries as dq
from oauth_shield.storage import Storage

D1, D2 = "2026-11-01", "2026-11-02"


def _scores(rows):
    """rows: (client_id, score, level, signals that fired)"""
    out = []
    for cid, score, level, fired in rows:
        row = {"client_id": cid, "risk_score": score, "risk_level": level, "reasons": "; ".join(fired)}
        row.update({s: s in fired for s in risk.WEIGHTS})
        out.append(row)
    return pd.DataFrame(out)


def _events(dt, rows):
    """rows: (source_ip, client_id, status_code, count)"""
    out = []
    for ip, cid, status, n in rows:
        out += [
            {
                "client_id": cid,
                "source_ip": ip,
                "country": "BR",
                "requested_scope": "payments:read",
                "status_code": status,
            }
        ] * n
    df = pd.DataFrame(out)
    df.insert(0, "event_ts", pd.Timestamp(dt))
    df.insert(0, "event_id", [f"{dt}-{i}" for i in range(len(df))])
    return df


def _metrics(dt, flagged, tp, fp, fn, precision, recall, ready):
    return pd.DataFrame(
        [
            {
                "run_date": dt,
                "flagged": flagged,
                "true_positives": tp,
                "false_positives": fp,
                "false_negatives": fn,
                "precision": precision,
                "recall": recall,
                "baseline_ready": ready,
            }
        ]
    )


def _client_daily(rows):
    cols = ["client_id", "total_requests", "success_count", "invalid_scope_count", "expected_daily_volume"]
    return pd.DataFrame(rows, columns=cols)


def _subnet_daily(rows):
    cols = ["client_id", "subnet", "total_requests", "success_count", "invalid_scope_count", "distinct_ips"]
    return pd.DataFrame(rows, columns=cols)


@pytest.fixture
def dash(tmp_path):
    """Two tiny, hand-checked days. D1: baseline not ready. D2: ready, and no benign events."""
    s = Storage(backend="local", data_dir=str(tmp_path))
    w = s.write
    w(
        _scores(
            [
                ("a", 80, "HIGH", ["s_scope_probing", "s_foreign_geo"]),
                ("b", 40, "HIGH", ["s_foreign_geo"]),
                ("c", 25, "MEDIUM", ["s_volume_burst"]),
                ("d", 0, "LOW", []),
            ]
        ),
        "gold",
        "risk_scores",
        D1,
    )
    w(
        _scores(
            [
                ("a", 0, "LOW", []),
                ("b", 40, "HIGH", ["s_new_subnet_scope_errors"]),
                ("c", 65, "HIGH", ["s_volume_burst", "s_suspicious_ip"]),
                ("d", 0, "LOW", []),
            ]
        ),
        "gold",
        "risk_scores",
        D2,
    )
    w(
        pd.DataFrame({"client_id": ["a", "d"], "attack_type": ["scope_probing", "credential_stuffing"]}),
        "bronze",
        "ground_truth",
        D1,
    )
    w(pd.DataFrame({"client_id": ["c"], "attack_type": ["volume_burst"]}), "bronze", "ground_truth", D2)
    benign_cols = ["client_id", "event_type", "subnet", "notified"]
    w(pd.DataFrame([("b", "foreign_region", "", False)], columns=benign_cols), "bronze", "benign_events", D1)
    w(
        pd.DataFrame({c: pd.Series(dtype="bool" if c == "notified" else "object") for c in benign_cols}),
        "bronze",
        "benign_events",
        D2,
    )
    w(_metrics(D1, 2, 1, 1, 1, 0.5, 0.5, False), "gold", "detection_metrics", D1)
    w(_metrics(D2, 2, 1, 1, 0, 0.5, 1.0, True), "gold", "detection_metrics", D2)
    w(
        _client_daily([("a", 100, 80, 20, 100), ("b", 50, 50, 0, 50), ("c", 300, 300, 0, 100), ("d", 30, 0, 0, 40)]),
        "silver",
        "client_daily",
        D1,
    )
    w(
        _client_daily([("a", 100, 100, 0, 100), ("b", 56, 50, 6, 50), ("c", 400, 395, 0, 100), ("d", 40, 40, 0, 40)]),
        "silver",
        "client_daily",
        D2,
    )
    ip_cols = ["source_ip", "country", "total_requests", "failed_requests", "distinct_clients"]
    w(
        pd.DataFrame([("9.9.9.9", "BR", 30, 30, 3), ("1.1.1.1", "BR", 100, 0, 1)], columns=ip_cols),
        "silver",
        "ip_daily",
        D1,
    )
    w(pd.DataFrame([("9.9.9.9", "BR", 10, 5, 2)], columns=ip_cols), "silver", "ip_daily", D2)
    w(
        _events(D1, [("9.9.9.9", c, 401, 10) for c in "abd"] + [("1.1.1.1", "a", 200, 100)]),
        "bronze",
        "oauth_events",
        D1,
    )
    w(_events(D2, [("9.9.9.9", "b", 200, 5), ("9.9.9.9", "c", 401, 5)]), "bronze", "oauth_events", D2)
    w(_subnet_daily([("b", "7.7.7.0/24", 9, 0, 9, 1)]), "silver", "client_subnet_daily", D1)
    w(
        _subnet_daily([("b", "1.1.1.0/24", 50, 50, 0, 2), ("b", "5.5.5.0/24", 6, 0, 6, 1)]),
        "silver",
        "client_subnet_daily",
        D2,
    )
    w(baseline.build_baseline(pd.DataFrame(), 0), "silver", "client_subnet_baseline", D1)
    hist = _subnet_daily([("b", "1.1.1.0/24", 50, 50, 0, 2)]).assign(dt="2026-10-31")
    w(baseline.build_baseline(hist, 14), "silver", "client_subnet_baseline", D2)
    for dt in (D1, D2):
        w(pd.DataFrame({"client_id": ["a"]}), "bronze", "client_profile", dt)
    return tmp_path


def test_missing_tables_on_empty_dir(tmp_path):  # Review Focus 1
    con = dq.connect(tmp_path)
    assert dq.missing_tables(con) == list(dq.TABLES)


def test_connect_full_dataset(dash):
    con = dq.connect(dash)
    assert dq.missing_tables(con) == []
    assert dq.available_dates(con) == [D1, D2]


def test_day_summary(dash):
    s = dq.day_summary(dq.connect(dash), D1)
    assert s == {"high": 2, "medium": 1, "attacks": 2, "precision": 0.5, "recall": 0.5, "baseline_ready": False}


def test_daily_outcomes(dash):
    df = dq.daily_outcomes(dq.connect(dash), D1, D2)
    assert df.to_dict("records") == [
        {"dt": D1, "outcome": "ataque real", "n": 1, "baseline_ready": False},
        {"dt": D1, "outcome": "falso positivo", "n": 1, "baseline_ready": False},
        {"dt": D2, "outcome": "ataque real", "n": 1, "baseline_ready": True},
        {"dt": D2, "outcome": "falso positivo", "n": 1, "baseline_ready": True},
    ]


def test_daily_outcomes_single_day(dash):  # Review Focus 4
    assert len(dq.daily_outcomes(dq.connect(dash), D2, D2)) == 2


def test_daily_signals(dash):
    df = dq.daily_signals(dq.connect(dash), D1, D2)
    got = {(r.dt, r.signal): r.n for r in df.itertuples()}
    assert got == {
        (D1, "s_foreign_geo"): 2,
        (D1, "s_scope_probing"): 1,
        (D1, "s_volume_burst"): 1,
        (D2, "s_new_subnet_scope_errors"): 1,
        (D2, "s_suspicious_ip"): 1,
        (D2, "s_volume_burst"): 1,
    }


def test_attacks_by_type_only_ready_days(dash):
    df = dq.attacks_by_type(dq.connect(dash), D1, D2)
    assert df.to_dict("records") == [{"attack_type": "volume_burst", "caught": 1, "missed": 0, "recall": 1.0}]


def test_day_errors_explained(dash):
    df = dq.day_errors(dq.connect(dash), D1)
    assert df[["kind", "client_id", "explanation"]].to_dict("records") == [
        {"kind": "ataque que escapou", "client_id": "d", "explanation": "credential_stuffing"},
        {"kind": "falso positivo", "client_id": "b", "explanation": "foreign_region"},
    ]


def test_day_errors_unexplained_fp(dash):  # Review Focus 2
    df = dq.day_errors(dq.connect(dash), D2)
    assert df[["kind", "client_id", "explanation"]].to_dict("records") == [
        {"kind": "falso positivo", "client_id": "b", "explanation": "sem explicação"}
    ]


def test_suspicious_ips(dash):
    df = dq.suspicious_ips(dq.connect(dash), D1, D2)
    assert df.to_dict("records") == [
        {
            "source_ip": "9.9.9.9",
            "country": "BR",
            "days_seen": 2,
            "max_clients": 3,
            "failed": 35,
            "total": 40,
            "fail_ratio": 0.875,
            "hit_real_attack": True,
        }
    ]


def test_unusual_subnet_scope_errors_ready_days_only(dash):
    df = dq.unusual_subnet_scope_errors(dq.connect(dash), D1, D2)
    assert df[["dt", "client_id", "subnet", "invalid_scope_count", "is_attack"]].to_dict("records") == [
        {"dt": D2, "client_id": "b", "subnet": "5.5.5.0/24", "invalid_scope_count": 6, "is_attack": False}
    ]  # D1 (7.7.7.0/24, 9 errors) is left out: baseline not ready


def test_ip_activity(dash):
    df = dq.ip_activity(dq.connect(dash), "9.9.9.9", D1, D2)
    assert df[["dt", "client_id", "requests", "s200", "s401", "is_attack"]].to_dict("records") == [
        {"dt": D1, "client_id": "a", "requests": 10, "s200": 0, "s401": 10, "is_attack": True},
        {"dt": D1, "client_id": "b", "requests": 10, "s200": 0, "s401": 10, "is_attack": False},
        {"dt": D1, "client_id": "d", "requests": 10, "s200": 0, "s401": 10, "is_attack": True},
        {"dt": D2, "client_id": "b", "requests": 5, "s200": 5, "s401": 0, "is_attack": False},
        {"dt": D2, "client_id": "c", "requests": 5, "s200": 0, "s401": 5, "is_attack": True},
    ]


def test_ip_activity_unknown_ip(dash):  # Review Focus 5
    df = dq.ip_activity(dq.connect(dash), "0.0.0.0", D1, D2)
    assert df.empty and "is_attack" in df.columns


def test_app_options(dash):
    df = dq.app_options(dq.connect(dash), D1, D2)
    assert list(df["client_id"]) == ["a", "c", "b", "d"] and list(df["max_score"]) == [80, 65, 40, 0]


def test_app_timeline(dash):
    df = dq.app_timeline(dq.connect(dash), "c", D1, D2)
    assert df[["dt", "risk_level", "truth"]].to_dict("records") == [
        {"dt": D1, "risk_level": "MEDIUM", "truth": None},
        {"dt": D2, "risk_level": "HIGH", "truth": "volume_burst"},
    ]
    b = dq.app_timeline(dq.connect(dash), "b", D1, D1)
    assert b["truth"].tolist() == ["foreign_region"]


def test_app_timeline_unknown_app(dash):  # Review Focus 5
    df = dq.app_timeline(dq.connect(dash), "zzz", D1, D2)
    assert df.empty and "truth" in df.columns


def test_app_subnets_status(dash):  # Review Focus 3: the baseline view also reads D1's empty partition
    df = dq.app_subnets(dq.connect(dash), "b", D2)
    assert df[["subnet", "baseline_status"]].to_dict("records") == [
        {"subnet": "1.1.1.0/24", "baseline_status": "usual"},
        {"subnet": "5.5.5.0/24", "baseline_status": "nova"},
    ]


def test_tables_written_after_connect_are_picked_up(tmp_path):
    """The app caches one connection; data that lands later (first DAG run, backfill) must show up."""
    con = dq.connect(tmp_path)
    assert "detection_metrics" in dq.missing_tables(con)
    Storage(backend="local", data_dir=str(tmp_path)).write(
        _metrics(D1, 0, 0, 0, 0, 0.0, 0.0, False), "gold", "detection_metrics", D1
    )
    assert "detection_metrics" not in dq.missing_tables(con)
    assert dq.available_dates(con) == [D1]
