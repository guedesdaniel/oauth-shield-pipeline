import pandas as pd

from oauth_shield import baseline


def _hist(rows):
    """rows: (dt, client_id, subnet, tokens)."""
    return pd.DataFrame(
        [
            {
                "client_id": c,
                "subnet": s,
                "total_requests": n,
                "success_count": n,
                "invalid_scope_count": 0,
                "distinct_ips": 1,
                "dt": d,
            }
            for d, c, s, n in rows
        ]
    )


def test_window_excludes_today():
    w = baseline.window_dates("2026-11-15")
    assert len(w) == 14
    assert w[0] == "2026-11-01" and w[-1] == "2026-11-14"


def test_95_percent_rule_includes_crossing_subnet():
    h = _hist(
        [
            ("2026-11-01", "a", "1.1.1.0/24", 900),
            ("2026-11-01", "a", "2.2.2.0/24", 80),
            ("2026-11-01", "a", "3.3.3.0/24", 20),
        ]
    )
    b = baseline.build_baseline(h, 14).set_index("subnet")
    assert b.loc["1.1.1.0/24", "is_usual"]
    assert b.loc["2.2.2.0/24", "is_usual"]  # cumulative 0.90 -> 0.98: crosses 95%, included
    assert not b.loc["3.3.3.0/24", "is_usual"]


def test_rule_is_per_client():
    h = _hist([("2026-11-01", "a", "1.1.1.0/24", 1000), ("2026-11-01", "b", "9.9.9.0/24", 3)])
    b = baseline.build_baseline(h, 14).set_index("client_id")
    assert b.loc["b", "is_usual"] and b.loc["b", "token_share"] == 1.0


def test_days_seen_and_share():
    h = _hist([("2026-11-01", "a", "1.1.1.0/24", 50), ("2026-11-02", "a", "1.1.1.0/24", 50)])
    b = baseline.build_baseline(h, 14).iloc[0]
    assert b["days_seen"] == 2 and b["window_tokens"] == 100 and b["token_share"] == 1.0
    assert b["window_days_available"] == 14


def test_subnet_without_tokens_is_not_usual():
    h = _hist([("2026-11-01", "a", "1.1.1.0/24", 100)])
    h = pd.concat([h, _hist([("2026-11-01", "a", "7.7.7.0/24", 0)]).assign(invalid_scope_count=30)])
    b = baseline.build_baseline(h, 14).set_index("subnet")
    assert "7.7.7.0/24" not in b.index or not b.loc["7.7.7.0/24", "is_usual"]


def test_empty_history_has_schema():
    b = baseline.build_baseline(pd.DataFrame(), 0)
    assert list(b.columns) == baseline.BASELINE_COLUMNS and b.empty
    assert b["is_usual"].dtype == bool and b["window_tokens"].dtype == "int64"


def test_readiness_is_per_day():
    assert not baseline.is_ready(0)
    assert not baseline.is_ready(13)  # one day of the window missing (failed run)
    assert baseline.is_ready(14)
