import pandas as pd

from oauth_shield import generator

from .conftest import DT


def test_profiles_are_deterministic(cfg):
    a = generator.build_client_profiles(cfg)
    b = generator.build_client_profiles(cfg)
    pd.testing.assert_frame_equal(a, b)
    assert a["client_id"].is_unique


def test_day_is_deterministic(profiles, cfg):
    ev1, gt1 = generator.generate_day(profiles, DT, cfg)
    ev2, gt2 = generator.generate_day(profiles, DT, cfg)
    pd.testing.assert_frame_equal(ev1, ev2)
    pd.testing.assert_frame_equal(gt1, gt2)


def test_events_schema_and_bounds(events):
    assert list(events.columns) == generator.EVENT_COLUMNS
    assert events["event_id"].is_unique
    assert set(events["status_code"]).issubset(generator.VALID_STATUSES)
    day_start = pd.Timestamp(DT)
    assert events["event_ts"].min() >= day_start
    assert events["event_ts"].max() < day_start + pd.Timedelta(days=1)


def test_every_attack_type_is_injected(ground_truth):
    assert set(ground_truth["attack_type"]) == set(generator.ATTACK_TYPES)
    assert ground_truth["client_id"].is_unique
