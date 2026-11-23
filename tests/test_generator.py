import pandas as pd

from oauth_shield import generator
from oauth_shield.network import subnet_of

from .conftest import DT


def test_profiles_are_deterministic(cfg):
    a = generator.build_client_profiles(cfg)
    b = generator.build_client_profiles(cfg)
    pd.testing.assert_frame_equal(a, b)
    assert a["client_id"].is_unique


def test_day_is_deterministic(profiles, cfg):
    ev1, gt1, be1 = generator.generate_day(profiles, DT, cfg)
    ev2, gt2, be2 = generator.generate_day(profiles, DT, cfg)
    pd.testing.assert_frame_equal(ev1, ev2)
    pd.testing.assert_frame_equal(gt1, gt2)
    pd.testing.assert_frame_equal(be1, be2)


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


def test_profiles_have_home_subnets(profiles):
    for _, p in profiles.iterrows():
        homes = set(p["home_subnets"].split())
        assert 1 <= len(homes) <= 3
        assert {subnet_of(ip) for ip in p["usual_ips"].split()} <= homes


def test_migrations_are_deterministic_and_bounded(profiles, cfg):
    a = generator.migrations_until(profiles, DT, cfg)
    b = generator.migrations_until(profiles, DT, cfg)
    pd.testing.assert_frame_equal(a, b)
    assert len(a) > 0
    assert (a["migration_date"] <= DT).all() and (a["migration_date"] >= cfg.migration_epoch).all()


def _normal_br(events, ground_truth):
    """Events of clients not attacked today, from Brazil (attacks add other IPs by design)."""
    return events[~events["client_id"].isin(ground_truth["client_id"]) & (events["country"] == "BR")]


def test_migrated_client_traffic_moves_entirely(profiles, cfg, events, ground_truth):
    mig = generator.migrations_until(profiles, DT, cfg)
    mig = mig[~mig["client_id"].isin(ground_truth["client_id"])]
    row = mig.sort_values("migration_date").iloc[-1]
    sub = _normal_br(events, ground_truth)
    sub = sub[sub["client_id"] == row["client_id"]]
    assert len(sub) > 0
    assert (sub["source_ip"].map(subnet_of) == row["new_subnet"]).all()


def test_registry_only_follows_notified_migrations(profiles, cfg):
    mig = generator.migrations_until(profiles, DT, cfg)
    reg = generator.registry_for_day(profiles, DT, cfg).set_index("client_id")
    assert mig["notified"].any() and (~mig["notified"]).any()
    last = mig.sort_values("migration_date").groupby("client_id").tail(1)
    for _, m in last.iterrows():
        regs = set(reg.loc[m["client_id"], "home_subnets"].split())
        assert (m["new_subnet"] in regs) == bool(m["notified"])


def test_rotation_stays_in_home_subnet(profiles, cfg, events, ground_truth):
    net = generator.network_for_day(profiles, DT, cfg).set_index("client_id")
    normal = _normal_br(events, ground_truth)
    homes = normal["client_id"].map(net["home_subnets"].str.split())
    in_home = [subnet_of(ip) in h for ip, h in zip(normal["source_ip"], homes, strict=True)]
    assert all(in_home)
    # rotation really happens: more distinct IPs than the declared hosts
    assert normal["source_ip"].nunique() > net["hosts"].str.split().str.len().sum()


def test_benign_events_are_todays_migrations(profiles, cfg, benign_events):
    assert list(benign_events.columns) == generator.BENIGN_COLUMNS
    mig = generator.migrations_until(profiles, DT, cfg)
    assert set(benign_events["client_id"]) == set(mig.loc[mig["migration_date"] == DT, "client_id"])
    assert (benign_events["event_type"] == "subnet_migration").all()
