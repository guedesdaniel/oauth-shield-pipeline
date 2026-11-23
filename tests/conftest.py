import pytest

from oauth_shield import aggregate, generator

DT = "2026-11-20"


@pytest.fixture(scope="session")
def cfg():
    return generator.GeneratorConfig(n_clients=120, seed=7, migration_rate_per_day=1 / 100)


@pytest.fixture(scope="session")
def profiles(cfg):
    return generator.build_client_profiles(cfg)


@pytest.fixture(scope="session")
def day(profiles, cfg):
    return generator.generate_day(profiles, DT, cfg)


@pytest.fixture(scope="session")
def events(day):
    return day[0]


@pytest.fixture(scope="session")
def ground_truth(day):
    return day[1]


@pytest.fixture(scope="session")
def benign_events(day):
    return day[2]


@pytest.fixture(scope="session")
def client_daily(events, profiles):
    return aggregate.client_daily(events, profiles)


@pytest.fixture(scope="session")
def ip_daily(events):
    return aggregate.ip_daily(events)
