"""Synthetic OAuth 2.0 token-endpoint traffic with injected attacks.

All data is fake. The generator mimics the shape of an Open Finance style
authorization server: registered client applications ("softwares"), each with
an allowed set of scopes, a small pool of usual source IPs and an expected
daily volume. On top of normal traffic (with realistic noise), a small share
of clients is hit by one of four attack patterns. The attacked clients are
returned separately as ground truth, so detection can be measured honestly.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd

from oauth_shield.network import random_br_subnet, random_host

SCOPES = [
    "openid",
    "accounts",
    "credit-cards-accounts",
    "consents",
    "customers",
    "payments",
    "resources",
    "investments",
    "loans",
    "financings",
]
FOREIGN_COUNTRIES = ["RU", "CN", "NG", "NL", "VN", "RO", "US", "IN"]
ATTACK_TYPES = ["scope_probing", "credential_stuffing", "geo_anomaly", "volume_burst", "new_subnet_probing"]

# Attack intensities (inclusive ranges). They deliberately straddle the detection thresholds in
# risk.py, so some attacks slip through: the point is to measure detection, not to guarantee it.
SCOPE_PROBING_ERRORS = (5, 60)
STUFFING_VICTIM_HITS = (10, 60)
STUFFING_SPRAY_CLIENTS = (6, 15)
GEO_REQUESTS = (2, 40)
BURST_MULTIPLIER = (2.0, 6.0)
NEW_SUBNET_REQUESTS = (8, 40)
NEW_SUBNET_SCOPE_ERROR_SHARE = (0.60, 0.85)

STATUS_OK = 200
STATUS_INVALID_SCOPE = 400
STATUS_INVALID_CLIENT = 401
STATUS_RATE_LIMITED = 429
VALID_STATUSES = {STATUS_OK, STATUS_INVALID_SCOPE, STATUS_INVALID_CLIENT, STATUS_RATE_LIMITED}

EVENT_COLUMNS = [
    "event_id",
    "event_ts",
    "client_id",
    "source_ip",
    "country",
    "requested_scope",
    "status_code",
]
BENIGN_COLUMNS = ["client_id", "event_type", "subnet", "notified"]
MIGRATION_COLUMNS = ["client_id", "migration_date", "new_subnet", "new_hosts", "notified"]


@dataclass(frozen=True)
class GeneratorConfig:
    n_clients: int = 300
    attack_rate: float = 0.04
    seed: int = 42
    volume_scale: float = 1.0
    # Day-to-day host rotation inside one of the app's own /24 subnets (cloud autoscaling).
    noise_ip_rotation_rate: float = 0.02
    noise_invalid_scope_rate: float = 0.005
    noise_invalid_client_rate: float = 0.01
    noise_rate_limited_rate: float = 0.003
    # Legitimate subnet migrations: each app moves all traffic to a new /24 with this daily probability.
    migration_rate_per_day: float = 1 / 600
    # Share of migrations the client reports, so the declared registry (usual_ips) gets updated.
    migration_notify_rate: float = 0.5
    migration_epoch: str = "2026-10-01"
    # new_subnet_probing only hits high-volume apps (top decile), where scope errors get diluted.
    new_subnet_victim_quantile: float = 0.9


def _br_ip(rng: np.random.Generator) -> str:
    return f"177.{rng.integers(0, 256)}.{rng.integers(0, 256)}.{rng.integers(1, 255)}"


def _foreign_ip(rng: np.random.Generator) -> str:
    return f"45.{rng.integers(0, 256)}.{rng.integers(0, 256)}.{rng.integers(1, 255)}"


def build_client_profiles(cfg: GeneratorConfig) -> pd.DataFrame:
    """Registry of client applications as registered (stable across days for a given seed).

    Each app owns 1-3 home /24 subnets with 1-2 known hosts each. Use `registry_for_day` for the
    registry as it stands on a given day (after reported migrations).
    """
    rng = np.random.default_rng(cfg.seed)
    rows = []
    for i in range(cfg.n_clients):
        subnets: list[str] = []
        while len(subnets) < int(rng.integers(1, 4)):
            sn = random_br_subnet(rng)
            if sn not in subnets:
                subnets.append(sn)
        hosts = sorted({random_host(sn, rng) for sn in subnets for _ in range(int(rng.integers(1, 3)))})
        n_scopes = int(rng.integers(2, 6))
        scopes = ["openid", *rng.choice(SCOPES[1:], size=n_scopes, replace=False).tolist()]
        rows.append(
            {
                "client_id": f"sw-{i:05d}",
                "home_country": "BR",
                "usual_ips": " ".join(hosts),
                "home_subnets": " ".join(subnets),
                "allowed_scopes": " ".join(scopes),
                "expected_daily_volume": int(np.clip(rng.lognormal(5.2, 1.3), 20, 6000)),
            }
        )
    return pd.DataFrame(rows)


def migrations_until(profiles: pd.DataFrame, dt: str, cfg: GeneratorConfig) -> pd.DataFrame:
    """Every legitimate subnet migration from `cfg.migration_epoch` up to and including `dt`.

    Deterministic and stateless: each day draws from its own seeded stream, so any day can be
    generated without the previous ones having been generated.
    """
    current = dict(zip(profiles["client_id"], profiles["home_subnets"].str.split(), strict=True))
    rows = []
    for day in pd.date_range(cfg.migration_epoch, dt, freq="D"):
        rng = np.random.default_rng([cfg.seed, int(day.strftime("%Y%m%d")), 7])
        moving = profiles["client_id"][rng.random(len(profiles)) < cfg.migration_rate_per_day]
        for cid in moving:
            new_subnet = random_br_subnet(rng)
            while new_subnet in current[cid]:
                new_subnet = random_br_subnet(rng)
            hosts = sorted({random_host(new_subnet, rng) for _ in range(int(rng.integers(1, 4)))})
            current[cid] = [new_subnet]
            rows.append(
                {
                    "client_id": cid,
                    "migration_date": day.strftime("%Y-%m-%d"),
                    "new_subnet": new_subnet,
                    "new_hosts": " ".join(hosts),
                    "notified": bool(rng.random() < cfg.migration_notify_rate),
                }
            )
    return pd.DataFrame(rows, columns=MIGRATION_COLUMNS)


def _apply_latest(base: pd.DataFrame, migrations: pd.DataFrame) -> pd.DataFrame:
    """Overwrite home_subnets/usual_ips with each client's latest migration in `migrations`."""
    latest = migrations.sort_values("migration_date", kind="stable").groupby("client_id").tail(1)
    out = base.set_index("client_id")
    latest = latest.set_index("client_id")
    out.loc[latest.index, "home_subnets"] = latest["new_subnet"]
    out.loc[latest.index, "usual_ips"] = latest["new_hosts"]
    return out.reset_index()


def network_for_day(profiles: pd.DataFrame, dt: str, cfg: GeneratorConfig) -> pd.DataFrame:
    """Where each app's traffic really comes from on `dt` (all traffic follows the latest migration)."""
    net = _apply_latest(profiles, migrations_until(profiles, dt, cfg))
    return net.rename(columns={"usual_ips": "hosts"})[["client_id", "home_subnets", "hosts"]]


def registry_for_day(profiles: pd.DataFrame, dt: str, cfg: GeneratorConfig) -> pd.DataFrame:
    """The declared registry on `dt`: only migrations the client reported are reflected."""
    mig = migrations_until(profiles, dt, cfg)
    return _apply_latest(profiles, mig[mig["notified"]])[profiles.columns]


def _normal_traffic(profile: pd.Series, n: int, rng: np.random.Generator, cfg: GeneratorConfig) -> list[dict]:
    """`profile` carries the app's *current* network: `hosts` and `home_subnets`."""
    hosts = profile["hosts"].split()
    subnets = profile["home_subnets"].split()
    allowed = profile["allowed_scopes"].split()
    not_allowed = [s for s in SCOPES if s not in allowed]
    p_scope = cfg.noise_invalid_scope_rate
    p_client = p_scope + cfg.noise_invalid_client_rate
    p_limit = p_client + cfg.noise_rate_limited_rate
    events = []
    for _ in range(n):
        if rng.random() < cfg.noise_ip_rotation_rate:
            ip = random_host(str(rng.choice(subnets)), rng)
        else:
            ip = str(rng.choice(hosts))
        roll = rng.random()
        if roll < p_scope and not_allowed:
            scope, status = str(rng.choice(not_allowed)), STATUS_INVALID_SCOPE
        elif roll < p_client:
            scope, status = str(rng.choice(allowed)), STATUS_INVALID_CLIENT
        elif roll < p_limit:
            scope, status = str(rng.choice(allowed)), STATUS_RATE_LIMITED
        else:
            scope, status = str(rng.choice(allowed)), STATUS_OK
        events.append(
            {
                "client_id": profile["client_id"],
                "source_ip": ip,
                "country": "BR",
                "requested_scope": scope,
                "status_code": status,
            }
        )
    return events


def _between(rng: np.random.Generator, bounds: tuple[int, int]) -> int:
    """Random integer in an inclusive range."""
    return int(rng.integers(bounds[0], bounds[1] + 1))


def _attack_traffic(
    attack: str,
    victim: pd.Series,
    profiles: pd.DataFrame,
    rng: np.random.Generator,
) -> list[dict]:
    allowed = victim["allowed_scopes"].split()
    not_allowed = [s for s in SCOPES if s not in allowed] or ["payments"]
    usual_ips = victim["hosts"].split()  # the app's current hosts (after any migration)
    cid = victim["client_id"]

    if attack == "scope_probing":
        # Valid credentials, but the app keeps asking for scopes it was never granted.
        return [
            {
                "client_id": cid,
                "source_ip": str(rng.choice(usual_ips)),
                "country": "BR",
                "requested_scope": str(rng.choice(not_allowed)),
                "status_code": STATUS_INVALID_SCOPE,
            }
            for _ in range(_between(rng, SCOPE_PROBING_ERRORS))
        ]

    if attack == "credential_stuffing":
        # One foreign IP hammers the victim and sprays a few attempts at many other clients.
        ip, country = _foreign_ip(rng), str(rng.choice(FOREIGN_COUNTRIES))
        events = [
            {
                "client_id": cid,
                "source_ip": ip,
                "country": country,
                "requested_scope": str(rng.choice(allowed)),
                "status_code": STATUS_INVALID_CLIENT,
            }
            for _ in range(_between(rng, STUFFING_VICTIM_HITS))
        ]
        n_spray = _between(rng, STUFFING_SPRAY_CLIENTS)
        others = profiles[profiles["client_id"] != cid].sample(n_spray, random_state=int(rng.integers(1e9)))
        for _, other in others.iterrows():
            for _ in range(int(rng.integers(1, 3))):
                events.append(
                    {
                        "client_id": other["client_id"],
                        "source_ip": ip,
                        "country": country,
                        "requested_scope": "openid",
                        "status_code": STATUS_INVALID_CLIENT,
                    }
                )
        return events

    if attack == "geo_anomaly":
        # Stolen credentials used successfully from abroad.
        ip, country = _foreign_ip(rng), str(rng.choice(FOREIGN_COUNTRIES))
        return [
            {
                "client_id": cid,
                "source_ip": ip,
                "country": country,
                "requested_scope": str(rng.choice(allowed)),
                "status_code": STATUS_OK,
            }
            for _ in range(_between(rng, GEO_REQUESTS))
        ]

    if attack == "volume_burst":
        # Token farming: several times the usual volume, half of it from unseen IPs.
        n = int(victim["expected_daily_volume"] * rng.uniform(*BURST_MULTIPLIER))
        new_ips = [_br_ip(rng) for _ in range(5)]
        return [
            {
                "client_id": cid,
                "source_ip": str(rng.choice(new_ips if rng.random() < 0.5 else usual_ips)),
                "country": "BR",
                "requested_scope": str(rng.choice(allowed)),
                "status_code": STATUS_OK,
            }
            for _ in range(n)
        ]

    if attack == "new_subnet_probing":
        # Stolen credentials used once, from a Brazilian IP in a /24 the app never uses: a few tokens
        # for granted scopes plus mostly attempts at scopes it was never granted. Gone the next day.
        homes = victim["home_subnets"].split()
        subnet = random_br_subnet(rng)
        while subnet in homes:
            subnet = random_br_subnet(rng)
        ip = random_host(subnet, rng)
        n = _between(rng, NEW_SUBNET_REQUESTS)
        n_err = round(n * rng.uniform(*NEW_SUBNET_SCOPE_ERROR_SHARE))
        return [
            {
                "client_id": cid,
                "source_ip": ip,
                "country": "BR",
                "requested_scope": str(rng.choice(not_allowed if k < n_err else allowed)),
                "status_code": STATUS_INVALID_SCOPE if k < n_err else STATUS_OK,
            }
            for k in range(n)
        ]

    raise ValueError(f"unknown attack type: {attack}")


def generate_day(
    profiles: pd.DataFrame, dt: str, cfg: GeneratorConfig
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Return (events, ground_truth, benign_events) for one calendar day (dt = 'YYYY-MM-DD').

    `benign_events` lists today's legitimate subnet migrations (analysis only, like ground_truth).
    """
    rng = np.random.default_rng(cfg.seed + int(dt.replace("-", "")))
    # The app's real network today (hosts + home_subnets after any migration).
    live = profiles.drop(columns="home_subnets").merge(network_for_day(profiles, dt, cfg), on="client_id")

    events: list[dict] = []
    for _, profile in live.iterrows():
        n = int(rng.poisson(profile["expected_daily_volume"] * cfg.volume_scale))
        events.extend(_normal_traffic(profile, n, rng, cfg))

    n_attacked = max(len(ATTACK_TYPES), round(len(live) * cfg.attack_rate))
    attacks = [ATTACK_TYPES[i % len(ATTACK_TYPES)] for i in range(n_attacked)]
    n_new_subnet = attacks.count("new_subnet_probing")
    big = live[live["expected_daily_volume"] >= live["expected_daily_volume"].quantile(cfg.new_subnet_victim_quantile)]
    big_victims = big.sample(n_new_subnet, random_state=int(rng.integers(1e9)))
    rest = live.drop(index=big_victims.index).sample(n_attacked - n_new_subnet, random_state=int(rng.integers(1e9)))
    big_iter, rest_iter = big_victims.iterrows(), rest.iterrows()
    truth = []
    for attack in attacks:
        _, victim = next(big_iter) if attack == "new_subnet_probing" else next(rest_iter)
        events.extend(_attack_traffic(attack, victim, live, rng))
        truth.append({"client_id": victim["client_id"], "attack_type": attack})

    mig = migrations_until(profiles, dt, cfg)
    today = mig[mig["migration_date"] == dt]
    benign = pd.DataFrame(
        {
            "client_id": today["client_id"].to_numpy(),
            "event_type": "subnet_migration",
            "subnet": today["new_subnet"].to_numpy(),
            "notified": today["notified"].astype(bool).to_numpy(),
        },
        columns=BENIGN_COLUMNS,
    )

    df = pd.DataFrame(events)
    day_start = pd.Timestamp(dt)
    offsets = rng.integers(0, 86_400_000, size=len(df))
    df["event_ts"] = day_start + pd.to_timedelta(offsets, unit="ms")
    df = df.sort_values("event_ts", kind="stable").reset_index(drop=True)
    df["event_id"] = [f"{dt.replace('-', '')}-{i:08d}" for i in range(len(df))]
    df["status_code"] = df["status_code"].astype("int64")
    return df[EVENT_COLUMNS], pd.DataFrame(truth), benign
