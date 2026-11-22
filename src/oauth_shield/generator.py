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
ATTACK_TYPES = ["scope_probing", "credential_stuffing", "geo_anomaly", "volume_burst"]

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


@dataclass(frozen=True)
class GeneratorConfig:
    n_clients: int = 300
    attack_rate: float = 0.04
    seed: int = 42
    volume_scale: float = 1.0
    noise_new_ip_rate: float = 0.02
    noise_invalid_scope_rate: float = 0.005
    noise_invalid_client_rate: float = 0.01
    noise_rate_limited_rate: float = 0.003


def _br_ip(rng: np.random.Generator) -> str:
    return f"177.{rng.integers(0, 256)}.{rng.integers(0, 256)}.{rng.integers(1, 255)}"


def _foreign_ip(rng: np.random.Generator) -> str:
    return f"45.{rng.integers(0, 256)}.{rng.integers(0, 256)}.{rng.integers(1, 255)}"


def build_client_profiles(cfg: GeneratorConfig) -> pd.DataFrame:
    """Registry of client applications (stable across days for a given seed)."""
    rng = np.random.default_rng(cfg.seed)
    rows = []
    for i in range(cfg.n_clients):
        n_ips = int(rng.integers(1, 4))
        n_scopes = int(rng.integers(2, 6))
        scopes = ["openid", *rng.choice(SCOPES[1:], size=n_scopes, replace=False).tolist()]
        rows.append(
            {
                "client_id": f"sw-{i:05d}",
                "home_country": "BR",
                "usual_ips": " ".join(_br_ip(rng) for _ in range(n_ips)),
                "allowed_scopes": " ".join(scopes),
                "expected_daily_volume": int(np.clip(rng.lognormal(5.0, 1.0), 20, 3000)),
            }
        )
    return pd.DataFrame(rows)


def _normal_traffic(profile: pd.Series, n: int, rng: np.random.Generator, cfg: GeneratorConfig) -> list[dict]:
    usual_ips = profile["usual_ips"].split()
    allowed = profile["allowed_scopes"].split()
    not_allowed = [s for s in SCOPES if s not in allowed]
    p_scope = cfg.noise_invalid_scope_rate
    p_client = p_scope + cfg.noise_invalid_client_rate
    p_limit = p_client + cfg.noise_rate_limited_rate
    events = []
    for _ in range(n):
        ip = _br_ip(rng) if rng.random() < cfg.noise_new_ip_rate else str(rng.choice(usual_ips))
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


def _attack_traffic(
    attack: str,
    victim: pd.Series,
    profiles: pd.DataFrame,
    rng: np.random.Generator,
) -> list[dict]:
    allowed = victim["allowed_scopes"].split()
    not_allowed = [s for s in SCOPES if s not in allowed] or ["payments"]
    usual_ips = victim["usual_ips"].split()
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
            for _ in range(int(rng.integers(40, 121)))
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
            for _ in range(int(rng.integers(30, 81)))
        ]
        others = profiles[profiles["client_id"] != cid].sample(15, random_state=int(rng.integers(1e9)))
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
            for _ in range(int(rng.integers(30, 101)))
        ]

    if attack == "volume_burst":
        # Token farming: several times the usual volume, half of it from unseen IPs.
        n = int(victim["expected_daily_volume"] * rng.uniform(5, 8))
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

    raise ValueError(f"unknown attack type: {attack}")


def generate_day(profiles: pd.DataFrame, dt: str, cfg: GeneratorConfig) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Return (events, ground_truth) for one calendar day (dt = 'YYYY-MM-DD')."""
    rng = np.random.default_rng(cfg.seed + int(dt.replace("-", "")))

    events: list[dict] = []
    for _, profile in profiles.iterrows():
        n = int(rng.poisson(profile["expected_daily_volume"] * cfg.volume_scale))
        events.extend(_normal_traffic(profile, n, rng, cfg))

    n_attacked = max(len(ATTACK_TYPES), round(len(profiles) * cfg.attack_rate))
    victims = profiles.sample(n_attacked, random_state=int(rng.integers(1e9))).reset_index(drop=True)
    truth = []
    for i, victim in victims.iterrows():
        attack = ATTACK_TYPES[i % len(ATTACK_TYPES)]
        events.extend(_attack_traffic(attack, victim, profiles, rng))
        truth.append({"client_id": victim["client_id"], "attack_type": attack})

    df = pd.DataFrame(events)
    day_start = pd.Timestamp(dt)
    offsets = rng.integers(0, 86_400_000, size=len(df))
    df["event_ts"] = day_start + pd.to_timedelta(offsets, unit="ms")
    df = df.sort_values("event_ts", kind="stable").reset_index(drop=True)
    df["event_id"] = [f"{dt.replace('-', '')}-{i:08d}" for i in range(len(df))]
    df["status_code"] = df["status_code"].astype("int64")
    return df[EVENT_COLUMNS], pd.DataFrame(truth)
