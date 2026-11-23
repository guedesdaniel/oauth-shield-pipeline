"""IPv4 /24 subnet helpers shared by the generator and the silver layer."""

from __future__ import annotations

import numpy as np


def subnet_of(ip: str) -> str:
    """'177.10.20.33' -> '177.10.20.0/24'."""
    a, b, c, _ = ip.split(".")
    return f"{a}.{b}.{c}.0/24"


def random_br_subnet(rng: np.random.Generator) -> str:
    """A random /24 inside the Brazilian address space used by the generator (177.x.y.0/24)."""
    return f"177.{rng.integers(0, 256)}.{rng.integers(0, 256)}.0/24"


def random_host(subnet: str, rng: np.random.Generator) -> str:
    """A random host address (1..254) inside a /24."""
    prefix = subnet.rsplit(".", 1)[0]
    return f"{prefix}.{rng.integers(1, 255)}"
