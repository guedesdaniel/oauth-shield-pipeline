import numpy as np

from oauth_shield.network import random_br_subnet, random_host, subnet_of


def test_subnet_of():
    assert subnet_of("177.10.20.33") == "177.10.20.0/24"
    assert subnet_of("45.1.2.254") == "45.1.2.0/24"


def test_random_host_stays_in_subnet():
    rng = np.random.default_rng(1)
    sn = random_br_subnet(rng)
    assert sn.startswith("177.") and sn.endswith(".0/24")
    for _ in range(50):
        h = random_host(sn, rng)
        assert subnet_of(h) == sn
        assert 1 <= int(h.split(".")[3]) <= 254
