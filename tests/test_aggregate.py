from oauth_shield import aggregate


def test_client_daily_covers_every_client(client_daily, profiles):
    assert list(client_daily.columns) == aggregate.CLIENT_DAILY_COLUMNS
    assert set(client_daily["client_id"]) == set(profiles["client_id"])


def test_client_daily_counts_reconcile(client_daily, events):
    assert client_daily["total_requests"].sum() == len(events)
    assert (client_daily["success_count"] + client_daily["error_count"] == client_daily["total_requests"]).all()
    assert (client_daily["invalid_scope_count"] <= client_daily["error_count"]).all()


def test_client_subnet_daily_reconciles(events):
    sd = aggregate.client_subnet_daily(events)
    assert list(sd.columns) == aggregate.CLIENT_SUBNET_DAILY_COLUMNS
    assert sd["total_requests"].sum() == len(events)
    assert sd["success_count"].sum() == (events["status_code"] == 200).sum()
    assert sd["invalid_scope_count"].sum() == (events["status_code"] == 400).sum()
    assert sd["subnet"].str.endswith(".0/24").all()
    assert not sd.duplicated(["client_id", "subnet"]).any()


def test_ip_daily_counts_reconcile(ip_daily, events):
    assert ip_daily["total_requests"].sum() == len(events)
    assert (ip_daily["failed_requests"] <= ip_daily["total_requests"]).all()
