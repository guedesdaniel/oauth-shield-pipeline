from oauth_shield import aggregate


def test_client_daily_covers_every_client(client_daily, profiles):
    assert list(client_daily.columns) == aggregate.CLIENT_DAILY_COLUMNS
    assert set(client_daily["client_id"]) == set(profiles["client_id"])


def test_client_daily_counts_reconcile(client_daily, events):
    assert client_daily["total_requests"].sum() == len(events)
    assert (client_daily["success_count"] + client_daily["error_count"] == client_daily["total_requests"]).all()
    assert (client_daily["invalid_scope_count"] <= client_daily["error_count"]).all()


def test_ip_daily_counts_reconcile(ip_daily, events):
    assert ip_daily["total_requests"].sum() == len(events)
    assert (ip_daily["failed_requests"] <= ip_daily["total_requests"]).all()
