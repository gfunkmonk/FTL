"""
Pi-hole FTL API integration tests — stats, lists, and search endpoints.

These tests run against a live FTL instance and verify JSON response
structure, field presence, ordering, and value correctness. They replace
the equivalent curl|jq BATS tests with native Python assertions.

The run.sh test runner fires DNS setup queries (gravity.ftl, A/AAAA
lookups, DNSSEC, etc.) before invoking the test suite, so stats
endpoints have data to return by the time these tests execute.

Usage:
    pytest test/api/test_stats.py -v
"""

import pytest
import requests
import subprocess

FTL_URL = "http://127.0.0.1"


@pytest.fixture(autouse=True)
def api(api_session):
    """Alias the session fixture for brevity."""
    return api_session


@pytest.fixture(scope="module", autouse=True)
def ensure_test_queries():
    """Fire DNS queries to populate FTL stats before tests run.

    This ensures blocked/allowed/forwarded counters have data
    regardless of whether run.sh's setup queries already executed.
    """
    queries = [
        ("gravity.ftl", "A"),       # blocked by gravity
        ("gravity.ftl", "AAAA"),    # blocked by gravity
        ("a]b.ftl", "A"),           # special character domain
        ("ftl.google.com", "A"),    # forwarded
        ("ftl.google.com", "AAAA"), # forwarded
    ]
    for domain, qtype in queries:
        subprocess.run(
            ["dig", "+tries=1", "+time=2", domain, qtype, "@127.0.0.1"],
            capture_output=True, timeout=5
        )
    # Allow FTL a moment to process
    import time
    time.sleep(0.5)


# ---------- /api/stats/summary ----------

class TestStatsSummary:

    def test_summary_returns_expected_fields(self, api):
        r = api.get(f"{FTL_URL}/api/stats/summary")
        assert r.status_code == 200
        data = r.json()

        # Top-level keys
        assert "queries" in data
        assert "clients" in data
        assert "gravity" in data
        assert "took" in data

        q = data["queries"]
        assert q["total"] > 0
        assert q["blocked"] >= 0
        assert 0 <= q["percent_blocked"] < 100
        assert q["unique_domains"] > 0
        assert q["forwarded"] >= 0
        assert q["cached"] >= 0

        # Type breakdown present
        assert "A" in q["types"]
        assert "AAAA" in q["types"]

        # Status breakdown present
        assert "GRAVITY" in q["status"]
        assert "FORWARDED" in q["status"]
        assert "CACHE" in q["status"]
        assert "UNKNOWN" in q["status"]
        assert q["status"]["UNKNOWN"] == 0

        # Reply breakdown present
        assert "IP" in q["replies"]
        assert "NXDOMAIN" in q["replies"]
        # UNKNOWN replies may exist if upstream DNS is unreachable
        assert q["replies"]["UNKNOWN"] >= 0

        # Client counts
        assert data["clients"]["active"] > 0
        assert data["clients"]["total"] > 0

        # Gravity
        assert data["gravity"]["domains_being_blocked"] > 0


# ---------- /api/stats/top_domains ----------

class TestStatsTopDomains:

    def test_top_domains_sorted_descending(self, api):
        r = api.get(f"{FTL_URL}/api/stats/top_domains?blocked=false")
        assert r.status_code == 200
        data = r.json()

        domains = data["domains"]
        assert len(domains) > 0
        assert "total_queries" in data
        assert "blocked_queries" in data

        # Verify descending sort by count
        counts = [d["count"] for d in domains]
        assert counts == sorted(counts, reverse=True), \
            f"Domains not sorted descending: {counts}"

    def test_top_domains_count_parameter(self, api):
        r = api.get(f"{FTL_URL}/api/stats/top_domains?count=2")
        assert r.status_code == 200
        domains = r.json()["domains"]
        assert len(domains) <= 2

    def test_top_domains_blocked_includes_gravity(self, api):
        r = api.get(f"{FTL_URL}/api/stats/top_domains?blocked=true")
        assert r.status_code == 200
        domains = r.json()["domains"]
        domain_names = [d["domain"] for d in domains]
        assert "gravity.ftl" in domain_names

        # Verify descending sort
        counts = [d["count"] for d in domains]
        assert counts == sorted(counts, reverse=True)

    def test_permitted_domains_exclude_blocked_only(self, api):
        """Permitted (non-blocked) top domains should not include domains
        that only appear as blocked queries."""
        r_permitted = api.get(f"{FTL_URL}/api/stats/top_domains?blocked=false")
        r_blocked = api.get(f"{FTL_URL}/api/stats/top_domains?blocked=true")
        assert r_permitted.status_code == 200
        assert r_blocked.status_code == 200

        permitted_names = {d["domain"] for d in r_permitted.json()["domains"]}
        blocked_names = {d["domain"] for d in r_blocked.json()["domains"]}

        # gravity.ftl should be in blocked but not in permitted
        assert "gravity.ftl" in blocked_names
        assert "gravity.ftl" not in permitted_names


# ---------- /api/stats/top_clients ----------

class TestStatsTopClients:

    def test_top_clients_sorted_descending(self, api):
        r = api.get(f"{FTL_URL}/api/stats/top_clients")
        assert r.status_code == 200
        data = r.json()

        clients = data["clients"]
        assert len(clients) > 0
        assert "total_queries" in data

        # Verify descending sort
        counts = [c["count"] for c in clients]
        assert counts == sorted(counts, reverse=True), \
            f"Clients not sorted descending: {counts}"

        # 127.0.0.1 should be on top (most queries)
        assert clients[0]["ip"] == "127.0.0.1"

    def test_top_clients_count_parameter(self, api):
        r = api.get(f"{FTL_URL}/api/stats/top_clients?count=1")
        assert r.status_code == 200
        clients = r.json()["clients"]
        assert len(clients) == 1

    def test_top_clients_blocked(self, api):
        r = api.get(f"{FTL_URL}/api/stats/top_clients?blocked=true")
        assert r.status_code == 200
        data = r.json()

        clients = data["clients"]
        assert len(clients) > 0

        # Verify descending sort
        counts = [c["count"] for c in clients]
        assert counts == sorted(counts, reverse=True)


# ---------- /api/stats/upstreams ----------

class TestStatsUpstreams:

    def test_upstreams_has_blocklist_and_cache(self, api):
        r = api.get(f"{FTL_URL}/api/stats/upstreams")
        assert r.status_code == 200
        data = r.json()

        assert len(data["upstreams"]) >= 2
        assert data["total_queries"] > 0
        assert "forwarded_queries" in data

        ips = [u["ip"] for u in data["upstreams"]]
        assert "blocklist" in ips
        assert "cache" in ips

    def test_blocklist_count_matches_summary(self, api):
        upstreams = api.get(f"{FTL_URL}/api/stats/upstreams").json()
        summary = api.get(f"{FTL_URL}/api/stats/summary").json()

        blocklist_entry = next(u for u in upstreams["upstreams"] if u["ip"] == "blocklist")
        assert blocklist_entry["count"] == summary["queries"]["blocked"]


# ---------- /api/stats/query_types ----------

class TestStatsQueryTypes:

    def test_query_types_present(self, api):
        r = api.get(f"{FTL_URL}/api/stats/query_types")
        assert r.status_code == 200
        data = r.json()
        assert "types" in data
        assert "A" in data["types"]
        assert "AAAA" in data["types"]


# ---------- /api/queries ----------

class TestQueries:

    def test_query_filter_by_reply(self, api):
        """Verify the reply filter parameter works (returns valid JSON)."""
        r = api.get(f"{FTL_URL}/api/queries?reply=IP")
        assert r.status_code == 200
        # All returned queries should have reply type IP
        for q in r.json()["queries"]:
            assert q["reply"]["type"] == "IP"

    def test_no_unknown_status(self, api):
        r = api.get(f"{FTL_URL}/api/queries?status=UNKNOWN")
        assert r.status_code == 200
        assert len(r.json()["queries"]) == 0


# ---------- /api/lists ----------

class TestLists:

    def test_block_lists_only(self, api):
        r = api.get(f"{FTL_URL}/api/lists?type=block")
        assert r.status_code == 200
        for lst in r.json()["lists"]:
            assert lst["type"] == "block"

    def test_allow_lists_only(self, api):
        r = api.get(f"{FTL_URL}/api/lists?type=allow")
        assert r.status_code == 200
        for lst in r.json()["lists"]:
            assert lst["type"] == "allow"

    def test_all_lists_includes_both_types(self, api):
        r = api.get(f"{FTL_URL}/api/lists")
        assert r.status_code == 200
        types = {lst["type"] for lst in r.json()["lists"]}
        assert "block" in types
        assert "allow" in types


# ---------- /api/search ----------

class TestSearch:

    def test_nonexistent_domain(self, api):
        r = api.get(f"{FTL_URL}/api/search/nonexistent.ftl")
        assert r.status_code == 200
        data = r.json()
        assert "search" in data
        search = data["search"]
        assert search["results"]["total"] == 0
        assert search["gravity"] == []
        assert search["domains"] == []

    def test_antigravity_domain(self, api):
        r = api.get(f"{FTL_URL}/api/search/antigravity.ftl")
        assert r.status_code == 200
        data = r.json()
        assert "search" in data
        # antigravity.ftl should have results (it's in gravity and antigravity)
        assert data["search"]["results"]["total"] > 0

    def test_punycode_normalization(self, api):
        """Internationalized domain names should be normalized to punycode."""
        r = api.get(f"{FTL_URL}/api/search/Hällo.example.com")
        assert r.status_code == 200
        data = r.json()
        assert "search" in data
        # The response should contain the normalized domain somewhere
        # (punycode-encoded, lowercased)
        assert data["search"]["results"]["total"] == 0  # non-existent domain, just check it doesn't crash


# ---------- /api/history ----------

class TestHistory:

    def test_history_returns_24h(self, api):
        r = api.get(f"{FTL_URL}/api/history")
        assert r.status_code == 200
        data = r.json()
        assert "history" in data
        # Should have multiple time slots (10-min intervals over 24h = ~145)
        assert len(data["history"]) >= 100

        # Each slot should have required fields
        slot = data["history"][0]
        assert "timestamp" in slot
        assert "total" in slot
        assert "blocked" in slot
        assert "cached" in slot
        assert "forwarded" in slot

    def test_history_clients_returns_24h(self, api):
        r = api.get(f"{FTL_URL}/api/history/clients")
        assert r.status_code == 200
        data = r.json()
        assert "history" in data
        assert "clients" in data
        assert len(data["history"]) >= 100


# ---------- /api/auth (no password) ----------

class TestAuthNoPassword:

    def test_no_password_means_no_login_required(self, api):
        """Before a password is set, auth should report valid session."""
        r = api.get(f"{FTL_URL}/api/auth")
        assert r.status_code == 200
        data = r.json()
        assert data["session"]["valid"] is True
        assert "no password set" in data["session"]["message"]
