"""
DNS blocking and allowing tests ported from test_suite.bats.

These tests exercise FTL's DNS resolver by issuing real dig queries
against 127.0.0.1 and verifying that domains are blocked, allowed,
or answered correctly depending on gravity, denylist, allowlist, regex,
CNAME inspection, DNSSEC, special-domain, and ABP-style rules.
"""

import subprocess

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def dig(domain, qtype="A", server="127.0.0.1", bind_addr=None, tcp=False,
        short=True):
    """Run dig and return the stripped stdout (``+short`` by default)."""
    cmd = ["dig", "+tries=1", "+time=3"]
    if short:
        cmd.append("+short")
    if tcp:
        cmd.append("+tcp")
    if bind_addr:
        cmd.extend(["-b", bind_addr])
    cmd.extend([qtype, domain, f"@{server}"])
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    return result.stdout.strip()


def dig_full(domain, qtype="A", server="127.0.0.1", bind_addr=None,
             tcp=False):
    """Run dig *without* ``+short`` and return the full output."""
    return dig(domain, qtype=qtype, server=server, bind_addr=bind_addr,
               tcp=tcp, short=False)


# ---------------------------------------------------------------------------
# 1. Blocking tests
# ---------------------------------------------------------------------------

class TestBlocking:
    """Domains that must be blocked (resolve to 0.0.0.0)."""

    def test_denied_domain_is_blocked(self):
        """denied.ftl is on the exact denylist and must return 0.0.0.0."""
        assert dig("denied.ftl") == "0.0.0.0"

    def test_denied_domain_ede(self):
        """denied.ftl full reply must contain EDE 15 (denylist)."""
        output = dig_full("denied.ftl")
        assert "EDE: 15 (Blocked): (denylist)" in output

    def test_gravity_domain_is_blocked(self):
        """gravity.ftl is in the gravity list and must return 0.0.0.0."""
        assert dig("gravity.ftl") == "0.0.0.0"

    def test_gravity_domain_ede(self):
        """gravity.ftl full reply must contain EDE 15 (gravity)."""
        output = dig_full("gravity.ftl")
        assert "EDE: 15 (Blocked): (gravity)" in output

    def test_gravity_domain_is_blocked_tcp(self):
        """gravity.ftl must also be blocked over TCP."""
        assert dig("gravity.ftl", tcp=True) == "0.0.0.0"

    def test_gravity_domain_ede_tcp(self):
        """gravity.ftl TCP reply must contain EDE 15 (gravity)."""
        output = dig_full("gravity.ftl", tcp=True)
        assert "EDE: 15 (Blocked): (gravity)" in output

    def test_regex_denied_match_is_blocked(self):
        """regex5.ftl matches a regex denylist entry and must be blocked."""
        assert dig("regex5.ftl") == "0.0.0.0"

    def test_regex_denied_match_ede(self):
        """regex5.ftl full reply must contain EDE 15 (regex)."""
        output = dig_full("regex5.ftl")
        assert "EDE: 15 (Blocked): (regex)" in output


# ---------------------------------------------------------------------------
# 2. Allowing tests
# ---------------------------------------------------------------------------

class TestAllowing:
    """Domains that should NOT be blocked due to allowlist / antigravity."""

    def test_allowed_exact_match_not_blocked(self):
        """allowed.ftl is on gravity but also exact-allowed; must resolve."""
        assert dig("allowed.ftl") == "192.168.1.4"

    def test_allowed_regex_match_not_blocked(self):
        """gravity-allowed.ftl is allowed by a regex allowlist entry."""
        assert dig("gravity-allowed.ftl") == "192.168.1.5"

    def test_antigravity_exact_match_not_blocked(self):
        """antigravity.ftl is in gravity AND antigravity; must resolve."""
        assert dig("antigravity.ftl") == "192.168.1.6"


# ---------------------------------------------------------------------------
# 3. Regex tests
# ---------------------------------------------------------------------------

class TestRegex:
    """Regex denylist/allowlist interaction."""

    def test_regex_mismatch_not_blocked(self):
        """regexA.ftl does not match any regex deny; must resolve."""
        assert dig("regexA.ftl") == "192.168.2.4"

    def test_regex_deny_with_exact_allow_not_blocked(self):
        """regex1.ftl matches regex deny but has exact allowlist override."""
        assert dig("regex1.ftl") == "192.168.2.1"

    def test_regex_deny_with_regex_allow_not_blocked(self):
        """regex2.ftl matches regex deny but has regex allowlist override."""
        assert dig("regex2.ftl") == "192.168.2.2"


# ---------------------------------------------------------------------------
# 4. Client-specific tests
# ---------------------------------------------------------------------------

class TestClientSpecific:
    """Client 2 (127.0.0.2) has a different group; client 3 (127.0.0.3)
    has no lists assigned."""

    # -- Client 2 (different group) --

    def test_client2_gravity_with_unassociated_allow_blocked(self):
        """Client 2: allowed.ftl's allowlist is not in client 2's group."""
        assert dig("allowed.ftl", bind_addr="127.0.0.2") == "0.0.0.0"

    def test_client2_regex_deny_with_unassociated_allow_blocked(self):
        """Client 2: regex1.ftl's allowlist is not in client 2's group."""
        assert dig("regex1.ftl", bind_addr="127.0.0.2") == "0.0.0.0"

    def test_client2_unassociated_denylist_not_blocked(self):
        """Client 2: denied.ftl's denylist is not in client 2's group."""
        assert dig("denied.ftl", bind_addr="127.0.0.2") == "192.168.1.3"

    # -- Client 1 vs Client 3 cross-check --

    def test_client1_regex1_not_blocked(self):
        """Client 1 (default): regex1.ftl is allowed."""
        assert dig("regex1.ftl") == "192.168.2.1"

    def test_client3_regex1_not_blocked(self):
        """Client 3: no lists at all, regex1.ftl resolves normally."""
        assert dig("regex1.ftl", bind_addr="127.0.0.3") == "192.168.2.1"

    # -- Client 3 (no lists) --

    def test_client3_exact_deny_not_blocked(self):
        """Client 3: denied.ftl is not blocked (no lists for client 3)."""
        assert dig("denied.ftl", bind_addr="127.0.0.3") == "192.168.1.3"

    def test_client3_regex_deny_not_blocked(self):
        """Client 3: regex1.ftl is not blocked (no lists for client 3)."""
        assert dig("regex1.ftl", bind_addr="127.0.0.3") == "192.168.2.1"

    def test_client3_gravity_not_blocked(self):
        """Client 3: a.ftl (in gravity) is not blocked for client 3."""
        assert dig("a.ftl", bind_addr="127.0.0.3") == "192.168.1.1"


# ---------------------------------------------------------------------------
# 5. Normal query types
# ---------------------------------------------------------------------------

class TestNormalQueries:
    """Standard local DNS records for each supported query type."""

    def test_a_record(self):
        """A a.ftl -> 192.168.1.1"""
        assert dig("a.ftl", qtype="A") == "192.168.1.1"

    def test_aaaa_record(self):
        """AAAA aaaa.ftl -> fe80::1c01 (over TCP)."""
        assert dig("aaaa.ftl", qtype="AAAA", tcp=True) == "fe80::1c01"

    def test_any_record(self):
        """ANY any.ftl returns A + AAAA but NOT TXT (filter-rr=ANY)."""
        output = dig("any.ftl", qtype="ANY")
        assert "192.168.3.1" in output
        assert "fe80::3c01" in output
        # TXT records must be filtered out for ANY queries
        assert "Some example text" not in output

    def test_cname_record(self):
        """CNAME cname-ok.ftl -> a.ftl."""
        assert dig("cname-ok.ftl", qtype="CNAME") == "a.ftl."

    def test_srv_record(self):
        """SRV srv.ftl -> 0 1 80 a.ftl."""
        assert dig("srv.ftl", qtype="SRV") == "0 1 80 a.ftl."

    def test_ptr_record(self):
        """PTR ptr.ftl -> ptr.ftl."""
        assert dig("ptr.ftl", qtype="PTR") == "ptr.ftl."

    def test_txt_record(self):
        """TXT txt.ftl -> quoted text."""
        assert dig("txt.ftl", qtype="TXT") == '"Some example text"'

    def test_naptr_record(self):
        """NAPTR naptr.ftl returns two records."""
        output = dig("naptr.ftl", qtype="NAPTR")
        assert '10 10 "u" "smtp+E2U" "!.*([^.]+[^.]+)$!mailto:postmaster@$1!i" .' in output
        assert '20 10 "s" "http+N2L+N2C+N2R" "" ftl.' in output

    def test_mx_record(self):
        """MX mx.ftl -> 50 ns1.ftl."""
        assert dig("mx.ftl", qtype="MX") == "50 ns1.ftl."

    def test_svcb_record(self):
        """SVCB svcb.ftl -> 1 port="80". (dig may escape the quotes)."""
        result = dig("svcb.ftl", qtype="SVCB")
        assert result in ('1 port="80".', '1 port=\\"80\\".'), \
            f"Unexpected SVCB result: {result}"

    def test_https_record(self):
        """HTTPS https.ftl -> 1 . alpn="h3,h2" (dig may escape the quotes)."""
        result = dig("https.ftl", qtype="HTTPS")
        assert result in ('1 . alpn="h3,h2"', '1 . alpn=\\"h3,h2\\"'), \
            f"Unexpected HTTPS result: {result}"


# ---------------------------------------------------------------------------
# 6. CNAME inspection
# ---------------------------------------------------------------------------

class TestCNAMEInspection:
    """CNAME chains where a target is on a blocklist."""

    def test_shallow_cname_blocked(self):
        """cname-1.ftl: shallow CNAME target is blocked."""
        assert dig("cname-1.ftl") == "0.0.0.0"

    def test_deep_cname_blocked(self):
        """cname-7.ftl: deep CNAME chain target is blocked."""
        assert dig("cname-7.ftl") == "0.0.0.0"

    def test_nodata_a_cname_blocked(self):
        """a-cname.ftl A query: NODATA CNAME target is blocked."""
        assert dig("a-cname.ftl", qtype="A") == "0.0.0.0"

    def test_nodata_a_cname_blocked_aaaa(self):
        """a-cname.ftl AAAA query: NODATA CNAME target is blocked."""
        assert dig("a-cname.ftl", qtype="AAAA") == "::"

    def test_nodata_aaaa_cname_blocked(self):
        """aaaa-cname.ftl A query: NODATA CNAME target is blocked."""
        assert dig("aaaa-cname.ftl", qtype="A") == "0.0.0.0"

    def test_nodata_aaaa_cname_blocked_aaaa(self):
        """aaaa-cname.ftl AAAA query: NODATA CNAME target is blocked."""
        assert dig("aaaa-cname.ftl", qtype="AAAA") == "::"


# ---------------------------------------------------------------------------
# 7. DNSSEC
# ---------------------------------------------------------------------------

class TestDNSSEC:
    """DNSSEC validation of secure and bogus domains."""

    def test_secure_domain_resolved(self):
        """a.dnssec must return NOERROR (valid DNSSEC)."""
        output = dig_full("a.dnssec")
        assert "status: NOERROR" in output

    def test_bogus_domain_rejected(self):
        """a.bogus must return SERVFAIL (DNSSEC validation failure)."""
        output = dig_full("a.bogus")
        assert "status: SERVFAIL" in output


# ---------------------------------------------------------------------------
# 8. Special domains
# ---------------------------------------------------------------------------

class TestSpecialDomains:
    """Domains with special handling (iCloud Private Relay canary, etc.)."""

    def test_mask_icloud_nxdomain(self):
        """mask.icloud.com returns NXDOMAIN by default."""
        output = dig_full("mask.icloud.com")
        assert "status: NXDOMAIN" in output

    def test_mask_icloud_allowed_for_client2(self):
        """mask.icloud.com returns NOERROR when queried from client 2."""
        output = dig_full("mask.icloud.com", bind_addr="127.0.0.2")
        assert "status: NOERROR" in output


# ---------------------------------------------------------------------------
# 9. Mozilla canary
# ---------------------------------------------------------------------------

class TestMozillaCanary:
    """The Mozilla DoH canary domain must be answered with NXDOMAIN."""

    def test_use_application_dns_net_nxdomain(self):
        """use-application-dns.net returns NXDOMAIN."""
        output = dig_full("use-application-dns.net")
        assert "status: NXDOMAIN" in output


# ---------------------------------------------------------------------------
# 10. ABP-style blocking
# ---------------------------------------------------------------------------

class TestABPStyle:
    """ABP (Adblock Plus) style gravity entries such as ||domain^."""

    def test_abp_exact_match_blocked(self):
        """special.gravity.ftl matches ABP pattern ||special.gravity.ftl^."""
        assert dig("special.gravity.ftl") == "0.0.0.0"

    def test_abp_subdomain_match_blocked(self):
        """a.b.c.d.special.gravity.ftl matches the same ABP pattern."""
        assert dig("a.b.c.d.special.gravity.ftl") == "0.0.0.0"


# ---------------------------------------------------------------------------
# 11. Antigravity
# ---------------------------------------------------------------------------

class TestAntigravity:
    """Domains removed from gravity via the antigravity mechanism."""

    def test_antigravity_domain_not_blocked(self):
        """antigravity.ftl is in gravity but removed by antigravity."""
        assert dig("antigravity.ftl") == "192.168.1.6"

    def test_antigravity_abp_domain_not_blocked(self):
        """x.y.z.abp.antigravity.ftl is removed from gravity via ABP-style
        antigravity entry @@||antigravity.ftl^."""
        assert dig("x.y.z.abp.antigravity.ftl") == "192.168.1.7"
