"""
Pi-hole FTL configuration, CLI, and environment variable integration tests.

Ported from test_suite.bats, covering:

- CLI argument validation (invalid arg, help, --config)
- Config file comparison (template vs runtime TOML)
- Binary integrity check (pihole-FTL verify)
- dnsmasq feature options (pihole-FTL -vv)
- Config validation via CLI (type-based and validator-based)
- Config validation via API (type-based and validator-based)
- Environment variable handling (favored, capitalized, invalid, unknown)
- DNS hosts sanitization (whitespace, comments)
- Read-only env-var config protection (CLI and API)
- Unknown config key suggestion

Usage:
    pytest test/api/test_config.py -v
"""

import subprocess
import time

import pytest
import requests

FTL_BIN = "/home/pihole/pihole-FTL"
FTL_URL = "http://127.0.0.1"
FTL_LOG = "/var/log/pihole/FTL.log"
TOML_RUNTIME = "/etc/pihole/pihole.toml"


def run_ftl(*args, **kwargs):
    """Run pihole-FTL with the given arguments and return the CompletedProcess."""
    return subprocess.run(
        [FTL_BIN, *args],
        capture_output=True, text=True, timeout=10, **kwargs,
    )


def run_shell(cmd):
    """Run a shell command string and return the CompletedProcess."""
    return subprocess.run(
        cmd, shell=True,
        capture_output=True, text=True, timeout=10,
    )


# ---------------------------------------------------------------------------
# CLI argument validation
# ---------------------------------------------------------------------------

class TestCLIArguments:
    """CLI argument handling: invalid args, help text."""

    def test_invalid_cli_argument(self):
        """Invalid CLI argument produces a clear error with suggestion."""
        result = run_ftl("abc")
        lines = result.stdout.splitlines()
        assert len(lines) >= 3, f"Expected 3+ lines, got: {result.stdout}"
        assert lines[0] == "pihole-FTL: invalid option -- 'abc'"
        assert lines[1] == "Command: '/home/pihole/pihole-FTL abc'"
        assert lines[2] == "Try '/home/pihole/pihole-FTL --help' for more information"

    def test_help_returns_help_text(self):
        """'help' sub-command returns banner starting with 'The Pi-hole FTL engine'."""
        result = run_ftl("help")
        lines = result.stdout.splitlines()
        assert len(lines) >= 1
        assert lines[0].startswith("The Pi-hole FTL engine - ")


# ---------------------------------------------------------------------------
# CLI --config output
# ---------------------------------------------------------------------------

class TestCLIConfigOutput:
    """CLI config output: partial match, exact match printing."""

    def test_partial_match_printing(self):
        """Partial key 'dns.upstream' prints key = value format."""
        result = run_ftl("--config", "dns.upstream")
        lines = result.stdout.splitlines()
        assert lines[0] == "dns.upstreams = [ 127.0.0.1#5555 ]"

    def test_exact_match_upstreams(self):
        """Exact key 'dns.upstreams' prints only the value."""
        result = run_ftl("--config", "dns.upstreams")
        lines = result.stdout.splitlines()
        assert lines[0] == "[ 127.0.0.1#5555 ]"

    def test_exact_match_piholePTR(self):
        result = run_ftl("--config", "dns.piholePTR")
        lines = result.stdout.splitlines()
        assert lines[0] == "PI.HOLE"

    def test_exact_match_dns_hosts(self):
        result = run_ftl("--config", "dns.hosts")
        lines = result.stdout.splitlines()
        assert lines[0] == "[ 1.1.1.1 abc-custom.com def-custom.de, 2.2.2.2 \u00e4ste.com ste\u00e4.com ]"

    def test_exact_match_webserver_port(self):
        result = run_ftl("--config", "webserver.port")
        lines = result.stdout.splitlines()
        assert lines[0] == "80o,443os,[::]:80o,[::]:443os"


# ---------------------------------------------------------------------------
# Config file comparison
# ---------------------------------------------------------------------------

class TestConfigFileComparison:
    """Compare the template pihole.toml with the runtime copy."""

    def test_template_matches_runtime(self):
        """Template and runtime TOML should be identical after the header (first 5 lines).

        Lines containing passwords or modification counts may differ if
        auth tests ran first, so we strip those before comparing.
        """
        result = run_shell(
            f"diff "
            f"<(tail -n +6 test/pihole.toml | grep -v 'pwhash\\|app_pwhash\\|entries are\\|Configuration statistics')"
            f" <(tail -n +6 {TOML_RUNTIME} | grep -v 'pwhash\\|app_pwhash\\|entries are\\|Configuration statistics')"
        )
        assert result.stdout.strip() == "", (
            f"Template and runtime TOML differ:\n{result.stdout}"
        )


# ---------------------------------------------------------------------------
# Binary integrity check
# ---------------------------------------------------------------------------

class TestBinaryIntegrity:
    """pihole-FTL verify should pass."""

    def test_binary_integrity(self):
        result = run_ftl("verify")
        lines = result.stdout.splitlines()
        assert any("Binary integrity check: OK" in l for l in lines), (
            f"Expected 'Binary integrity check: OK' in output:\n{result.stdout}"
        )


# ---------------------------------------------------------------------------
# dnsmasq options
# ---------------------------------------------------------------------------

class TestDnsmasqOptions:
    """dnsmasq features reported by pihole-FTL -vv."""

    def test_dnsmasq_features(self):
        result = run_ftl("-vv")
        output = result.stdout
        # Find the features line
        features_line = None
        for line in output.splitlines():
            if "dumpfile" in line:
                features_line = line
                break
        assert features_line is not None, f"No 'dumpfile' line in -vv output:\n{output}"
        assert features_line == (
            "Features:        IPv6 GNU-getopt no-DBus no-UBus no-i18n IDN2 "
            "DHCP DHCPv6 Lua TFTP no-conntrack ipset no-nftset auth DNSSEC "
            "loop-detect inotify dumpfile"
        )


# ---------------------------------------------------------------------------
# Config validation: CLI type-based
# ---------------------------------------------------------------------------

class TestConfigValidationCLIType:
    """Config validation on the CLI: type-based checking."""

    def test_dns_port_rejects_boolean(self):
        result = run_ftl("--config", "dns.port", "true")
        assert result.returncode == 2
        lines = result.stdout.splitlines()
        assert lines[0] == "Config setting dns.port is invalid, allowed options are: unsigned integer (16 bit)"

    def test_dns_revServers_rejects_invalid_json(self):
        result = run_ftl("--config", "dns.revServers", "abc")
        assert result.returncode == 2
        lines = result.stdout.splitlines()
        assert lines[0] == "Config setting dns.revServers is invalid: not valid JSON, error at: abc"


# ---------------------------------------------------------------------------
# Config validation: API type-based
# ---------------------------------------------------------------------------

class TestConfigValidationAPIType:
    """Config validation on the API: type-based checking."""

    def test_blockESNI_rejects_float(self):
        r = requests.patch(
            f"{FTL_URL}/api/config",
            json={"config": {"dns": {"blockESNI": 15.5}}},
        )
        data = r.json()
        assert data["error"]["key"] == "bad_request"
        assert data["error"]["message"] == "Config item is invalid"
        assert "dns.blockESNI: not of type bool" in data["error"]["hint"]

    def test_piholePTR_rejects_invalid_option(self):
        r = requests.patch(
            f"{FTL_URL}/api/config",
            json={"config": {"dns": {"piholePTR": "something_else"}}},
        )
        data = r.json()
        assert data["error"]["key"] == "bad_request"
        assert data["error"]["message"] == "Config item is invalid"
        assert "dns.piholePTR: invalid option" in data["error"]["hint"]


# ---------------------------------------------------------------------------
# Config validation: CLI validator-based
# ---------------------------------------------------------------------------

class TestConfigValidationCLIValidator:
    """Config validation on the CLI: validator-based checking."""

    def test_dns_hosts_rejects_invalid_ip(self):
        result = run_ftl("--config", "dns.hosts", '["111.222.333.444 abc"]')
        assert result.returncode == 3
        lines = result.stdout.splitlines()
        assert lines[0] == 'Invalid value: dns.hosts[0]: neither a valid IPv4 nor IPv6 address ("111.222.333.444")'

    def test_dns_hosts_rejects_missing_hostname(self):
        result = run_ftl("--config", "dns.hosts", '["1.1.1.1 cf","8.8.8.8 google","1.2.3.4"]')
        assert result.returncode == 3
        lines = result.stdout.splitlines()
        assert lines[0] == 'Invalid value: dns.hosts[2]: entry does not have at least one hostname ("1.2.3.4")'

    def test_revServers_rejects_non_boolean_enabled(self):
        result = run_ftl("--config", "dns.revServers", '["abc,def,ghi"]')
        assert result.returncode == 3
        lines = result.stdout.splitlines()
        assert lines[0] == 'Invalid value: dns.revServers[0]: <enabled> not a boolean ("abc")'

    def test_revServers_rejects_invalid_ip_address(self):
        result = run_ftl("--config", "dns.revServers", '["true,abc,def,ghi"]')
        assert result.returncode == 3
        lines = result.stdout.splitlines()
        assert lines[0] == 'Invalid value: dns.revServers[0]: <ip-address> neither a valid IPv4 nor IPv6 address ("abc")'

    def test_revServers_rejects_invalid_ipv4_prefix(self):
        result = run_ftl("--config", "dns.revServers", '["true,1.2.3.4/55,def,ghi"]')
        assert result.returncode == 3
        lines = result.stdout.splitlines()
        assert lines[0] == 'Invalid value: dns.revServers[0]: <prefix-len> not a valid IPv4 prefix length ("55")'

    def test_revServers_rejects_invalid_ipv6_prefix(self):
        result = run_ftl("--config", "dns.revServers", '["true,::1/255,def,ghi"]')
        assert result.returncode == 3
        lines = result.stdout.splitlines()
        assert lines[0] == 'Invalid value: dns.revServers[0]: <prefix-len> not a valid IPv6 prefix length ("255")'

    def test_revServers_rejects_bad_dnsmasq_config(self):
        result = run_ftl("--config", "dns.revServers", '["true,1.1.1.1,def,ghi"]')
        assert result.returncode == 3
        lines = result.stdout.splitlines()
        # The message includes a dynamic line number, so use partial matching
        assert lines[0].startswith("New dnsmasq configuration is not valid (")
        assert 'rev-server=1.1.1.1,def' in lines[0]
        assert "config remains unchanged" in lines[0]

    def test_excludeClients_rejects_invalid_regex(self):
        result = run_ftl("--config", "webserver.api.excludeClients", '[".*","$$$","[[["]')
        assert result.returncode == 3
        lines = result.stdout.splitlines()
        assert lines[0] == "Invalid value: webserver.api.excludeClients[2]: not a valid regex (\"[[[\"): Missing ']'"


# ---------------------------------------------------------------------------
# Config validation: API validator-based
# ---------------------------------------------------------------------------

class TestConfigValidationAPIValidator:
    """Config validation on the API: validator-based checking."""

    def test_files_pcap_rejects_invalid_path(self):
        r = requests.patch(
            f"{FTL_URL}/api/config",
            json={"config": {"files": {"pcap": "%gh4b"}}},
        )
        data = r.json()
        assert data["error"]["key"] == "bad_request"
        assert data["error"]["message"] == "Config item validation failed"
        assert 'files.pcap: not a valid file path ("%gh4b")' in data["error"]["hint"]

    def test_cnameRecords_rejects_too_few_elements(self):
        r = requests.patch(
            f"{FTL_URL}/api/config",
            json={"config": {"dns": {"cnameRecords": ["a"]}}},
        )
        data = r.json()
        assert data["error"]["key"] == "bad_request"
        assert data["error"]["message"] == "Config item validation failed"
        assert "dns.cnameRecords[0]: not a valid CNAME definition (too few elements)" in data["error"]["hint"]

    def test_cnameRecords_rejects_empty_string_position(self):
        r = requests.patch(
            f"{FTL_URL}/api/config",
            json={"config": {"dns": {"cnameRecords": ["a,b,c", "a,b,c,,c"]}}},
        )
        data = r.json()
        assert data["error"]["key"] == "bad_request"
        assert data["error"]["message"] == "Config item validation failed"
        assert "dns.cnameRecords[1]: contains an empty string at position 3" in data["error"]["hint"]

    def test_cnameRecords_rejects_non_string_element(self):
        r = requests.patch(
            f"{FTL_URL}/api/config",
            json={"config": {"dns": {"cnameRecords": ["a,b,c", "a,b,c", 5]}}},
        )
        data = r.json()
        assert data["error"]["key"] == "bad_request"
        assert data["error"]["message"] == "Config item is invalid"
        assert "dns.cnameRecords: array has invalid elements" in data["error"]["hint"]


# ---------------------------------------------------------------------------
# Environment variable handling
# ---------------------------------------------------------------------------

class TestEnvironmentVariables:
    """Environment variables: favored, capitalized, invalid, unknown."""

    def test_env_favored_over_config(self):
        """FTLCONF_misc_nice=-11 overrides the config file value of -10."""
        result = run_shell(f"grep 'nice = -11' {TOML_RUNTIME}")
        lines = result.stdout.splitlines()
        assert len(lines) >= 1
        assert lines[0].strip() == "nice = -11 ### CHANGED (env), default = -10"

    def test_capitalized_env_used(self):
        """FTLCONF_MISC_CHECK_SHMEM=91 (capitalized) overrides default of 90."""
        result = run_shell(f"grep 'shmem = 91' {TOML_RUNTIME}")
        lines = result.stdout.splitlines()
        assert len(lines) >= 1
        assert lines[0].strip() == "shmem = 91 ### CHANGED (env), default = 90"

    def test_correct_number_of_env_vars_logged(self):
        """FTL log reports the correct count of FTLCONF environment variables."""
        result = run_shell(
            f"grep -q '5 FTLCONF environment variables found (2 used, 2 invalid, 1 ignored)' {FTL_LOG}"
        )
        assert result.returncode == 0, (
            "Expected '5 FTLCONF environment variables found (2 used, 2 invalid, 1 ignored)' in FTL.log"
        )

    def test_correct_env_var_logged(self):
        """FTLCONF_misc_nice usage is logged."""
        result = run_shell(f"grep -q 'FTLCONF_misc_nice is used' {FTL_LOG}")
        assert result.returncode == 0, "Expected 'FTLCONF_misc_nice is used' in FTL.log"

    def test_invalid_env_type_mismatch_logged(self):
        """FTLCONF_debug_api with non-boolean value is flagged."""
        result = run_shell(
            f"grep -q 'FTLCONF_debug_api is not a boolean, using default instead' {FTL_LOG}"
        )
        assert result.returncode == 0, (
            "Expected 'FTLCONF_debug_api is not a boolean, using default instead' in FTL.log"
        )

    def test_invalid_env_validation_failed_logged(self):
        """FTLCONF_files_pcap with invalid path is flagged."""
        result = run_shell(
            f'grep -Fq \'FTLCONF_files_pcap files.pcap: not a valid file path ("*123#./test/pcap"), using default instead\' {FTL_LOG}'
        )
        assert result.returncode == 0, (
            "Expected FTLCONF_files_pcap validation failure in FTL.log"
        )

    def test_unknown_env_var_suggestion_logged(self):
        """FTLCONF_dns_upstrrr produces a suggestion for dns_upstreams."""
        result = run_shell(f"grep -A1 'FTLCONF_dns_upstrrr is unknown' {FTL_LOG}")
        lines = result.stdout.splitlines()
        assert len(lines) >= 2, f"Expected 2+ lines, got: {result.stdout}"
        assert "FTLCONF_dns_upstrrr is unknown, did you mean any of these?" in lines[0]
        assert "FTLCONF_dns_upstreams" in lines[1]


# ---------------------------------------------------------------------------
# Envvar-protected config: cannot change via CLI or API
# ---------------------------------------------------------------------------

class TestEnvvarProtectedConfig:
    """Config options set via env vars are read-only."""

    def test_cli_rejects_envvar_override(self):
        """CLI cannot change misc.nice when set via FTLCONF_misc_nice."""
        result = run_ftl("--config", "misc.nice", "-12")
        assert result.returncode == 5
        lines = result.stdout.splitlines()
        assert lines[0] == "Config option misc.nice is read-only (set via environmental variable)"

    def test_api_rejects_envvar_override(self):
        """API cannot change misc.nice when set via FTLCONF_misc_nice."""
        r = requests.patch(
            f"{FTL_URL}/api/config/misc/nice",
            json={"config": {"misc": {"nice": -12}}},
        )
        data = r.json()
        assert data["error"]["key"] == "bad_request"
        assert "cannot be changed via the API" in data["error"]["message"]
        assert data["error"]["hint"] == "misc.nice"


# ---------------------------------------------------------------------------
# Unknown config key suggestions via CLI
# ---------------------------------------------------------------------------

class TestUnknownConfigKeySuggestion:
    """CLI suggests alternatives for mistyped config keys."""

    def test_dbg_all_suggests_debug_all(self):
        result = run_ftl("--config", "dbg.all")
        assert result.returncode == 4
        lines = result.stdout.splitlines()
        assert lines[0] == "Unknown config option dbg.all, did you mean:"
        assert lines[1].strip() == "- debug.all"

    def test_misc_privacyLLL_suggests_privacylevel(self):
        result = run_ftl("--config", "misc.privacyLLL")
        assert result.returncode == 4
        lines = result.stdout.splitlines()
        assert lines[0] == "Unknown config option misc.privacyLLL, did you mean:"
        assert lines[1].strip() == "- misc.privacylevel"


# ---------------------------------------------------------------------------
# DNS hosts sanitization
# ---------------------------------------------------------------------------

class TestDNSHostsSanitization:
    """DNS hosts entries are sanitized: whitespace normalized, comments handled."""

    # The original dns.hosts value that must be restored after tests.
    # Use punycode forms because the CLI validator (valid_domain()) only
    # accepts ASCII characters; raw IDN chars like "äste.com" are rejected.
    _ORIGINAL_HOSTS = '["1.1.1.1 abc-custom.com def-custom.de","2.2.2.2 xn--ste-pla.com xn--ste-sla.com"]'

    @staticmethod
    def _wait_for_hosts_written():
        """Wait for FTL to write the HOSTS file after a config change."""
        import os
        log_size = os.path.getsize(FTL_LOG)
        result = run_ftl(
            "wait-for",
            "HOSTS file written to /etc/pihole/hosts/custom.list",
            FTL_LOG,
            "5",
            str(log_size),
        )
        # Give a tiny extra margin
        time.sleep(0.2)
        return result

    def test_whitespace_normalized(self):
        """Leading/trailing/excessive internal whitespace and tabs are collapsed."""
        import os
        log_size = os.path.getsize(FTL_LOG)
        result = run_ftl(
            "--config", "dns.hosts",
            '["  192.168.1.1    host1.local  ", '
            '"   10.0.0.1\\t\\thost2.local   host3.local", '
            '"127.0.0.1     host4.local\\t\\thost5.local"]',
        )
        assert result.returncode == 0, f"Setting dns.hosts failed: {result.stdout}"

        # Wait for the hosts file write
        wait_result = run_ftl(
            "wait-for",
            "HOSTS file written to /etc/pihole/hosts/custom.list",
            FTL_LOG,
            "5",
            str(log_size),
        )
        assert wait_result.returncode == 0, f"Timed out waiting for hosts write: {wait_result.stdout}"

        # Read back and verify normalization
        check = run_ftl("--config", "dns.hosts")
        lines = check.stdout.splitlines()
        assert lines[0] == "[ 192.168.1.1 host1.local, 10.0.0.1 host2.local host3.local, 127.0.0.1 host4.local host5.local ]"

        # Restore original value
        self._restore_hosts()

    def test_comments_handled(self):
        """Inline comments are preserved; trailing whitespace/tabs removed."""
        import os
        log_size = os.path.getsize(FTL_LOG)
        result = run_ftl(
            "--config", "dns.hosts",
            '["192.168.1.1   host1.local   # this is a comment with  double spaces", '
            '"   10.0.0.1\\thost2.local\\t\\t\\t"]',
        )
        assert result.returncode == 0, f"Setting dns.hosts failed: {result.stdout}"

        # Wait for the hosts file write
        wait_result = run_ftl(
            "wait-for",
            "HOSTS file written to /etc/pihole/hosts/custom.list",
            FTL_LOG,
            "5",
            str(log_size),
        )
        assert wait_result.returncode == 0, f"Timed out waiting for hosts write: {wait_result.stdout}"

        # Read back and verify
        check = run_ftl("--config", "dns.hosts")
        lines = check.stdout.splitlines()
        assert lines[0] == "[ 192.168.1.1 host1.local # this is a comment with  double spaces, 10.0.0.1 host2.local ]"

        # Restore original value
        self._restore_hosts()

    def _restore_hosts(self):
        """Restore the original dns.hosts value so later tests are unaffected."""
        import os
        log_size = os.path.getsize(FTL_LOG)
        result = run_ftl("--config", "dns.hosts", self._ORIGINAL_HOSTS)
        assert result.returncode == 0, f"Restoring dns.hosts failed: {result.stdout}"
        # Wait for the write to complete
        run_ftl(
            "wait-for",
            "HOSTS file written to /etc/pihole/hosts/custom.list",
            FTL_LOG,
            "5",
            str(log_size),
        )
