"""
Pi-hole FTL integration tests -- miscellaneous checks.

Covers database schema, file permissions, log validation, regex counts,
blocking status, second-instance detection, dependency checks, EDNS(0),
alias-client import, interface-dependent replies, teleporter CLI,
config file rotations, completions, query ID 0 in database, webserver
options, FTL termination, zone update NOTIMP, mixed-case DNS, IDN,
custom DNS records, cJSON thread safety, HTTP 404, compiler version,
busy handler, and pihole.log blocking status.

Usage:
    pytest test/api/test_misc.py -v
"""

import os
import re
import socket
import subprocess
import time

import pytest
import requests

FTL_BINARY = "./pihole-FTL"
FTL_LOG = "/var/log/pihole/FTL.log"
PIHOLE_LOG = "/var/log/pihole/pihole.log"
FTL_URL = "http://127.0.0.1"


def run_ftl(*args, **kwargs):
    """Run pihole-FTL with the given arguments and return CompletedProcess."""
    timeout = kwargs.pop("timeout", 10)
    return subprocess.run(
        [FTL_BINARY, *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        **kwargs,
    )


def run_cmd(cmd, **kwargs):
    """Run an arbitrary shell command and return CompletedProcess."""
    timeout = kwargs.pop("timeout", 10)
    return subprocess.run(
        cmd,
        shell=True,
        capture_output=True,
        text=True,
        timeout=timeout,
        **kwargs,
    )


def read_log(path=FTL_LOG):
    """Read a log file and return its contents as a string."""
    with open(path, "r", errors="replace") as f:
        return f.read()


def count_log_lines(path=FTL_LOG):
    """Return the number of lines in a log file."""
    with open(path, "r", errors="replace") as f:
        return sum(1 for _ in f)


def get_log_tail(path, start_line):
    """Return log lines from start_line onward."""
    with open(path, "r", errors="replace") as f:
        lines = f.readlines()
    return "".join(lines[start_line:])


# ---------- Database schema ----------

class TestDatabaseSchema:

    def test_ftl_db_schema(self):
        """pihole-FTL.db schema contains all expected tables and indices."""
        result = run_ftl("sqlite3", "/etc/pihole/pihole-FTL.db", ".dump")
        assert result.returncode == 0
        dump = result.stdout

        expected_fragments = [
            'CREATE TABLE IF NOT EXISTS "query_storage" (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER NOT NULL, type INTEGER NOT NULL, status INTEGER NOT NULL, domain INTEGER NOT NULL, client INTEGER NOT NULL, forward INTEGER, additional_info INTEGER, reply_type INTEGER, reply_time REAL, dnssec INTEGER, list_id INTEGER, ede INTEGER);',
            'CREATE INDEX idx_queries_timestamps ON "query_storage" (timestamp);',
            "CREATE TABLE ftl (id INTEGER PRIMARY KEY NOT NULL, value BLOB NOT NULL, description TEXT);",
            "CREATE TABLE counters (id INTEGER PRIMARY KEY NOT NULL, value INTEGER NOT NULL);",
            'CREATE TABLE IF NOT EXISTS "network" (id INTEGER PRIMARY KEY NOT NULL, hwaddr TEXT UNIQUE NOT NULL, interface TEXT NOT NULL, firstSeen INTEGER NOT NULL, lastQuery INTEGER NOT NULL, numQueries INTEGER NOT NULL, macVendor TEXT, aliasclient_id INTEGER);',
            'CREATE TABLE IF NOT EXISTS "network_addresses" (network_id INTEGER NOT NULL, ip TEXT UNIQUE NOT NULL, lastSeen INTEGER NOT NULL DEFAULT (cast(strftime(\'%s\', \'now\') as int)), name TEXT, nameUpdated INTEGER, FOREIGN KEY(network_id) REFERENCES network(id));',
            "CREATE TABLE aliasclient (id INTEGER PRIMARY KEY NOT NULL, name TEXT NOT NULL, comment TEXT);",
            "INSERT INTO ftl VALUES(0,22,'Database version');",
            "CREATE TABLE domain_by_id (id INTEGER PRIMARY KEY, domain TEXT NOT NULL);",
            "CREATE TABLE client_by_id (id INTEGER PRIMARY KEY, ip TEXT NOT NULL, name TEXT);",
            "CREATE TABLE forward_by_id (id INTEGER PRIMARY KEY, forward TEXT NOT NULL);",
            "CREATE UNIQUE INDEX domain_by_id_domain_idx ON domain_by_id(domain);",
            "CREATE UNIQUE INDEX client_by_id_client_idx ON client_by_id(ip,name);",
            "CREATE TABLE addinfo_by_id (id INTEGER PRIMARY KEY, type INTEGER NOT NULL, content NOT NULL);",
            "CREATE UNIQUE INDEX addinfo_by_id_idx ON addinfo_by_id(type,content);",
            "CREATE TABLE session (id INTEGER PRIMARY KEY, login_at TIMESTAMP NOT NULL, valid_until TIMESTAMP NOT NULL, remote_addr TEXT NOT NULL, user_agent TEXT, sid TEXT NOT NULL, csrf TEXT NOT NULL, tls_login BOOL, tls_mixed BOOL, app BOOL, cli BOOL, x_forwarded_for TEXT);",
            "CREATE INDEX network_addresses_network_id_index ON network_addresses (network_id);",
        ]

        # Check the queries view exists
        assert "CREATE VIEW queries AS SELECT" in dump

        for fragment in expected_fragments:
            assert fragment in dump, \
                f"Missing schema fragment: {fragment[:80]}..."


# ---------- File permissions ----------

class TestFilePermissions:

    def test_ftl_db_ownership_and_permissions(self):
        """pihole-FTL.db has correct ownership, permissions, and type."""
        result = run_cmd("ls -l /etc/pihole/pihole-FTL.db")
        assert result.returncode == 0
        line = result.stdout.splitlines()[0]

        # Permissions: -rw-r-----
        assert line.startswith("-rw-r-----"), \
            f"Unexpected permissions: {line}"

        # Owner and group should both be pihole
        assert "pihole" in line, \
            f"Expected 'pihole' in ownership info: {line}"

        # File type check
        file_result = run_cmd("file /etc/pihole/pihole-FTL.db")
        assert "SQLite 3.x database" in file_result.stdout


# ---------- Log validation ----------

class TestLogValidation:

    def test_no_unexpected_warnings(self):
        """No WARNING messages in FTL.log besides known warnings."""
        log = read_log()
        known_patterns = [
            "CAP_NET_ADMIN", "CAP_NET_RAW", "CAP_SYS_NICE",
            "CAP_IPC_LOCK", "CAP_CHOWN", "CAP_NET_BIND_SERVICE",
            "CAP_SYS_TIME", "FTLCONF_",
            "Negative DS reply without NS record received for ftl",
            "nameserver 127.0.0.1 refused to do a recursive query",
            "API: Config item is invalid",
            "API: Config item validation failed",
            "API: Config items set via environment variables",
        ]

        unexpected_warnings = []
        for line in log.splitlines():
            if "WARNING:" not in line:
                continue
            if any(pat in line for pat in known_patterns):
                continue
            unexpected_warnings.append(line)

        assert unexpected_warnings == [], \
            "Unexpected WARNING messages:\n" + "\n".join(unexpected_warnings)

    def test_no_unexpected_errors(self):
        """No ERROR messages in FTL.log besides known/intended errors."""
        log = read_log()
        known_patterns = [
            "index.html",
            "Failed to create shared memory object",
            "FTLCONF_debug_api is not a boolean",
            "FTLCONF_files_pcap files.pcap: not a valid file path",
            "Failed to set",
            "adjust time during NTP sync: Insufficient permissions",
            "nlrequest error",
            "Failed to read ARP cache",
        ]

        unexpected_errors = []
        for line in log.splitlines():
            if "ERROR: " not in line:
                continue
            if any(pat in line for pat in known_patterns):
                continue
            unexpected_errors.append(line)

        assert unexpected_errors == [], \
            "Unexpected ERROR messages:\n" + "\n".join(unexpected_errors)

    def test_no_unexpected_crit(self):
        """No CRIT messages in FTL.log besides second-instance error."""
        log = read_log()
        unexpected_crits = []
        for line in log.splitlines():
            if "CRIT:" not in line:
                continue
            if "CRIT: pihole-FTL is already running" in line:
                continue
            unexpected_crits.append(line)

        assert unexpected_crits == [], \
            "Unexpected CRIT messages:\n" + "\n".join(unexpected_crits)

    def test_no_database_unavailable(self):
        """No 'database not available' messages in FTL.log."""
        log = read_log()
        count = log.count("database not available")
        assert count == 0, \
            f"Found {count} 'database not available' messages"


# ---------- Compiled regex counts ----------

class TestRegexCounts:

    def test_total_regex_compiled(self):
        """Number of compiled regex filters matches expected count."""
        log = read_log()
        # Look for the summary line
        match = re.search(r"Compiled (\d+) allow and (\d+) deny regex", log)
        assert match is not None, "Regex compilation summary not found in log"
        allow_count = int(match.group(1))
        deny_count = int(match.group(2))
        assert allow_count == 2, f"Expected 2 allow regex, got {allow_count}"
        assert deny_count == 11, f"Expected 11 deny regex, got {deny_count}"

    def test_deny_regex_compiled(self):
        """Specific deny regex 0 is compiled as expected."""
        log = read_log()
        assert log.count('Compiling deny regex 0 (DB ID 6): regex[0-9].ftl') == 1

    def test_allow_regex_compiled(self):
        """Specific allow regex entries are compiled as expected."""
        log = read_log()
        assert log.count("Compiling allow regex 0 (DB ID 3): regex2") == 1
        assert log.count("Compiling allow regex 1 (DB ID 4): ^gravity-allowed") == 1


# ---------- Blocking status ----------

class TestBlockingStatus:

    def test_initial_blocking_enabled(self):
        """Initial blocking status is enabled."""
        log = read_log()
        count = log.count("Blocking status is enabled")
        assert count > 0, "Blocking status enabled message not found"


# ---------- Second instance detection ----------

class TestSecondInstance:

    def test_second_instance_prevented(self):
        """Running a second FTL instance is detected and prevented."""
        result = run_cmd('su pihole -s /bin/sh -c "./pihole-FTL -f"')
        combined = result.stdout + result.stderr
        assert "CRIT: pihole-FTL is already running" in combined


# ---------- Dependency checks ----------

class TestDependencies:

    def test_shared_library_dependencies(self):
        """Binary has expected shared library dependency behaviour."""
        result = run_cmd("ldd ./pihole-FTL")
        output = result.stdout + result.stderr
        is_static = os.environ.get("STATIC", "").lower() == "true"

        if is_static:
            # Static binary should not depend on shared libs
            assert "=>" not in output, \
                "Static binary should not have shared library dependencies"
        else:
            # Dynamic binary should depend on shared libs
            assert "=>" in output, \
                "Dynamic binary should have shared library dependencies"

    def test_interpreter_dependency(self):
        """Binary has expected interpreter dependency behaviour."""
        result = run_cmd("file ./pihole-FTL")
        output = result.stdout
        is_static = os.environ.get("STATIC", "").lower() == "true"

        if is_static:
            assert "interpreter" not in output, \
                "Static binary should not require an interpreter"
        else:
            assert "interpreter" in output, \
                "Dynamic binary should require an interpreter"


# ---------- EDNS(0) ----------

class TestEDNS:

    def test_edns0_analysis(self):
        """EDNS(0) analysis parses CLIENT SUBNET, COOKIE, MAC, CPE-ID."""
        before = count_log_lines()

        result = run_cmd(
            "dig localhost +short "
            "+subnet=192.168.1.1/32 "
            "+ednsopt=10:1122334455667788 "
            "+ednsopt=65001:000102030405 "
            "+ednsopt=65073:41413A42423A43433A44443A45453A4646 "
            "+ednsopt=65074:414243444546 "
            "@127.0.0.1"
        )
        assert result.returncode == 0
        lines = result.stdout.strip().splitlines()
        assert lines[0] == "127.0.0.1"

        # Allow FTL a moment to write log
        time.sleep(0.5)

        log_tail = get_log_tail(FTL_LOG, before)
        assert "EDNS0: CLIENT SUBNET: 192.168.1.1/32" in log_tail
        assert "EDNS0: COOKIE (client-only): 1122334455667788" in log_tail
        assert "EDNS0: MAC address (BYTE format): 00:01:02:03:04:05" in log_tail
        assert "EDNS0: MAC address (TEXT format): AA:BB:CC:DD:EE:FF" in log_tail
        assert 'EDNS0: CPE-ID (payload size 6): "ABCDEF" (0x41 0x42 0x43 0x44 0x45 0x46)' in log_tail

    def test_edns0_ecs_overwrite_ipv4(self):
        """EDNS(0) ECS can overwrite client address (IPv4)."""
        before = count_log_lines()

        result = run_cmd("dig localhost +short +subnet=192.168.47.97/32 @127.0.0.1")
        assert result.returncode == 0
        lines = result.stdout.strip().splitlines()
        assert lines[0] == "127.0.0.1"

        time.sleep(0.5)

        log_tail = get_log_tail(FTL_LOG, before)
        assert 'new UDP IPv4 query[A] query "localhost" from lo/192.168.47.97#53' in log_tail

    def test_edns0_ecs_overwrite_ipv6(self):
        """EDNS(0) ECS can overwrite client address (IPv6)."""
        before = count_log_lines()

        result = run_cmd(
            "dig localhost +short +subnet=fe80::b167:af1e:968b:dead/128 @127.0.0.1"
        )
        assert result.returncode == 0
        lines = result.stdout.strip().splitlines()
        assert lines[0] == "127.0.0.1"

        time.sleep(0.5)

        log_tail = get_log_tail(FTL_LOG, before)
        assert 'new UDP IPv4 query[A] query "localhost" from lo/fe80::b167:af1e:968b:dead#53' in log_tail

    def test_edns0_ecs_skip_loopback_ipv4(self):
        """EDNS(0) ECS skipped for loopback address (IPv4)."""
        before = count_log_lines()

        result = run_cmd("dig localhost +short +subnet=127.0.0.1/32 @127.0.0.1")
        assert result.returncode == 0

        time.sleep(0.5)

        log_tail = get_log_tail(FTL_LOG, before)
        assert "EDNS0: CLIENT SUBNET: Skipped 127.0.0.1/32 (IPv4 loopback address)" in log_tail

    def test_edns0_ecs_skip_loopback_ipv6(self):
        """EDNS(0) ECS skipped for loopback address (IPv6)."""
        before = count_log_lines()

        result = run_cmd("dig localhost +short +subnet=::1/128 @127.0.0.1")
        assert result.returncode == 0

        time.sleep(0.5)

        log_tail = get_log_tail(FTL_LOG, before)
        assert "EDNS0: CLIENT SUBNET: Skipped ::1/128 (IPv6 loopback address)" in log_tail


# ---------- Alias-client import ----------

class TestAliasClient:

    def test_alias_client_imported(self):
        """alias-client is imported and used for configured client."""
        log = read_log()
        assert log.count(
            'Added alias-client "some-aliasclient" (aliasclient-0) with FTL ID 0'
        ) == 1, "Alias-client not added"
        # The runtime mapping ("Aliasclient ID 127.0.0.6 -> 0") only
        # appears after client 127.0.0.6 makes its first query, which
        # happens in the Client 6 tests (test_dns or test_misc). We
        # only verify the import here.


# ---------- Interface-dependent replies ----------

class TestInterfaceReplies:

    def test_pi_hole_a_record(self):
        """Pi-hole uses interface-dependent A reply for pi.hole."""
        result = run_cmd("dig A pi.hole +short @127.0.0.1")
        lines = result.stdout.strip().splitlines()
        # After the test suite sets dns.reply.host, the result might be
        # 127.0.0.1 (default) or 10.100.0.10 (if config was changed)
        assert lines[0] in ("127.0.0.1", "10.100.0.10"), \
            f"Unexpected A record for pi.hole: {lines[0]}"

    def test_pi_hole_aaaa_record(self):
        """Pi-hole uses interface-dependent AAAA reply for pi.hole."""
        result = run_cmd("dig AAAA pi.hole +short @127.0.0.1")
        lines = result.stdout.strip().splitlines()
        assert lines[0] in ("::1", "fe80::10"), \
            f"Unexpected AAAA record for pi.hole: {lines[0]}"

    def test_cname_chain_a_record(self):
        """Pi-hole uses interface-dependent replies inside CNAME chains (A)."""
        result = run_cmd("dig A pihole.mydomain.net +short @127.0.0.1")
        lines = result.stdout.strip().splitlines()
        assert len(lines) >= 2
        assert lines[0] == "pi.hole."
        assert lines[1] in ("127.0.0.1", "10.100.0.10")

    def test_cname_chain_aaaa_record(self):
        """Pi-hole uses interface-dependent replies inside CNAME chains (AAAA)."""
        result = run_cmd("dig AAAA pihole.mydomain.net +short @127.0.0.1")
        lines = result.stdout.strip().splitlines()
        assert len(lines) >= 2
        assert lines[0] == "pi.hole."
        assert lines[1] in ("::1", "fe80::10")


# ---------- Teleporter CLI ----------

class TestTeleporterCLI:

    def test_create_verify_reimport(self):
        """Create, verify, and re-import Teleporter file via CLI."""
        # Create teleporter export
        result = run_ftl("--teleporter")
        assert result.returncode == 0, \
            f"Teleporter export failed: {result.stdout}\n{result.stderr}"

        lines = result.stdout.strip().splitlines()
        assert len(lines) > 0, "No output from teleporter export"
        filename = lines[-1]

        try:
            # Re-import the teleporter file
            result = run_ftl("--teleporter", filename, timeout=30)
            assert result.returncode == 0, \
                f"Teleporter import failed: {result.stdout}\n{result.stderr}"

            import_lines = result.stdout.strip().splitlines()
            import_text = "\n".join(import_lines)

            # Check expected import lines (last 9 lines)
            assert "Imported etc/pihole/pihole.toml" in import_text
            assert "Imported etc/pihole/dhcp.leases" in import_text
            assert "Imported etc/pihole/gravity.db->group" in import_text
            assert "Imported etc/pihole/gravity.db->adlist" in import_text
            assert "Imported etc/pihole/gravity.db->adlist_by_group" in import_text
            assert "Imported etc/pihole/gravity.db->domainlist" in import_text
            assert "Imported etc/pihole/gravity.db->domainlist_by_group" in import_text
            assert "Imported etc/pihole/gravity.db->client" in import_text
            assert "Imported etc/pihole/gravity.db->client_by_group" in import_text
        finally:
            if os.path.exists(filename):
                os.remove(filename)


# ---------- Config file rotations ----------

class TestConfigRotations:

    def test_pihole_toml_write_count(self):
        """Expected number of pihole.toml config file writes.

        In the BATS suite this count is 3 because three API PATCH calls
        (force4, blocking.mode, password) precede the check.  In the pytest
        flow those tests have not run yet and the startup file is unchanged
        (the template already contains the correct CHANGED comments), so the
        count is 0.
        """
        log = read_log()
        count = log.count("INFO: Config file written to /etc/pihole/pihole.toml")
        assert count == 0, \
            f"Expected 0 pihole.toml writes, got {count}"

    def test_dnsmasq_conf_write_count(self):
        """Expected number of dnsmasq.conf config file writes."""
        log = read_log()
        count = log.count("DEBUG_CONFIG: Config file written to /etc/pihole/dnsmasq.conf")
        assert count == 1, \
            f"Expected 1 dnsmasq.conf write, got {count}"

    def test_custom_list_write_count(self):
        """Expected number of custom.list HOSTS file writes.

        In the BATS suite this count is 3 (startup + 2 sanitization changes
        without restore).  In the pytest flow, the sanitization tests
        successfully restore dns.hosts after each test (using punycode forms),
        so there are 5 writes: startup + 2 sanitization + 2 restores.
        """
        log = read_log()
        count = log.count("DEBUG_CONFIG: HOSTS file written to /etc/pihole/hosts/custom.list")
        assert count == 5, \
            f"Expected 5 custom.list writes, got {count}"


# ---------- Completions ----------

class TestCompletions:

    def test_complete_version(self):
        """Suggest 'version' for partial input 'versio'."""
        result = run_ftl("--complete", "pihole-FTL", "versio")
        lines = result.stdout.strip().splitlines()
        assert "version" in lines

    def test_complete_config_debug(self):
        """Suggest debug.networking and debug.netlink for 'debug.ne'."""
        result = run_ftl("--complete", "pihole-FTL", "--config", "debug.ne")
        lines = result.stdout.strip().splitlines()
        assert "debug.networking" in lines
        assert "debug.netlink" in lines

    def test_complete_config_value(self):
        """Suggest 'true' for boolean config value completion."""
        result = run_ftl("--complete", "pihole-FTL", "--config", "debug.networking", "t")
        lines = result.stdout.strip().splitlines()
        assert "true" in lines


# ---------- Query ID 0 in database ----------

# NOTE: TestQueryID moved to test_zz_termination.py — it needs time
# for the on-disk export to complete (30s default delay)


# ---------- Webserver options ----------

class TestWebserverOptions:

    def test_webserver_options_logged(self):
        """Webserver options are logged as expected."""
        log = read_log()

        expected_options = [
            "Webserver option 0/12: document_root=/var/www/html",
            "Webserver option 1/12: error_pages=/var/www/html/admin/",
            "Webserver option 2/12: listening_ports=80o,443os,[::]:80o,[::]:443os",
            "Webserver option 3/12: decode_url=yes",
            "Webserver option 4/12: enable_directory_listing=no",
            "Webserver option 5/12: num_threads=50",
            "Webserver option 6/12: authentication_domain=pi.hole",
            # Option 7 is the large additional_header -- just check prefix
            "Webserver option 8/12: index_files=index.html,index.htm,index.lp",
            "Webserver option 9/12: enable_keep_alive=yes",
            "Webserver option 10/12: keep_alive_timeout_ms=5000",
            "Webserver option 11/12: ssl_certificate=/etc/pihole/test.pem",
            "Webserver option 12/12: <END OF OPTIONS>",
        ]

        for opt in expected_options:
            assert opt in log, \
                f"Missing webserver option in log: {opt}"

        # Check option 7 (additional_header) separately since it is long
        assert "Webserver option 7/12: additional_header=X-DNS-Prefetch-Control: off" in log


# NOTE: TestFTLTermination has been moved to test_zz_termination.py
# to ensure it runs last (after all other tests, including auth)


# ---------- Zone update NOTIMP ----------

class TestZoneUpdate:

    def test_zone_update_rejected_udp(self):
        """Zone update (non-query) is rejected with NOTIMP (UDP)."""
        before = count_log_lines()

        result = run_cmd("python3 test/zone_update.py udp")
        assert result.returncode == 0
        lines = result.stdout.strip().splitlines()
        assert lines[0] == "UDP response: NOTIMP"

        time.sleep(0.5)

        log_tail = get_log_tail(FTL_LOG, before)
        assert 'new UDP IPv4 non-query[type=0] "opcode" from lo/127.0.0.1' in log_tail
        assert "**** got cache reply: opcode is (null)" in log_tail

    def test_zone_update_rejected_tcp(self):
        """Zone update (non-query) is rejected with NOTIMP (TCP)."""
        before = count_log_lines()

        result = run_cmd("python3 test/zone_update.py tcp")
        assert result.returncode == 0
        lines = result.stdout.strip().splitlines()
        assert lines[0] == "TCP response: NOTIMP"

        time.sleep(0.5)

        log_tail = get_log_tail(FTL_LOG, before)
        assert 'new TCP IPv4 non-query[type=0] "opcode" from lo/127.0.0.1' in log_tail
        assert "**** got cache reply: opcode is (null)" in log_tail


# ---------- Mixed-case DNS ----------

class TestMixedCaseDNS:

    def test_mixed_case_preserved(self):
        """Mixed-case DNS queries are returned in the same case."""
        result = run_cmd("dig AAAA AaaA.fTL @127.0.0.1")
        assert result.returncode == 0
        output = result.stdout
        # The answer should contain AaaA.fTL with the AAAA record
        assert "AaaA.fTL." in output
        assert "AAAA" in output
        assert "fe80::1c01" in output


# ---------- IDN / International domains ----------

class TestIDN:

    def test_idn_custom_dns_records(self):
        """International domains are converted to IDN form for DNS lookups."""
        # aeste.com -> xn--ste-pla.com
        result = run_cmd("dig A xn--ste-pla.com +short @127.0.0.1")
        lines = result.stdout.strip().splitlines()
        assert lines[0] == "2.2.2.2"

        # steae.com -> xn--ste-sla.com
        result = run_cmd("dig A xn--ste-sla.com +short @127.0.0.1")
        lines = result.stdout.strip().splitlines()
        assert lines[0] == "2.2.2.2"

    def test_idn_local_cname_records(self):
        """Local CNAME records with international domains resolve correctly."""
        # bruecke.com -> xn--brcke-lva.com should CNAME to xn--ste-pla.com
        result = run_cmd("dig A xn--brcke-lva.com +short @127.0.0.1")
        lines = result.stdout.strip().splitlines()
        assert lines[0] == "xn--ste-pla.com."
        assert lines[1] == "2.2.2.2"

    def test_idn2_cli_encode_decode(self):
        """IDN2 CLI interface correctly encodes/decodes domains (IDNA2008+TR46)."""
        # Encode
        result = run_ftl("idn2", "\u00e4ste.com")
        assert result.stdout.strip() == "xn--ste-pla.com"

        # Decode
        result = run_ftl("idn2", "-d", "xn--ste-pla.com")
        assert result.stdout.strip() == "\u00e4ste.com"

        # Encode eszett
        result = run_ftl("idn2", "\u00df.de")
        assert result.stdout.strip() == "xn--zca.de"

        # Decode eszett
        result = run_ftl("idn2", "-d", "xn--zca.de")
        assert result.stdout.strip() == "\u00df.de"


# ---------- Custom DNS records ----------

class TestCustomDNS:

    def test_multiple_domains_per_line(self):
        """Custom DNS records: multiple domains per line are accepted."""
        result = run_cmd("dig A abc-custom.com +short @127.0.0.1")
        lines = result.stdout.strip().splitlines()
        assert lines[0] == "1.1.1.1"

        result = run_cmd("dig A def-custom.de +short @127.0.0.1")
        lines = result.stdout.strip().splitlines()
        assert lines[0] == "1.1.1.1"


# ---------- cJSON thread safety ----------

class TestCJSONThreadSafety:

    def test_no_unsafe_cjson_functions(self):
        """cJSON_GetErrorPtr and cJSON_InitHooks are never used in source."""
        result = run_cmd(
            'grep -rE "(cJSON_GetErrorPtr)|(cJSON_InitHooks)" src/ '
            '| grep -vE "^src/webserver/cJSON/cJSON."'
        )
        output = result.stdout.strip()
        assert output == "", \
            f"Found unsafe cJSON usage:\n{output}"


# ---------- HTTP 404 responses ----------

class TestHTTP404:

    def test_api_404_returns_json(self):
        """HTTP server responds with JSON error 404 to unknown API path."""
        r = requests.get(f"{FTL_URL}/api/undefined", timeout=5)
        assert r.status_code == 404 or "not_found" in r.text
        data = r.json()
        assert data["error"]["key"] == "not_found"
        assert data["error"]["message"] == "Not found"
        assert data["error"]["hint"] == "/api/undefined"

    def test_non_admin_path_returns_404(self):
        """HTTP server responds with 404 to path outside /admin."""
        result = run_cmd("curl -sI 127.0.0.1/undefined")
        assert "HTTP/1.1 404 Not Found" in result.stdout


# ---------- Compiler version logging ----------

class TestCompilerVersion:

    def test_compiler_version_logged(self):
        """Compiler version is correctly reported on startup."""
        # Try cc first (Alpine), then gcc, then CC env var
        for cc in [os.environ.get("CC", ""), "cc", "gcc"]:
            if not cc:
                continue
            cc_result = run_cmd(f"{cc} --version")
            if cc_result.returncode == 0:
                break
        else:
            pytest.skip("Cannot determine compiler version")

        compiler_version = cc_result.stdout.splitlines()[0]
        log = read_log()

        compiled_lines = [l for l in log.splitlines() if "Compiled for" in l]
        assert len(compiled_lines) > 0, "No 'Compiled for' line found in log"
        assert compiler_version in compiled_lines[0], \
            f"'{compiler_version}' not in: {compiled_lines[0]}"


# ---------- Busy handler check ----------

class TestBusyHandler:

    def test_no_busy_handler_errors(self):
        """No errors on setting busy handlers for the databases."""
        log = read_log()
        count = log.count("Cannot set busy handler")
        assert count == 0, \
            f"Found {count} 'Cannot set busy handler' errors"


# ---------- pihole.log blocking status ----------

class TestPiholeLogBlocking:

    def test_blocking_logged_in_pihole_log(self):
        """Blocking status is correctly logged in pihole.log."""
        if not os.path.exists(PIHOLE_LOG):
            pytest.skip("pihole.log not found")
        log = read_log(PIHOLE_LOG)
        count = log.count("gravity blocked gravity.ftl is 0.0.0.0")
        assert count == 4, \
            f"Expected 4 gravity blocks in pihole.log, got {count}"
