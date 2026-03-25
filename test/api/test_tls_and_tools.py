"""
Pi-hole FTL API integration tests -- TLS, X.509, embedded tools, PTR resolution.

Tests the TLS/SSL webserver, X.509 certificate parser, embedded GZIP
compressor, SHA256 checksum tool, embedded SQLite3 shell, LUA engine,
and internal PTR resolution.

Usage:
    pytest test/api/test_tls_and_tools.py -v
"""

import os
import subprocess
import tempfile

import pytest

FTL_BINARY = "./pihole-FTL"


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


# ---------- TLS / SSL ----------

class TestTLS:

    def test_tls_self_signed_cert(self):
        """TLS/SSL server responds correctly using self-signed certificate."""
        result = run_cmd(
            "curl -sI "
            "--cacert /etc/pihole/test.crt "
            "--resolve pi.hole:443:127.0.0.1 "
            "https://pi.hole/"
        )
        lines = result.stdout.splitlines()
        assert len(lines) > 0, "No response from HTTPS server"
        assert lines[0].startswith("HTTP/1.1 "), \
            f"Unexpected first line: {lines[0]}"

    def test_tls_verbose_no_error(self):
        """TLS/SSL connection succeeds without curl errors."""
        result = run_cmd(
            "curl -I "
            "--cacert /etc/pihole/test.crt "
            "--resolve pi.hole:443:127.0.0.1 "
            "https://pi.hole/"
        )
        assert result.returncode == 0, \
            f"curl failed with rc={result.returncode}: {result.stderr}"


# ---------- X.509 certificate parser ----------

class TestX509:

    def test_read_x509_certificate(self):
        """X.509 certificate parser returns expected certificate fields."""
        result = run_ftl("--read-x509")
        assert result.returncode == 0
        lines = result.stdout.splitlines()

        assert lines[0] == "Reading certificate from /etc/pihole/test.pem ..."
        assert lines[1] == "Certificate (X.509):"
        assert lines[2] == "  cert. version     : 3"
        assert lines[3] == "  serial number     : 36:36:32:32:35:31:37:36:30:30:39:31:30:30:37"
        assert lines[4] == "  issuer name       : CN=pi.hole, O=Pi-hole, C=DE"
        assert lines[5] == "  subject name      : CN=pi.hole"
        assert lines[6] == "  issued  on        : 2023-01-16 21:15:12"
        assert lines[7] == "  expires on        : 2053-01-16 21:15:12"
        assert lines[8] == "  signed using      : ECDSA with SHA256"
        assert lines[9] == "  EC key size       : 384 bits"
        assert lines[10] == "  basic constraints : CA=false"
        assert lines[11] == "  subject alt name  :"
        assert lines[12] == "      dNSName : pi.hole"
        assert lines[13] == ""  # blank line between cert and key
        assert lines[14] == "Public key (PEM):"
        assert lines[15] == "-----BEGIN PUBLIC KEY-----"
        assert lines[16] == "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEuH7sWfGRkvm5s5LVYTwbM6PjZmuK4KPh"
        assert lines[17] == "A5qaWfVqJw4jeEMkvyT4CKtiruLEBcqzimkBhP6dlMOUM/K0caRC5Jm46fMC9bV3"
        assert lines[18] == "74ibYXxiX4bkiu8m/GDjM5RgiS1D1x+U"
        assert lines[19] == "-----END PUBLIC KEY-----"

    def test_read_x509_with_private_key(self):
        """X.509 parser with --read-x509-key returns certificate and private key."""
        result = run_ftl("--read-x509-key", "/etc/pihole/test.pem")
        assert result.returncode == 0
        lines = result.stdout.splitlines()

        assert lines[0] == "Reading certificate from /etc/pihole/test.pem ..."
        assert lines[1] == "Certificate (X.509):"
        assert lines[2] == "  cert. version     : 3"
        assert lines[3] == "  serial number     : 36:36:32:32:35:31:37:36:30:30:39:31:30:30:37"
        assert lines[4] == "  issuer name       : CN=pi.hole, O=Pi-hole, C=DE"
        assert lines[5] == "  subject name      : CN=pi.hole"
        assert lines[6] == "  issued  on        : 2023-01-16 21:15:12"
        assert lines[7] == "  expires on        : 2053-01-16 21:15:12"
        assert lines[8] == "  signed using      : ECDSA with SHA256"
        assert lines[9] == "  EC key size       : 384 bits"
        assert lines[10] == "  basic constraints : CA=false"
        assert lines[11] == "  subject alt name  :"
        assert lines[12] == "      dNSName : pi.hole"

        # Blank line between cert and private key section
        assert lines[13] == ""
        assert lines[14] == "Private key:"
        assert lines[15] == "  ID: 0"
        assert lines[16] == "  Keysize: 384 bits"
        assert lines[17] == "  Algorithm: 151126016"
        assert lines[18] == "  Lifetime: 0"
        assert lines[19] == "  Type: ECC (key pair)"
        assert lines[20] == "  Curvetype: SEC random curve over prime fields (secp384r1)"
        assert lines[21] == ""
        assert lines[22] == "Private key (PEM):"
        assert lines[23] == "-----BEGIN EC PRIVATE KEY-----"
        assert lines[24] == "MIGkAgEBBDBGWIbQ11v8sQjrlj+KUS7OJoR0M9xyZyMLhkejtXlHGNXn2lK8ZzPW"
        assert lines[25] == "UUA6+ZqgdA+gBwYFK4EEACKhZANiAAS4fuxZ8ZGS+bmzktVhPBszo+Nma4rgo+ED"
        assert lines[26] == "mppZ9WonDiN4QyS/JPgIq2Ku4sQFyrOKaQGE/p2Uw5Qz8rRxpELkmbjp8wL1tXfv"
        assert lines[27] == "iJthfGJfhuSK7yb8YOMzlGCJLUPXH5Q="
        assert lines[28] == "-----END EC PRIVATE KEY-----"
        assert lines[29] == ""
        assert lines[30] == "Public key (PEM):"
        assert lines[31] == "-----BEGIN PUBLIC KEY-----"
        assert lines[32] == "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEuH7sWfGRkvm5s5LVYTwbM6PjZmuK4KPh"
        assert lines[33] == "A5qaWfVqJw4jeEMkvyT4CKtiruLEBcqzimkBhP6dlMOUM/K0caRC5Jm46fMC9bV3"
        assert lines[34] == "74ibYXxiX4bkiu8m/GDjM5RgiS1D1x+U"
        assert lines[35] == "-----END PUBLIC KEY-----"

    def test_x509_domain_match(self):
        """X.509 parser can verify domain matches certificate SAN."""
        # Matching domain
        result = run_ftl("--read-x509-key", "/etc/pihole/test.pem", "pi.hole")
        assert result.returncode == 0
        lines = result.stdout.splitlines()
        assert lines[0] == "Reading certificate from /etc/pihole/test.pem ..."
        assert lines[1] == "Certificate matches domain pi.hole"

    def test_x509_domain_no_match(self):
        """X.509 parser reports non-matching domain."""
        result = run_ftl("--read-x509-key", "/etc/pihole/test.pem", "pi-hole.net")
        assert result.returncode == 1
        lines = result.stdout.splitlines()
        assert lines[0] == "Reading certificate from /etc/pihole/test.pem ..."
        assert lines[1] == "Certificate does not match domain pi-hole.net"


# ---------- Embedded GZIP compressor ----------

class TestGzip:

    def test_gzip_compress_and_decompress(self):
        """Embedded GZIP compressor round-trips a file correctly."""
        src = "test/pihole-FTL.db.sql"
        gz = src + ".gz"
        out_ftl = src + ".1"
        out_sys = src + ".2"

        try:
            # Compress
            result = run_ftl("gzip", src)
            assert result.returncode == 0, \
                f"Compression failed: {result.stdout} {result.stderr}"
            assert "size reduction" in result.stdout.splitlines()[0]

            # Decompress with FTL
            result = run_ftl("gzip", gz, out_ftl)
            assert result.returncode == 0, \
                f"FTL decompression failed: {result.stdout} {result.stderr}"
            assert "size increase" in result.stdout.splitlines()[0]

            # Decompress with system gzip
            sys_result = run_cmd(f"gzip -dkc {gz} > {out_sys}")
            assert sys_result.returncode == 0, \
                f"System gzip failed: {sys_result.stderr}"

            # Compare original with FTL-decompressed
            cmp1 = run_cmd(f"cmp {src} {out_ftl}")
            assert cmp1.returncode == 0, \
                "FTL-decompressed file differs from original"

            # Compare original with system-decompressed
            cmp2 = run_cmd(f"cmp {src} {out_sys}")
            assert cmp2.returncode == 0, \
                "System-decompressed file differs from original"
        finally:
            # Cleanup generated files
            for f in (gz, out_ftl, out_sys):
                if os.path.exists(f):
                    os.remove(f)


# ---------- SHA256 checksum ----------

class TestSHA256:

    def test_sha256_checksum(self):
        """SHA256 checksum tool returns expected digest for test.pem."""
        result = run_ftl("sha256sum", "test/test.pem")
        assert result.returncode == 0
        lines = result.stdout.splitlines()
        assert lines[0] == "ce4c01340ef46bf3bc26831f7c53763d57c863528826aa795f1da5e16d6e7b2d  test/test.pem"


# ---------- Embedded SQLite3 shell ----------

class TestSQLite3Shell:

    def test_sqlite3_help(self):
        """Embedded SQLite3 shell shows help text."""
        result = run_ftl("sqlite3", "-help")
        # Help output may go to stdout or stderr depending on SQLite version
        output = result.stdout or result.stderr
        lines = output.splitlines()
        assert len(lines) > 0, f"No output from sqlite3 -help (rc={result.returncode})"
        assert lines[0] == "Usage: sqlite3 [OPTIONS] [FILENAME [SQL...]]"

    def test_sqlite3_called_for_db_file(self):
        """SQLite3 shell is invoked when FTL is called with a .db file."""
        result = run_ftl("abc.db", ".version")
        lines = result.stdout.splitlines()
        assert lines[0].startswith("SQLite 3."), \
            f"Expected SQLite 3.x version, got: {lines[0]}"

    def test_sqlite3_interactive_mode_prints_ftl_version(self):
        """SQLite3 shell in interactive mode prints FTL version banner."""
        result = subprocess.run(
            [FTL_BINARY, "sqlite3", "-interactive"],
            input=".quit\n",
            capture_output=True,
            text=True,
            timeout=10,
        )
        lines = result.stdout.splitlines()
        assert lines[0].startswith("Pi-hole FTL"), \
            f"Expected 'Pi-hole FTL...' banner, got: {lines[0]}"

    def test_sqlite3_ignores_sqliterc_with_ni(self):
        """SQLite3 shell with -ni flag ignores .sqliterc."""
        home = os.path.expanduser("~")
        sqliterc_path = os.path.join(home, ".sqliterc")
        sqliterc_src = "test/sqliterc"
        created = False
        try:
            # Install .sqliterc
            if os.path.exists(sqliterc_src):
                import shutil
                shutil.copy(sqliterc_src, sqliterc_path)
                created = True

            # Without -ni: .sqliterc may alter output
            result_with_rc = run_ftl(
                "sqlite3", "/etc/pihole/gravity.db",
                "SELECT value FROM info WHERE property = 'abp_domains';",
            )
            # The sqliterc adds headers/formatting so output differs
            lines_with = result_with_rc.stdout.splitlines()

            # With -ni: .sqliterc is ignored
            result_no_rc = run_ftl(
                "sqlite3", "-ni", "/etc/pihole/gravity.db",
                "SELECT value FROM info WHERE property = 'abp_domains';",
            )
            lines_no = result_no_rc.stdout.splitlines()

            # With -ni the raw value should be returned
            assert lines_no[0] == "1", \
                f"Expected '1' with -ni, got: {lines_no[0]}"

            # Without -ni the output should differ (headers from .sqliterc)
            if created:
                assert lines_with[0] != "1", \
                    "Without -ni the .sqliterc should change output"
        finally:
            if created and os.path.exists(sqliterc_path):
                os.remove(sqliterc_path)


# ---------- LUA engine ----------

class TestLuaEngine:

    def test_lua_returns_ftl_version(self):
        """LUA interpreter returns FTL version string."""
        result = run_ftl("lua", "-e", 'print(pihole.ftl_version())')
        assert result.returncode == 0
        lines = result.stdout.splitlines()
        assert lines[0].startswith("v"), \
            f"Expected version starting with 'v', got: {lines[0]}"

    def test_lua_inspect_library(self):
        """LUA interpreter loads bundled 'inspect' library."""
        result = run_ftl("lua", "-e", "print(inspect(inspect))")
        assert result.returncode == 0
        output = result.stdout
        assert '_DESCRIPTION = "human-readable representations of tables"' in output
        assert '_VERSION = "inspect.lua 3.1.0"' in output

    def test_lua_called_for_lua_file(self):
        """LUA engine is invoked when FTL is called with a .lua file."""
        lua_file = "test_temp_lua_engine.lua"
        try:
            with open(lua_file, "w") as f:
                f.write('print("Hello from LUA")\n')
            result = run_ftl(lua_file)
            assert result.returncode == 0
            lines = result.stdout.splitlines()
            assert lines[0] == "Hello from LUA"
        finally:
            if os.path.exists(lua_file):
                os.remove(lua_file)


# ---------- Internal PTR resolution ----------

class TestPTRResolution:

    def test_ptr_udp_ipv4(self):
        """Internal IP -> name resolution works (UDP IPv4)."""
        result = run_ftl("ptr", "127.0.0.1")
        assert result.returncode == 0
        lines = result.stdout.strip().splitlines()
        # May resolve to "localhost" or "pi.hole" depending on config
        assert lines[-1] in ("localhost", "pi.hole"), \
            f"Expected 'localhost' or 'pi.hole', got: {lines[-1]}"

    def test_ptr_udp_ipv6(self):
        """Internal IP -> name resolution works (UDP IPv6)."""
        result = run_ftl("ptr", "::1")
        assert result.returncode == 0
        lines = result.stdout.strip().splitlines()
        # May resolve to "localhost" or "pi.hole" depending on config
        assert lines[-1] in ("localhost", "pi.hole"), \
            f"Expected 'localhost' or 'pi.hole', got: {lines[-1]}"

    def test_ptr_tcp_ipv4(self):
        """Internal IP -> name resolution works (TCP IPv4)."""
        result = run_ftl("ptr", "127.0.0.1", "tcp")
        assert result.returncode == 0
        lines = result.stdout.strip().splitlines()
        # May resolve to "localhost" or "pi.hole" depending on config
        assert lines[-1] in ("localhost", "pi.hole"), \
            f"Expected 'localhost' or 'pi.hole', got: {lines[-1]}"

    def test_ptr_tcp_ipv6(self):
        """Internal IP -> name resolution works (TCP IPv6)."""
        result = run_ftl("ptr", "::1", "tcp")
        assert result.returncode == 0
        lines = result.stdout.strip().splitlines()
        # May resolve to "localhost" or "pi.hole" depending on config
        assert lines[-1] in ("localhost", "pi.hole"), \
            f"Expected 'localhost' or 'pi.hole', got: {lines[-1]}"
