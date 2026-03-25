"""
FTL termination test — must run LAST because it kills the FTL process.

This file is named test_zz_* to ensure alphabetical ordering places it
after all other test files including test_z_auth.py.
"""

import os
import pytest
import subprocess

FTL_LOG = "/var/log/pihole/FTL.log"
FTL_BIN = "/home/pihole/pihole-FTL"


def run_ftl(*args, timeout=10):
    return subprocess.run(
        [FTL_BIN, *args],
        capture_output=True, text=True, timeout=timeout
    )


class TestQueryExport:

    def test_query_id_zero_in_db(self):
        """Query with ID 0 has been saved to the on-disk database.

        FTL exports queries from the in-memory DB to disk after a
        configurable delay (default 30s). By running in test_zz_*, enough
        time has elapsed for the export to complete. We still poll to be safe.
        """
        import time
        for _ in range(30):
            result = run_ftl(
                "sqlite3", "/etc/pihole/pihole-FTL.db",
                "SELECT COUNT(*) FROM queries WHERE id=0;"
            )
            if result.returncode == 0 and result.stdout.strip() == "1":
                return
            time.sleep(2)
        assert False, "Query with ID 0 was not exported to on-disk DB within 60 seconds"


class TestFTLTermination:

    def test_termination_with_message(self):
        """FTL terminates gracefully with termination message."""
        pid_path = "/run/pihole-FTL.pid"
        if not os.path.exists(pid_path):
            pytest.skip("FTL PID file not found")

        with open(pid_path, "r") as f:
            pid = int(f.read().strip())

        log_size_before = os.path.getsize(FTL_LOG)

        # Send SIGTERM
        result = subprocess.run(["kill", str(pid)], capture_output=True, text=True)
        assert result.returncode == 0

        # Wait for FTL to terminate
        wait_result = run_ftl(
            "wait-for",
            "########## FTL terminated after",
            FTL_LOG,
            "30",
            str(log_size_before),
            timeout=35,
        )
        assert wait_result.returncode == 0, \
            f"FTL did not terminate in time: {wait_result.stdout}"
