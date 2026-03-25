"""
Pi-hole FTL regex engine integration tests.

These tests exercise the ``pihole-FTL regex-test`` CLI command, covering:

- Basic pattern matching (anchored, character classes, back-references,
  approximate/fuzzy matching)
- Invalid regex error messages
- Quiet mode (``-q``)
- Regex options (;querytype=, ;reply=, ;invert) reported on the CLI
- DNS-level regex behaviour via ``dig`` (querytype filters, reply overrides)

The original tests lived in test_suite.bats (Regex Test 1-53). This file
ports them to pytest with ``subprocess.run`` calls.

Usage:
    pytest test/api/test_regex.py -v
"""

import subprocess
import pytest

FTL_BIN = "/home/pihole/pihole-FTL"


def run_ftl(*args, **kwargs):
    """Run pihole-FTL with the given arguments and return the CompletedProcess."""
    return subprocess.run(
        [FTL_BIN, *args],
        capture_output=True, text=True, timeout=10, **kwargs,
    )


def run_shell(cmd):
    """Run a shell command and return the CompletedProcess."""
    return subprocess.run(
        cmd, shell=True,
        capture_output=True, text=True, timeout=10,
    )


# ---------------------------------------------------------------------------
# Regex Test 1: database regex match (no explicit pattern argument)
# ---------------------------------------------------------------------------

class TestRegexDatabaseMatch:
    """Regex Test 1: match a domain against the loaded database regexes."""

    def test_database_regex_match(self):
        """regex7.ftl should match against the database regex."""
        result = run_ftl("regex-test", "regex7.ftl")
        assert result.returncode == 0, result.stdout + result.stderr


# ---------------------------------------------------------------------------
# Regex Tests 2-23: pattern matching (parametrized)
# ---------------------------------------------------------------------------

# (domain, regex, expected_returncode)
# returncode 0 = MATCH, 2 = NO MATCH
MATCH_CASES = [
    # Test  2: simple literal
    ("a", "a", 0),
    # Test  3: anchored character class, length 1-3
    ("aa", "^[a-z]{1,3}$", 0),
    # Test  4: anchored character class, too long
    ("aaaa", "^[a-z]{1,3}$", 2),
    # Test  5: comments inside regex
    ("aa", "^a(?#some comment)a$", 0),
    # Test  6: back-reference with dot
    ("abc.abc", r"([a-z]*)\.\1", 0),
    # Test  7: complex character set
    ("__abc#LMN012$x%yz789*", "[[:digit:]a-z#$%]+", 0),
    # Test  8: range expression
    ("!ABC-./XYZ~", "[--Z]+", 0),
    # Test  9: back-reference with repetition
    ("aabc", r"(a)\1{1,2}", 0),
    # Test 10: back-reference at end
    ("foo", r"(.)\1$", 0),
    # Test 11: back-reference at end, no match
    ("foox", r"(.)\1$", 2),
    # Test 12: 5-digit back-reference match
    ("1234512345", r"([0-9]{5})\1", 0),
    # Test 13: 5-digit back-reference, too short
    ("12345", r"([0-9]{5})\1", 2),
    # Test 14: complex multi-group back-reference
    ("cat.foo.dog---cat%dog!foo", r"(cat)\.(foo)\.(dog)---\1%\3!\2", 0),
    # Test 15: approximate matching, 0 errors
    ("foobarzap", "foo(bar){~1}zap", 0),
    # Test 16: approximate matching, 1 error inside tolerant area
    ("foobrzap", "foo(bar){~1}zap", 0),
    # Test 17: approximate matching, 1 error outside tolerant area
    ("foxbrazap", "foo(bar){~1}zap", 2),
    # Test 18: global approximate matching, 0 errors
    ("foobar", "^(foobar){~1}$", 0),
    # Test 19: global approximate matching, 1 error
    ("cfoobar", "^(foobar){~1}$", 0),
    # Test 20: global approximate matching, 2 errors -> no match
    ("ccfoobar", "^(foobar){~1}$", 2),
    # Test 21: insert + substitute approximate matching
    ("oobargoobaploowap", "(foobar){+2#2~2}", 0),
    # Test 22: insert + delete approximate matching
    ("3oifaowefbaoraofuiebofasebfaobfaorfeoaro", "(foobar){+1 -2}", 0),
    # Test 23: insert + delete (insufficient tolerance)
    ("3oifaowefbaoraofuiebofasebfaobfaorfeoaro", "(foobar){+1 -1}", 2),
]


class TestRegexPatternMatching:
    """Regex Tests 2-23: pattern matching via ``pihole-FTL regex-test``."""

    @pytest.mark.parametrize(
        "domain,regex,expected_rc",
        MATCH_CASES,
        ids=[
            "literal_a_match",
            "anchored_class_match",
            "anchored_class_no_match",
            "comment_match",
            "backref_dot_match",
            "complex_charset_match",
            "range_expression_match",
            "backref_repetition_match",
            "backref_end_match",
            "backref_end_no_match",
            "5digit_backref_match",
            "5digit_backref_no_match",
            "complex_multigroup_backref",
            "approx_0_errors_match",
            "approx_1_error_inside_match",
            "approx_1_error_outside_no_match",
            "approx_global_0_errors_match",
            "approx_global_1_error_match",
            "approx_global_2_errors_no_match",
            "approx_insert_sub_match",
            "approx_insert_del_match",
            "approx_insert_del_insufficient",
        ],
    )
    def test_regex_match(self, domain, regex, expected_rc):
        result = run_ftl("regex-test", domain, regex)
        assert result.returncode == expected_rc, (
            f"Expected rc={expected_rc} for '{domain}' vs '{regex}', "
            f"got rc={result.returncode}\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )


# ---------------------------------------------------------------------------
# Regex Tests 24-33: invalid regex error messages
# ---------------------------------------------------------------------------

# (regex, expected_error_fragment)
INVALID_REGEX_CASES = [
    # Test 24
    ("f{x}", 'Invalid regex CLI filter "f{x}": Invalid contents of {}'),
    # Test 25
    ("a**", 'Invalid regex CLI filter "a**": Invalid use of repetition operators'),
    # Test 26
    ("x\\", 'Invalid regex CLI filter "x\\": Trailing backslash'),
    # Test 27
    ("[", "Invalid regex CLI filter \"[\": Missing ']'"),
    # Test 28
    ("(", "Invalid regex CLI filter \"(\": Missing ')'"),
    # Test 29
    ("{1", "Invalid regex CLI filter \"{1\": Missing '}'"),
    # Test 30
    ("[[.foo.]]", 'Invalid regex CLI filter "[[.foo.]]": Unknown collating element'),
    # Test 31
    ("[[:foobar:]]", 'Invalid regex CLI filter "[[:foobar:]]": Unknown character class name'),
    # Test 32
    ("(a)\\2", 'Invalid regex CLI filter "(a)\\2": Invalid back reference'),
    # Test 33
    ("[g-1]", 'Invalid regex CLI filter "[g-1]": Invalid character range'),
]


class TestRegexInvalidPatterns:
    """Regex Tests 24-33: invalid patterns produce useful error messages."""

    @pytest.mark.parametrize(
        "regex,expected_msg",
        INVALID_REGEX_CASES,
        ids=[
            "invalid_contents_of_braces",
            "invalid_repetition",
            "trailing_backslash",
            "missing_bracket",
            "missing_paren",
            "missing_brace",
            "unknown_collating",
            "unknown_char_class",
            "invalid_back_reference",
            "invalid_char_range",
        ],
    )
    def test_invalid_regex_error(self, regex, expected_msg):
        result = run_ftl("regex-test", "fbcdn.net", regex)
        assert result.returncode == 1, (
            f"Expected rc=1 for invalid regex '{regex}', got {result.returncode}"
        )
        lines = result.stdout.splitlines()
        assert len(lines) >= 2, f"Expected at least 2 lines of output, got: {result.stdout}"
        assert lines[1] == expected_msg, (
            f"Expected error: {expected_msg!r}\nGot: {lines[1]!r}"
        )


# ---------------------------------------------------------------------------
# Regex Tests 34-36: quiet mode
# ---------------------------------------------------------------------------

class TestRegexQuietMode:
    """Regex Tests 34-36: quiet mode (``-q``)."""

    def test_quiet_match_returns_0(self):
        """Quiet match returns rc=0 with no output."""
        result = run_ftl("-q", "regex-test", "fbcdn.net", "f")
        assert result.returncode == 0

    def test_quiet_invalid_regex_returns_1_with_message(self):
        """Quiet mode still prints error for invalid regex, rc=1."""
        result = run_ftl("-q", "regex-test", "fbcdn.net", "g{x}")
        assert result.returncode == 1
        lines = result.stdout.splitlines()
        assert lines[0] == 'Invalid regex CLI filter "g{x}": Invalid contents of {}'

    def test_quiet_no_match_returns_2(self):
        """Quiet no-match returns rc=2 with no output."""
        result = run_ftl("-q", "regex-test", "fbcdn.net", "g")
        assert result.returncode == 2


# ---------------------------------------------------------------------------
# Regex Test 39: ;invert option via CLI
# ---------------------------------------------------------------------------

class TestRegexInvertOption:
    """Regex Test 39: ;invert option inverts match logic."""

    def test_invert_non_matching_becomes_match(self):
        """'f' vs 'g;invert' -> MATCH (rc=0) because g does not match f."""
        result = run_ftl("-q", "regex-test", "f", "g;invert")
        assert result.returncode == 0

    def test_invert_matching_becomes_no_match(self):
        """'g' vs 'g;invert' -> NO MATCH (rc=2) because g matches g, inverted."""
        result = run_ftl("-q", "regex-test", "g", "g;invert")
        assert result.returncode == 2


# ---------------------------------------------------------------------------
# Regex Test 40: ;querytype sanity check (overwrite warning)
# ---------------------------------------------------------------------------

class TestRegexQuerytypeSanity:
    """Regex Test 40: multiple querytype options produce a warning."""

    def test_querytype_overwrite_warning(self):
        result = run_ftl("regex-test", "f", "g;querytype=!A;querytype=A")
        output = result.stdout
        assert "Overwriting previous querytype setting" in output


# ---------------------------------------------------------------------------
# Regex Tests 47-51: options reported on CLI
# ---------------------------------------------------------------------------

class TestRegexCLIOptionReporting:
    """Regex Tests 47-51: regex options are reported in verbose CLI output."""

    def test_querytype_A_reported(self):
        """Test 47: ;querytype=A shows '- A' in output."""
        result = run_ftl("regex-test", "f", "f;querytype=A")
        assert result.returncode == 0
        lines = result.stdout.splitlines()
        assert any("- A" in line for line in lines), (
            f"Expected '- A' in output:\n{result.stdout}"
        )

    def test_querytype_not_TXT_excludes_TXT(self):
        """Test 48: ;querytype=!TXT does NOT show '- TXT' in output."""
        result = run_ftl("regex-test", "f", "f;querytype=!TXT")
        assert result.returncode == 0
        assert "- TXT" not in result.stdout

    def test_reply_NXDOMAIN_reported(self):
        """Test 49: ;reply=NXDOMAIN shows hint."""
        result = run_ftl("regex-test", "f", "f;reply=NXDOMAIN")
        assert result.returncode == 0
        lines = result.stdout.splitlines()
        assert any("Hint: This regex forces reply type NXDOMAIN" in l for l in lines), (
            f"Expected NXDOMAIN hint in output:\n{result.stdout}"
        )

    def test_invert_reported(self):
        """Test 50: ;invert shows hint."""
        result = run_ftl("regex-test", "f", "g;invert")
        assert result.returncode == 0
        lines = result.stdout.splitlines()
        assert any("Hint: This regex is inverted" in l for l in lines), (
            f"Expected invert hint in output:\n{result.stdout}"
        )

    def test_querytype_multi_A_HTTPS_reported(self):
        """Test 51: ;querytype=A,HTTPS shows both '- A' and '- HTTPS'."""
        result = run_ftl("regex-test", "f", "f;querytype=A,HTTPS")
        assert result.returncode == 0
        lines = result.stdout.splitlines()
        a_found = any("- A" in l for l in lines)
        https_found = any("- HTTPS" in l for l in lines)
        assert a_found, f"Expected '- A' in output:\n{result.stdout}"
        assert https_found, f"Expected '- HTTPS' in output:\n{result.stdout}"


# ---------------------------------------------------------------------------
# Regex Tests 37-38, 41-46, 52-53: DNS-level regex behaviour via dig
# ---------------------------------------------------------------------------

def dig(qtype, domain, short=False):
    """Run dig and return stdout as a string."""
    cmd = ["dig", qtype, domain, "@127.0.0.1"]
    if short:
        cmd.append("+short")
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    return result.stdout


class TestRegexDNSQuerytype:
    """Regex Tests 37-38: ;querytype= filters via live DNS."""

    def test_querytype_A_blocks_A_only(self):
        """Test 37: regex-A blocked for A but not AAAA."""
        a_short = dig("A", "regex-A", short=True).strip()
        assert a_short == "0.0.0.0"
        aaaa_short = dig("AAAA", "regex-A", short=True).strip()
        assert aaaa_short != "::"

    def test_querytype_not_A_blocks_AAAA_only(self):
        """Test 38: regex-notA not blocked for A, blocked for AAAA."""
        a_short = dig("A", "regex-notA", short=True).strip()
        assert a_short != "0.0.0.0"
        aaaa_short = dig("AAAA", "regex-notA", short=True).strip()
        assert aaaa_short == "::"


class TestRegexDNSReply:
    """Regex Tests 41-46: ;reply= overrides via live DNS."""

    def test_reply_NXDOMAIN(self):
        """Test 41: regex-NXDOMAIN returns NXDOMAIN status."""
        output = dig("A", "regex-NXDOMAIN")
        assert "status: NXDOMAIN" in output

    def test_reply_NODATA(self):
        """Test 42: regex-NODATA returns NOERROR status (with no answer)."""
        output = dig("A", "regex-NODATA")
        assert "status: NOERROR" in output

    def test_reply_REFUSED(self):
        """Test 43: regex-REFUSED returns REFUSED status."""
        output = dig("A", "regex-REFUSED")
        assert "status: REFUSED" in output

    def test_reply_ipv4(self):
        """Test 44: regex-REPLYv4 returns 1.2.3.4 for A, :: for AAAA."""
        a_short = dig("A", "regex-REPLYv4", short=True).strip()
        assert a_short == "1.2.3.4"
        aaaa_short = dig("AAAA", "regex-REPLYv4", short=True).strip()
        assert aaaa_short == "::"

    def test_reply_ipv6(self):
        """Test 45: regex-REPLYv6 returns 0.0.0.0 for A, fe80::1234 for AAAA."""
        a_short = dig("A", "regex-REPLYv6", short=True).strip()
        assert a_short == "0.0.0.0"
        aaaa_short = dig("AAAA", "regex-REPLYv6", short=True).strip()
        assert aaaa_short == "fe80::1234"

    def test_reply_dual_stack(self):
        """Test 46: regex-REPLYv46 returns 1.2.3.4/A and fe80::1234/AAAA."""
        a_short = dig("A", "regex-REPLYv46", short=True).strip()
        assert a_short == "1.2.3.4"
        aaaa_short = dig("AAAA", "regex-REPLYv46", short=True).strip()
        assert aaaa_short == "fe80::1234"


class TestRegexDNSMultipleQuerytypes:
    """Regex Tests 52-53: multi-querytype filters via live DNS."""

    def test_querytype_any_https_svcb_refused(self):
        """Test 52: ;querytype=ANY,HTTPS,SVCB;reply=refused blocks only those types."""
        # A and AAAA should NOT be refused
        a_out = dig("A", "regex-multiple.ftl")
        assert "status: NOERROR" in a_out
        aaaa_out = dig("AAAA", "regex-multiple.ftl")
        assert "status: NOERROR" in aaaa_out
        # SVCB, HTTPS, ANY should be refused
        svcb_out = dig("SVCB", "regex-multiple.ftl")
        assert "status: REFUSED" in svcb_out
        https_out = dig("HTTPS", "regex-multiple.ftl")
        assert "status: REFUSED" in https_out
        any_out = dig("ANY", "regex-multiple.ftl")
        assert "status: REFUSED" in any_out

    def test_querytype_not_any_https_svcb_refused(self):
        """Test 53: ;querytype=!ANY,HTTPS,SVCB;reply=refused blocks everything except those."""
        # A and AAAA should be refused
        a_out = dig("A", "regex-notMultiple.ftl")
        assert "status: REFUSED" in a_out
        aaaa_out = dig("AAAA", "regex-notMultiple.ftl")
        assert "status: REFUSED" in aaaa_out
        # SVCB, HTTPS, ANY should NOT be refused
        svcb_out = dig("SVCB", "regex-notMultiple.ftl")
        assert "status: NOERROR" in svcb_out
        https_out = dig("HTTPS", "regex-notMultiple.ftl")
        assert "status: NOERROR" in https_out
        any_out = dig("ANY", "regex-notMultiple.ftl")
        assert "status: NOERROR" in any_out
