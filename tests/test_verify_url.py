"""Tests for URL matching (Phase 2, Block 4): _url_matches + step 10 in verify.py.

Exercises every rule of Section 11.4 -- both as a unit on _url_matches and
end-to-end through verify_apertoid step 10 (url_mismatch at 11.2#10). Via
StaticResolver, no live DNS.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from apertoid.resolver import StaticResolver  # noqa: E402
from apertoid.verify import Outcome, Policy, _url_matches, verify_apertoid  # noqa: E402

DOMAIN = "example.com"
SELECTOR = "leadhunter"
POLICY_NAME = f"_apertoid.{DOMAIN}"
AGENT_NAME = f"{SELECTOR}._apertoid.{DOMAIN}"
POLICY_REJECT = "v=APERTOID1; p=reject"
FUTURE = 4102444800
NOW = 1700000000


# ---------------------------------------------------------------------------
# _url_matches unit tests -- one per Section 11.4 rule
# ---------------------------------------------------------------------------

def test_exact_match():
    assert _url_matches("https://h.example.com/mcp", "https://h.example.com/mcp")


def test_http_scheme_never_matches_presented():
    # security: an http presented url never matches, even if the rest is equal.
    assert not _url_matches("http://h.example.com/mcp", "https://h.example.com/mcp")


def test_http_scheme_never_matches_declared():
    assert not _url_matches("https://h.example.com/mcp", "http://h.example.com/mcp")


def test_both_http_still_no_match():
    # http MUST NOT be accepted at all, even if both sides are http.
    assert not _url_matches("http://h.example.com/mcp", "http://h.example.com/mcp")


def test_host_case_insensitive():
    assert _url_matches("https://H.Example.COM/mcp", "https://h.example.com/mcp")


def test_path_case_sensitive():
    assert not _url_matches("https://h.example.com/MCP", "https://h.example.com/mcp")


def test_trailing_slash_normalized():
    assert _url_matches("https://h.example.com/mcp", "https://h.example.com/mcp/")
    assert _url_matches("https://h.example.com/mcp/", "https://h.example.com/mcp")


def test_multiple_trailing_slashes_normalized():
    assert _url_matches("https://h.example.com/mcp///", "https://h.example.com/mcp")


def test_root_path_equals_empty_path():
    assert _url_matches("https://h.example.com", "https://h.example.com/")


def test_interior_slashes_not_collapsed():
    # only trailing slashes are normalized; interior ones are significant.
    assert not _url_matches("https://h.example.com/a//b", "https://h.example.com/a/b")


def test_query_string_ignored():
    assert _url_matches(
        "https://h.example.com/mcp?token=abc", "https://h.example.com/mcp"
    )
    assert _url_matches(
        "https://h.example.com/mcp", "https://h.example.com/mcp?x=1"
    )


def test_fragment_ignored():
    assert _url_matches(
        "https://h.example.com/mcp#section", "https://h.example.com/mcp"
    )


def test_explicit_443_equals_absent_port():
    assert _url_matches("https://h.example.com:443/mcp", "https://h.example.com/mcp")
    assert _url_matches("https://h.example.com/mcp", "https://h.example.com:443/mcp")


def test_different_port_no_match():
    assert not _url_matches(
        "https://h.example.com:8443/mcp", "https://h.example.com/mcp"
    )


def test_different_host_no_match():
    assert not _url_matches("https://other.example.com/mcp", "https://h.example.com/mcp")


def test_malformed_port_no_match_not_exception():
    # a bad port must yield no-match, never raise.
    assert not _url_matches("https://h.example.com:notaport/mcp",
                            "https://h.example.com/mcp")


# ---------------------------------------------------------------------------
# End-to-end through verify_apertoid step 10
# ---------------------------------------------------------------------------

DECLARED = "https://agent.example.com/mcp"


def _resolver(url=DECLARED):
    agent = f"v=APERTOID1; url={url}; k=ed25519; pk={'A'*43}; type=ai; exp={FUTURE}"
    return StaticResolver({POLICY_NAME: POLICY_REJECT, AGENT_NAME: agent})


def _verify(agent_url, resolver=None):
    return verify_apertoid(
        DOMAIN, SELECTOR, agent_url, resolver or _resolver(),
        current_time=NOW,
    )


def test_step10_exact_match_passes():
    res = _verify(DECLARED)
    assert res.outcome is Outcome.PASS
    assert res.step == "pass"


def test_step10_host_case_difference_passes():
    res = _verify("https://AGENT.EXAMPLE.COM/mcp")
    assert res.outcome is Outcome.PASS


def test_step10_trailing_slash_passes():
    res = _verify("https://agent.example.com/mcp/")
    assert res.outcome is Outcome.PASS


def test_step10_query_ignored_passes():
    res = _verify("https://agent.example.com/mcp?session=xyz")
    assert res.outcome is Outcome.PASS


def test_step10_fragment_ignored_passes():
    res = _verify("https://agent.example.com/mcp#frag")
    assert res.outcome is Outcome.PASS


def test_step10_explicit_443_passes():
    res = _verify("https://agent.example.com:443/mcp")
    assert res.outcome is Outcome.PASS


def test_step10_wrong_path_is_url_mismatch():
    res = _verify("https://agent.example.com/other")
    assert res.outcome is Outcome.URL_MISMATCH
    assert res.step == "11.2#10"
    assert res.policy is Policy.REJECT


def test_step10_path_case_is_url_mismatch():
    res = _verify("https://agent.example.com/MCP")
    assert res.outcome is Outcome.URL_MISMATCH
    assert res.step == "11.2#10"


def test_step10_http_scheme_is_url_mismatch():
    res = _verify("http://agent.example.com/mcp")
    assert res.outcome is Outcome.URL_MISMATCH
    assert res.step == "11.2#10"


def test_step10_different_port_is_url_mismatch():
    res = _verify("https://agent.example.com:9443/mcp")
    assert res.outcome is Outcome.URL_MISMATCH
    assert res.step == "11.2#10"


def test_step10_url_mismatch_carries_pk():
    # F-4: the resolved pk is exposed even on a step-10 mismatch.
    res = _verify("https://agent.example.com/wrong")
    assert res.outcome is Outcome.URL_MISMATCH
    assert res.pk == "A" * 43
