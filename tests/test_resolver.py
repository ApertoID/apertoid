"""Tests for the DNS transport layer (Phase 2, Block 1): src/apertoid/resolver.py.

Covers: StaticResolver FOUND/EMPTY/TEMPFAIL outcomes, RFC 1035 3.3.14
character-string concatenation, TxtLookup invariants, and the DnsPythonResolver
exception-to-status mapping. NO live DNS: the dnspython mapping is tested against
directly-constructed exception objects (or a fully mocked resolver), never a real
network query.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from apertoid.resolver import (  # noqa: E402
    DnsPythonResolver,
    LookupStatus,
    Resolver,
    StaticResolver,
    TxtLookup,
    classify_dns_exception,
    join_character_strings,
)


# ---------------------------------------------------------------------------
# TxtLookup invariants
# ---------------------------------------------------------------------------

def test_found_requires_records():
    with pytest.raises(ValueError):
        TxtLookup(LookupStatus.FOUND)


def test_empty_must_not_carry_records():
    with pytest.raises(ValueError):
        TxtLookup(LookupStatus.EMPTY, ("v=APERTOID1",))


def test_tempfail_must_not_carry_records():
    with pytest.raises(ValueError):
        TxtLookup(LookupStatus.TEMPFAIL, ("x",))


def test_empty_and_tempfail_construct_cleanly():
    assert TxtLookup(LookupStatus.EMPTY).records == ()
    assert TxtLookup(LookupStatus.TEMPFAIL).records == ()


# ---------------------------------------------------------------------------
# StaticResolver: FOUND / EMPTY / TEMPFAIL
# ---------------------------------------------------------------------------

def test_static_resolver_is_a_resolver():
    assert isinstance(StaticResolver(), Resolver)


def test_found_single_string_record():
    r = StaticResolver({"_apertoid.example.com": "v=APERTOID1; p=reject"})
    out = r.txt("_apertoid.example.com")
    assert out.status is LookupStatus.FOUND
    assert out.records == ("v=APERTOID1; p=reject",)


def test_absent_name_is_empty_nxdomain():
    r = StaticResolver({"_apertoid.example.com": "v=APERTOID1; p=none"})
    out = r.txt("nope._apertoid.example.com")
    assert out.status is LookupStatus.EMPTY
    assert out.records == ()


def test_explicit_tempfail():
    r = StaticResolver(
        {"_apertoid.example.com": TxtLookup(LookupStatus.TEMPFAIL)}
    )
    assert r.txt("_apertoid.example.com").status is LookupStatus.TEMPFAIL


def test_multiple_logical_records_at_one_name():
    # Section 6.1: several TXT records may exist at a name; the resolver returns
    # them all and selection happens later in verify.py.
    r = StaticResolver(
        {"_apertoid.example.com": ["v=APERTOID1; p=reject", "some other txt"]}
    )
    out = r.txt("_apertoid.example.com")
    assert out.status is LookupStatus.FOUND
    assert out.records == ("v=APERTOID1; p=reject", "some other txt")


def test_name_matching_is_case_insensitive_and_dot_tolerant():
    r = StaticResolver({"_apertoid.Example.COM.": "v=APERTOID1; p=none"})
    assert r.txt("_APERTOID.example.com").status is LookupStatus.FOUND
    assert r.txt("_apertoid.example.com.").status is LookupStatus.FOUND


def test_set_adds_and_replaces():
    r = StaticResolver()
    assert r.txt("_apertoid.example.com").status is LookupStatus.EMPTY
    r.set("_apertoid.example.com", "v=APERTOID1; p=warn")
    assert r.txt("_apertoid.example.com").records == ("v=APERTOID1; p=warn",)
    r.set("_apertoid.example.com", "v=APERTOID1; p=reject")
    assert r.txt("_apertoid.example.com").records == ("v=APERTOID1; p=reject",)


def test_invalid_spec_type_rejected():
    with pytest.raises(TypeError):
        StaticResolver({"x": 123})


# ---------------------------------------------------------------------------
# RFC 1035 3.3.14 character-string concatenation
# ---------------------------------------------------------------------------

def test_join_character_strings_no_separator():
    assert join_character_strings(["v=APERTOID1; ", "p=reject"]) == (
        "v=APERTOID1; p=reject"
    )
    assert join_character_strings([]) == ""


def test_static_resolver_concatenates_split_record():
    # The draft's rotation example: one logical record split mid-Base64 inside
    # the "prev" signature across three character-strings, joined with no
    # separator (see draft Section 10.2 and the conformance harness).
    parts = [
        "v=APERTOID1; url=https://agent.example.com/mcp; ",
        "k=ed25519; pk=QV8LAsXQn7cwPMrfpSs/1CbTXO6uTPdq0y9IOUGpAIQ; ",
        "prev=sig:bxX1qXatIGHLYDyXAZw6T2VIAWGBuwkNxGHyYJO+UPO2uWPI",
        "35gzIdsi9tg1xa6Y0lUW3PDcZJ9b6OYPMjEgDQ; type=ai; exp=1762000000",
    ]
    r = StaticResolver({"leadhunter._apertoid.example.com": [parts]})
    out = r.txt("leadhunter._apertoid.example.com")
    assert out.status is LookupStatus.FOUND
    assert len(out.records) == 1
    joined = out.records[0]
    assert joined == "".join(parts)
    # The mid-Base64 split point vanishes: the signature is contiguous.
    assert "UPO2uWPI35gzIdsi" in joined
    assert "; type=ai; exp=1762000000" in joined


def test_split_record_alongside_a_plain_record():
    r = StaticResolver(
        {"x._apertoid.example.com": [["a", "b", "c"], "single"]}
    )
    out = r.txt("x._apertoid.example.com")
    assert out.records == ("abc", "single")


# ---------------------------------------------------------------------------
# DnsPythonResolver: importable + mapping unit-testable without a network
# ---------------------------------------------------------------------------

def test_dnspython_resolver_class_is_importable():
    # The class must import even when dnspython is absent; only instantiation
    # or use requires the package.
    assert DnsPythonResolver is not None
    assert isinstance(DnsPythonResolver.txt, object)


@pytest.mark.parametrize(
    "exc_name, expected",
    [
        ("NXDOMAIN", LookupStatus.EMPTY),
        ("NoAnswer", LookupStatus.EMPTY),
        ("Timeout", LookupStatus.TEMPFAIL),
        ("LifetimeTimeout", LookupStatus.TEMPFAIL),
        ("NoNameservers", LookupStatus.TEMPFAIL),  # dnspython surfaces SERVFAIL here
        ("SomethingUnexpected", LookupStatus.TEMPFAIL),  # conservative default
    ],
)
def test_classify_dns_exception_mapping(exc_name, expected):
    # Build a throwaway exception type with the given dnspython class name,
    # so the mapping is exercised without importing or hitting dnspython.
    exc_type = type(exc_name, (Exception,), {})
    assert classify_dns_exception(exc_type()) is expected


class _FakeStrings:
    """Minimal stand-in for a dnspython TXT rdata (has a .strings attribute)."""

    def __init__(self, *strings: bytes):
        self.strings = list(strings)


def test_rdata_concatenation_via_helper():
    from apertoid.resolver import _rdata_to_record

    rdata = _FakeStrings(b"v=APERTOID1; ", b"p=reject")
    assert _rdata_to_record(rdata) == "v=APERTOID1; p=reject"


def test_dnspython_resolver_txt_maps_a_mocked_answer(monkeypatch):
    """Drive DnsPythonResolver.txt() end to end against a fully mocked
    dns.resolver, proving FOUND records get concatenated and NXDOMAIN maps to
    EMPTY -- with no real network."""
    import types

    # Build a fake `dns.resolver` module.
    fake_dns_resolver = types.ModuleType("dns.resolver")

    class NXDOMAIN(Exception):
        pass

    class NoAnswer(Exception):
        pass

    class Timeout(Exception):
        pass

    class NoNameservers(Exception):
        pass

    fake_dns_resolver.NXDOMAIN = NXDOMAIN
    fake_dns_resolver.NoAnswer = NoAnswer
    fake_dns_resolver.Timeout = Timeout
    fake_dns_resolver.NoNameservers = NoNameservers

    scripted = {}

    class FakeResolver:
        def resolve(self, name, rdtype, lifetime=None):
            result = scripted[name]
            if isinstance(result, Exception):
                raise result
            return result

    fake_dns_resolver.Resolver = FakeResolver

    fake_dns = types.ModuleType("dns")
    fake_dns.resolver = fake_dns_resolver

    monkeypatch.setitem(sys.modules, "dns", fake_dns)
    monkeypatch.setitem(sys.modules, "dns.resolver", fake_dns_resolver)

    r = DnsPythonResolver()

    scripted["found.example.com"] = [_FakeStrings(b"v=APERTOID1; ", b"p=reject")]
    out = r.txt("found.example.com")
    assert out.status is LookupStatus.FOUND
    assert out.records == ("v=APERTOID1; p=reject",)

    scripted["gone.example.com"] = NXDOMAIN()
    assert r.txt("gone.example.com").status is LookupStatus.EMPTY

    scripted["quiet.example.com"] = NoAnswer()
    assert r.txt("quiet.example.com").status is LookupStatus.EMPTY

    scripted["slow.example.com"] = Timeout()
    assert r.txt("slow.example.com").status is LookupStatus.TEMPFAIL

    scripted["broken.example.com"] = NoNameservers()
    assert r.txt("broken.example.com").status is LookupStatus.TEMPFAIL
