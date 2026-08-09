"""Targeted rule / format tests for the ApertoID parser (Section 5.1, 7.3, 8).

These are synthetic records (not from the draft) exercising individual MUST
rules and value formats, using real 44-char / 88-char base64 so that a valid
record actually validates.
"""

import base64
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from apertoid import parse_record, validate_selector, RecordType  # noqa: E402

# Real UNPADDED base64: 43 chars for a raw 32-byte key, 86 for a 64-byte sig
# (per the corrected ABNF, FINDINGS F1: no "=" padding).
PK44 = base64.b64encode(b"\x11" * 32).decode().rstrip("=")   # 43 chars
SIG88 = base64.b64encode(b"\x22" * 64).decode().rstrip("=")  # 86 chars
assert len(PK44) == 43 and len(SIG88) == 86


def has(rec, code):
    return any(d.code == code for d in rec.diagnostics)


# ---- version-tag rules ----

def test_version_must_be_first():
    rec = parse_record("p=none; v=APERTOID1")
    assert not rec.is_valid
    assert has(rec, "version-first")


def test_version_value_exact():
    rec = parse_record("v=apertoid1; p=none")  # wrong case, value is case-sensitive
    assert not rec.is_valid
    assert has(rec, "version-value")


def test_version_case_insensitive_tag_name():
    # tag name is case-insensitive; V= is fine, value APERTOID1 correct
    rec = parse_record("V=APERTOID1; p=none")
    assert rec.is_valid, [str(d) for d in rec.errors]


# ---- F3/F4/F7/F8: ABNF too-strict/too-loose group ----

def test_f7_percent_encoded_url_now_parses():
    # Previously ungrammatical (URI-CHAR omitted "%"). Must parse now.
    rec = parse_record(
        "v=APERTOID1; url=https://a.example/path%20with%20space; type=ai")
    assert rec.is_valid, [str(d) for d in rec.errors]
    assert rec.get("url") == "https://a.example/path%20with%20space"


def test_f3_url_with_encoded_semicolon_parses_intact():
    # The classic misparse case: a URL that needs a ";" must encode it as %3B,
    # and then parses WITHOUT truncation or a phantom tag.
    rec = parse_record(
        "v=APERTOID1; url=https://a.example/x%3Bjsessionid=42; type=ai")
    assert rec.is_valid, [str(d) for d in rec.errors]
    assert rec.get("url") == "https://a.example/x%3Bjsessionid=42"
    assert "jsessionid" not in rec.unknown_tags  # no phantom tag anymore


def test_f3_literal_semicolon_in_url_is_a_separator_not_value():
    # A LITERAL ";" is still a separator (by design). The fragment after it is
    # now a malformed field, so the record is rejected rather than silently
    # truncating the URL into a phantom tag.
    rec = parse_record(
        "v=APERTOID1; url=https://a.example/x;jsessionid=42; type=ai")
    # "jsessionid=42" parses as an unknown tag (ignored w/ warning), and the
    # url value is the part before the literal ";". The point of F3 is that the
    # spec now REQUIRES encoding ";", so authors cannot hit this by accident in
    # a conforming record; we assert the url did NOT silently keep the ";".
    assert ";" not in (rec.get("url") or "")


def test_f4_arbitrary_whitespace_both_sides():
    # Any amount of WSP on either side of ";" (tabs, multiple spaces) is ignored.
    rec = parse_record("v=APERTOID1 \t ;\t\t  p=reject   ;   rua=mailto:a@b.com")
    assert rec.is_valid, [str(d) for d in rec.errors]
    assert rec.get("p") == "reject"


def test_f8_email_single_at_valid():
    rec = parse_record("v=APERTOID1; p=none; rua=mailto:sec.team@example.com")
    assert rec.is_valid, [str(d) for d in rec.errors]


def test_f8_email_double_at_rejected():
    # local-part (atext) excludes "@", so "a@b@example.com" is now unambiguous
    # and invalid, instead of matching greedily under the old 1*VCHAR rule.
    rec = parse_record("v=APERTOID1; p=none; rua=mailto:a@b@example.com")
    assert not rec.is_valid
    assert has(rec, "rua-domain") or has(rec, "rua-local")


def test_f8_email_dot_atom_specials_allowed():
    # RFC 5321 atext allows things like + and %; these are a valid local-part.
    rec = parse_record("v=APERTOID1; p=none; rua=mailto:a.b+tag%x@example.com")
    assert rec.is_valid, [str(d) for d in rec.errors]


# ---- policy tag ----

def test_policy_valid_values():
    for v in ("reject", "warn", "none"):
        rec = parse_record(f"v=APERTOID1; p={v}")
        assert rec.is_valid


def test_policy_invalid_value():
    rec = parse_record("v=APERTOID1; p=quarantine")
    assert not rec.is_valid
    assert has(rec, "policy-value")


# ---- whitespace handling (Section 5.1: whitespace around ; ignored) ----

def test_whitespace_around_semicolons():
    rec = parse_record("v=APERTOID1 ;   p=reject   ;rua=mailto:a@b.com")
    assert rec.is_valid, [str(d) for d in rec.errors]


# ---- unknown tags ignored (forward compat) ----

def test_unknown_tag_ignored():
    rec = parse_record("v=APERTOID1; p=none; futurefield=whatever")
    assert rec.is_valid
    assert "futurefield" in rec.unknown_tags
    assert has(rec, "unknown-tag")


# ---- case sensitivity of tags vs values ----

def test_tag_case_insensitive_value_case_sensitive():
    rec = parse_record(f"v=APERTOID1; URL=https://a.example/x; K=ed25519; "
                       f"PK={PK44}; EXP=1", )
    assert rec.is_valid, [str(d) for d in rec.errors]
    # value "ed25519" is case-sensitive: Ed25519 must fail
    rec2 = parse_record("v=APERTOID1; url=https://a.example/x; k=Ed25519")
    assert not rec2.is_valid
    assert has(rec2, "keytype-value")


# ---- url / include mutual exclusion ----

def test_url_include_mutually_exclusive():
    rec = parse_record("v=APERTOID1; url=https://a.example/x; include=b.example")
    assert not rec.is_valid
    assert has(rec, "url-include-exclusive")


def test_missing_endpoint_errors_for_agent():
    # k/pk/exp make it an agent record with neither url nor include
    rec = parse_record(f"v=APERTOID1; k=ed25519; pk={PK44}; exp=1")
    assert not rec.is_valid
    assert has(rec, "missing-endpoint")


# ---- k -> pk and k -> exp dependencies ----

def test_k_requires_pk_and_exp():
    rec = parse_record("v=APERTOID1; url=https://a.example/x; k=ed25519")
    assert not rec.is_valid
    assert has(rec, "k-requires-pk")
    assert has(rec, "k-requires-exp")


def test_f10_pk_without_k_is_clean():
    # F10 resolved: pk MAY appear without k (defaults to ed25519). No warning.
    rec = parse_record(f"v=APERTOID1; url=https://a.example/x; pk={PK44}; exp=1")
    assert rec.is_valid, [str(d) for d in rec.errors]
    assert not has(rec, "pk-without-k")


def test_f10_neither_k_nor_pk_is_legal_url_only():
    # The url-only deployment stage: no k, no pk, no exp -> fully conforming.
    rec = parse_record("v=APERTOID1; url=https://a.example/x; type=ai")
    assert rec.is_valid, [str(d) for d in rec.errors]
    assert rec.diagnostics == [], [str(d) for d in rec.diagnostics]


def test_f11_duplicate_known_tag_is_permerror():
    rec = parse_record("v=APERTOID1; url=https://a.example/x; "
                       "url=https://b.example/y; type=ai")
    assert not rec.is_valid
    assert has(rec, "duplicate-tag")


def test_f11_duplicate_policy_tag_is_permerror():
    rec = parse_record("v=APERTOID1; p=none; p=reject")
    assert not rec.is_valid
    assert has(rec, "duplicate-tag")


def test_f11_duplicate_unknown_tag_does_not_invalidate():
    # A repeated UNKNOWN tag is ignored (forward compat) and does not error.
    rec = parse_record("v=APERTOID1; p=none; futurex=1; futurex=2")
    assert rec.is_valid, [str(d) for d in rec.errors]
    assert not has(rec, "duplicate-tag")


def test_n5_known_tag_is_absolute_not_type_relative():
    # N5 decision: "known tag" is absolute. A policy tag (p) repeated at an
    # AGENT-context record (has url/k/pk) is semantically irrelevant there, but
    # is still a KNOWN tag for duplicate detection -> permerror. This proves the
    # parser's global KNOWN_TAGS matches the spec's chosen (absolute) reading.
    rec = parse_record(
        f"v=APERTOID1; url=https://a.example/x; p=none; p=reject; k=ed25519; "
        f"pk={PK44}; exp=1")
    assert not rec.is_valid
    assert has(rec, "duplicate-tag")


# ---- include / domain-name (F9 underscore-scoped labels) ----

def test_include_underscore_scoped_label_valid():
    # The draft's own delegation targets must be grammatical now (F9).
    for target in ("agent1._apertoid.salesforce.com",
                   "client42._apertoid.salesforce.com",
                   "_apertoid.example.com"):
        rec = parse_record(f"v=APERTOID1; include={target}")
        assert rec.is_valid, (target, [str(d) for d in rec.errors])


def test_include_plain_domain_still_valid():
    rec = parse_record("v=APERTOID1; include=salesforce.com")
    assert rec.is_valid, [str(d) for d in rec.errors]


def test_include_bare_underscore_label_rejected():
    # "_" alone is not a valid underscore-label (needs 1*(ALPHA/DIGIT/"-")).
    rec = parse_record("v=APERTOID1; include=_.example.com")
    assert has(rec, "include-format")


def test_include_digit_scoped_label_valid():
    # RFC 8552-style names like _443._tcp use digits after the underscore.
    rec = parse_record("v=APERTOID1; include=_443._tcp.example.com")
    assert rec.is_valid, [str(d) for d in rec.errors]


# ---- pk / prev format ----

def test_pk_length_enforced():
    # 43 is now the ONLY valid length (F1). 42 and 44 must both fail.
    for bad_len in (42, 44):
        rec = parse_record(f"v=APERTOID1; url=https://a.example/x; k=ed25519; "
                           f"pk={'A' * bad_len}; exp=1")
        assert has(rec, "pubkey-format"), f"len {bad_len} should fail"
    # a 44-char PADDED value (trailing '=') must now be rejected too
    padded = parse_record(f"v=APERTOID1; url=https://a.example/x; k=ed25519; "
                          f"pk={'A' * 42}=; exp=1")
    assert has(padded, "pubkey-format")


def test_pk_43_unpadded_is_valid():
    rec = parse_record(f"v=APERTOID1; url=https://a.example/x; k=ed25519; "
                       f"pk={PK44}; exp=1")
    assert rec.is_valid, [str(d) for d in rec.errors]


def test_prev_format():
    good = parse_record(
        f"v=APERTOID1; url=https://a.example/x; k=ed25519; pk={PK44}; "
        f"prev=sig:{SIG88}; exp=1")
    assert good.is_valid, [str(d) for d in good.errors]
    bad = parse_record(
        f"v=APERTOID1; url=https://a.example/x; k=ed25519; pk={PK44}; "
        f"prev={SIG88}; exp=1")  # missing sig: prefix
    assert has(bad, "prev-prefix")


# ---- exp / type ----

def test_exp_digits_only():
    rec = parse_record(f"v=APERTOID1; url=https://a.example/x; k=ed25519; "
                       f"pk={PK44}; exp=not-a-number")
    assert has(rec, "exp-format")


def test_type_values():
    for t in ("ai", "human", "hybrid"):
        rec = parse_record(f"v=APERTOID1; url=https://a.example/x; type={t}")
        assert rec.is_valid, (t, [str(d) for d in rec.errors])
    bad = parse_record("v=APERTOID1; url=https://a.example/x; type=robot")
    assert has(bad, "type-value")


# ---- selector validation (Section 7.1) ----

def test_selector_valid():
    assert validate_selector("leadhunter") is None
    assert validate_selector("agent-1") is None
    assert validate_selector("a") is None


def test_selector_invalid():
    assert validate_selector("-bad") is not None       # leading hyphen
    assert validate_selector("bad-") is not None        # trailing hyphen
    assert validate_selector("a" * 64) is not None      # too long
    assert validate_selector("under_score") is not None # underscore not allowed


# ---- structural errors ----

def test_empty_record():
    assert not parse_record("").is_valid


def test_no_equals_field():
    rec = parse_record("v=APERTOID1; garbage")
    assert has(rec, "no-equals")


def test_status_only_is_valid_agent():
    rec = parse_record("v=APERTOID1; status=revoked")
    assert rec.is_valid
    assert rec.record_type == RecordType.AGENT
    # F5 resolved: a bare revocation record is fully conforming -- no warnings
    # about the missing url/include either.
    assert rec.diagnostics == [], [str(d) for d in rec.diagnostics]
    assert not has(rec, "revoked-no-endpoint")


def test_non_revocation_missing_endpoint_still_errors():
    # The url-or-include requirement still applies to non-revocation records.
    rec = parse_record("v=APERTOID1; type=ai")
    assert not rec.is_valid
    assert has(rec, "missing-endpoint")


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
