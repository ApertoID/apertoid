"""Tests for verify_apertoid() core flow (Phase 2, Block 2): src/apertoid/verify.py.

One test per Section 11.2 outcome, driven entirely by StaticResolver (no live
DNS). Each test asserts outcome AND step AND policy, per decision F-6. The
ordering test proves revocation is checked before expiry (Section 10.1).

Steps 8 (include) and 10 (url matching) are BLOCK 3 / BLOCK 4 seams and are not
exercised here beyond confirming the include seam surfaces honestly.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from apertoid.resolver import LookupStatus, StaticResolver, TxtLookup  # noqa: E402
from apertoid.verify import (  # noqa: E402
    Outcome,
    Policy,
    VerificationResult,
    _is_expired,
    _select_record,
    verify_apertoid,
)
from apertoid.parser import RecordType, parse_record  # noqa: E402

# --- fixtures ---------------------------------------------------------------

DOMAIN = "example.com"
SELECTOR = "leadhunter"
POLICY_NAME = f"_apertoid.{DOMAIN}"
AGENT_NAME = f"{SELECTOR}._apertoid.{DOMAIN}"
AGENT_URL = "https://agent.example.com/mcp"

# A real 43-char unpadded Ed25519 pk from the draft's Section 7.2 example.
PK = "2TmyMjizLUEeS0F9GJvGedF4syZFYvrWl+oFHv56VSY"

POLICY_REJECT = "v=APERTOID1; p=reject; rua=mailto:apertoid@example.com"
POLICY_WARN = "v=APERTOID1; p=warn"
POLICY_NONE = "v=APERTOID1; p=none"

# Far-future exp so "valid" records never expire during the test run.
FUTURE = 4102444800   # 2100-01-01
PAST = 1000000000     # 2001-09-09
NOW = 1700000000      # 2023-11-14 (between PAST and FUTURE)

AGENT_VALID = (
    f"v=APERTOID1; url={AGENT_URL}; k=ed25519; pk={PK}; type=ai; exp={FUTURE}"
)
AGENT_EXPIRED = (
    f"v=APERTOID1; url={AGENT_URL}; k=ed25519; pk={PK}; type=ai; exp={PAST}"
)
AGENT_REVOKED = "v=APERTOID1; status=revoked"
# Both revoked AND (would-be) expired: proves revocation wins the ordering.
AGENT_REVOKED_AND_EXPIRED = f"v=APERTOID1; status=revoked; exp={PAST}"
AGENT_NO_EXP = f"v=APERTOID1; url={AGENT_URL}"          # url-only, never expires
AGENT_PK_NO_K = f"v=APERTOID1; url={AGENT_URL}; pk={PK}; exp={FUTURE}"  # F10


def _resolver(policy=POLICY_REJECT, agent=AGENT_VALID, **extra):
    mapping = {}
    if policy is not None:
        mapping[POLICY_NAME] = policy
    if agent is not None:
        mapping[AGENT_NAME] = agent
    mapping.update(extra)
    return StaticResolver(mapping)


def _verify(resolver, *, agent_pubkey=None, now=NOW):
    return verify_apertoid(
        DOMAIN, SELECTOR, AGENT_URL, resolver,
        current_time=now, agent_pubkey=agent_pubkey,
    )


# --- Step 1-2: policy lookup ------------------------------------------------

def test_temperror_at_policy_lookup():
    r = StaticResolver({POLICY_NAME: TxtLookup(LookupStatus.TEMPFAIL)})
    res = _verify(r)
    assert res.outcome is Outcome.TEMPERROR
    assert res.step == "11.2#1"
    assert res.policy is Policy.UNSET  # policy not yet known
    assert res.lookups == 1


def test_none_when_domain_publishes_no_policy():
    r = StaticResolver({})  # NXDOMAIN at the policy name
    res = _verify(r)
    assert res.outcome is Outcome.NONE
    assert res.step == "11.2#2"
    assert res.policy is Policy.UNSET


def test_none_when_txt_present_but_no_apertoid_record():
    r = _resolver(policy="v=spf1 include:_spf.example.com ~all")
    res = _verify(r)
    assert res.outcome is Outcome.NONE
    assert res.step == "11.2#2"


# --- Step 3: malformed policy ----------------------------------------------

def test_permerror_on_malformed_policy():
    # duplicate known tag -> parser marks the record invalid (permerror)
    r = _resolver(policy="v=APERTOID1; p=reject; p=warn")
    res = _verify(r)
    assert res.outcome is Outcome.PERMERROR
    assert res.step == "11.2#3"
    assert res.policy is Policy.UNSET  # policy unusable


# --- Step 4-5: agent lookup -------------------------------------------------

def test_temperror_at_agent_lookup():
    r = _resolver(agent=None)
    r.set(AGENT_NAME, TxtLookup(LookupStatus.TEMPFAIL))
    res = _verify(r)
    assert res.outcome is Outcome.TEMPERROR
    assert res.step == "11.2#4"
    assert res.policy is Policy.REJECT  # policy resolved before the agent query
    assert res.lookups == 2


def test_permerror_when_no_agent_record():
    r = _resolver(agent=None)  # policy exists, agent name is NXDOMAIN
    res = _verify(r)
    assert res.outcome is Outcome.PERMERROR
    assert res.step == "11.2#5"
    assert res.policy is Policy.REJECT


# --- Step 6: malformed agent record ----------------------------------------

def test_permerror_on_malformed_agent_record():
    # k= without pk= is a Section 7.3 error -> malformed
    r = _resolver(agent="v=APERTOID1; url=https://a.example.com/x; k=ed25519")
    res = _verify(r)
    assert res.outcome is Outcome.PERMERROR
    assert res.step == "11.2#6"
    assert res.policy is Policy.REJECT


# --- Step 7: revocation, and its mandatory ordering -------------------------

def test_revoked():
    r = _resolver(agent=AGENT_REVOKED)
    res = _verify(r)
    assert res.outcome is Outcome.REVOKED
    assert res.step == "11.2#7"
    assert res.policy is Policy.REJECT


def test_revocation_checked_before_expiry():
    # Record is BOTH revoked AND expired; Section 10.1 requires revocation first.
    r = _resolver(agent=AGENT_REVOKED_AND_EXPIRED)
    res = _verify(r, now=NOW)  # NOW > PAST, so it WOULD be expired
    assert res.outcome is Outcome.REVOKED     # not EXPIRED
    assert res.step == "11.2#7"


# --- Step 9: expiry ---------------------------------------------------------

def test_expired():
    r = _resolver(agent=AGENT_EXPIRED)
    res = _verify(r)
    assert res.outcome is Outcome.EXPIRED
    assert res.step == "11.2#9"
    assert res.policy is Policy.REJECT


def test_no_exp_never_expires():
    # url-only record (no k/pk/exp) is legal (FINDINGS F10) and never expires.
    r = _resolver(agent=AGENT_NO_EXP)
    res = _verify(r)
    assert res.outcome is Outcome.PASS
    assert res.step == "pass"
    assert res.pk is None  # no key published


# --- Step 11: key check + F-4 pk exposure -----------------------------------

def test_key_mismatch():
    wrong = "A" * 43  # 43 chars, not the record's pk
    r = _resolver(agent=AGENT_VALID)
    res = _verify(r, agent_pubkey=wrong)
    assert res.outcome is Outcome.KEY_MISMATCH
    assert res.step == "11.2#11"
    assert res.policy is Policy.REJECT
    assert res.pk == PK  # F-4: resolved pk still exposed on mismatch


def test_pass_with_matching_key_exposes_pk():
    r = _resolver(agent=AGENT_VALID)
    res = _verify(r, agent_pubkey=PK)
    assert res.outcome is Outcome.PASS
    assert res.step == "pass"
    assert res.policy is Policy.REJECT
    assert res.pk == PK


def test_pass_without_agent_pubkey_still_returns_pk():
    # F-4: no presented key -> step-11 match skipped, but pk is still returned.
    r = _resolver(agent=AGENT_VALID)
    res = _verify(r, agent_pubkey=None)
    assert res.outcome is Outcome.PASS
    assert res.pk == PK


def test_pk_without_k_defaults_ed25519_and_passes():
    r = _resolver(agent=AGENT_PK_NO_K)
    res = _verify(r, agent_pubkey=PK)
    assert res.outcome is Outcome.PASS
    assert res.pk == PK


# --- policy propagation across policies -------------------------------------

def test_policy_warn_propagates_on_failure():
    r = _resolver(policy=POLICY_WARN, agent=AGENT_REVOKED)
    res = _verify(r)
    assert res.outcome is Outcome.REVOKED
    assert res.policy is Policy.WARN
    assert res.enforced_reject is False


def test_policy_reject_sets_enforced_reject():
    r = _resolver(policy=POLICY_REJECT, agent=AGENT_REVOKED)
    res = _verify(r)
    assert res.enforced_reject is True


# --- Step 8 include= (delegation detail lives in test_verify_include.py) ----

def test_include_to_missing_target_is_permerror():
    # BLOCK 3 replaced the old not-yet-implemented seam: an include= is now
    # actually followed. With no record at the target, that is a permerror.
    r = _resolver(agent="v=APERTOID1; include=agent1._apertoid.salesforce.com")
    res = _verify(r)
    assert res.outcome is Outcome.PERMERROR
    assert res.step == "11.2#8"
    assert res.policy is Policy.REJECT


# --- helper unit tests ------------------------------------------------------

def test_select_record_picks_apertoid_among_several():
    txt = TxtLookup(
        LookupStatus.FOUND,
        ("v=spf1 ~all", POLICY_NONE, "some other txt"),
    )
    rec = _select_record(txt, RecordType.POLICY)
    assert rec is not None
    assert rec.record_type is RecordType.POLICY  # authoritative from query name
    assert rec.get("p") == "none"


def test_select_record_none_when_no_version_valid():
    txt = TxtLookup(LookupStatus.FOUND, ("v=spf1 ~all", "v=WRONG; p=none"))
    assert _select_record(txt, RecordType.POLICY) is None


def test_select_record_type_from_query_name_not_content():
    # A policy-looking body queried at an AGENT name is typed AGENT (Section 6.1
    # / F6: type from query name, never inferred from tags).
    txt = TxtLookup(LookupStatus.FOUND, (POLICY_NONE,))
    rec = _select_record(txt, RecordType.AGENT)
    assert rec.record_type is RecordType.AGENT


def test_is_expired():
    assert _is_expired(parse_record(AGENT_EXPIRED), NOW) is True
    assert _is_expired(parse_record(AGENT_VALID), NOW) is False
    assert _is_expired(parse_record(AGENT_NO_EXP), NOW) is False  # no exp
