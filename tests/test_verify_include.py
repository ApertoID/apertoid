"""Tests for include= delegation (Phase 2, Block 3): _follow_includes in verify.py.

Covers Section 8 delegation semantics and its mandatory DoS limits (depth,
total lookups, cycle detection), decision F-2 (revocation re-checked on every
resolved target), and the DNS-outcome mapping for include targets (TEMPFAIL ->
temperror, EMPTY -> permerror). Delegation chains are built as static mappings;
no live DNS. Each test asserts outcome + step + policy + lookups.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from apertoid.resolver import LookupStatus, StaticResolver, TxtLookup  # noqa: E402
from apertoid.verify import Outcome, Policy, verify_apertoid  # noqa: E402

# --- fixtures ---------------------------------------------------------------

DOMAIN = "example.com"
SELECTOR = "leadhunter"
POLICY_NAME = f"_apertoid.{DOMAIN}"
AGENT_NAME = f"{SELECTOR}._apertoid.{DOMAIN}"
AGENT_URL = "https://agent.example.com/mcp"
FINAL_URL = "https://agents.salesforce.com/crm"

PK = "Hr4Z0cjlqCxFhRYKi2uEOkznCCXMELANsOif7KRkhJk"  # draft §8 example key
FUTURE = 4102444800
NOW = 1700000000

POLICY_REJECT = "v=APERTOID1; p=reject"

# Delegation-target names.
B_NAME = "agent1._apertoid.salesforce.com"
C_NAME = "agent2._apertoid.partner.com"
D_NAME = "agent3._apertoid.deep.com"

FINAL_AGENT = (
    f"v=APERTOID1; url={FINAL_URL}; k=ed25519; pk={PK}; type=ai; exp={FUTURE}"
)


def _include(target):
    return f"v=APERTOID1; include={target}"


def _verify(resolver, *, agent_pubkey=None, agent_url=AGENT_URL, **kw):
    # After BLOCK 4, step 10 matches agent_url against the RESOLVED record's
    # url=. For a delegation, that is the final target's url (FINAL_URL), so the
    # PASS cases pass agent_url=FINAL_URL; error cases fail before step 10 and
    # the default AGENT_URL is irrelevant.
    return verify_apertoid(
        DOMAIN, SELECTOR, agent_url, resolver,
        current_time=NOW, agent_pubkey=agent_pubkey, **kw,
    )


def _base(agent):
    return {POLICY_NAME: POLICY_REJECT, AGENT_NAME: agent}


# --- valid delegation -------------------------------------------------------

def test_single_include_passes_with_target_pk_and_url():
    # A (include) -> B (url + pk). Result carries B's pk.
    r = StaticResolver({
        **_base(_include(B_NAME)),
        B_NAME: FINAL_AGENT,
    })
    res = _verify(r, agent_pubkey=PK, agent_url=FINAL_URL)
    assert res.outcome is Outcome.PASS
    assert res.step == "pass"
    assert res.policy is Policy.REJECT
    assert res.pk == PK
    # policy + agent + one include = 3 DNS queries
    assert res.lookups == 3


# --- security limits --------------------------------------------------------

def test_two_level_include_exceeds_depth():
    # A -> B -> C : a SECOND include hop. Per §8's "(original + one include)"
    # only ONE include hop is allowed (FINDINGS P2), so this now FAILS.
    r = StaticResolver({
        **_base(_include(B_NAME)),
        B_NAME: _include(C_NAME),
        C_NAME: FINAL_AGENT,
    })
    res = _verify(r)
    assert res.outcome is Outcome.TEMPERROR
    assert res.step == "11.2#8"
    assert res.policy is Policy.REJECT
    assert "depth exceeded" in res.detail
    # policy + agent + B (the hop to C is refused before any DNS query for C)
    assert res.lookups == 3


def test_depth_exceeded_is_temperror():
    # A -> B -> C -> D : still fails; depth is checked at the second hop.
    r = StaticResolver({
        **_base(_include(B_NAME)),
        B_NAME: _include(C_NAME),
        C_NAME: _include(D_NAME),
        D_NAME: FINAL_AGENT,
    })
    res = _verify(r)
    assert res.outcome is Outcome.TEMPERROR
    assert res.step == "11.2#8"
    assert res.policy is Policy.REJECT
    assert "depth exceeded" in res.detail


def test_cycle_is_temperror():
    # A -> B -> A : circular reference. Depth raised to 2 so the second hop is
    # attempted and the CYCLE check (not the depth limit) is what rejects it --
    # isolating cycle detection from the one-hop depth default.
    r = StaticResolver({
        **_base(_include(B_NAME)),
        B_NAME: _include(AGENT_NAME),
    })
    res = _verify(r, max_include_depth=2)
    assert res.outcome is Outcome.TEMPERROR
    assert res.step == "11.2#8"
    assert "circular" in res.detail
    assert AGENT_NAME in res.detail


def test_self_include_cycle():
    # A -> A directly.
    r = StaticResolver({**_base(_include(AGENT_NAME))})
    res = _verify(r)
    assert res.outcome is Outcome.TEMPERROR
    assert "circular" in res.detail


def test_lookup_budget_exceeded_is_temperror():
    # Force the total-lookup cap low so the chain runs out of DNS budget before
    # depth. max_include_lookups=2 means policy+agent already spent it.
    r = StaticResolver({
        **_base(_include(B_NAME)),
        B_NAME: FINAL_AGENT,
    })
    res = _verify(r, max_include_lookups=2)
    assert res.outcome is Outcome.TEMPERROR
    assert res.step == "11.2#8"
    assert "lookup budget exceeded" in res.detail


def test_higher_depth_allowed_when_limit_raised():
    # Raising the depth limit to 2 lets the two-hop chain A -> B -> C resolve;
    # the limit is the only thing stopping it (the mechanics are otherwise
    # sound). Confirms the depth knob is what enforces the conservative default.
    r = StaticResolver({
        **_base(_include(B_NAME)),
        B_NAME: _include(C_NAME),
        C_NAME: FINAL_AGENT,
    })
    res = _verify(r, max_include_depth=2, agent_url=FINAL_URL)
    assert res.outcome is Outcome.PASS
    assert res.lookups == 4  # policy + agent + B + C


# --- F-2: revocation of a delegation target ---------------------------------

def test_include_target_revoked_stops_chain():
    # A (include) -> B (revoked). F-2: must return revoked, NOT follow to a url.
    r = StaticResolver({
        **_base(_include(B_NAME)),
        B_NAME: "v=APERTOID1; status=revoked",
    })
    res = _verify(r)
    assert res.outcome is Outcome.REVOKED
    assert res.step == "11.2#7-via-include"
    assert res.policy is Policy.REJECT
    assert B_NAME in res.detail


def test_deep_include_target_revoked_stops_chain():
    # A -> B -> C(revoked): with the depth limit raised to 2 so the second hop
    # is actually followed, F-2's per-hop revocation check (not the depth limit)
    # is what fires. Proves revocation is re-checked at every resolved target.
    r = StaticResolver({
        **_base(_include(B_NAME)),
        B_NAME: _include(C_NAME),
        C_NAME: "v=APERTOID1; status=revoked",
    })
    res = _verify(r, max_include_depth=2)
    assert res.outcome is Outcome.REVOKED
    assert res.step == "11.2#7-via-include"


# --- DNS outcomes at an include target --------------------------------------

def test_include_target_tempfail_is_temperror():
    r = StaticResolver({
        **_base(_include(B_NAME)),
        B_NAME: TxtLookup(LookupStatus.TEMPFAIL),
    })
    res = _verify(r)
    assert res.outcome is Outcome.TEMPERROR
    assert res.step == "11.2#8"
    assert "temporary failure" in res.detail


def test_include_target_empty_is_permerror():
    # B_NAME absent from the mapping -> NXDOMAIN/EMPTY at the include target.
    r = StaticResolver({**_base(_include(B_NAME))})
    res = _verify(r)
    assert res.outcome is Outcome.PERMERROR
    assert res.step == "11.2#8"
    assert "no record at include target" in res.detail


def test_include_target_malformed_is_permerror():
    r = StaticResolver({
        **_base(_include(B_NAME)),
        B_NAME: "v=APERTOID1; url=https://x.example.com/y; k=ed25519",  # k w/o pk
    })
    res = _verify(r)
    assert res.outcome is Outcome.PERMERROR
    assert res.step == "11.2#8"
    assert "malformed record at include target" in res.detail


def test_include_target_not_apertoid_is_permerror():
    r = StaticResolver({
        **_base(_include(B_NAME)),
        B_NAME: "v=spf1 ~all",
    })
    res = _verify(r)
    assert res.outcome is Outcome.PERMERROR
    assert res.step == "11.2#8"
    assert "no ApertoID record at include target" in res.detail


# --- dead-end delegation ----------------------------------------------------

def test_resolved_record_with_neither_url_nor_include_is_permerror():
    # A version-only degenerate record reached via include: not revoked, no url,
    # no include -> dead end. The parser types it UNKNOWN (only v=), so the
    # backstop in _follow_includes catches it as permerror.
    r = StaticResolver({
        **_base(_include(B_NAME)),
        B_NAME: "v=APERTOID1",
    })
    res = _verify(r)
    assert res.outcome is Outcome.PERMERROR
    assert res.step == "11.2#8"
    assert "neither url nor include" in res.detail
