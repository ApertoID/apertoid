"""End-to-end ApertoID verification (Phase 2).

This module ties the DNS transport (resolver.py), the record parser (parser.py),
and the HTTP signature layer (sig.py) into the verification procedure of
draft-ferro-dnsop-apertoid-01 Section 11.2 and the sig<->DNS bridge of
draft-ferro-httpbis-apertoid-sig-01 Section 4.

SCOPE so far: verify_apertoid() core flow (Section 11.2 steps 1-7, 9, 11, 12),
Section 6.1 multi-record selection, and (BLOCK 3) Section 8 include= delegation
via _follow_includes(). One step remains an explicit seam:

  * Step 10 (url matching)         -> BLOCK 4: _url_matches()

The seam is marked with a TODO so the later block slots in without reshaping the
surrounding flow. verify_request() (the sig bridge, F-5) is BLOCK 5 and is not
built here.

RESULT TYPE (decision F-6): every outcome carries the failing step id and the
domain's resolved policy p=, so a caller learns both "unauthorized" and "the
domain says reject/warn/none". Every "apply policy p=" branch in Section 11.2
therefore returns a VerificationResult whose .policy is already populated.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional

from .parser import VERSION, ParsedRecord, RecordType, parse_record
from .resolver import LookupStatus, Resolver, TxtLookup

# Section 8 delegation limits. DEFAULT_MAX_INCLUDE_DEPTH is the number of
# include= hops a verifier may follow. Per the §8 parenthetical "(the original
# record plus one level of include)" this is ONE hop: origin -> one target with
# a url (FINDINGS P2, conservative reading). DEFAULT_MAX_INCLUDE_LOOKUPS is the
# §8 hard cap of 10 total DNS queries for the whole attempt.
DEFAULT_MAX_INCLUDE_DEPTH = 1
DEFAULT_MAX_INCLUDE_LOOKUPS = 10


class Outcome(str, Enum):
    """Unified verification outcome (Section 11.3 + Section 4.1).

    The DNS-layer values come from [APERTOID-DNS] Section 11.3; the four
    sig-layer values (MALFORMED..SIG_INVALID) come from [APERTOID-SIG]
    Section 4.1 and are produced only by verify_request() (BLOCK 5).
    """

    # DNS layer (Section 11.3)
    PASS = "pass"
    NONE = "none"
    REVOKED = "revoked"
    EXPIRED = "expired"
    URL_MISMATCH = "url_mismatch"
    KEY_MISMATCH = "key_mismatch"
    PERMERROR = "permerror"
    TEMPERROR = "temperror"
    # sig layer (Section 4.1) -- produced by verify_request(), BLOCK 5
    MALFORMED = "malformed"
    TIMESTAMP_INVALID = "timestamp_invalid"
    NONCE_REUSED = "nonce_reused"
    SIG_INVALID = "sig_invalid"


class Policy(str, Enum):
    """The domain's enforcement policy p= (Section 6.3)."""

    REJECT = "reject"
    WARN = "warn"
    NONE = "none"
    UNSET = "unset"  # no policy resolved yet (before step 3, or none/temperror)


# p= value -> Policy. p is REQUIRED and constrained to these three by the parser.
_POLICY_FROM_TAG = {
    "reject": Policy.REJECT,
    "warn": Policy.WARN,
    "none": Policy.NONE,
}


@dataclass
class VerificationResult:
    """The result of a verification attempt (decision F-6).

    outcome  the unified Outcome (Section 11.3 / 4.1).
    step     the algorithm step that produced this result, e.g. "11.2#7",
             "pass", or (BLOCK 5) "sig#3". Lets a caller/log pinpoint the branch.
    policy   the domain's resolved p= (F-6c). UNSET before the policy record is
             read (outcomes none/temperror at steps 1-2) and set from step 3 on.
    pk       the resolved agent public key (unpadded Base64, 43 chars) when one
             was published (F-4). Populated on pass and on step-11 key_mismatch,
             and available to the sig bridge regardless of agent_pubkey.
    detail   human-readable context (mismatch values, cycle path, TODO markers).
    lookups  number of DNS TXT queries consumed (feeds the Section 8 <=10 budget
             once BLOCK 3 lands; also handy for tests).
    """

    outcome: Outcome
    step: str
    policy: Policy = Policy.UNSET
    pk: Optional[str] = None
    detail: str = ""
    lookups: int = 0

    @property
    def ok(self) -> bool:
        return self.outcome is Outcome.PASS

    @property
    def enforced_reject(self) -> bool:
        """True if verification failed AND the domain's policy is reject."""
        return not self.ok and self.policy is Policy.REJECT


# ---------------------------------------------------------------------------
# Section 6.1 multi-record selection
# ---------------------------------------------------------------------------

def _select_record(
    txt: TxtLookup, expected_type: RecordType
) -> Optional[ParsedRecord]:
    """Select the ApertoID record among the TXT records at a name (Section 6.1).

    A name may carry several TXT records (e.g. an SPF record alongside an
    ApertoID record). Per Section 6.1 the verifier selects the record whose
    FIRST tag is a valid version tag with value "APERTOID1" -- i.e. the record
    parses with v=APERTOID1 as its first tag -- and discards the others. This
    selection is on the PARSED version tag, NOT a literal byte-prefix: leading
    whitespace or an uppercase "V=" is still valid (the parser normalises both).

    Returns the parsed record (whose record_type is set authoritatively from the
    query name per Section 6.1 / FINDINGS F6, NOT inferred from content), or
    None if no version-valid ApertoID record is present. Note: a selected
    record may still be malformed elsewhere (e.g. a duplicate tag); that is a
    separate concern the caller reports as permerror. Selection only decides
    "which of these is the ApertoID record".
    """
    candidates: list[ParsedRecord] = []
    for raw in txt.records:
        rec = parse_record(raw)
        # Version-valid: first tag present and equal to v=APERTOID1. The parser
        # lowercases the tag name and appends the version tag as ordered[0].
        if rec.ordered and rec.ordered[0] == ("v", VERSION):
            candidates.append(rec)

    if not candidates:
        return None

    # Section 6.1: a domain MUST NOT publish more than one; if it does, pick
    # deterministically (first) so the result is stable.
    selected = candidates[0]
    # The record type is authoritative from the query name (Section 6.1 / F6),
    # overriding whatever the parser guessed from content.
    selected.record_type = expected_type
    return selected


# ---------------------------------------------------------------------------
# Section 7.3 / Section 9 expiry
# ---------------------------------------------------------------------------

def _is_expired(rec: ParsedRecord, now: int) -> bool:
    """True iff the record carries exp= and it has passed (Section 7.3, 9).

    A record with no exp= does NOT expire at the DNS layer (FINDINGS F10:
    url-only records, and pk-without-k records that omit exp, are legal). exp=
    is validated as 1*DIGIT by the parser, so int() is safe here.
    """
    exp = rec.get("exp")
    if exp is None:
        return False
    return now > int(exp)


# ---------------------------------------------------------------------------
# Section 8 include= delegation
# ---------------------------------------------------------------------------

def _follow_includes(
    record: ParsedRecord,
    resolver: Resolver,
    policy: Policy,
    budget: dict,
) -> tuple[Optional[ParsedRecord], Optional[VerificationResult]]:
    """Follow the include= chain from `record` to the final resolved record (§8).

    `record` is the agent record that carries an include= tag; its OWN
    revocation was already checked by verify_apertoid step 7 before this is
    called. `budget` is a mutable dict threaded through the whole chain:

        lookups      running count of DNS TXT queries for the WHOLE attempt
                     (policy + agent + every include target); Section 8 caps it
        seen         set of DNS names already resolved (incl. the original agent
                     name), for circular-reference detection
        max_lookups  total DNS query cap (Section 8: MUST NOT exceed 10)
        max_depth    maximum include hops that may be followed (Section 8)
        chain        ordered list of names resolved so far, for error detail

    Returns (resolved_record, None) on success, or (None, failure_result) with a
    VerificationResult to propagate: temperror (depth/lookup/cycle/DNS-timeout),
    permerror (empty target, malformed target, dead-end with no url/include), or
    revoked.

    SECURITY LIMITS (Section 8, DoS prevention): delegation depth <= max_depth,
    total DNS queries <= max_lookups, circular references detected and rejected.

    DECISION F-2: status=revoked is re-checked on EVERY resolved target, not
    just the original record (the numbered algorithm of Section 11.2 does not
    specify this; see FINDINGS.md). A revoked delegation target stops the chain.
    """
    depth = 0
    current = record

    while current.get("include") is not None:
        target = current.get("include")
        chain_str = " -> ".join(budget["chain"] + [target])

        # Section 8: maximum delegation depth (counted as include hops).
        depth += 1
        if depth > budget["max_depth"]:
            return None, VerificationResult(
                Outcome.TEMPERROR, "11.2#8", policy,
                detail=f"include delegation depth exceeded "
                       f"(max {budget['max_depth']} include "
                       f"hop{'' if budget['max_depth'] == 1 else 's'}); "
                       f"chain: {chain_str}",
                lookups=budget["lookups"],
            )

        # Section 8: circular reference detection.
        if target in budget["seen"]:
            return None, VerificationResult(
                Outcome.TEMPERROR, "11.2#8", policy,
                detail=f"circular include reference: {target} already visited; "
                       f"chain: {chain_str}",
                lookups=budget["lookups"],
            )

        # Section 8: total lookup budget (count every DNS query in the attempt).
        if budget["lookups"] >= budget["max_lookups"]:
            return None, VerificationResult(
                Outcome.TEMPERROR, "11.2#8", policy,
                detail=f"include lookup budget exceeded "
                       f"(max {budget['max_lookups']} DNS queries); "
                       f"chain: {chain_str}",
                lookups=budget["lookups"],
            )

        # Resolve the delegated name.
        txt = resolver.txt(target)
        budget["lookups"] += 1
        budget["seen"].add(target)
        budget["chain"].append(target)

        if txt.status is LookupStatus.TEMPFAIL:
            return None, VerificationResult(
                Outcome.TEMPERROR, "11.2#8", policy,
                detail=f"DNS temporary failure at include target {target}",
                lookups=budget["lookups"],
            )
        if txt.status is LookupStatus.EMPTY:
            return None, VerificationResult(
                Outcome.PERMERROR, "11.2#8", policy,
                detail=f"no record at include target {target}",
                lookups=budget["lookups"],
            )

        resolved = _select_record(txt, RecordType.AGENT)
        if resolved is None:
            return None, VerificationResult(
                Outcome.PERMERROR, "11.2#8", policy,
                detail=f"no ApertoID record at include target {target}",
                lookups=budget["lookups"],
            )
        if not resolved.is_valid:
            return None, VerificationResult(
                Outcome.PERMERROR, "11.2#8", policy,
                detail=f"malformed record at include target {target}: "
                       f"{'; '.join(str(e) for e in resolved.errors)}",
                lookups=budget["lookups"],
            )

        # F-2: re-check revocation on THIS resolved target (not only the origin).
        if resolved.get("status") == "revoked":
            return None, VerificationResult(
                Outcome.REVOKED, "11.2#7-via-include", policy,
                detail=f"include target {target} is revoked",
                lookups=budget["lookups"],
            )

        current = resolved

    # The chain terminated at a record with no include=. Section 8: the final
    # resolved record MUST carry a url. A non-revoked record with neither url
    # nor include is a dead-end delegation (the parser flags most such records
    # as malformed above; this is the defensive backstop for the degenerate
    # version-only record the classifier cannot type).
    if current.get("url") is None:
        return None, VerificationResult(
            Outcome.PERMERROR, "11.2#8", policy,
            detail="resolved record has neither url nor include",
            lookups=budget["lookups"],
        )
    return current, None


# ---------------------------------------------------------------------------
# Section 11.2 verification algorithm -- core flow
# ---------------------------------------------------------------------------

def verify_apertoid(
    claimed_domain: str,
    selector: str,
    agent_url: str,
    resolver: Resolver,
    *,
    current_time: int,
    agent_pubkey: Optional[str] = None,
    max_include_depth: int = DEFAULT_MAX_INCLUDE_DEPTH,
    max_include_lookups: int = DEFAULT_MAX_INCLUDE_LOOKUPS,
) -> VerificationResult:
    """Verify an agent's authorization via DNS per [APERTOID-DNS] Section 11.2.

    Follows the numbered algorithm in order EXACTLY. Step 10 (url matching) is
    the remaining BLOCK 4 seam; step 8 (include delegation) is implemented via
    _follow_includes.

    agent_pubkey is OPTIONAL: when provided it is matched against the record's
    pk= (step 11); when omitted the match is skipped but the resolved pk is
    still returned in the result (decision F-4), so the sig bridge can consume
    it.

    max_include_depth / max_include_lookups expose the Section 8 DoS limits
    (default 2 hops / 10 total DNS queries) as keyword-only parameters so each
    limit can be exercised independently; production callers use the defaults.
    """
    lookups = 0

    # --- Step 1: query the policy record --------------------------------
    policy_name = f"_apertoid.{claimed_domain}"
    policy_txt = resolver.txt(policy_name)
    lookups += 1
    if policy_txt.status is LookupStatus.TEMPFAIL:
        return VerificationResult(
            Outcome.TEMPERROR, "11.2#1", Policy.UNSET,
            detail=f"DNS temporary failure at {policy_name}", lookups=lookups,
        )

    # --- Step 2: no policy record -> none -------------------------------
    if policy_txt.status is LookupStatus.EMPTY:
        return VerificationResult(
            Outcome.NONE, "11.2#2", Policy.UNSET,
            detail="domain does not publish ApertoID", lookups=lookups,
        )

    # --- Step 3: select + parse the policy record; extract p= -----------
    policy_rec = _select_record(policy_txt, RecordType.POLICY)
    if policy_rec is None:
        # TXT records exist but none is an ApertoID policy record -> the domain
        # does not publish an ApertoID policy (Section 6.1 selection found none).
        return VerificationResult(
            Outcome.NONE, "11.2#2", Policy.UNSET,
            detail="no ApertoID policy record among TXT records", lookups=lookups,
        )
    if not policy_rec.is_valid:
        return VerificationResult(
            Outcome.PERMERROR, "11.2#3", Policy.UNSET,
            detail=f"malformed policy record: "
                   f"{'; '.join(str(e) for e in policy_rec.errors)}",
            lookups=lookups,
        )
    # F-6: from here on, every result carries the domain's resolved policy.
    policy = _POLICY_FROM_TAG.get(policy_rec.get("p"), Policy.UNSET)

    # --- Step 4: query the agent declaration record ---------------------
    agent_name = f"{selector}._apertoid.{claimed_domain}"
    agent_txt = resolver.txt(agent_name)
    lookups += 1
    if agent_txt.status is LookupStatus.TEMPFAIL:
        return VerificationResult(
            Outcome.TEMPERROR, "11.2#4", policy,
            detail=f"DNS temporary failure at {agent_name}", lookups=lookups,
        )

    # --- Step 5: no agent record -> permerror ---------------------------
    if agent_txt.status is LookupStatus.EMPTY:
        return VerificationResult(
            Outcome.PERMERROR, "11.2#5", policy,
            detail="no agent declaration record found", lookups=lookups,
        )

    # --- Step 6: select + parse the agent record ------------------------
    agent_rec = _select_record(agent_txt, RecordType.AGENT)
    if agent_rec is None:
        return VerificationResult(
            Outcome.PERMERROR, "11.2#5", policy,
            detail="no ApertoID agent record among TXT records", lookups=lookups,
        )
    if not agent_rec.is_valid:
        return VerificationResult(
            Outcome.PERMERROR, "11.2#6", policy,
            detail=f"malformed agent record: "
                   f"{'; '.join(str(e) for e in agent_rec.errors)}",
            lookups=lookups,
        )

    # --- Step 7: revocation FIRST among substantive checks (Section 10.1)
    # This ordering is mandatory: status=revoked is checked BEFORE exp/url/key.
    if agent_rec.get("status") == "revoked":
        return VerificationResult(
            Outcome.REVOKED, "11.2#7", policy,
            detail="agent is revoked", lookups=lookups,
        )

    # --- Step 8: include= delegation (Section 8) ------------------------
    # Follow include= to the final resolved record, enforcing the Section 8 DoS
    # limits (depth, total lookups, cycle detection) and re-checking revocation
    # on every hop (decision F-2). url and include are mutually exclusive
    # (parser enforces), so a record with include= has no url= of its own.
    resolved = agent_rec
    if agent_rec.get("include") is not None:
        budget = {
            "lookups": lookups,          # policy + agent queries already spent
            "seen": {agent_name},        # origin name, for cycle detection
            "chain": [agent_name],
            "max_depth": max_include_depth,
            "max_lookups": max_include_lookups,
        }
        resolved, failure = _follow_includes(agent_rec, resolver, policy, budget)
        lookups = budget["lookups"]
        if failure is not None:
            return failure

    # --- Step 9: exp expiry (Section 7.3 / 9) ---------------------------
    if _is_expired(resolved, current_time):
        return VerificationResult(
            Outcome.EXPIRED, "11.2#9", policy,
            detail=f"key expired at exp={resolved.get('exp')} "
                   f"(now={current_time})",
            lookups=lookups,
        )

    # --- Step 10: url matching (Section 11.4) ---------------------------
    # TODO(BLOCK 4): _url_matches(agent_url, resolved.get("url")) per Section
    # 11.4 (https-only, case-insensitive host, case-sensitive path, trailing
    # slash normalised, query/fragment ignored, port must match with 443
    # default). On no match -> url_mismatch (11.2#10), policy applied. Skipped
    # in BLOCK 2.

    # --- Step 11: key check (Section 11.2 step 11) ----------------------
    # F-4: ALWAYS expose the resolved pk, whether or not a key is matched. The
    # key type is that of k=, defaulting to ed25519 when k= is absent (FINDINGS
    # F10 pk-without-k).
    resolved_pk = resolved.get("pk")
    if resolved_pk is not None and agent_pubkey is not None:
        if agent_pubkey != resolved_pk:
            return VerificationResult(
                Outcome.KEY_MISMATCH, "11.2#11", policy,
                pk=resolved_pk,
                detail="presented public key does not match record pk=",
                lookups=lookups,
            )

    # --- Step 12: pass --------------------------------------------------
    return VerificationResult(
        Outcome.PASS, "pass", policy, pk=resolved_pk, lookups=lookups,
    )
