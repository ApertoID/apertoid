"""End-to-end ApertoID verification (Phase 2).

This module ties the DNS transport (resolver.py), the record parser (parser.py),
and the HTTP signature layer (sig.py) into the verification procedure of
draft-ferro-dnsop-apertoid-01 Section 11.2 and the sig<->DNS bridge of
draft-ferro-httpbis-apertoid-sig-01 Section 4.

SCOPE: Phase 2 is complete. verify_apertoid() implements Section 11.2 steps
1-12 (with Section 6.1 selection, Section 8 include= delegation, Section 11.4
url matching), and verify_request() is the sig<->DNS bridge (-sig Section 4,
decision F-5): it resolves the key via verify_apertoid then verifies the request
signature via sig.verify, returning one unified VerificationResult.

NOT built (stated honestly): prev= key-rotation continuity verification (§10.2,
decision F-1 -- deferred, needs a historical key cache); live DNS is optional
via resolver.DnsPythonResolver (the core logic depends only on the injected
Resolver protocol).

RESULT TYPE (decision F-6): every outcome carries the failing step id and the
domain's resolved policy p=, so a caller learns both "unauthorized" and "the
domain says reject/warn/none". Every "apply policy p=" branch in Section 11.2
therefore returns a VerificationResult whose .policy is already populated.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import sig
from .parser import VERSION, ParsedRecord, RecordType, parse_record
from .resolver import LookupStatus, Resolver, TxtLookup

# Section 8 delegation limits. DEFAULT_MAX_INCLUDE_DEPTH is the number of
# include= hops a verifier may follow: TWO (origin record + up to two delegated
# targets), preserving what -01's "maximum delegation depth is 2" already
# permitted rather than narrowing it in -02 (FINDINGS P2). So A->B passes,
# A->B->C passes, A->B->C->D (a third hop) fails with temperror. Safety at this
# depth comes NOT from reducing it but from the other §8 limits kept unchanged:
# per-hop revocation re-check (F-2/P1), cycle detection, and the hard cap of
# DEFAULT_MAX_INCLUDE_LOOKUPS (10) total DNS queries for the whole attempt.
DEFAULT_MAX_INCLUDE_DEPTH = 2
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
    BODY_TOO_LARGE = "body_too_large"
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
             in _follow_includes; also handy for tests).
    signature_verified
             True ONLY when an Ed25519 request signature was cryptographically
             checked and passed. False everywhere else, including: every DNS-only
             verify_apertoid result (that layer never checks a signature), every
             failure, AND a url-only agent record (no pk= published) that is
             authorized by URL match alone -- a PASS whose authorization came from
             the URL, NOT from crypto. A caller MUST NOT read a PASS as
             cryptographic proof unless this flag is True (F-4 / V1).
    """

    outcome: Outcome
    step: str
    policy: Policy = Policy.UNSET
    pk: Optional[str] = None
    detail: str = ""
    lookups: int = 0
    signature_verified: bool = False

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
# Section 11.4 URL matching
# ---------------------------------------------------------------------------

def _url_matches(agent_url: str, declared_url: str) -> bool:
    """Compare the agent's URL against the declared url= per Section 11.4.

    The section specifies EXACTLY these rules (implemented verbatim, nothing
    invented):

      * scheme MUST be "https"; HTTP MUST NOT be accepted. Either side using a
        non-https scheme is an automatic no-match (security: a declared or
        presented http URL never matches, even if the rest is identical).
      * host comparison is case-INsensitive (per RFC 3986).
      * path comparison is case-SENSITIVE.
      * trailing slashes are normalized (see FINDINGS P3 for the exact reading:
        all trailing "/" are stripped from each path on both sides, so "/x",
        "/x/" and "/x//" compare equal, and root "/" compares equal to "").
      * query strings and fragments are IGNORED.
      * port numbers, if present, MUST match; the default HTTPS port 443 is
        assumed when absent (so "https://h/p" == "https://h:443/p").

    Anything that fails to parse as a URL is treated as a no-match rather than
    raising: verification returns url_mismatch, never an exception.
    """
    try:
        a = urlsplit(agent_url)
        d = urlsplit(declared_url)
    except ValueError:
        return False

    # scheme: both MUST be exactly https (case-insensitive per RFC 3986 scheme
    # rules; "HTTPS" is still https, but "http" is never accepted).
    if a.scheme.lower() != "https" or d.scheme.lower() != "https":
        return False

    # host: case-insensitive. urlsplit already lowercases nothing, so fold here.
    if (a.hostname or "") .lower() != (d.hostname or "").lower():
        return False

    # port: 443 assumed when absent. urlsplit.port is None when absent or, for a
    # malformed port, raises ValueError on access -- guard it.
    try:
        a_port = a.port if a.port is not None else 443
        d_port = d.port if d.port is not None else 443
    except ValueError:
        return False
    if a_port != d_port:
        return False

    # path: case-sensitive, with trailing slashes normalized on both sides.
    if _normalize_path(a.path) != _normalize_path(d.path):
        return False

    # query and fragment are ignored entirely (not compared).
    return True


def _normalize_path(path: str) -> str:
    """Strip trailing slashes for the Section 11.4 comparison (see FINDINGS P3).

    "/x/" -> "/x", "/x" -> "/x", "/" -> "", "" -> "". Applied to both sides so
    the comparison is symmetric.
    """
    return path.rstrip("/")


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

    Follows the numbered algorithm in order EXACTLY (steps 1-12), including
    step 8 include delegation (_follow_includes) and step 10 url matching
    (_url_matches).

    agent_pubkey is OPTIONAL: when provided it is matched against the record's
    pk= (step 11); when omitted the match is skipped but the resolved pk is
    still returned in the result (decision F-4), so the sig bridge can consume
    it.

    max_include_depth / max_include_lookups expose the Section 8 DoS limits
    (default 2 include hops / 10 total DNS queries) as keyword-only parameters so
    each limit can be exercised independently; production callers use the
    defaults.
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
    # Compare the caller-supplied canonical agent_url against the resolved
    # record's url= per Section 11.4. url-only records go through this too. A
    # record reached via include= always carries a url (enforced by
    # _follow_includes), so resolved.get("url") is present here.
    declared_url = resolved.get("url")
    if not _url_matches(agent_url, declared_url):
        return VerificationResult(
            Outcome.URL_MISMATCH, "11.2#10", policy,
            pk=resolved.get("pk"),
            detail=f"agent url {agent_url!r} does not match declared "
                   f"url {declared_url!r}",
            lookups=lookups,
        )

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


# ---------------------------------------------------------------------------
# Section 4 (-sig): the signature <-> DNS bridge (decision F-5)
# ---------------------------------------------------------------------------

# sig.verify() result string -> unified Outcome (Section 4.1 values).
_SIG_OUTCOME = {
    "pass": Outcome.PASS,
    "malformed": Outcome.MALFORMED,
    "timestamp_invalid": Outcome.TIMESTAMP_INVALID,
    "nonce_reused": Outcome.NONCE_REUSED,
    "body_too_large": Outcome.BODY_TOO_LARGE,
    "sig_invalid": Outcome.SIG_INVALID,
}

# sig.verify() result string -> step id for the unified result. body_too_large
# is a local guard applied at the nonce/body stage, before signing-input
# reconstruction (sig.verify step 7); label it "sig#4b" to sit between the
# nonce check (sig#4) and signature verification (sig#9).
_SIG_STEP = {
    "malformed": "sig#2",
    "timestamp_invalid": "sig#3",
    "nonce_reused": "sig#4",
    "body_too_large": "sig#4b",
    "sig_invalid": "sig#9",
    "pass": "pass",
}


def verify_request(
    header_value: str,
    resolver: Resolver,
    method: str,
    target: str,
    body: bytes,
    agent_url: str,
    *,
    current_time: int,
    window: int = sig.DEFAULT_WINDOW,
    seen_nonces: Optional[set] = None,
    max_body_size: Optional[int] = None,
) -> VerificationResult:
    """Verify a signed HTTP request end to end (-sig Section 4, decision F-5).

    Ties the DNS layer (verify_apertoid) to the signature layer (sig.verify).
    Returns a single unified VerificationResult carrying outcome + step + the
    domain's policy p= (F-6).

    max_body_size, when set, caps the request-body length the verifier will
    hash: a larger body yields outcome=BODY_TOO_LARGE (step "sig#4b") and the
    body is rejected BEFORE the SHA-256 over it is computed, closing the
    body-hash DoS vector. Default None means no limit (backwards compatible);
    the caller owns the policy, as with the injectable resolver and window.
    The check runs inside sig.verify, so it applies only on the signature path
    (a DNS-fail or url-only result returns earlier and never hashes the body).

    agent_url is the canonical URL the request was RECEIVED on, supplied
    explicitly by the caller (decision F-Q1). It is deliberately NOT
    reconstructed from the Host header: Host is not part of the signing input
    (-sig Section 6.1/6.2), so trusting it for the Section 11.4 url match would
    let an attacker who can set Host bypass the check. The caller, which knows
    the real endpoint the request hit, owns this value.

    ORDERING NOTE (F-Q2): the numbered -sig Section 4 algorithm checks the
    timestamp (step 3) and nonce (step 4) BEFORE the DNS lookup (steps 5-6).
    This bridge resolves DNS FIRST and then calls sig.verify() whole, which runs
    the timestamp/nonce checks internally. That reorders steps 3-4 after 5-6 for
    efficiency (a request to a domain that publishes no ApertoID, or names a
    revoked/expired agent, is rejected without any crypto or clock work), but
    preserves Section 4 semantics: sig.verify is the single source of truth for
    timestamp, nonce, and the step-9a rule that the nonce is inserted into the
    cache ONLY after the signature verifies. An unauthenticated request still
    never mutates verifier state.

    A consequence of the reorder: Section 4's "malformed" (step 2) is also moved
    after DNS for the common case. Only a header MISSING d= or s= is caught up
    front (it cannot be routed to a DNS name); a header that is malformed for a
    non-routing reason -- e.g. missing sig=, or a badly-formed t=/n= -- but whose
    d=/s= are present is sent through DNS FIRST, so if the domain fails DNS
    (none/temperror/etc.) the DNS result is returned and "malformed" is never
    reached. The request is unauthorized under either verdict; the reorder only
    changes which reason is reported.

    Raises ValueError if window is outside the Section 5 range [60, 600]. This is
    checked up front (via the same sig._check_window used by sig.verify) so a
    misconfigured window fails loudly even on a path that returns before reaching
    sig.verify (e.g. a DNS failure or a url-only agent).
    """
    sig._check_window(window)

    # Parse the header enough to get d= and s= for the DNS lookup. sig.verify
    # re-parses and fully validates the header (it is the source of truth for
    # "malformed"); here we only need the routing tags. If the header is
    # unparseable or missing d/s, hand off to sig.verify to produce the
    # canonical "malformed" result rather than guessing.
    ph = sig.parse_header(header_value)
    if "d" not in ph.tags or "s" not in ph.tags:
        result = sig.verify(
            header_value, _NULL_PUBKEY, method, target, body,
            current_time=current_time, window=window, seen_nonces=seen_nonces,
            max_body_size=max_body_size,
        )
        return VerificationResult(
            _SIG_OUTCOME.get(result.result, Outcome.MALFORMED),
            _SIG_STEP.get(result.result, "sig#2"),
            Policy.UNSET, detail=result.detail,
        )

    # --- DNS layer (Section 4 steps 5-6): resolve + validate, get pk ----
    dns = verify_apertoid(
        ph.tags["d"], ph.tags["s"], agent_url, resolver,
        current_time=current_time,
    )
    if dns.outcome is not Outcome.PASS:
        # DNS verification failed (none/revoked/expired/url_mismatch/permerror/
        # temperror). Return it verbatim: it already carries outcome + step +
        # policy. The signature is NOT checked -- no point, and we avoid doing
        # crypto for an agent the domain does not authorize.
        return dns

    # --- url-only agent record: authorized by URL, no key to verify against --
    # A record with url= but no pk= is a legal, DNS-layer PASS (FINDINGS F10;
    # the "url-only" deployment stage of [APERTOID-DNS] Section 12.1, where the
    # key check is skipped -- Section 11.2 step 11 is conditional on pk=, and
    # Section 11.3 "pass" says the key matches only "if applicable"). There is
    # no published key to check the signature against, so we do NOT call
    # sig.verify. The verdict is the DNS-layer pass on URL authorization, but
    # signature_verified stays False so the caller is not given false
    # cryptographic assurance (decision V1). [APERTOID-SIG] Section 4 does not
    # specify this keyless case -- see FINDINGS.md P4.
    if dns.pk is None:
        return VerificationResult(
            Outcome.PASS, "pass", dns.policy, pk=None,
            detail="authorized by URL match; agent record publishes no pk, "
                   "signature not cryptographically verified",
            lookups=dns.lookups, signature_verified=False,
        )

    # --- Signature layer (Section 4 steps 3-4, 7-9a): sig.verify whole --
    # Decode the DNS-resolved raw 32-byte Ed25519 key. dns.pk passed pk-format
    # validation in the parser (43 unpadded Base64 chars), but guard the decode
    # so a surprising value yields malformed rather than an exception.
    try:
        pubkey = Ed25519PublicKey.from_public_bytes(
            sig.b64_unpadded_decode(dns.pk)
        )
    except (ValueError, InvalidSignature, TypeError) as exc:
        return VerificationResult(
            Outcome.MALFORMED, "sig#8", dns.policy,
            pk=dns.pk, detail=f"resolved pk is not a valid Ed25519 key: {exc}",
            lookups=dns.lookups,
        )

    result = sig.verify(
        header_value, pubkey, method, target, body,
        current_time=current_time, window=window, seen_nonces=seen_nonces,
        max_body_size=max_body_size,
    )
    return VerificationResult(
        _SIG_OUTCOME.get(result.result, Outcome.MALFORMED),
        _SIG_STEP.get(result.result, "sig#2"),
        dns.policy, pk=dns.pk, detail=result.detail, lookups=dns.lookups,
        # signature_verified is True ONLY when the Ed25519 check actually passed.
        signature_verified=(result.result == "pass"),
    )


# A syntactically-valid but useless key, used only to let sig.verify produce the
# canonical "malformed" result for a header missing d=/s= (it never reaches the
# crypto step in that case, because parse_header fails first).
_NULL_PUBKEY = Ed25519PublicKey.from_public_bytes(b"\x00" * 32)
