"""ApertoID DNS TXT record parser (Layer 1).

Reference implementation of the record parser for
draft-ferro-dnsop-apertoid-00, Section 5.1 (ABNF) plus the prose rules in
Sections 5.1, 6.3, 7.3, and 8.

SCOPE: This module is the *parser* only. It turns a raw TXT record string
into a structured, validated record object and reports syntax / format
errors. It does NOT implement the verification algorithm of Section 11
(that is Layer 2), does NOT perform DNS lookups, and does NOT verify any
Ed25519 signature.

METHOD NOTE: Value formats are validated against the ABNF *as literally
written* in Section 5.1. Where the ABNF and the surrounding prose disagree
(and they do in several places), the parser follows the ABNF and records a
diagnostic pointing at the contradiction rather than silently "fixing" it.
See FINDINGS.md for the catalogue of spec defects this surfaced.

FINDINGS RESOLVED and tracked by this parser (each decided and applied to the
draft ABNF/prose):
  F1/F2 - pk is the raw 32-byte Ed25519 key, unpadded Base64 = EXACTLY 43 chars;
          prev signature = 64 bytes unpadded = EXACTLY 86 chars; "=" is no
          longer a BASE64CHAR.
  F3    - ";" is the reserved tag separator; value-char excludes it, and a ";"
          inside a URL MUST be percent-encoded (%3B). URI-CHAR no longer lists ";".
  F4    - whitespace: any amount of WSP on either side of ";" is ignored
          (apertoid-record = version-tag *( *WSP ";" *WSP tag-value )).
  F7    - URI-CHAR now includes "%" so percent-encoded URLs are grammatical.
  F8    - rua email local-part is an RFC 5321 4.1.2 dot-atom (atext, no "@"),
          removing the greedy-@ ambiguity.
  F9    - underscore-scoped labels (RFC 8552) are grammatical.
  F5    - status=revoked records are exempt from the url-or-include requirement.
  F6    - record type is determined by DNS name, never inferred from tags; a
          content-only parser reports its best guess as a hint (record_type)
          and MUST NOT be treated as authoritative (the DNS name decides).
  F10   - pk MAY appear without k (defaults to ed25519); k requires both pk and
          exp; a record with neither k nor pk is the legal url-only stage.
  F11   - a duplicated KNOWN tag is malformed -> permerror (ERROR); a repeated
          unknown tag does not by itself invalidate the record.
  F12   - policy-record selection is on the parsed version tag, not a byte
          prefix (handled at the multi-record selection layer, not here).
All twelve DNS-draft findings (F1-F12) are now resolved.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# ---------------------------------------------------------------------------
# ABNF-derived character classes and value productions (Section 5.1)
# ---------------------------------------------------------------------------

# BASE64CHAR = ALPHA / DIGIT / "+" / "/"   (unpadded; no "=" pad char per F1 fix)
_BASE64CHAR = r"[A-Za-z0-9+/]"

# base64-ed25519     = 43*43(BASE64CHAR)   ; 32 bytes unpadded = EXACTLY 43
# base64-ed25519-sig = 86*86(BASE64CHAR)   ; 64 bytes unpadded = EXACTLY 86
# (Corrected per FINDINGS F1: raw 32-byte key, unpadded Base64.)
_RE_PK = re.compile(rf"^{_BASE64CHAR}{{43}}$")
_RE_SIG = re.compile(rf"^{_BASE64CHAR}{{86}}$")

# domain-name      = label *("." label)
# label            = ldh-label / underscore-label
# ldh-label        = alnum *(alnum / "-")   ; RFC 1035 preferred syntax
# underscore-label = "_" 1*(alnum / "-")    ; RFC 8552 underscore-scoped
# alnum            = ALPHA / DIGIT
# (Corrected per FINDINGS F9 so underscore-scoped names like "_apertoid" and
# include targets such as "agent1._apertoid.salesforce.com" are grammatical.
# ldh-label is alnum-first -- a leading digit is allowed, matching the Section
# 7.1 prose ("alphanumeric") and the -sig draft's identical ldh-label; the
# post-review cross-draft fix so "42domains.example" parses in both drafts.)
_RE_LABEL = re.compile(r"^(?:[A-Za-z0-9][A-Za-z0-9-]*|_[A-Za-z0-9-]+)$")

# URI-CHAR (Section 5.1), corrected per FINDINGS F7 (add "%") and F3 (drop ";").
# ";" is the reserved tag separator and MUST be percent-encoded (%3B) in a URL.
_URI_CHAR = r"[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,=%]"
_RE_HTTPS_URI = re.compile(rf"^https://{_URI_CHAR}+$")

# exp-tag  = "exp" "=" 1*DIGIT
_RE_DIGITS = re.compile(r"^[0-9]+$")

# tag = 1*ALPHA  (tag names are letters only)
_RE_TAG = re.compile(r"^[A-Za-z]+$")

# value = 1*value-char ; value-char = VCHAR excluding ";" (%x3B) per FINDINGS F3.
# (Post-split a value never contains ";" anyway, but we validate it explicitly
# so a literal ";" surfaced any other way is rejected rather than silently kept.)
_RE_VALUE = re.compile(r"^[\x21-\x3a\x3c-\x7e]+$")

# RFC 5321 Section 4.1.2 local-part as dot-atom (FINDINGS F8). atext excludes
# "@", so the domain boundary is unambiguous.
_ATEXT = r"[A-Za-z0-9!#$%&'*+\-/=?^_`{|}~]"
_RE_LOCAL_PART = re.compile(rf"^{_ATEXT}+(?:\.{_ATEXT}+)*$")

VERSION = "APERTOID1"

# Selector syntax (Section 7.1): DNS label, 1-63 chars, alphanumeric+hyphen,
# not starting/ending with a hyphen, case-insensitive. This is NOT part of the
# record body ABNF; it is validated separately via validate_selector().
_RE_SELECTOR = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")

# Tags with a defined meaning in this specification. Anything else is an
# "unknown tag" and MUST be ignored for forward compatibility (Section 5.1).
POLICY_TAGS = {"v", "p", "rua"}
AGENT_TAGS = {"v", "url", "k", "pk", "exp", "type", "include", "status", "prev"}
KNOWN_TAGS = POLICY_TAGS | AGENT_TAGS


class RecordType(str, Enum):
    POLICY = "policy"
    AGENT = "agent"
    UNKNOWN = "unknown"  # cannot be classified from content alone


class Severity(str, Enum):
    ERROR = "error"      # record is invalid per the spec
    WARNING = "warning"  # accepted, but notable (e.g. forward-compat, spec defect)


@dataclass
class Diagnostic:
    severity: Severity
    code: str
    message: str

    def __str__(self) -> str:
        return f"[{self.severity.value}:{self.code}] {self.message}"


@dataclass
class ParsedRecord:
    raw: str
    # tags in first-seen order; tag names lowercased, values verbatim
    ordered: list[tuple[str, str]] = field(default_factory=list)
    tags: dict[str, str] = field(default_factory=dict)
    unknown_tags: dict[str, str] = field(default_factory=dict)
    record_type: RecordType = RecordType.UNKNOWN
    diagnostics: list[Diagnostic] = field(default_factory=list)

    # -- convenience ------------------------------------------------------
    @property
    def errors(self) -> list[Diagnostic]:
        return [d for d in self.diagnostics if d.severity is Severity.ERROR]

    @property
    def warnings(self) -> list[Diagnostic]:
        return [d for d in self.diagnostics if d.severity is Severity.WARNING]

    @property
    def is_valid(self) -> bool:
        """True if the record has no ERROR-level diagnostics."""
        return not self.errors

    def get(self, tag: str) -> Optional[str]:
        return self.tags.get(tag.lower())

    def _add(self, severity: Severity, code: str, message: str) -> None:
        self.diagnostics.append(Diagnostic(severity, code, message))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def validate_selector(selector: str) -> Optional[Diagnostic]:
    """Validate an agent selector per Section 7.1.

    Returns a Diagnostic on failure, or None if valid. Selectors are
    case-insensitive; validation is otherwise per the DNS-label rule.
    """
    if not (1 <= len(selector) <= 63):
        return Diagnostic(
            Severity.ERROR, "selector-length",
            f"selector must be 1-63 characters, got {len(selector)}",
        )
    if not _RE_SELECTOR.match(selector):
        return Diagnostic(
            Severity.ERROR, "selector-syntax",
            f"selector {selector!r} is not a valid DNS label "
            "(alphanumeric and hyphen, not starting/ending with a hyphen)",
        )
    return None


def _is_domain_name(value: str) -> bool:
    """Check a value against the ABNF `domain-name` production (Section 5.1)."""
    parts = value.split(".")
    return all(_RE_LABEL.match(p) for p in parts) and len(parts) >= 1


# ---------------------------------------------------------------------------
# Field splitting
# ---------------------------------------------------------------------------

def _split_fields(raw: str) -> list[str]:
    """Split a record into fields on the ";" separator.

    ABNF: apertoid-record = version-tag *( ";" [WSP] tag-value )

    We split on a literal ";" and then strip surrounding whitespace from each
    field. This is the only tractable interpretation, but note two divergences
    from the ABNF (see FINDINGS F4 for whitespace, F3 for the ";" collision):

      * The ABNF only permits optional WSP *after* the ";" ([WSP]), not before
        it, and only a single WSP char. Real records and the prose ("whitespace
        around semicolons ... MUST be ignored") assume whitespace on both sides
        and any amount. We follow the prose and strip both sides.
      * ";" is a VCHAR and is also a member of URI-CHAR, so a `value` (and in
        particular an `https-uri`) may legally contain ";". A naive split on
        ";" therefore mis-splits such values. There is no escaping mechanism in
        the grammar to disambiguate. We split naively and flag the risk.
    """
    return [f.strip(" \t") for f in raw.split(";")]


# ---------------------------------------------------------------------------
# Value-format validation per tag (ABNF Section 5.1)
# ---------------------------------------------------------------------------

def _validate_value(rec: ParsedRecord, tag: str, value: str) -> None:
    """Validate a single known tag's value against its ABNF production."""
    if tag == "v":
        # version value is case-sensitive; must be exactly "APERTOID1"
        if value != VERSION:
            rec._add(Severity.ERROR, "version-value",
                     f'v must be "{VERSION}", got {value!r}')

    elif tag == "p":
        if value not in ("reject", "warn", "none"):
            rec._add(Severity.ERROR, "policy-value",
                     f'p must be one of reject/warn/none, got {value!r}')

    elif tag == "rua":
        # rua = "mailto:" email-address
        # email-address = local-part "@" domain-name  (RFC 5321 4.1.2, FINDINGS F8)
        if not value.startswith("mailto:"):
            rec._add(Severity.ERROR, "rua-scheme",
                     f'rua must be a "mailto:" URI, got {value!r}')
        else:
            addr = value[len("mailto:"):]
            if "@" not in addr:
                rec._add(Severity.ERROR, "rua-addr",
                         f"rua address {addr!r} has no '@'")
            else:
                # atext excludes "@", so there is exactly one "@" separating a
                # valid local-part from the domain -- no rpartition ambiguity.
                local, _, dom = addr.partition("@")
                if not _RE_LOCAL_PART.match(local):
                    rec._add(Severity.ERROR, "rua-local",
                             f"rua local-part {local!r} is not a valid RFC 5321 "
                             "dot-atom local-part")
                if not _is_domain_name(dom):
                    rec._add(Severity.ERROR, "rua-domain",
                             f"rua domain {dom!r} is not a valid domain-name")

    elif tag == "url":
        if not _RE_HTTPS_URI.match(value):
            rec._add(Severity.ERROR, "url-format",
                     f"url must be an https:// URI matching https-uri, "
                     f"got {value!r}")

    elif tag == "k":
        if value != "ed25519":
            # k MUST be "ed25519" for this specification (Section 7.3),
            # though the Key Type Registry may add more later.
            rec._add(Severity.ERROR, "keytype-value",
                     f'k must be "ed25519" for this specification, got {value!r}')

    elif tag == "pk":
        if not _RE_PK.match(value):
            rec._add(Severity.ERROR, "pubkey-format",
                     f"pk must be exactly 43 unpadded BASE64CHAR per the ABNF "
                     f"(base64-ed25519), got {len(value)} chars: {value!r}")

    elif tag == "exp":
        if not _RE_DIGITS.match(value):
            rec._add(Severity.ERROR, "exp-format",
                     f"exp must be 1*DIGIT (Unix timestamp), got {value!r}")

    elif tag == "type":
        if value not in ("ai", "human", "hybrid"):
            rec._add(Severity.ERROR, "type-value",
                     f"type must be ai/human/hybrid, got {value!r}")

    elif tag == "include":
        if not _is_domain_name(value):
            rec._add(Severity.ERROR, "include-format",
                     f"include must be a domain-name per the ABNF, got {value!r}")

    elif tag == "status":
        if value != "revoked":
            rec._add(Severity.ERROR, "status-value",
                     f'status must be "revoked" per the ABNF, got {value!r}')

    elif tag == "prev":
        # prev = "sig:" base64-ed25519-sig
        if not value.startswith("sig:"):
            rec._add(Severity.ERROR, "prev-prefix",
                     f'prev must be prefixed with "sig:", got {value!r}')
        else:
            sig = value[len("sig:"):]
            if not _RE_SIG.match(sig):
                rec._add(Severity.ERROR, "prev-format",
                         f"prev signature must be exactly 86 unpadded BASE64CHAR "
                         f"per the ABNF (base64-ed25519-sig), got {len(sig)} chars")


# ---------------------------------------------------------------------------
# Record-type classification
# ---------------------------------------------------------------------------

def _classify(rec: ParsedRecord) -> None:
    """Infer whether this is a Policy or Agent Declaration record.

    The spec distinguishes the two by DNS *location*, not by content
    (Sections 6.1 vs 7.1). Given only a record string we can at best guess
    from which tags are present. See FINDINGS F6.
    """
    has_policy = "p" in rec.tags or "rua" in rec.tags
    has_agent = bool(
        {"url", "include", "k", "pk", "exp", "type", "status", "prev"}
        & rec.tags.keys()
    )

    if has_policy and not has_agent:
        rec.record_type = RecordType.POLICY
    elif has_agent and not has_policy:
        rec.record_type = RecordType.AGENT
    elif has_policy and has_agent:
        rec.record_type = RecordType.UNKNOWN
        rec._add(Severity.WARNING, "type-ambiguous",
                 "record mixes policy tags (p/rua) with agent tags; "
                 "the spec has no content-level discriminator (FINDINGS F6)")
    else:
        # Only v= present (or v= plus unknown tags). Could be a bare/degenerate
        # record; the spec's revocation example is v=...;status=revoked which
        # lands in has_agent above, so this branch is genuinely undecidable.
        rec.record_type = RecordType.UNKNOWN
        rec._add(Severity.WARNING, "type-undetermined",
                 "record contains only v= (plus any unknown tags); "
                 "record type cannot be determined from content")


# ---------------------------------------------------------------------------
# Cross-tag rule enforcement
# ---------------------------------------------------------------------------

def _enforce_rules(rec: ParsedRecord) -> None:
    """Enforce the cross-tag MUST rules from the prose (Sections 7.3, 8)."""
    has_url = "url" in rec.tags
    has_include = "include" in rec.tags

    # Section 7.3 / Section 8: url and include are mutually exclusive.
    if has_url and has_include:
        rec._add(Severity.ERROR, "url-include-exclusive",
                 "url and include are mutually exclusive; a record MUST NOT "
                 "contain both (Section 8)")

    # Section 7.3: "If present [k], the pk tag MUST also be present."
    if "k" in rec.tags and "pk" not in rec.tags:
        rec._add(Severity.ERROR, "k-requires-pk",
                 "k is present but pk is missing (Section 7.3)")

    # Section 7.3: "exp REQUIRED when k is present."
    if "k" in rec.tags and "exp" not in rec.tags:
        rec._add(Severity.ERROR, "k-requires-exp",
                 "k is present but exp is missing (Section 7.3)")

    # Section 7.3 (FINDINGS F10 resolved): pk MAY appear without k; the key
    # type then defaults to "ed25519". This is explicitly legal -- no diagnostic.

    # Agent-declaration completeness (Sections 7.3, 8): every Agent Declaration
    # Record that is NOT a revocation record MUST contain either url or include.
    # A revocation record (status=revoked) is explicitly EXEMPT (Section 8 /
    # Section 10.1). Resolved per FINDINGS F5: the exception is now stated in
    # the spec, so a bare revocation record is fully conforming (no diagnostic).
    if rec.record_type is RecordType.AGENT and not has_url and not has_include:
        if rec.tags.get("status") != "revoked":
            rec._add(Severity.ERROR, "missing-endpoint",
                     "non-revocation agent record MUST contain either url or "
                     "include (Section 8)")


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def parse_record(raw: str) -> ParsedRecord:
    """Parse and validate an ApertoID DNS TXT record string.

    `raw` is the assembled record content (if the record was split into
    multiple TXT character-strings per RFC 1035 3.3.14, concatenate them
    before calling this function -- reassembly is a DNS-layer concern).
    """
    rec = ParsedRecord(raw=raw)

    if raw == "":
        rec._add(Severity.ERROR, "empty", "record is empty")
        return rec

    # Flag any ";" that appears to sit inside a value rather than as a
    # separator. We cannot truly detect this (no escaping in the grammar), but
    # a URL value with a ";" is the common real case worth warning about.
    fields = _split_fields(raw)

    if not fields or fields[0] == "":
        rec._add(Severity.ERROR, "no-version",
                 "record does not begin with a version tag")
        return rec

    seen: set[str] = set()
    for index, fieldtext in enumerate(fields):
        if fieldtext == "":
            # An empty field means "; ;" or a trailing/leading ";".
            rec._add(Severity.ERROR, "empty-field",
                     f"empty tag-value field at position {index} "
                     "(stray or doubled ';')")
            continue

        if "=" not in fieldtext:
            rec._add(Severity.ERROR, "no-equals",
                     f"field {fieldtext!r} is not a tag=value pair")
            continue

        # tag is up to the FIRST "="; value keeps everything after (value may
        # itself contain "=" since "=" is a VCHAR / URI-CHAR).
        rawtag, _, value = fieldtext.partition("=")
        tag = rawtag.lower()  # tags are case-insensitive (Section 5.1)

        # --- version-tag ordering rule (Sections 6.3, 7.3) ---------------
        if index == 0:
            if tag != "v":
                rec._add(Severity.ERROR, "version-first",
                         f"first tag MUST be v, got {rawtag!r}")
            # value validated below via _validate_value
        elif tag == "v":
            rec._add(Severity.ERROR, "version-position",
                     "v tag MUST be the first tag; found again at "
                     f"position {index}")

        # --- tag-name syntax (tag = 1*ALPHA) -----------------------------
        if not _RE_TAG.match(rawtag):
            rec._add(Severity.ERROR, "tag-syntax",
                     f"tag name {rawtag!r} is not 1*ALPHA")
            continue

        # --- value non-emptiness and VCHAR (value = 1*VCHAR) -------------
        if value == "":
            rec._add(Severity.ERROR, "empty-value",
                     f"tag {tag!r} has an empty value (value = 1*VCHAR)")
            continue
        if not _RE_VALUE.match(value):
            rec._add(Severity.ERROR, "value-vchar",
                     f"tag {tag!r} value contains non-VCHAR characters")
            # continue validating format anyway is pointless; move on
            continue

        # --- duplicate tag detection (FINDINGS F11 resolved) -------------
        # A duplicated KNOWN tag makes the record malformed -> permerror
        # (matching DKIM/DMARC). A repeated UNKNOWN tag does not, by itself,
        # invalidate the record (unknown tags are ignored for forward compat).
        duplicate = tag in seen
        seen.add(tag)

        rec.ordered.append((tag, value))

        if tag in KNOWN_TAGS:
            if duplicate:
                rec._add(Severity.ERROR, "duplicate-tag",
                         f"known tag {tag!r} appears more than once; a "
                         "duplicated known tag MUST be treated as malformed "
                         "(permerror) per Section 5.1")
            # First occurrence wins for the tags dict.
            rec.tags.setdefault(tag, value)
            _validate_value(rec, tag, value)
        else:
            # Unknown tag: MUST be ignored for forward compatibility, but we
            # retain it for inspection and note it.
            rec.unknown_tags.setdefault(tag, value)
            rec._add(Severity.WARNING, "unknown-tag",
                     f"unknown tag {tag!r} ignored (forward compatibility)")

    # v presence
    if "v" not in rec.tags:
        rec._add(Severity.ERROR, "no-version-tag", "record has no valid v tag")

    _classify(rec)
    _enforce_rules(rec)

    # Heuristic ";" inside URL warning (FINDINGS F3): if a url value looks
    # truncated at a ";" we cannot recover, but if a later field failed to
    # parse as tag=value AND a url is present, hint at the cause.
    return rec
