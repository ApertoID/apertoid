"""ApertoID-Signature signing and verification (Layer 3).

Reference implementation of draft-ferro-httpbis-apertoid-sig-00:
  - Section 3.1  signing-input construction
  - Section 3.2  producing the signature
  - Section 4    verification procedure
  - Section 2.2  header ABNF / tag parsing

SCOPE: crypto + signing-input + header parse/verify only. It does NOT do the
DNS lookup for pk= (that is the DNS layer / Layer 2), nonce-cache storage, or
network I/O. The caller supplies the public key and (for verification) decides
the clock.

METHOD NOTE (same as the DNS parser): implemented strictly from the spec. The
normative *signing procedure* in Section 3.2 says "producing a 64-byte
signature ... Encode the signature as unpadded Base64" -- i.e. a raw Ed25519
signature, unpadded, which is 86 Base64 characters. This module follows that
normative procedure. Where OTHER parts of the draft contradict it (Section 2.2
ABNF, Section 2.3 tag description, and the examples all say "88"), this module
does NOT silently reconcile -- see FINDINGS-sig.md. This matches the already-
decided project convention (raw bytes, standard Base64 alphabet, unpadded).
"""

from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass, field
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature

LF = "\n"

# SHA-256 of the empty string (Section 3.1 empty-body hash).
EMPTY_BODY_SHA256 = hashlib.sha256(b"").hexdigest()

# Standard (unpadded) Base64 alphabet, 86 chars for a 64-byte Ed25519 sig.
# NB: the draft's ABNF names this "base64url" but lists "+" "/" "=" -- see
# FINDINGS-sig.md S2. We implement the normative Section 3.2 encoding (unpadded
# standard Base64), and validate against that.
_RE_SIG_B64 = re.compile(r"^[A-Za-z0-9+/]{86}$")

# Header tag productions (Section 2.2 ABNF).
_RE_DOMAIN = re.compile(r"^(?:[A-Za-z][A-Za-z0-9-]*)(?:\.[A-Za-z][A-Za-z0-9-]*)*$")
_RE_SELECTOR = re.compile(r"^[A-Za-z][A-Za-z0-9-]*$")   # ABNF: selector = ALPHA *(...)
_RE_TIMESTAMP = re.compile(r"^[0-9]+$")
# ABNF: nonce = 1*16HEXDIG. RFC 5234 HEXDIG is UPPERCASE A-F, but the prose says
# lowercase -- see FINDINGS-sig.md S7. We accept either case here and flag it.
_RE_NONCE = re.compile(r"^[0-9A-Fa-f]{1,16}$")


# ---------------------------------------------------------------------------
# Encoding helpers
# ---------------------------------------------------------------------------

def b64_unpadded(raw: bytes) -> str:
    """Standard Base64, no '=' padding (Section 3.2 step 7)."""
    return base64.b64encode(raw).decode("ascii").rstrip("=")


def b64_unpadded_decode(s: str) -> bytes:
    """Decode standard unpadded Base64."""
    return base64.b64decode(s + "=" * (-len(s) % 4))


def sha256_hex(body: bytes) -> str:
    """Lowercase hex SHA-256 of the body; empty body -> hash of empty string."""
    return hashlib.sha256(body if body else b"").hexdigest()


# ---------------------------------------------------------------------------
# Signing input (Section 3.1)
# ---------------------------------------------------------------------------

def construct_signing_input(
    d: str,
    s: str,
    t: str,
    n: str,
    method: str,
    target: str,
    body: bytes,
) -> bytes:
    """Build the signing input byte string per Section 3.1.

    Seven components, each terminated by LF (0x0A), UTF-8 encoded:
        d_value LF s_value LF t_value LF n_value LF method LF target LF body_hash LF

    Per the prose: d/s lowercased, n lowercase hex, method uppercased, t as a
    decimal string, target as sent on the request line (path[?query]). The
    trailing LF after body_hash IS present (all seven components are
    "terminated by" LF).
    """
    d_value = d.lower()
    s_value = s.lower()
    t_value = str(t)
    n_value = n.lower()
    method_u = method.upper()
    body_hash = sha256_hex(body)

    parts = [d_value, s_value, t_value, n_value, method_u, target, body_hash]
    return (LF.join(parts) + LF).encode("utf-8")


# ---------------------------------------------------------------------------
# Signing (Section 3.2)
# ---------------------------------------------------------------------------

def sign(
    private_key: Ed25519PrivateKey,
    d: str,
    s: str,
    t: str,
    n: str,
    method: str,
    target: str,
    body: bytes,
) -> str:
    """Produce the unpadded-Base64 Ed25519 signature over the signing input."""
    signing_input = construct_signing_input(d, s, t, n, method, target, body)
    raw_sig = private_key.sign(signing_input)  # 64 bytes, raw Ed25519
    return b64_unpadded(raw_sig)


def build_header(d: str, s: str, t: str, n: str, sig: str) -> str:
    """Assemble the ApertoID-Signature header value (Section 2.2)."""
    return f"d={d}; s={s}; t={t}; n={n}; sig={sig}"


# ---------------------------------------------------------------------------
# Header parsing (Section 2.2)
# ---------------------------------------------------------------------------

REQUIRED_TAGS = ("d", "s", "t", "n", "sig")


@dataclass
class ParsedHeader:
    raw: str
    tags: dict[str, str] = field(default_factory=dict)
    diagnostics: list[str] = field(default_factory=list)

    @property
    def is_valid(self) -> bool:
        return not self.diagnostics


def parse_header(header_value: str) -> ParsedHeader:
    """Parse an ApertoID-Signature header value into its tags.

    Accepts an optional "ApertoID-Signature:" prefix. Splits on ";" and strips
    OWS. Validates presence of the five required tags and each value's format.
    """
    ph = ParsedHeader(raw=header_value)
    body = header_value
    if body.lower().startswith("apertoid-signature:"):
        body = body.split(":", 1)[1]

    for field_text in body.split(";"):
        field_text = field_text.strip(" \t")
        if not field_text:
            continue
        if "=" not in field_text:
            ph.diagnostics.append(f"field {field_text!r} is not a tag=value pair")
            continue
        k, _, v = field_text.partition("=")
        ph.tags[k.strip().lower()] = v

    for req in REQUIRED_TAGS:
        if req not in ph.tags:
            ph.diagnostics.append(f"missing required tag {req!r}")

    if "d" in ph.tags and not _RE_DOMAIN.match(ph.tags["d"]):
        ph.diagnostics.append(f"d= {ph.tags['d']!r} is not a valid domain-name")
    if "s" in ph.tags and not _RE_SELECTOR.match(ph.tags["s"]):
        ph.diagnostics.append(f"s= {ph.tags['s']!r} is not a valid selector")
    if "t" in ph.tags and not _RE_TIMESTAMP.match(ph.tags["t"]):
        ph.diagnostics.append(f"t= {ph.tags['t']!r} is not 1*DIGIT")
    if "n" in ph.tags and not _RE_NONCE.match(ph.tags["n"]):
        ph.diagnostics.append(f"n= {ph.tags['n']!r} is not 1-16 HEXDIG")
    if "sig" in ph.tags and not _RE_SIG_B64.match(ph.tags["sig"]):
        ph.diagnostics.append(
            f"sig= is not 86 unpadded Base64 chars (got {len(ph.tags['sig'])})"
        )
    return ph


# ---------------------------------------------------------------------------
# Verification (Section 4)
# ---------------------------------------------------------------------------

@dataclass
class VerifyResult:
    result: str                 # pass / malformed / timestamp_invalid /
                                # nonce_reused / body_too_large / sig_invalid
    detail: str = ""


def verify(
    header_value: str,
    public_key: Ed25519PublicKey,
    method: str,
    target: str,
    body: bytes,
    current_time: int,
    window: int = 300,
    seen_nonces: Optional[set] = None,
    max_body_size: Optional[int] = None,
) -> VerifyResult:
    """Verify an ApertoID-Signature per Section 4 (crypto + local checks only).

    DNS resolution of pk= is out of scope; the caller supplies public_key.
    Steps 5-6 (DNS) are therefore skipped. Nonce cache is an optional set.

    max_body_size, when set, is the maximum request-body length (in bytes) the
    verifier will hash. A body larger than the limit is rejected ("body_too_large")
    BEFORE the SHA-256 over the body is computed, so an attacker cannot force the
    verifier to hash an arbitrarily large body with a request that was never going
    to verify. Default None means no limit (backwards compatible): the library
    provides the mechanism, the caller sets the policy.
    """
    ph = parse_header(header_value)
    if not ph.is_valid:
        return VerifyResult("malformed", "; ".join(ph.diagnostics))

    t = int(ph.tags["t"])
    if abs(current_time - t) > window:
        return VerifyResult("timestamp_invalid", f"|{current_time}-{t}| > {window}")

    # Section 4 step 4: check the nonce cache READ-ONLY here. The nonce is NOT
    # inserted yet -- insertion happens only after the signature verifies (step
    # 9a below). This prevents an attacker from burning a victim's nonce (or
    # flooding the cache) with a bogus-signature request: an unauthenticated
    # request MUST NOT mutate verifier state.
    n = ph.tags["n"]
    if seen_nonces is not None and n in seen_nonces:
        return VerifyResult("nonce_reused", n)

    # Body-size guard: reject an over-large body BEFORE hashing it, so a bogus
    # request cannot make the verifier do the expensive SHA-256 over an
    # arbitrarily large body. Placed after the cheap header/timestamp/nonce
    # checks (which never touch the body) and before construct_signing_input,
    # the only place the body is hashed. No effect when max_body_size is None.
    if max_body_size is not None and len(body) > max_body_size:
        return VerifyResult(
            "body_too_large", f"body {len(body)} bytes exceeds limit {max_body_size}"
        )

    signing_input = construct_signing_input(
        ph.tags["d"], ph.tags["s"], ph.tags["t"], n, method, target, body
    )
    try:
        public_key.verify(b64_unpadded_decode(ph.tags["sig"]), signing_input)
    except InvalidSignature:
        return VerifyResult("sig_invalid", "Ed25519 verify failed")

    # Section 4 step 9a: the signature is valid, so NOW record the nonce.
    if seen_nonces is not None:
        seen_nonces.add(n)

    return VerifyResult("pass")
