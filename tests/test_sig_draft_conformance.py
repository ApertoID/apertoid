"""Conformance checks against the CORRECTED -sig draft's own examples.

Unlike test_sig_draft_examples.py (which diagnosed the original -00 draft's
defects), this suite reads the shipped draft text and asserts that the
post-corrections examples are self-consistent and cryptographically valid:

  * the §3.3 / Appendix A signature de-wraps to a single 86-char token,
  * the pk= shown is the raw 43-char key (not SPKI),
  * the body_hash shown is the real SHA-256 of the shown body,
  * the embedded signature verifies against the embedded pk and the signing
    input reconstructed per §3.1 (including the trailing LF), and
  * the same signature FAILS when replayed to DELETE /mcp/data/all.

This tests the actual artifact in spec/, so a future edit that desyncs the
example from the crypto will fail here.
"""

import base64
import hashlib
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from apertoid import sig  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: E402
    Ed25519PublicKey,
)

SPEC = Path(__file__).resolve().parents[1] / "spec"
DRAFT_TXT = SPEC / "draft-ferro-httpbis-apertoid-sig-00.txt"

# The example request (§3.3 / Appendix A).
EX_D = "example.com"
EX_S = "leadhunter"
EX_T = "1711100000"
EX_N = "a1b2c3d4e5f6"
EX_METHOD = "POST"
EX_TARGET = "/mcp/tools/search"
EX_BODY = b'{"query": "find leads in tech sector", "limit": 10}'

# Raw 43-char key from the corrected draft; the private key is the Ed25519 key
# seeded by SHA-256("apertoid-sig-example:leadhunter"), so this is reproducible.
EXPECTED_PK_B64 = "ZgUmBeB/kgMsrD8+qlFCfJ7KeRse6RSJnvlL4qQnyGE"


def _draft_text():
    return DRAFT_TXT.read_text(encoding="utf-8")


def _dewrap_sig_after(text, marker):
    """Extract the sig= token following `marker`, joining any wrapped lines.

    A wrapped 86-char Base64 token spans two indented lines; there is no
    trailing '=' (unpadded) and Base64 has no whitespace, so we can join
    consecutive indented Base64 runs until we have 86 chars.
    """
    idx = text.index(marker)
    tail = text[idx:]
    m = re.search(r"sig=([A-Za-z0-9+/]+)", tail)
    assert m, "no sig= token found after marker"
    token = m.group(1)
    # If wrapped, the continuation is the next line's leading Base64 run.
    rest = tail[m.end():]
    while len(token) < 86:
        m2 = re.search(r"^\s*([A-Za-z0-9+/]+)", rest, re.MULTILINE)
        assert m2, f"could not de-wrap sig (have {len(token)} chars)"
        token += m2.group(1)
        rest = rest[m2.end():]
    return token[:86]


def test_draft_pk_is_raw_43_char_key():
    text = _draft_text()
    assert f"pk={EXPECTED_PK_B64}" in text, "corrected raw pk= not present in draft"
    # No SPKI-wrapped key (MCow...) should remain anywhere.
    assert "pk=MCow" not in text, "SPKI-wrapped pk=MCow... still present (S14)"
    assert len(EXPECTED_PK_B64) == 43


def test_draft_body_hash_is_real_sha256_of_shown_body():
    real = hashlib.sha256(EX_BODY).hexdigest()
    text = _draft_text()
    assert real in text, "real SHA-256 of the example body is not in the draft"
    # The old placeholder must be gone.
    assert "7d5e4a8b" not in text, "stale body_hash placeholder 7d5e4a8b still present (S5)"


def test_draft_has_no_88_or_der_or_base64url_artifacts():
    text = _draft_text()
    assert "88chars" not in text and "88 base64" not in text and \
        "88 characters" not in text, "signature length '88' still present (S1)"
    assert "MEUCIQD" not in text, "ASN.1 DER ECDSA placeholder sig still present (S4)"
    assert "base64url" not in text, "ABNF still names the type 'base64url' (S2)"


def _verify_embedded(marker):
    text = _draft_text()
    token = _dewrap_sig_after(text, marker)
    assert len(token) == 86, f"embedded sig is {len(token)} chars, not 86 (S1)"

    raw_pk = sig.b64_unpadded_decode(EXPECTED_PK_B64)
    pk = Ed25519PublicKey.from_public_bytes(raw_pk)

    header = sig.build_header(EX_D, EX_S, EX_T, EX_N, token)
    res = sig.verify(header, pk, EX_METHOD, EX_TARGET, EX_BODY,
                     current_time=int(EX_T), seen_nonces=set())
    assert res.result == "pass", f"embedded sig failed to verify: {res.detail}"
    return token


def test_section_3_3_example_signature_verifies():
    _verify_embedded("3.3.")


def test_appendix_a_example_signature_verifies():
    _verify_embedded("=== Agent sends signed POST request ===")


def test_appendix_a_signature_replayed_to_delete_fails():
    token = _dewrap_sig_after(_draft_text(),
                              "=== Agent sends signed POST request ===")
    raw_pk = sig.b64_unpadded_decode(EXPECTED_PK_B64)
    pk = Ed25519PublicKey.from_public_bytes(raw_pk)
    header = sig.build_header(EX_D, EX_S, EX_T, EX_N, token)
    res = sig.verify(header, pk, "DELETE", "/mcp/data/all", b"",
                     current_time=int(EX_T), seen_nonces=set())
    assert res.result == "sig_invalid"
