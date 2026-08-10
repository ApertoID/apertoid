"""Negative / adversarial tests for sig.verify().

The happy path is covered in test_sig_draft_examples.py. This file proves the
security-relevant REJECTIONS: for each tampering/attack case we build a valid
signed request, break exactly ONE thing, and assert the specific VerifyResult
that Section 4 requires. These are the checks that make the mechanism worth
anything -- a verifier that accepts a tampered request is worse than none.

Deterministic keys (seeded) so the tests are reproducible.
"""

import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from apertoid import sig  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: E402
    Ed25519PrivateKey,
)

# Same example request as the draft (matches test_sig_draft_examples.py).
EX_D = "example.com"
EX_S = "leadhunter"
EX_T = "1711100000"
EX_N = "a1b2c3d4e5f6"
EX_METHOD = "POST"
EX_TARGET = "/mcp/tools/search"
EX_BODY = b'{"query": "find leads in tech sector", "limit": 10}'


def _key():
    seed = hashlib.sha256(b"apertoid-sig-example:leadhunter").digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


def _other_key():
    seed = hashlib.sha256(b"apertoid-sig-example:attacker").digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


def _signed_header(sk, d=EX_D, s=EX_S, t=EX_T, n=EX_N,
                   method=EX_METHOD, target=EX_TARGET, body=EX_BODY):
    """Build a genuinely valid ApertoID-Signature header for the given inputs."""
    signature = sig.sign(sk, d, s, t, n, method, target, body)
    return sig.build_header(d, s, t, n, signature)


def test_baseline_valid_request_passes():
    """Sanity anchor: the unbroken request verifies, so any failure below is
    caused by the single thing we tampered, not by a broken fixture."""
    sk = _key()
    header = _signed_header(sk)
    res = sig.verify(header, sk.public_key(), EX_METHOD, EX_TARGET, EX_BODY,
                     current_time=int(EX_T), seen_nonces=set())
    assert res.result == "pass", res.detail


def test_tampered_body_rejected():
    """Sign over body A, verify against body B -> sig_invalid (body binding)."""
    sk = _key()
    header = _signed_header(sk, body=b'{"query": "original"}')
    res = sig.verify(header, sk.public_key(), EX_METHOD, EX_TARGET,
                     b'{"query": "TAMPERED"}',
                     current_time=int(EX_T), seen_nonces=set())
    assert res.result == "sig_invalid", res.detail


def test_tampered_method_rejected():
    """Sign as POST, verify as GET -> sig_invalid (action binding)."""
    sk = _key()
    header = _signed_header(sk, method="POST")
    res = sig.verify(header, sk.public_key(), "GET", EX_TARGET, EX_BODY,
                     current_time=int(EX_T), seen_nonces=set())
    assert res.result == "sig_invalid", res.detail


def test_tampered_target_rejected():
    """Sign for /a, verify for /b -> sig_invalid (endpoint binding)."""
    sk = _key()
    header = _signed_header(sk, target="/mcp/tools/search")
    res = sig.verify(header, sk.public_key(), EX_METHOD, "/mcp/tools/delete",
                     EX_BODY, current_time=int(EX_T), seen_nonces=set())
    assert res.result == "sig_invalid", res.detail


def test_wrong_key_rejected():
    """A valid signature verified against a DIFFERENT public key -> sig_invalid."""
    sk = _key()
    header = _signed_header(sk)
    wrong_pub = _other_key().public_key()
    res = sig.verify(header, wrong_pub, EX_METHOD, EX_TARGET, EX_BODY,
                     current_time=int(EX_T), seen_nonces=set())
    assert res.result == "sig_invalid", res.detail


def test_expired_timestamp_rejected():
    """t far in the PAST (outside the window) -> timestamp_invalid."""
    sk = _key()
    header = _signed_header(sk)
    # now is 10 minutes after t; default window is 300s.
    res = sig.verify(header, sk.public_key(), EX_METHOD, EX_TARGET, EX_BODY,
                     current_time=int(EX_T) + 600, seen_nonces=set())
    assert res.result == "timestamp_invalid", res.detail


def test_future_timestamp_rejected():
    """t far in the FUTURE (two-sided window) -> timestamp_invalid."""
    sk = _key()
    header = _signed_header(sk)
    # now is 10 minutes BEFORE t; a one-sided (past-only) check would wrongly
    # accept this, so this test also pins the two-sidedness of the window.
    res = sig.verify(header, sk.public_key(), EX_METHOD, EX_TARGET, EX_BODY,
                     current_time=int(EX_T) - 600, seen_nonces=set())
    assert res.result == "timestamp_invalid", res.detail


def test_nonce_reuse_rejected():
    """Same nonce twice with a valid sig and a shared cache -> nonce_reused."""
    sk = _key()
    pk = sk.public_key()
    header = _signed_header(sk)
    cache: set = set()
    first = sig.verify(header, pk, EX_METHOD, EX_TARGET, EX_BODY,
                       current_time=int(EX_T), seen_nonces=cache)
    assert first.result == "pass", first.detail
    second = sig.verify(header, pk, EX_METHOD, EX_TARGET, EX_BODY,
                        current_time=int(EX_T), seen_nonces=cache)
    assert second.result == "nonce_reused", second.detail


def test_malformed_header_missing_tag_rejected():
    """A header missing a REQUIRED tag (n=) -> malformed."""
    sk = _key()
    signature = sig.sign(sk, EX_D, EX_S, EX_T, EX_N, EX_METHOD, EX_TARGET, EX_BODY)
    # Hand-build a header WITHOUT the n= tag (build_header always includes it).
    header = f"d={EX_D}; s={EX_S}; t={EX_T}; sig={signature}"
    res = sig.verify(header, sk.public_key(), EX_METHOD, EX_TARGET, EX_BODY,
                     current_time=int(EX_T), seen_nonces=set())
    assert res.result == "malformed", res.detail


def test_flipped_signature_char_rejected_and_nonce_not_consumed():
    """Flip one char of a valid sig -> sig_invalid, AND the nonce is NOT
    consumed (ties to the Section 4 step 9a fix: a bad-sig request must not
    mutate the replay cache)."""
    sk = _key()
    pk = sk.public_key()
    good = sig.sign(sk, EX_D, EX_S, EX_T, EX_N, EX_METHOD, EX_TARGET, EX_BODY)
    # Flip the first character to a different valid Base64 char.
    flipped = ("B" if good[0] != "B" else "C") + good[1:]
    assert flipped != good and len(flipped) == 86
    header = sig.build_header(EX_D, EX_S, EX_T, EX_N, flipped)
    cache: set = set()
    res = sig.verify(header, pk, EX_METHOD, EX_TARGET, EX_BODY,
                     current_time=int(EX_T), seen_nonces=cache)
    assert res.result == "sig_invalid", res.detail
    assert EX_N not in cache, "tampered-signature request consumed the nonce"
