"""Body-size guard tests (body-hash DoS mitigation).

The verifier hashes the request body as part of the signing input. Without a
limit, an attacker can force the verifier to SHA-256 an arbitrarily large body
with a request that was never going to verify. The optional max_body_size caps
this: an over-limit body is rejected ("body_too_large" / Outcome.BODY_TOO_LARGE)
BEFORE the body is hashed. Default None preserves the pre-existing behavior.

Tested at both layers: sig.verify() (where the guard lives and the hash happens)
and verify_request() (which forwards the parameter). The "rejected before
hashing" property is proven non-vacuously by patching construct_signing_input --
the only place the body is hashed -- and asserting it is never called on the
over-limit path.
"""

import hashlib
import sys
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from apertoid import sig  # noqa: E402
from apertoid.resolver import StaticResolver  # noqa: E402
from apertoid.verify import Outcome, Policy, verify_request  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: E402
    Ed25519PrivateKey,
)

EX_D = "example.com"
EX_S = "leadhunter"
EX_T = "1711100000"
EX_N = "a1b2c3d4e5f6"
EX_METHOD = "POST"
EX_TARGET = "/mcp/tools/search"
NOW = int(EX_T)


def _key():
    return Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(b"apertoid-sig-example:leadhunter").digest()
    )


def _signed_header(sk, body):
    signature = sig.sign(sk, EX_D, EX_S, EX_T, EX_N, EX_METHOD, EX_TARGET, body)
    return sig.build_header(EX_D, EX_S, EX_T, EX_N, signature)


# ---------------------------------------------------------------------------
# sig.verify() layer
# ---------------------------------------------------------------------------

def test_body_under_limit_passes():
    sk = _key()
    body = b"x" * 100
    header = _signed_header(sk, body)
    res = sig.verify(header, sk.public_key(), EX_METHOD, EX_TARGET, body,
                     current_time=NOW, seen_nonces=set(), max_body_size=1000)
    assert res.result == "pass", res.detail


def test_body_at_limit_passes():
    # Boundary: exactly max_body_size is allowed (reject is on strictly greater).
    sk = _key()
    body = b"x" * 500
    header = _signed_header(sk, body)
    res = sig.verify(header, sk.public_key(), EX_METHOD, EX_TARGET, body,
                     current_time=NOW, seen_nonces=set(), max_body_size=500)
    assert res.result == "pass", res.detail


def test_body_over_limit_rejected():
    sk = _key()
    body = b"x" * 1001
    header = _signed_header(sk, body)
    res = sig.verify(header, sk.public_key(), EX_METHOD, EX_TARGET, body,
                     current_time=NOW, seen_nonces=set(), max_body_size=1000)
    assert res.result == "body_too_large", res.detail
    assert "1001" in res.detail and "1000" in res.detail


def test_over_limit_rejected_before_hashing():
    # NON-VACUITY: construct_signing_input is the ONLY place the body is hashed.
    # On the over-limit path it must never be called.
    sk = _key()
    body = b"x" * 5000
    header = _signed_header(sk, body)
    with mock.patch.object(
        sig, "construct_signing_input", wraps=sig.construct_signing_input
    ) as spy:
        res = sig.verify(header, sk.public_key(), EX_METHOD, EX_TARGET, body,
                         current_time=NOW, seen_nonces=set(), max_body_size=100)
    assert res.result == "body_too_large"
    spy.assert_not_called()  # body was NOT hashed


def test_under_limit_does_hash():
    # Complement: a within-limit request DOES reach the hash (proves the spy
    # above is meaningful -- construct_signing_input is genuinely on the path).
    sk = _key()
    body = b"x" * 50
    header = _signed_header(sk, body)
    with mock.patch.object(
        sig, "construct_signing_input", wraps=sig.construct_signing_input
    ) as spy:
        res = sig.verify(header, sk.public_key(), EX_METHOD, EX_TARGET, body,
                         current_time=NOW, seen_nonces=set(), max_body_size=100)
    assert res.result == "pass"
    spy.assert_called_once()


def test_default_none_preserves_behavior():
    # No limit -> arbitrarily large body still hashed and verified as before.
    sk = _key()
    body = b"x" * 100000
    header = _signed_header(sk, body)
    res = sig.verify(header, sk.public_key(), EX_METHOD, EX_TARGET, body,
                     current_time=NOW, seen_nonces=set())  # max_body_size default
    assert res.result == "pass", res.detail


def test_over_limit_does_not_consume_nonce():
    # An over-limit request is unauthenticated; like a bad signature, it MUST
    # NOT burn the nonce (the guard returns before the step-9a insertion).
    sk = _key()
    body = b"x" * 2000
    header = _signed_header(sk, body)
    cache: set = set()
    res = sig.verify(header, sk.public_key(), EX_METHOD, EX_TARGET, body,
                     current_time=NOW, seen_nonces=cache, max_body_size=100)
    assert res.result == "body_too_large"
    assert EX_N not in cache


# ---------------------------------------------------------------------------
# verify_request() layer (parameter forwarded)
# ---------------------------------------------------------------------------

AGENT_URL = "https://agent.example.com/mcp"
POLICY_NAME = f"_apertoid.{EX_D}"
AGENT_NAME = f"{EX_S}._apertoid.{EX_D}"
FUTURE = 4102444800


def _resolver(pk_b64):
    return StaticResolver({
        POLICY_NAME: "v=APERTOID1; p=reject",
        AGENT_NAME: (
            f"v=APERTOID1; url={AGENT_URL}; k=ed25519; pk={pk_b64}; "
            f"type=ai; exp={FUTURE}"
        ),
    })


def _pk_b64(sk):
    return sig.b64_unpadded(sk.public_key().public_bytes_raw())


def test_verify_request_under_limit_passes():
    sk = _key()
    body = b"x" * 100
    header = _signed_header(sk, body)
    res = verify_request(header, _resolver(_pk_b64(sk)), EX_METHOD, EX_TARGET,
                         body, AGENT_URL, current_time=NOW, seen_nonces=set(),
                         max_body_size=1000)
    assert res.outcome is Outcome.PASS
    assert res.signature_verified is True


def test_verify_request_over_limit_is_body_too_large():
    sk = _key()
    body = b"x" * 2000
    header = _signed_header(sk, body)
    res = verify_request(header, _resolver(_pk_b64(sk)), EX_METHOD, EX_TARGET,
                         body, AGENT_URL, current_time=NOW, seen_nonces=set(),
                         max_body_size=1000)
    assert res.outcome is Outcome.BODY_TOO_LARGE
    assert res.step == "sig#4b"
    assert res.policy is Policy.REJECT  # DNS passed, policy carried through
    assert res.signature_verified is False


def test_verify_request_default_none_preserves_behavior():
    sk = _key()
    body = b"x" * 50000
    header = _signed_header(sk, body)
    res = verify_request(header, _resolver(_pk_b64(sk)), EX_METHOD, EX_TARGET,
                         body, AGENT_URL, current_time=NOW, seen_nonces=set())
    assert res.outcome is Outcome.PASS
