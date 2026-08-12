"""Timestamp-window range enforcement (Section 5: default 300s, [60, 600]).

The draft states the validity window is configurable "within the range of 60 to
600 seconds" (inclusive). An out-of-range window is an insecure configuration
(too large widens the replay window; too small fails legitimate requests on
normal skew), so the verifier rejects it with a ValueError at call time rather
than accepting silently. Validation lives in one place (sig._check_window) and
is invoked by both sig.verify and verify_request.
"""

import hashlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from apertoid import sig  # noqa: E402
from apertoid.resolver import StaticResolver  # noqa: E402
from apertoid.verify import Outcome, verify_request  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: E402
    Ed25519PrivateKey,
)

EX_D, EX_S, EX_T, EX_N = "example.com", "leadhunter", "1711100000", "a1b2c3d4e5f6"
EX_METHOD, EX_TARGET, EX_BODY = "POST", "/mcp/tools/search", b"{}"
NOW = int(EX_T)
AGENT_URL = "https://agent.example.com/mcp"


def _key():
    return Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(b"apertoid-sig-example:leadhunter").digest()
    )


def _signed_header(sk):
    signature = sig.sign(sk, EX_D, EX_S, EX_T, EX_N, EX_METHOD, EX_TARGET, EX_BODY)
    return sig.build_header(EX_D, EX_S, EX_T, EX_N, signature)


def _pk_b64(sk):
    return sig.b64_unpadded(sk.public_key().public_bytes_raw())


def _resolver(pk_b64):
    return StaticResolver({
        f"_apertoid.{EX_D}": "v=APERTOID1; p=reject",
        f"{EX_S}._apertoid.{EX_D}": (
            f"v=APERTOID1; url={AGENT_URL}; k=ed25519; pk={pk_b64}; "
            f"type=ai; exp=4102444800"
        ),
    })


# ---------------------------------------------------------------------------
# bounds constants match the draft
# ---------------------------------------------------------------------------

def test_bounds_constants():
    assert sig.DEFAULT_WINDOW == 300
    assert sig.MIN_WINDOW == 60
    assert sig.MAX_WINDOW == 600


# ---------------------------------------------------------------------------
# sig.verify() layer
# ---------------------------------------------------------------------------

def _verify(sk, window):
    return sig.verify(_signed_header(sk), sk.public_key(), EX_METHOD, EX_TARGET,
                      EX_BODY, current_time=NOW, window=window, seen_nonces=set())


def test_default_window_works():
    assert _verify(_key(), 300).result == "pass"


@pytest.mark.parametrize("w", [60, 600, 61, 599, 300])
def test_in_range_windows_accepted(w):
    # Inclusive boundaries 60 and 600 both work, per "within the range of 60 to
    # 600 seconds".
    assert _verify(_key(), w).result == "pass"


@pytest.mark.parametrize("w", [59, 601, 0, 1, 3600, -1])
def test_out_of_range_windows_raise(w):
    with pytest.raises(ValueError) as ei:
        _verify(_key(), w)
    msg = str(ei.value)
    assert str(w) in msg            # value received
    assert "60" in msg and "600" in msg   # allowed range


def test_error_message_is_informative():
    with pytest.raises(ValueError) as ei:
        _verify(_key(), 5000)
    msg = str(ei.value)
    assert "5000" in msg
    assert "60 to 600" in msg
    assert "Section 5" in msg


# ---------------------------------------------------------------------------
# verify_request() layer -- validated up front, even before DNS
# ---------------------------------------------------------------------------

def test_verify_request_in_range_passes():
    sk = _key()
    res = verify_request(_signed_header(sk), _resolver(_pk_b64(sk)), EX_METHOD,
                         EX_TARGET, EX_BODY, AGENT_URL, current_time=NOW,
                         window=60, seen_nonces=set())
    assert res.outcome is Outcome.PASS


def test_verify_request_out_of_range_raises():
    sk = _key()
    with pytest.raises(ValueError):
        verify_request(_signed_header(sk), _resolver(_pk_b64(sk)), EX_METHOD,
                       EX_TARGET, EX_BODY, AGENT_URL, current_time=NOW,
                       window=601, seen_nonces=set())


def test_verify_request_window_checked_before_dns():
    # Even when DNS would fail (empty resolver -> 'none'), an out-of-range window
    # must raise FIRST -- proving the check is up front, not only inside
    # sig.verify (which a DNS-fail path never reaches).
    sk = _key()
    empty = StaticResolver({})
    with pytest.raises(ValueError):
        verify_request(_signed_header(sk), empty, EX_METHOD, EX_TARGET, EX_BODY,
                       AGENT_URL, current_time=NOW, window=10, seen_nonces=set())


def test_shared_validator_single_source():
    # Both entry points route through the same function; calling it directly
    # reproduces the behavior (single source of truth).
    sig._check_window(300)          # no raise
    sig._check_window(60)           # inclusive
    sig._check_window(600)          # inclusive
    with pytest.raises(ValueError):
        sig._check_window(59)
