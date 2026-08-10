"""Tests for verify_request() -- the sig<->DNS bridge (Phase 2, Block 5).

End-to-end: a signed HTTP request is verified against DNS-published records via
verify_request(header, resolver, method, target, body, agent_url, ...). Uses
real Ed25519 keys and a StaticResolver (no live DNS). These tests prove:

  * happy path: valid signature + DNS record with matching pk/url -> pass;
  * DNS failure short-circuits BEFORE any signature check (none/permerror/
    revoked -- the sig is never examined);
  * valid DNS but a bad signature -> sig_invalid;
  * timestamp/nonce handling is delegated to sig.verify (surfaced through the
    bridge), and the nonce is inserted into the cache only after full success.
"""

import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from apertoid import sig  # noqa: E402
from apertoid.resolver import LookupStatus, StaticResolver, TxtLookup  # noqa: E402
from apertoid.verify import Outcome, Policy, verify_request  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: E402
    Ed25519PrivateKey,
)

# --- fixtures ---------------------------------------------------------------

EX_D = "example.com"
EX_S = "leadhunter"
EX_T = "1711100000"
EX_N = "a1b2c3d4e5f6"
EX_METHOD = "POST"
EX_TARGET = "/mcp/tools/search"
EX_BODY = b'{"query": "find leads", "limit": 10}'
AGENT_URL = "https://agent.example.com/mcp"

POLICY_NAME = f"_apertoid.{EX_D}"
AGENT_NAME = f"{EX_S}._apertoid.{EX_D}"
NOW = int(EX_T)
FUTURE = 4102444800


def _key():
    seed = hashlib.sha256(b"apertoid-sig-example:leadhunter").digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


def _other_key():
    seed = hashlib.sha256(b"apertoid-sig-example:attacker").digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


def _pk_b64(sk):
    return sig.b64_unpadded(sk.public_key().public_bytes_raw())


def _signed_header(sk, d=EX_D, s=EX_S, t=EX_T, n=EX_N,
                   method=EX_METHOD, target=EX_TARGET, body=EX_BODY):
    signature = sig.sign(sk, d, s, t, n, method, target, body)
    return sig.build_header(d, s, t, n, signature)


def _agent_record(pk_b64, url=AGENT_URL, extra=""):
    return f"v=APERTOID1; url={url}; k=ed25519; pk={pk_b64}; type=ai; exp={FUTURE}{extra}"


def _resolver(pk_b64, policy="v=APERTOID1; p=reject", agent=None, **overrides):
    mapping = {POLICY_NAME: policy}
    if agent is None:
        agent = _agent_record(pk_b64)
    if agent is not False:
        mapping[AGENT_NAME] = agent
    mapping.update(overrides)
    return StaticResolver(mapping)


def _verify(header, resolver, *, method=EX_METHOD, target=EX_TARGET,
            body=EX_BODY, agent_url=AGENT_URL, now=NOW, seen_nonces=None,
            window=300):
    return verify_request(
        header, resolver, method, target, body, agent_url,
        current_time=now, window=window, seen_nonces=seen_nonces,
    )


# --- happy path -------------------------------------------------------------

def test_happy_path_passes():
    sk = _key()
    header = _signed_header(sk)
    res = _verify(header, _resolver(_pk_b64(sk)), seen_nonces=set())
    assert res.outcome is Outcome.PASS
    assert res.step == "pass"
    assert res.policy is Policy.REJECT
    assert res.pk == _pk_b64(sk)


def test_keyed_record_success_sets_signature_verified():
    # A real Ed25519 check that PASSES must set signature_verified True (V1).
    sk = _key()
    header = _signed_header(sk)
    res = _verify(header, _resolver(_pk_b64(sk)), seen_nonces=set())
    assert res.outcome is Outcome.PASS
    assert res.signature_verified is True


def test_url_only_record_passes_without_crypto():
    # A url-only agent record (no pk=) is a legal DNS-layer PASS (F10). A signed
    # request to it is authorized by URL match, but the signature is NOT
    # cryptographically verified: PASS with signature_verified False, pk None
    # (decision V1; spec gap P4). sig.verify is never reached, so even a
    # wrong-key signature is irrelevant here.
    header = _signed_header(_other_key())  # any signature; not checked
    r = _resolver(_pk_b64(_key()), agent=f"v=APERTOID1; url={AGENT_URL}")
    res = _verify(header, r, seen_nonces=set())
    assert res.outcome is Outcome.PASS
    assert res.step == "pass"
    assert res.policy is Policy.REJECT
    assert res.signature_verified is False
    assert res.pk is None
    assert res.lookups == 2  # policy + agent, no crypto
    assert "not cryptographically verified" in res.detail


# --- DNS failure short-circuits before the signature check ------------------

def test_no_policy_is_none_without_sig_check():
    sk = _key()
    # Even a totally BOGUS signature must not matter: DNS says the domain
    # publishes no ApertoID, so we return none before touching crypto.
    header = _signed_header(_other_key())  # signed by the wrong key
    empty = StaticResolver({})             # no policy record
    res = _verify(header, empty)
    assert res.outcome is Outcome.NONE
    assert res.step == "11.2#2"


def test_no_agent_record_is_permerror_without_sig_check():
    sk = _key()
    header = _signed_header(_other_key())  # wrong-key sig, must not be reached
    r = _resolver(_pk_b64(sk), agent=False)  # policy present, no agent record
    res = _verify(header, r)
    assert res.outcome is Outcome.PERMERROR
    assert res.step == "11.2#5"


def test_revoked_agent_short_circuits_before_sig():
    sk = _key()
    header = _signed_header(_other_key())  # bad sig, must be irrelevant
    r = _resolver(_pk_b64(sk), agent="v=APERTOID1; status=revoked")
    res = _verify(header, r)
    assert res.outcome is Outcome.REVOKED
    assert res.step == "11.2#7"
    assert res.policy is Policy.REJECT


def test_url_mismatch_short_circuits_before_sig():
    sk = _key()
    header = _signed_header(sk)  # a VALID signature...
    r = _resolver(_pk_b64(sk))
    # ...but the request arrived on a different URL than the record declares.
    res = _verify(header, r, agent_url="https://agent.example.com/other")
    assert res.outcome is Outcome.URL_MISMATCH
    assert res.step == "11.2#10"


def test_dns_temperror_short_circuits():
    sk = _key()
    header = _signed_header(sk)
    r = _resolver(_pk_b64(sk))
    r.set(AGENT_NAME, TxtLookup(LookupStatus.TEMPFAIL))
    res = _verify(header, r)
    assert res.outcome is Outcome.TEMPERROR
    assert res.step == "11.2#4"


# --- valid DNS, bad signature -> sig_invalid --------------------------------

def test_valid_dns_wrong_signing_key_is_sig_invalid():
    # DNS publishes the REAL key; the request is signed by a different key.
    real = _key()
    attacker = _other_key()
    header = _signed_header(attacker)
    r = _resolver(_pk_b64(real))  # record carries real's pk
    res = _verify(header, r, seen_nonces=set())
    assert res.outcome is Outcome.SIG_INVALID
    assert res.step == "sig#9"
    assert res.policy is Policy.REJECT  # policy still attached from DNS
    assert res.signature_verified is False  # V1: a failed crypto check is not "verified"


def test_tampered_body_is_sig_invalid():
    sk = _key()
    header = _signed_header(sk, body=b'{"query": "original"}')
    r = _resolver(_pk_b64(sk))
    res = _verify(header, r, body=b'{"query": "TAMPERED"}', seen_nonces=set())
    assert res.outcome is Outcome.SIG_INVALID
    assert res.step == "sig#9"


# --- timestamp / nonce delegated to sig.verify, surfaced by the bridge ------

def test_timestamp_outside_window_surfaces():
    sk = _key()
    header = _signed_header(sk)
    r = _resolver(_pk_b64(sk))
    # 10 minutes of skew, window 300s -> timestamp_invalid (two-sided).
    res = _verify(header, r, now=NOW + 600, seen_nonces=set())
    assert res.outcome is Outcome.TIMESTAMP_INVALID
    assert res.step == "sig#3"
    assert res.policy is Policy.REJECT


def test_nonce_reuse_surfaces():
    sk = _key()
    header = _signed_header(sk)
    r = _resolver(_pk_b64(sk))
    seen = {EX_N}  # nonce already used
    res = _verify(header, r, seen_nonces=seen)
    assert res.outcome is Outcome.NONCE_REUSED
    assert res.step == "sig#4"


def test_malformed_header_is_malformed():
    r = _resolver(_pk_b64(_key()))
    # Missing required tags: sig.verify owns the "malformed" verdict. This one
    # has no d/s either, exercising the early hand-off path.
    res = _verify("t=1711100000; n=abcd", r)
    assert res.outcome is Outcome.MALFORMED
    assert res.step == "sig#2"


# --- nonce inserted only after FULL success (Section 4 step 9a) -------------

def test_nonce_inserted_only_after_full_success():
    sk = _key()
    header = _signed_header(sk)
    seen = set()
    res = _verify(header, _resolver(_pk_b64(sk)), seen_nonces=seen)
    assert res.outcome is Outcome.PASS
    assert EX_N in seen  # recorded after the signature verified


def test_bad_signature_does_not_consume_nonce():
    # A request that fails the signature check must NOT burn the nonce (step 9a).
    real = _key()
    header = _signed_header(_other_key())  # wrong key -> sig_invalid
    seen = set()
    res = _verify(header, _resolver(_pk_b64(real)), seen_nonces=seen)
    assert res.outcome is Outcome.SIG_INVALID
    assert EX_N not in seen  # verifier state untouched by an unauthenticated req


def test_dns_failure_does_not_consume_nonce():
    # A DNS short-circuit happens before sig.verify runs at all, so the nonce
    # cache is never touched.
    sk = _key()
    header = _signed_header(sk)
    seen = set()
    r = _resolver(_pk_b64(sk), agent="v=APERTOID1; status=revoked")
    res = _verify(header, r, seen_nonces=seen)
    assert res.outcome is Outcome.REVOKED
    assert EX_N not in seen
