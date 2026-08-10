"""Run the ApertoID-Signature impl against the -sig draft's own examples.

Exercises Section 3.1 (signing input), 3.3 (example), and Appendix A (full
request/response) exactly as written, and records where the draft's own
examples cannot be reproduced or verified. Diagnostic, not fix.

Run standalone for the report:  python tests/test_sig_draft_examples.py
"""

import base64
import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from apertoid import sig  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

# The example request from Section 3.3 / Appendix A.
EX_D = "example.com"
EX_S = "leadhunter"
EX_T = "1711100000"
EX_N = "a1b2c3d4e5f6"
EX_METHOD = "POST"
EX_TARGET = "/mcp/tools/search"
EX_BODY = b'{"query": "find leads in tech sector", "limit": 10}'

# The signing-input body_hash placeholder shown in the draft (§3.3): "7d5e4a8b..."
DRAFT_BODY_HASH_PREFIX = "7d5e4a8b"

# The placeholder signature strings that appear in the draft.
DRAFT_SIG_PLACEHOLDERS = [
    "MEUCIQDx4f",                              # §3.3, Appendix A (truncated)
    "MEUCIQDx4fakebase64signaturehere",        # Appendix A full-request
]


def report():
    print("=== ApertoID-Signature draft-example diagnosis ===\n")

    # 1. Does the real SHA-256 of the shown body match the draft's placeholder?
    real_hash = hashlib.sha256(EX_BODY).hexdigest()
    print(f"[1] body_hash of the §3.3 JSON body:")
    print(f"    real   : {real_hash}")
    print(f"    draft  : {DRAFT_BODY_HASH_PREFIX}...  -> matches: "
          f"{real_hash.startswith(DRAFT_BODY_HASH_PREFIX)}")

    # 2. What does the placeholder signature decode to?
    print("\n[2] placeholder sig decode:")
    for p in DRAFT_SIG_PLACEHOLDERS:
        try:
            raw = base64.b64decode(p + "=" * (-len(p) % 4))
            is_der = len(raw) >= 1 and raw[0] == 0x30
            kind = "ASN.1 DER (0x30 SEQUENCE)" if is_der else "raw?"
            print(f"    {p!r:40} -> {raw.hex()} ({kind})")
        except Exception as e:
            print(f"    {p!r:40} -> undecodable: {e}")

    # 3. Round-trip: sign the example with a real key, verify it. Proves the
    #    signing-input construction is self-consistent even though the draft's
    #    own example signature is a placeholder.
    print("\n[3] round-trip with a REAL Ed25519 key (deterministic seed):")
    seed = hashlib.sha256(b"apertoid-sig-example:leadhunter").digest()
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    pk = sk.public_key()
    signing_input = sig.construct_signing_input(
        EX_D, EX_S, EX_T, EX_N, EX_METHOD, EX_TARGET, EX_BODY)
    print("    signing_input bytes (repr):")
    print("    " + repr(signing_input))
    real_sig = sig.sign(sk, EX_D, EX_S, EX_T, EX_N, EX_METHOD, EX_TARGET, EX_BODY)
    print(f"    signature (unpadded b64): {real_sig}")
    print(f"    signature length        : {len(real_sig)} chars "
          f"(draft says 88; correct is 86)")

    header = sig.build_header(EX_D, EX_S, EX_T, EX_N, real_sig)
    res = sig.verify(header, pk, EX_METHOD, EX_TARGET, EX_BODY,
                     current_time=int(EX_T), seen_nonces=set())
    print(f"    verify result           : {res.result}")

    # 4. Action-binding: replay to DELETE /mcp/data/all must fail (Appendix A).
    res2 = sig.verify(header, pk, "DELETE", "/mcp/data/all", b"",
                      current_time=int(EX_T), seen_nonces=set())
    print(f"\n[4] replay to DELETE /mcp/data/all -> {res2.result} "
          f"(expected sig_invalid)")


# ---- pytest ----

def _key():
    seed = hashlib.sha256(b"apertoid-sig-example:leadhunter").digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


def test_signing_input_is_reproducible_and_verifiable():
    sk = _key()
    pk = sk.public_key()
    s = sig.sign(sk, EX_D, EX_S, EX_T, EX_N, EX_METHOD, EX_TARGET, EX_BODY)
    assert len(s) == 86  # raw 64-byte sig, unpadded -> 86, NOT 88
    header = sig.build_header(EX_D, EX_S, EX_T, EX_N, s)
    res = sig.verify(header, pk, EX_METHOD, EX_TARGET, EX_BODY,
                     current_time=int(EX_T), seen_nonces=set())
    assert res.result == "pass", res.detail


def test_draft_body_hash_placeholder_is_wrong():
    # The draft shows body_hash "7d5e4a8b..." for the given JSON; it is a
    # placeholder that does not match the real SHA-256 (FINDINGS-sig S5).
    real = hashlib.sha256(EX_BODY).hexdigest()
    assert not real.startswith(DRAFT_BODY_HASH_PREFIX)


def test_action_binding_blocks_replay():
    sk = _key()
    pk = sk.public_key()
    s = sig.sign(sk, EX_D, EX_S, EX_T, EX_N, EX_METHOD, EX_TARGET, EX_BODY)
    header = sig.build_header(EX_D, EX_S, EX_T, EX_N, s)
    res = sig.verify(header, pk, "DELETE", "/mcp/data/all", b"",
                     current_time=int(EX_T), seen_nonces=set())
    assert res.result == "sig_invalid"


def test_placeholder_sig_is_der_not_raw():
    # sig=MEUCIQD... decodes to an ASN.1 DER ECDSA structure (0x30 SEQUENCE),
    # not a raw Ed25519 signature (FINDINGS-sig S4).
    raw = base64.b64decode("MEUCIQD" + "=" * ((-len("MEUCIQD")) % 4))
    assert raw[0] == 0x30  # ASN.1 SEQUENCE tag


def test_bad_signature_does_not_consume_nonce():
    """Section 4 step 9a (S11/L1): the nonce is inserted into the cache ONLY
    after the signature verifies. A request with an INVALID signature MUST NOT
    add its nonce to the cache -- otherwise an unauthenticated attacker could
    burn a victim's future nonce or flood the cache (nonce-burn / DoS).

    This fails on the old ordering (which added the nonce before verifying)
    and passes once the insert is moved to after a successful verify.
    """
    sk = _key()
    pk = sk.public_key()
    cache: set = set()

    # A bogus signature (valid 86-char base64 shape, wrong bytes) over the
    # example request. Verification must fail...
    bogus_sig = "A" * 86
    bad_header = sig.build_header(EX_D, EX_S, EX_T, EX_N, bogus_sig)
    res_bad = sig.verify(bad_header, pk, EX_METHOD, EX_TARGET, EX_BODY,
                         current_time=int(EX_T), seen_nonces=cache)
    assert res_bad.result == "sig_invalid", res_bad.detail
    # ...and CRUCIALLY it must NOT have consumed the nonce.
    assert EX_N not in cache, (
        "invalid-signature request burned the nonce (step 9a violated): "
        "nonce was inserted before the signature verified"
    )

    # The legitimate agent's genuine request with the SAME nonce still passes,
    # because the bad request left the cache untouched.
    good_sig = sig.sign(sk, EX_D, EX_S, EX_T, EX_N, EX_METHOD, EX_TARGET, EX_BODY)
    good_header = sig.build_header(EX_D, EX_S, EX_T, EX_N, good_sig)
    res_good = sig.verify(good_header, pk, EX_METHOD, EX_TARGET, EX_BODY,
                          current_time=int(EX_T), seen_nonces=cache)
    assert res_good.result == "pass", res_good.detail
    # A valid request DOES record the nonce (so a genuine replay is caught).
    assert EX_N in cache
    res_replay = sig.verify(good_header, pk, EX_METHOD, EX_TARGET, EX_BODY,
                            current_time=int(EX_T), seen_nonces=cache)
    assert res_replay.result == "nonce_reused"


if __name__ == "__main__":
    report()
