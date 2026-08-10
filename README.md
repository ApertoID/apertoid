# apertoid

Reference implementation of **ApertoID**, an open protocol for AI agent
identity built on DNS. ApertoID lets a domain owner declare which AI agents act
on its behalf, publish Ed25519 public keys for them in DNS, and lets agents
cryptographically sign each HTTP request so a service can verify the request
really came from the declared agent. It follows the same layered pattern as
SPF/DKIM/DMARC for email.

The protocol is specified in two IETF Internet-Drafts:

- **DNS records** — [draft-ferro-dnsop-apertoid-01](https://datatracker.ietf.org/doc/draft-ferro-dnsop-apertoid/)
  (Policy Record and Agent Declaration Record).
- **HTTP request signing** — [draft-ferro-httpbis-apertoid-sig-01](https://datatracker.ietf.org/doc/draft-ferro-httpbis-apertoid-sig/)
  (the `ApertoID-Signature` header).

This package is the reference implementation of the core operations in those
drafts, written strictly from the spec text (the same text lives in `spec/`).

## What this package provides

**DNS record parsing and validation** (`apertoid.parser`)
- `parse_record(raw)` turns a single TXT record string into a validated
  `ParsedRecord`, checking every tag value against the draft's Section 5.1 ABNF
  and enforcing the cross-tag rules from Sections 7.3 and 8 (for example
  `url`/`include` mutual exclusion, `k` requires `pk` and `exp`, duplicate known
  tags are a `permerror`, revocation records are exempt from needing an
  endpoint). It never raises; malformed input is reported as diagnostics, which
  mirrors the spec's `permerror` posture.
- `validate_selector(selector)` checks an agent selector against the Section 7.1
  DNS-label rule.

**HTTP request signing and verification** (`apertoid.sig`)
- `construct_signing_input(...)` builds the deterministic, byte-exact signing
  input of Section 3.1 (seven LF-terminated components).
- `sign(...)` produces a raw 64-byte Ed25519 signature, unpadded Base64
  (86 characters).
- `build_header(...)` assembles the `ApertoID-Signature` header value.
- `parse_header(...)` parses that header back into its tags.
- `verify(...)` performs the local verification of Section 4: header parse, a
  two-sided timestamp window, nonce replay check, and the Ed25519 signature
  check. Per the draft's Section 4 step 9a, a nonce is recorded in the caller's
  replay cache only *after* the signature verifies, so a request with a bad
  signature cannot burn a nonce or flood the cache.

**End-to-end verification** (`apertoid.verify`)
- `verify_apertoid(claimed_domain, selector, agent_url, resolver, ...)`
  implements the DNS verification procedure of Section 11.2 in full: policy and
  agent-record lookup, Section 6.1 multi-record selection, revocation
  (checked first), `include=` delegation with the Section 8 DoS limits (one
  delegation hop, at most 10 total DNS queries, cycle detection) and a
  revocation re-check on every delegated record, `exp` expiry against
  wall-clock time, and Section 11.4 URL matching. It returns a
  `VerificationResult` carrying the outcome, the algorithm step that produced
  it, the domain's enforcement policy `p=`, and the resolved public key.
- `verify_request(header_value, resolver, method, target, body, agent_url, ...)`
  is the signature-to-DNS bridge (`-sig` Section 4): it resolves and validates
  the agent via `verify_apertoid`, and only if that passes verifies the request
  signature via `sig.verify` with the DNS-published key. DNS is resolved through
  an injectable `Resolver`, so verification runs offline in tests and against
  live DNS in production via `DnsPythonResolver` (optional, needs `dnspython`).

**Conformance harness** (`tests/`)
- The test suite parses the record and signature examples printed in the two
  drafts and checks them byte-for-byte: every example DNS record parses as the
  spec dictates, and the drafts' own example signature cryptographically
  verifies against the published public key.
- Run in CI across Python 3.10 through 3.14.

The spec work also produced two catalogues of ambiguities and defects found
while implementing from the text: [`FINDINGS.md`](FINDINGS.md) (DNS draft) and
[`FINDINGS-sig.md`](FINDINGS-sig.md) (signing draft).

## Scope

Both layers and the bridge between them are implemented. `verify_apertoid`
covers the full Section 11.2 DNS verification algorithm — record lookup and
selection, revocation, `include=` delegation with its Section 8 limits, `exp`
expiry, and Section 11.4 URL matching — and `verify_request` ties that to the
signature check of `-sig` Section 4, resolving the agent's key from DNS instead
of taking it as an argument. DNS access goes through an injectable `Resolver`;
`DnsPythonResolver` provides live lookups (optional, needs `dnspython`), while
`StaticResolver` drives the tests offline.

What is genuinely **not** built:

- **`prev=` key-rotation continuity verification** (Section 10.2). Following a
  key rotation requires a cache of previously seen keys to check the `prev`
  signature against; that historical key store is deferred to future work. Key
  rotation still works at the DNS-authority level (a new key published by the
  zone owner is accepted); only the extra continuity proof is unverified.
- **Live DNS is optional, not the default.** The core logic depends only on the
  `Resolver` protocol. Production callers pass a `DnsPythonResolver`; nothing in
  the library performs network I/O on its own.

The implementation was written strictly from the spec, and the ambiguities that
surfaced in the verification procedure are catalogued as findings P1–P3 in
[`FINDINGS.md`](FINDINGS.md) (revocation of an `include=` target, the delegation
depth wording, and the trailing-slash URL rule).

## Install

```bash
pip install apertoid
```

Requires Python >= 3.9 and depends on `cryptography` (for Ed25519).

## Usage

```python
from apertoid import parse_record, sig
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# Parse and validate a DNS Agent Declaration Record.
rec = parse_record(
    "v=APERTOID1; url=https://agent.example.com/mcp; "
    "k=ed25519; pk=2TmyMjizLUEeS0F9GJvGedF4syZFYvrWl+oFHv56VSY; "
    "type=ai; exp=1759276800"
)
print(rec.record_type)   # RecordType.AGENT
print(rec.is_valid)      # True
print(rec.get("pk"))     # the 43-char raw Ed25519 key
for d in rec.diagnostics:
    print(d)             # [severity:code] message

# Sign an HTTP request and verify it.
sk = Ed25519PrivateKey.generate()
d, s, t, n = "example.com", "leadhunter", "1711100000", "a1b2c3d4e5f6"
method, target, body = "POST", "/mcp/tools/search", b'{"query": "leads"}'

signature = sig.sign(sk, d, s, t, n, method, target, body)
header = sig.build_header(d, s, t, n, signature)   # ApertoID-Signature value

result = sig.verify(
    header, sk.public_key(), method, target, body,
    current_time=int(t), seen_nonces=set(),
)
print(result.result)     # "pass"
```

`sig.verify(...)` returns a `VerifyResult` whose `.result` is one of `pass`,
`malformed`, `timestamp_invalid`, `nonce_reused`, or `sig_invalid`. It takes the
public key as an argument. To resolve that key from DNS and verify the whole
request in one call, use `verify_request` below.

### End-to-end: verify a signed request against DNS

```python
from apertoid import verify_request, StaticResolver, sig, Outcome
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# The agent's signing key, and its raw public key encoded for the DNS record
# (43-char unpadded Base64).
sk = Ed25519PrivateKey.generate()
pk_raw = sk.public_key().public_bytes_raw()
pk_b64 = sig.b64_unpadded(pk_raw)

d, s, t, n = "example.com", "leadhunter", "1711100000", "a1b2c3d4e5f6"
method, target, body = "POST", "/mcp/tools/search", b'{"query": "leads"}'
agent_url = "https://agent.example.com/mcp"   # canonical URL the request hit

# The domain's DNS records. In production this is a DnsPythonResolver; here a
# StaticResolver stands in so the example is self-contained.
resolver = StaticResolver({
    "_apertoid.example.com": "v=APERTOID1; p=reject",
    "leadhunter._apertoid.example.com": (
        f"v=APERTOID1; url={agent_url}; k=ed25519; pk={pk_b64}; "
        f"type=ai; exp=4102444800"
    ),
})

# The agent signs the request and sends the header.
signature = sig.sign(sk, d, s, t, n, method, target, body)
header = sig.build_header(d, s, t, n, signature)

# The service verifies it end to end: DNS lookup + key resolution + signature.
result = verify_request(
    header, resolver, method, target, body, agent_url,
    current_time=int(t), seen_nonces=set(),
)
print(result.outcome)   # Outcome.PASS
print(result.step)      # "pass"
print(result.policy)    # Policy.REJECT  (what to do if it had failed)
```

`verify_request(...)` and `verify_apertoid(...)` return a `VerificationResult`
with `.outcome` (an `Outcome`: `pass`, `none`, `revoked`, `expired`,
`url_mismatch`, `key_mismatch`, `permerror`, `temperror`, or the signature-layer
`malformed`, `timestamp_invalid`, `nonce_reused`, `sig_invalid`), `.step` (the
algorithm step that produced it), `.policy` (the domain's `p=`, so a caller
learns both that a request failed *and* whether the domain says to reject it),
and `.pk` (the resolved key). If the DNS side fails, `verify_request` returns
that result without checking the signature.

## Development

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[test]"
.venv/bin/python -m pytest -q
```

## License

MIT. Source: <https://github.com/ApertoID/apertoid>
