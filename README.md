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

**Conformance harness** (`tests/`)
- The test suite parses the record and signature examples printed in the two
  drafts and checks them byte-for-byte: every example DNS record parses as the
  spec dictates, and the drafts' own example signature cryptographically
  verifies against the published public key.
- **82 tests**, run in CI across Python 3.10 through 3.14.

The spec work also produced two catalogues of ambiguities and defects found
while implementing from the text: [`FINDINGS.md`](FINDINGS.md) (DNS draft) and
[`FINDINGS-sig.md`](FINDINGS-sig.md) (signing draft).

## Scope

This is a reference implementation of the core, per-record and per-request
operations, plus a harness proving the drafts' own examples are correct. It is
**not** a full turnkey verifier yet. In particular, the end-to-end resolver that
ties the two layers together — receive a signed HTTP request, look up the
agent's key in DNS, follow `include=` delegation, check `exp`/revocation, then
verify the signature (a single `verify_apertoid(...)` entry point) — is **not
yet built**. Also not yet implemented: live DNS lookups, `include=` delegation
resolution, `exp` expiry checks against wall-clock time, Section 11.4 URL
matching, and `prev=` key-rotation continuity verification. `verify()` today
takes the public key as an argument rather than resolving it from DNS.

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

`verify(...)` returns a `VerifyResult` whose `.result` is one of `pass`,
`malformed`, `timestamp_invalid`, `nonce_reused`, or `sig_invalid`. In a real
deployment the `public_key` argument is the key published in the agent's DNS
record; resolving it from DNS is the not-yet-built end-to-end step described
under Scope.

## Development

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[test]"
.venv/bin/python -m pytest -q        # 82 tests
```

## License

MIT. Source: <https://github.com/ApertoID/apertoid>
