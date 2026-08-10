# ApertoID-Signature spec findings — draft-ferro-httpbis-apertoid-sig-00

Ambiguities, contradictions, and bugs found while implementing the signing and
verification mechanism **strictly from the -sig draft** (Sections 2-4 and the
appendices). Same method and format as the DNS-draft `FINDINGS.md`: each item
cites the section, states the conflict, shows how the reference implementation
behaves, and proposes a fix. Severity is from an implementer's standpoint.

IDs are `S1`..`Sn` to keep them distinct from the DNS draft's `F1`..`F12`.

Nothing here is fixed and the draft source is untouched — this is diagnosis
only. The reference implementation is `src/apertoid/sig.py`; the draft-example
diagnosis harness is `tests/test_sig_draft_examples.py`.

The single highest-impact finding is **S1**: the signature length "88" is the
exact same padded-vs-unpadded defect that F1 was in the DNS draft, and it is
stated in four places, all of which contradict the draft's own normative
"unpadded" signing step.

---

## S1 — Signature length "88" contradicts "unpadded Base64" (CRITICAL, self-contradictory)

This is the S-side of DNS finding F1 and is a hard, arithmetic contradiction.

**§3.2 (Producing the Signature), step 6-7 (normative):** "producing a **64-byte
signature** ... Encode the signature as **unpadded Base64** per [RFC4648]
Section 4."
**§2.3 (sig tag):** "encoded as **unpadded Base64** ... (**88 characters** for
64 bytes)."
**§2.2 ABNF example / §3.3 / Appendix A:** `sig=<base64-ed25519-signature-**88chars**>`,
`sig=MEUCIQDx4f... (**88** base64 characters)`.

The arithmetic (verified): a 64-byte value in Base64 is **88 characters padded**
(one `=`) or **86 characters unpadded**. You cannot have "unpadded" AND "88".

- Unpadded 64-byte Base64 = **86** chars.
- 88 chars is the **padded** length, which contradicts "unpadded".

This is identical in kind to DNS F1 (which was resolved to raw/unpadded: pk=43,
sig=86). For coherence with the corrected DNS draft, the answer is the same:
raw 64-byte Ed25519 signature, standard Base64, unpadded = **86 characters**.

**Impl behavior:** follows the normative §3.2 procedure — raw 64-byte signature,
unpadded Base64 → 86 chars. `sig.py` validates `sig=` as exactly 86 Base64 chars.
The round-trip test produces an 86-char signature that verifies.

**Proposed fix:** replace every "88" with "86" (four locations: §2.2 ABNF
example comment, §2.3 sig-tag prose, §3.3 example, Appendix A × 2), and keep
"unpadded". State explicitly "86 characters (64 bytes, unpadded)".

---

## S2 — ABNF names the type "base64url" but lists the standard Base64 alphabet (HIGH)

**§2.2 ABNF:**
```
signature-tag = "sig=" base64url
base64url     = 1*( ALPHA / DIGIT / "+" / "/" / "=" )
```
Two problems in one production:
1. The production is **named `base64url`**, but "base64url" (RFC 4648 §5) uses
   `-` and `_`, NOT `+` and `/`. The alphabet listed (`+` `/`) is **standard**
   Base64 (RFC 4648 §4), which is also what §3.2 step 7 references (Section 4,
   standard). So the *name* is wrong; the *alphabet* is standard Base64.
2. It includes `"="` (padding), contradicting the "unpadded" prose in §2.3 and
   §3.2 (see S1). An unpadded alphabet must not list `=`.

**Impl behavior:** treats `sig=` as **standard** Base64, **unpadded** (alphabet
`A-Za-z0-9+/`, no `=`, length 86). This matches the §3.2 normative step and the
DNS-draft convention.

**Proposed fix:** rename the production to `base64` (or `base64-ed25519-sig` to
mirror the DNS draft), drop `"="`, and bound the length:
`base64-ed25519-sig = 86*86( ALPHA / DIGIT / "+" / "/" )`. Also reconcile the
name/alphabet: standard Base64 unpadded is the intended encoding.

---

## S3 — ABNF uses fixed "SP" between tags; header syntax and examples use OWS/newlines (HIGH)

**§2.2 ABNF:**
```
apertoid-sig-hdr = "ApertoID-Signature" ":" OWS sig-value OWS
sig-value        = domain-tag ";" SP selector-tag ";"
                   SP timestamp-tag ";" SP nonce-tag ";"
                   SP signature-tag
```
The separator between tags is a **single, mandatory `SP`**. But:
- The header field-value definition uses `OWS` (optional whitespace) at the
  ends, implying flexible whitespace elsewhere.
- The §2.2 example and the Appendix A example **wrap across multiple physical
  lines with leading indentation** (`;\n  t=...`). That whitespace is a newline
  + spaces, which is **not** `SP` (a single 0x20). Read literally, the draft's
  **own examples do not match its own ABNF.**
- HTTP header field values can legitimately be folded/normalized by
  intermediaries; a fixed single-`SP` grammar is fragile.

**Impl behavior:** the parser splits on `;` and strips arbitrary surrounding
OWS (spaces/tabs), which accepts the examples. It does NOT enforce exactly one
`SP`.

**Proposed fix:** change the separator to `OWS` (or `*WSP`) around `;`, e.g.
`sig-value = domain-tag *( OWS ";" OWS tag )`. Note obs-fold is deprecated in
HTTP; if multi-line presentation is only for the draft's readability (like the
DNS draft's note), say so explicitly and keep the wire format single-line.

---

## S4 — Every example signature is an ASN.1 DER ECDSA blob, not a raw Ed25519 signature (HIGH)

**§3.3 and Appendix A:** `sig=MEUCIQDx4f...`, `sig=MEUCIQDx4fakebase64signaturehere...88chars`.

Decoding the placeholder (verified): `MEUCIQD...` → bytes
`30 45 02 21 00 ...`. That is an **ASN.1 DER SEQUENCE (0x30), length 0x45,
INTEGER (0x02) length 0x21** — i.e. the classic **ECDSA `Ecdsa-Sig-Value`
(r,s) DER encoding**, exactly what a `openssl dgst -sign` with an ECDSA key
emits. Ed25519 signatures per RFC 8032 are a **raw 64-byte** string with **no
ASN.1 wrapping**. So the examples gesture at the wrong signature format entirely
— and at the wrong curve family (ECDSA vs EdDSA).

This is the direct analogue of DNS F2 (the DNS examples were SPKI-DER-wrapped
keys instead of raw keys). Here the examples are DER-wrapped ECDSA signatures
instead of raw Ed25519.

**Impl behavior:** produces and verifies **raw 64-byte** Ed25519 signatures
(via `cryptography`'s Ed25519, which is raw per RFC 8032). The `MEUCIQD...`
placeholders are unusable and would fail `sig=` length/format validation.

**Proposed fix:** replace all example signatures with a **real** raw Ed25519
signature over the actual example signing input, encoded as 86-char unpadded
Base64 — generated from a real key so the example is copy-paste verifiable
(mirroring what was done for the DNS draft's pk/prev examples).

---

## S5 — The example body_hash placeholder does not match the shown body (MEDIUM)

**§3.3:** the request body is `{"query": "find leads in tech sector", "limit":
10}`, and the signing input's `body_hash` line is shown as `7d5e4a8b... (SHA-256
of the JSON body)`.

The real SHA-256 of that exact byte string is (verified):
`628e22adadb97ae8d0de9bbf50b3556d252763f2d5710c2c6b342173c1aa4675`. It does
**not** start with `7d5e4a8b`. So the placeholder hash is not the hash of the
shown body — a reader cannot reproduce the example.

There is also an ambiguity that makes the "right" hash under-defined: the draft
does not say whether the body is hashed **as shown** (with the space after `:`
and after `,`) or in some canonical/minified JSON form. Since §3.1 says "raw
HTTP request body", it should be the exact bytes on the wire — but the example
doesn't pin the exact bytes (whitespace, trailing newline).

**Impl behavior:** hashes the raw body bytes exactly as given, no JSON
canonicalization (per "raw HTTP request body").

**Proposed fix:** replace `7d5e4a8b...` with the real hex hash of the exact
example body bytes, and add a sentence: "the body is hashed exactly as
transmitted on the wire; no JSON or other canonicalization is applied."

---

## S6 — Trailing-LF ambiguity in the signing input (MEDIUM)

**§3.1:** "concatenating the following components, each **terminated by** a
newline character (0x0A)" — the diagram shows 7 components each followed by
`LF`, including `body_hash LF`. That implies a **trailing LF** after the last
component.

But the §3.3 example and Appendix A render the signing input as 7 lines with a
`\n` shown after each — including after `body_hash` — which is consistent with a
trailing LF, yet the Appendix A "signing input that was signed" block visually
ends with `<sha256-hex-of-body>\n` on its own, which a reader could interpret as
either "LF terminates each line" (trailing LF present) or "lines joined by LF"
(no trailing LF). The reference impl in Appendix B builds
`f"...{body_hash}\n"` — **with** a trailing LF, agreeing with the "terminated
by" reading.

This is a 1-byte ambiguity that **breaks interoperability**: a signer that omits
the trailing LF and a verifier that includes it (or vice versa) produce
different signing inputs and every signature fails. The DNS draft had no
equivalent because it never concatenated a signing input; here it is critical.

**Impl behavior:** includes the trailing LF (`LF.join(parts) + LF`), matching
"each component terminated by LF" and the Appendix B reference code.

**Proposed fix:** state explicitly and unambiguously, e.g. "The signing input is
the concatenation `component LF` for each of the seven components in order;
there IS a trailing LF after body_hash. The total signing input therefore ends
with 0x0A." Consider showing the exact byte length or a hex dump for one
worked example.

---

## S7 — Nonce ABNF `1*16HEXDIG` vs "lowercase hex" prose vs RFC 5234 HEXDIG (MEDIUM)

**§2.2 ABNF:** `nonce-tag = "n=" 1*16HEXDIG`.
**§2.3 / §3.1:** the nonce is "lowercase" hex; the example is `a1b2c3d4e5f6`.

RFC 5234's core `HEXDIG` is `DIGIT / "A" / "B" / "C" / "D" / "E" / "F"` —
**UPPERCASE only**. So the ABNF as written **rejects the draft's own lowercase
example nonce** `a1b2c3d4e5f6`. Either the ABNF must define a lowercase HEXDIG,
or the prose/example must be uppercase.

Additionally the signing input lowercases n (`n_value = the nonce, lowercase
hex`), so if the wire value were uppercase the signed value would differ from
the wire value unless the verifier also lowercases — the impl does, but the
draft should say so.

**Impl behavior:** accepts 1-16 hex chars in either case (`[0-9A-Fa-f]{1,16}`)
and lowercases the nonce when building the signing input.

**Proposed fix:** define `HEXDIG = DIGIT / "a"-"f"` locally (lowercase), or state
"n is lowercase hexadecimal (a-f, 0-9)" and adjust the ABNF; and state that the
signing input uses the nonce verbatim (recommend requiring lowercase on the wire
to avoid the case-normalization step).

---

## S8 — Nonce length: ABNF `1*16` vs RECOMMENDED `8-16` (LOW)

**§2.2 ABNF:** `1*16HEXDIG` (1 to 16 hex chars, i.e. as few as 4 bits).
**§3.2 step 3:** "Generate a unique nonce (**RECOMMENDED: 8-16** random hex
characters)."

A 1-hex-char nonce (16 possible values) is grammatically valid but useless for
replay protection. The ranges are inconsistent and the lower bound is unsafe.

**Impl behavior:** accepts 1-16 per the ABNF (does not enforce the RECOMMENDED
8-char floor, since it is only RECOMMENDED).

**Proposed fix:** raise the ABNF floor to match a security minimum, e.g.
`8*32HEXDIG` (64-128 bits), and reconcile the upper bound (16 hex = only 64 bits
of nonce; consider allowing more). State the security rationale.

---

## S9 — `target` construction is HTTP/1.1-request-line-specific and misses edge cases (MEDIUM)

**§3.1 (target):** "The request target **as sent in the HTTP request line**: the
path and query string, without the scheme, host, or fragment."

Problems:
- **HTTP/2 and HTTP/3 have no request line**; the target is carried in
  `:path` / `:authority` pseudo-headers. "as sent in the request line" is
  undefined there. Since agents commonly speak HTTP/2 to modern services, this
  matters.
- **Percent-encoding / normalization is unspecified.** Is the target the raw
  `:path` bytes, or normalized (dot-segments removed, case, %-decoding)? A proxy
  that normalizes `/a/../b` → `/b`, or re-encodes, breaks the signature. RFC 9421
  addresses this with `@path`/`@query` derived components; the draft says nothing.
- **`OPTIONS *`** (asterisk-form) and **`CONNECT authority-form`** targets are
  not paths; the rule doesn't cover them.
- **Empty query** vs **`?` with empty query**: §3.1 says "if there is no query
  string, only the path is included" — good — but doesn't say whether a present-
  but-empty `?` is dropped.

**Impl behavior:** uses the caller-supplied target string verbatim (no
normalization); the caller is responsible for supplying the exact bytes.

**Proposed fix:** define target normatively independent of HTTP version, e.g.
"the origin-form request target: `path [ '?' query ]`, taken from the `:path`
pseudo-header (HTTP/2+) or the request-line (HTTP/1.1), with no normalization,
percent-encoding preserved as sent." Address asterisk-form/CONNECT explicitly
or scope the mechanism to origin-form requests.

---

## S10 — Signing input omits scheme, authority (Host), and port (LOW/MEDIUM; documented but weak)

**§5.1 (Action Binding Scope):** acknowledges the Host and scheme are not signed,
and argues TLS mitigates cross-host replay. This is documented, so it is not a
hidden bug — but it is a real limitation worth flagging alongside the others:
- A signature is valid for the same `method + path?query + body` against **any
  host**. A malicious or compromised service that receives a request can replay
  it to a **different backend on a different host** that honors the same agent
  key, within the 5-minute window and with the original nonce (the target
  verifier's nonce cache is per-service, so a *different* service has not seen
  the nonce). The nonce cache does not protect cross-service replay.
- The `d=` in the header is the **agent's** domain, not the **destination**;
  nothing binds the signature to the intended recipient.

**Impl behavior:** N/A (matches spec — recipient not part of signing input).

**Proposed fix:** consider adding the destination authority (host[:port]) to the
signing input, or an explicit `aud`-like binding, so a signature cannot be
replayed to a different service. At minimum, strengthen §5.1 to state that the
nonce cache does NOT stop cross-service replay and that this relies entirely on
each destination being distinct + TLS.

---

## S11 — Verification algorithm ordering: signature checked last, after nonce is cached (LOW)

**§4 algorithm:** step 4 adds the nonce to the cache **before** the signature is
verified (step 8). An attacker can therefore **burn a victim's future nonce** by
sending a request with a valid `(d,s,t,n)` but a bogus signature: the nonce is
cached at step 4, then the request is rejected at step 9 — but if the legitimate
agent later uses that same nonce within the window, it is now a false
`nonce_reused`. This is a (minor) denial-of-service / nonce-exhaustion vector.

Also, step 3-4 (timestamp/nonce) run **before** DNS/signature verification, so
an unauthenticated attacker can populate the nonce cache at will (cache-flooding
DoS), since nothing has been authenticated yet.

**Impl behavior:** mirrors the spec order (timestamp, then nonce-add, then
verify) so the diagnosis is faithful — BUT this means a bad-signature request
consumes the nonce. Flagged rather than silently reordered.

**Proposed fix:** add the nonce to the cache **only after** the signature
verifies (move step 4's "Add n= to cache" to just before step 10). Optionally
rate-limit nonce-cache insertion per source.

---

## S12 — Cross-draft selector rule mismatch with the corrected DNS draft (MEDIUM)

**-sig §2.2 ABNF:** `selector = ALPHA *(ALPHA / DIGIT / "-")` — MUST start with a
letter, no length bound, no "not ending in hyphen" rule.
**DNS draft §7.1 (authoritative for selectors):** selector = DNS label, **1-63
chars**, alphanumeric+hyphen, **not starting or ending with a hyphen**,
case-insensitive.

These disagree (verified):
- `42agents` (leading digit): **valid** per DNS draft, **rejected** by -sig ABNF
  (ALPHA-first).
- `agent-` (trailing hyphen): **rejected** by DNS draft, **valid** per -sig ABNF.
- 64-char selector: **rejected** by DNS draft (>63), **valid** per -sig ABNF
  (no bound).

Since the `s=` value is used to locate the DNS Agent Declaration Record at
`<s>._apertoid.<d>`, the two grammars MUST agree or a selector valid in one
context is unusable in the other.

**Impl behavior:** `sig.py` validates `s=` against the -sig ABNF form as
written; this test surfaces the divergence rather than silently adopting the DNS
rule.

**Proposed fix:** make -sig reference the DNS draft's selector definition
verbatim (or reproduce it): 1-63 chars, LDH, no leading/trailing hyphen,
case-insensitive. Same for `d=` domain-name (see S13).

---

## S13 — `d=` / `domain-name` ABNF is the pre-F9 form (LOW)

**-sig §2.2 ABNF:** `domain-name = label *("." label)`,
`label = ALPHA *(ALPHA / DIGIT / "-")`.

This is the **same too-strict `label` production that DNS finding F9 fixed** (it
cannot express underscore-scoped labels, and forbids leading digits in a label —
so `d=42domains.example` would be rejected, and labels like `3com.com` are
grammatically impossible). Impact is lower than DNS F9 because `d=` carries a
registrable domain (never an `_apertoid` name), but the grammar is still
inconsistent with real DNS names and with the corrected DNS draft.

**Impl behavior:** validates `d=` against `label = ALPHA *(...)` as written
(rejects leading-digit labels), matching the literal ABNF.

**Proposed fix:** align with the corrected DNS draft's `domain-name` (allow
leading digits per RFC 1035 relaxed rules; underscore labels are not needed for
`d=` but the letter-first restriction should be dropped for consistency).

---

## S14 — Appendix A shows a DNS `pk=MCow...` (SPKI) key, contradicting the corrected DNS draft (LOW)

**Appendix A, verifier step 5:** `DNS: leadhunter._apertoid.example.com ->
pk=MCow...`.

`MCow...` is the Base64 of the DER **SubjectPublicKeyInfo** prefix — exactly the
SPKI-wrapped key format that DNS finding **F2 removed** (the corrected DNS draft
now uses raw 43-char keys). So this appendix reintroduces the old, now-wrong key
format, and is inconsistent with the corrected companion draft this document
normatively references.

**Impl behavior:** N/A (DNS key resolution is out of scope for `sig.py`), but the
example is wrong per the corrected DNS draft.

**Proposed fix:** change `pk=MCow...` to a raw 43-char unpadded-Base64 key
consistent with the corrected DNS draft (ideally the actual key that verifies
the Appendix A signature, once S4's real signature is generated).

---

## S15 — Timestamp has no upper-bound / future-skew rule stated in the tag, only in the algorithm (LOW)

**§2.3 (t tag):** "MUST be within the validity window (default 300 seconds) of
the verifier's current time." **§4 step 3:** `If |current_time - t| > 300`.

The absolute-value check does bound future timestamps, which is good. But:
- The tag prose says "within ... of the verifier's current time" without
  specifying the two-sided nature; a naive reader might implement only
  `current_time - t > 300` (past-only), allowing far-future timestamps.
- No guidance on `t` being non-numeric-overflow / leading zeros / bounded width
  (ABNF `1*DIGIT` allows `000...0` and arbitrarily long integers).

**Impl behavior:** two-sided `abs(current_time - t) > window`, matching §4 step 3.

**Proposed fix:** make the two-sided window explicit in §2.3, and bound the
timestamp width or state it is a 64-bit Unix seconds value.

---

## S16 — §4 assumes a pk always exists; keyless (url-only) agent case unspecified (MEDIUM)

Surfaced when wiring the signature layer to the DNS layer end-to-end
(`verify_request`). Recorded in full as **P4** in the DNS-draft
[`FINDINGS.md`](FINDINGS.md); summarized here because the defect is in this draft.

**§4 steps 5 and 8:** step 5 says unconditionally "Perform DNS verification per
[APERTOID-DNS]: ... Extract pk= (public key) and check exp=", and step 8 says
"Verify Ed25519 signature sig= ... using public key pk= from DNS record". Both
assume the resolved Agent Declaration Record carries a `pk=`. But the DNS draft
(§7.3, §12.1) makes a **url-only** record -- `url=` with no `pk=` -- legal and
indeed the recommended early deployment stage. When such a record is resolved for
a request that DOES carry an `ApertoID-Signature` header, §4 has no branch: there
is no key to run step 8 against, and §4.1's result values
(`malformed`/`timestamp_invalid`/`nonce_reused`/`sig_invalid`) do not cover it.

**Implementation behavior:** `verify_request` follows the DNS draft's optional-key
semantics -- returns the DNS-layer `pass` (authorized by URL match) but sets
`VerificationResult.signature_verified = False` and does not call `sig.verify`
(there is no key). The caller gets the pass without false cryptographic assurance.

**Proposed fix:** §4 should explicitly handle the keyless resolved record: after
step 5, if the record has no `pk=`, the request is authorized on the DNS-layer
verification alone (the url-only stage), the signature is not cryptographically
verified, and the verifier MUST NOT report a cryptographically-verified result.

---

## Summary table

| ID  | Section(s)          | Severity | One-liner |
|-----|---------------------|----------|-----------|
| S1  | 2.3, 3.2, 3.3, App A| CRITICAL | "88 chars" vs "unpadded" — unpadded 64-byte sig is 86; the F1 defect on the sig side |
| S2  | 2.2                 | HIGH     | ABNF calls it "base64url" but lists standard Base64 `+/=`; and lists `=` despite "unpadded" |
| S3  | 2.2, 3.3, App A     | HIGH     | tag separator is fixed `SP` in ABNF, but examples wrap with newlines+indent → examples fail own ABNF |
| S4  | 3.3, App A          | HIGH     | example `sig=MEUCIQD...` is ASN.1 DER ECDSA, not raw Ed25519 (analogue of DNS F2) |
| S5  | 3.3                 | MEDIUM   | example body_hash `7d5e4a8b...` ≠ real SHA-256 of the shown body; body-bytes not pinned |
| S6  | 3.1, App A/B        | MEDIUM   | trailing-LF after body_hash ambiguous → 1-byte interop break; impl includes it |
| S7  | 2.2, 2.3, 3.1       | MEDIUM   | `1*16HEXDIG` is uppercase-only per RFC 5234, but nonce is lowercase → ABNF rejects own example |
| S8  | 2.2 vs 3.2          | LOW      | nonce length ABNF `1*16` vs RECOMMENDED `8-16`; 1-char nonce unsafe |
| S9  | 3.1                 | MEDIUM   | `target` defined via HTTP/1.1 request line; undefined for HTTP/2+, normalization, OPTIONS*/CONNECT |
| S10 | 5.1                 | LOW/MED  | scheme/host/port not signed; nonce cache doesn't stop cross-service replay (documented but weak) |
| S11 | 4                   | LOW      | nonce cached before signature verified → nonce-burn / cache-flood DoS |
| S12 | 2.2 vs DNS §7.1     | MEDIUM   | selector ABNF disagrees with corrected DNS selector rule (leading digit, trailing hyphen, length) |
| S13 | 2.2                 | LOW      | `d=` domain-name uses the pre-F9 too-strict label form |
| S14 | App A               | LOW      | verifier example shows `pk=MCow...` SPKI key, contradicting corrected DNS draft (F2) |
| S15 | 2.3, 4              | LOW      | two-sided timestamp window only in the algorithm, not the tag prose; `t` width unbounded |
| S16 | 4 (5/8); DNS 7.3/12.1| MEDIUM  | §4 assumes pk always exists; keyless url-only agent + signature unspecified (= DNS P4) |

**Consistency-with-DNS-draft summary:** S1 (sig length ↔ F1), S4 (DER sig ↔ F2
SPKI key), S12 (selector rule ↔ DNS §7.1), S13 (`label` ABNF ↔ F9), and S14
(`pk=MCow...` ↔ F2) are the points where -sig contradicts the corrected DNS
draft. S1/S2/S4 also mean the intended raw/standard-Base64/unpadded convention
is not yet reflected here.
