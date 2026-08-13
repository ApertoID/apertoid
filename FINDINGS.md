# ApertoID spec findings — draft-ferro-dnsop-apertoid-00

> STATUS: all 12 spec findings (F1-F12) and 5 review findings (N1-N5) resolved. This file is kept as a historical record of what was found and fixed.

Ambiguities and contradictions found while implementing the Layer 1 record
parser **strictly from the spec**. Each item cites the section, states the
conflict, shows how the parser currently behaves, and proposes a fix. Severity
is from an implementer's standpoint.

The single highest-impact finding is **F3**: the ABNF's own base64 length
rule contradicts the "unpadded Base64" prose, and as a direct consequence
**every `pk=` and `prev=` value in every example record in the draft is
invalid**. This is not a parser bug — it is reproducible from the arithmetic.

---

## F1 — `pk`/`prev` length rule vs. "unpadded Base64" (CRITICAL, self-contradictory)

This is the crux, so stated precisely:

**§5.1 ABNF:**
```
base64-ed25519     = 44*44(BASE64CHAR)   ; 32 bytes = 44 chars
base64-ed25519-sig = 88*88(BASE64CHAR)   ; 64 bytes = 88 chars
BASE64CHAR         = ALPHA / DIGIT / "+" / "/" / "="
```
**§7.3 (pk) and §9.1 prose:** "encoded as **unpadded** Base64 per [RFC4648]
Section 4. For Ed25519, this is exactly **44 characters** (32 bytes encoded)."
**§10.2 (prev) prose:** signature "Encode ... as unpadded Base64" (and the SIG
companion says "88 characters for 64 bytes").

The arithmetic (verified):

| bytes | padded len | unpadded len |
|-------|-----------|--------------|
| 32    | 44        | **43**       |
| 64    | 88        | **86**       |

So the two normative statements are mutually exclusive:
- **Unpadded** 32-byte Base64 is **43** chars, not 44. Unpadded 64-byte is
  **86**, not 88.
- The ABNF requires **exactly 44 / 88**, and includes `"="` in `BASE64CHAR`,
  which only makes sense for **padded** Base64.

You cannot satisfy "unpadded" and "exactly 44" simultaneously. A 44-char value
that is valid Base64 for 32 bytes **must** carry one `=` pad; that is padded,
not unpadded.

**Parser behavior:** follows the ABNF literally (exactly 44 / 88, `=`
allowed). Real 32-byte keys must therefore be supplied **padded** to pass.

**Impact:** the "unpadded" instruction in §7.3/§9.1/§10.2 is wrong, OR the
ABNF `44*44` / `88*88` is wrong. An implementer coding to the prose and one
coding to the ABNF will reject each other's records.

**Proposed fix (pick one, apply consistently in all four places):**
- If unpadded is intended: `base64-ed25519 = 43*43(BASE64CHAR)`,
  `base64-ed25519-sig = 86*86`, and drop `"="` from `BASE64CHAR`.
- If padded is intended: keep 44/88, keep `"="`, and change the prose from
  "unpadded" to "padded", and require the trailing `=`/`==` explicitly.

---

## F2 — Every `pk=`/`prev=` value in the draft's examples is invalid

Direct consequence of F1, but worth calling out separately because it means
**none of the agent-record examples in the draft can be a conforming record**.
Measured lengths of the literal example values:

| Example        | value                                    | len | needs |
|----------------|------------------------------------------|-----|-------|
| §7.2 `pk`      | `MCowBQYDK2VwAyEAexamplekeybase64here`    | 36  | 44    |
| A.1 `pk`       | `MCowBQYDK2VwAyEAb5VxRcGh1biKLfQ5YD4mFkq` | 39  | 44    |
| A.2 `pk`       | `MCowBQYDK2VwAyEAxyz123base64keyhere456`  | 38  | 44    |
| §8, §10.2, A.3 | `<...>` placeholders                       | —   | 44/88 |

Two distinct problems here:

1. **Placeholder values** (`<base64-pubkey>`, `<new-public-key>`,
   `<signature-...>`) contain `<`, `>`, `-`, which are not even `BASE64CHAR`,
   and are the wrong length. Fine as "fill this in" prose, but they are
   presented inside otherwise-complete `IN TXT` records, so a naive test
   harness treats them as real records and they fail.
2. **The "realistic" example keys (§7.2, A.1, A.2) are also wrong length** —
   36/38/39 chars — so even the non-placeholder examples are non-conforming.

Separately: the example keys begin `MCowBQYDK2VwAyEA`, which is the Base64 of
the **DER SubjectPublicKeyInfo prefix** `30 2a 30 05 06 03 2b 65 70 03 21 00`
for Ed25519 — i.e. these look like **SPKI-wrapped** keys (44 bytes → ~60 Base64
chars), not the **raw 32-byte** key §9.1 mandates ("published as the **raw**
32-byte Ed25519 public key"). So the examples gesture at the wrong encoding on
two axes: length and structure.

**Proposed fix:** replace all example `pk`/`prev` values with real,
correctly-encoded keys of the exact length the (fixed) ABNF requires, generated
from an actual Ed25519 key so the examples are copy-paste verifiable.

---

## F3 — `;` is a legal value character but also the field separator (no escaping)

**§5.1:**
```
tag-value = tag "=" value
value     = 1*VCHAR
```
`VCHAR` is `%x21-7E`, which **includes `;`**. Worse, `;` is also explicitly in
`URI-CHAR`:
```
URI-CHAR = ... "/" ... ";" "=" ...
```
So an `https-uri` value **may legally contain `;`** (e.g.
`https://a.example/x;jsessionid=42`, a classic path parameter). But
`apertoid-record` uses bare `;` as the field separator, and the grammar
provides **no quoting or escaping** mechanism. A value containing `;` is
therefore ambiguous: the parser cannot tell a value-internal `;` from a
separator.

**Parser behavior (demonstrated):** splitting on `;`, the record
`v=APERTOID1; url=https://a.example/x;jsessionid=42; type=ai` parses with the
URL silently **truncated** to `https://a.example/x`, and `jsessionid=42`
becoming a phantom "unknown tag" that is silently ignored — **no error
raised**. That is a silent security-relevant misparse (the declared endpoint is
not what the domain owner wrote).

**Proposed fix:** either (a) remove `;` (and ideally `=`) from `URI-CHAR` and
forbid them in values, or (b) define an escaping mechanism, or (c) percent-
encode reserved chars in URLs (but note `%` is **not** in `URI-CHAR` either —
see F7). The cleanest is to state that `;` MUST NOT appear literally in any
value and MUST be percent-encoded, and to add `%` to `URI-CHAR`.

---

## F4 — Whitespace rule: ABNF vs. prose

**§5.1 ABNF:** `apertoid-record = version-tag *( ";" [WSP] tag-value )`.
This permits **at most one** optional `WSP` and **only after** the `;`.
**§5.1 prose:** "Whitespace around semicolons is OPTIONAL and MUST be ignored
by parsers."

Conflicts:
- Prose says whitespace **around** (both sides); ABNF allows it only **after**.
- "MUST be ignored" implies any amount; ABNF `[WSP]` is a single optional char.
- The draft's own examples (§6.2, A.1) render as `...; p=reject; rua=...` with
  a space after `;` — consistent with `[WSP]` — but the prose is broader.

**Parser behavior:** follows the prose (strips any amount of leading/trailing
WSP from each field, both sides).

**Proposed fix:** change the ABNF to match the prose, e.g.
`apertoid-record = version-tag *( *WSP ";" *WSP tag-value )` (and note whether
whitespace inside `version-tag` / around `=` is allowed — currently it is not,
which is probably intended).

---

## F5 — Revocation record contradicts "MUST contain url or include"

**§8:** "A record MUST contain either 'url' or 'include', but not both."
**§10.1 & A.3 example:** `v=APERTOID1; status=revoked` — a record with
**neither** url nor include.

These directly conflict. Read literally, the revocation record in the draft's
own examples **violates §8's MUST**.

**Parser behavior:** treats a `status=revoked` record with no url/include as
**valid** (no error), but emits a `revoked-no-endpoint` **warning** noting the
conflict. A non-revoked agent record with neither url nor include is a hard
error (`missing-endpoint`).

**Proposed fix:** scope the §8 rule: "A record that is not a revocation record
(status=revoked) MUST contain either url or include, but not both." Or state
explicitly that status=revoked records omit url/include.

---

## F6 — Record-type discrimination is by DNS name only, not content

**§6.1 vs §7.1:** Policy records live at `_apertoid.<domain>`; Agent records at
`<selector>._apertoid.<domain>`. The record **body** has no discriminator field
— both start `v=APERTOID1`. A parser handed only the TXT string (as this Layer
1 parser is) cannot always tell which type it is.

Concretely: `v=APERTOID1` alone, or `v=APERTOID1; status=revoked` (status is an
agent-only tag but has neither url nor include), or a record mixing `p=` with
`url=`, are all undecidable or ambiguous from content.

**Parser behavior:** classifies heuristically (`p`/`rua` ⇒ policy; any of
url/include/k/pk/exp/type/status/prev ⇒ agent), and emits `type-ambiguous`
(both families present) or `type-undetermined` (only `v=`) warnings. The caller
is expected to pass the DNS owner-name to disambiguate authoritatively in
Layer 2.

**Proposed fix:** this is arguably fine (SPF/DKIM/DMARC also key off name), but
the spec should **state explicitly** that record type is determined by the
query name, not content, and that a verifier MUST NOT infer type from tags.

---

## F7 — `URI-CHAR` omits `%`, so percent-encoded URLs are ungrammatical

**§5.1:** `URI-CHAR` enumerates sub-delims and unreserved chars but **omits
`%`**. Per RFC 3986 (which §11.4 references for host comparison), percent-
encoding is fundamental to URIs. Any real declared URL containing an escaped
character (space `%20`, non-ASCII, etc.) is **not** a valid `https-uri` under
this ABNF.

**Parser behavior:** a `url=` containing `%` fails `url-format`.

**Proposed fix:** add `"%"` to `URI-CHAR` (and see F3 re: `;`/`=` — the whole
`URI-CHAR` set should be reconciled against RFC 3986's `pchar`/`query`
productions, or the field should just be defined as "a URI per RFC 3986 with
scheme https").

---

## F8 — `email-address` ABNF is under-specified / permits `@` in local part

**§5.1:** `email-address = 1*VCHAR "@" domain-name ; per RFC 5321`. `1*VCHAR`
includes `@`, so `a@b@example.com` matches ambiguously (greedy vs. lazy). Also
the referenced production is called *addr-spec* and lives in **RFC 5322**, not
RFC 5321 (5321 uses `Mailbox`/`Local-part`); §16 lists RFC 5321. And the ABNF's
`domain-name` (letters-first labels, no IP-literals) is far narrower than what
RFC 5321 actually allows.

**Parser behavior:** splits on the **last** `@`, requires a non-empty local
part and a `domain-name`-valid domain. Pragmatic, but not what the literal ABNF
says.

**Proposed fix:** replace `1*VCHAR` with a real local-part production (or
reference `Mailbox` from RFC 5321 and drop the inline ABNF), and fix the
citation.

---

## F9 — `include` target ABNF cannot express the draft's own delegation examples

**§5.1:** `include-tag = "include" "=" domain-name` where
`label = ALPHA *(ALPHA / DIGIT / "-")` — every label **must start with a
letter**.
**§8 / A.2 examples:** `include=agent1._apertoid.salesforce.com` and
`include=client42._apertoid.salesforce.com`.

The label `_apertoid` starts with `_`, which is **not** `ALPHA`, so these
targets do **not** match the `domain-name` production. Verified: both example
include targets fail the ABNF. (Underscore-scoped labels are exactly what
RFC 8552 / the whole `_apertoid` design relies on, so the grammar is
self-defeating here.)

**Parser behavior:** both delegation examples fail `include-format`.

**Proposed fix:** allow `_` in the leading position of a label (or define a
dedicated `dns-name` production that permits underscore-scoped labels), e.g.
`label = (ALPHA / "_") *(ALPHA / DIGIT / "-" / "_")`, or reference the RFC 1035
`<domain>` grammar which is more permissive. This also affects `rua` domains in
principle, and any future underscore-scoped target.

---

## F10 — `k` is RECOMMENDED but `exp` is "REQUIRED when k is present"; a keyless record has no expiry

**§7.3:** `k` is RECOMMENDED; `pk` RECOMMENDED; `exp` "REQUIRED **when k is
present**". §12.1 explicitly describes a deployment stage with "url= only" (no
key). So a url-only agent record has **no `exp`** and thus never expires at the
DNS layer. That is intended per §12.1, but §7.2's "all recommended fields"
example and §7.4's "170 bytes with all recommended fields" blur whether exp is
expected in the common case. Minor, but the REQUIRED/RECOMMENDED interplay
(`k`⇒`pk`, `k`⇒`exp`, but `pk` without `k`?) is not fully pinned down.

**Parser behavior:** enforces `k`⇒`pk` and `k`⇒`exp` as errors; treats `pk`
without `k` as a **warning** only (the spec states only the `k`⇒`pk`
direction, never `pk`⇒`k`).

**Proposed fix:** state the `pk`⇒`k` direction explicitly (is a bare `pk`
without `k` legal?), and clarify whether `exp` is expected on url-only records.

---

## F11 — Duplicate tags: behavior undefined

The spec never says what happens if a tag appears twice (e.g. two `url=`).
DKIM/DMARC generally treat duplicate tags as an error. ApertoID is silent.

**Parser behavior:** first occurrence wins for the value map; emits a
`duplicate-tag` **warning**.

**Proposed fix:** state that a duplicated tag (other than unknown tags) MUST be
treated as a syntax error (permerror), matching DMARC's posture.

---

## F12 — "select the record that begins with v=APERTOID1" vs. whitespace/leading-tag rules

**§6.1:** if multiple TXT records exist, "the verifier MUST select the record
that **begins with** 'v=APERTOID1'". But §5.1 allows the tag name to be
**case-insensitive** (`V=APERTOID1` is valid) and (per the prose) whitespace
around separators. A literal "begins with the string `v=APERTOID1`" test would
**reject** a valid `V=APERTOID1;...` record or one with leading whitespace.

**Parser behavior:** N/A at the single-record layer, but flagged for the Layer 2
selection logic: selection must use the parsed/normalized version tag, not a
literal string prefix match.

**Proposed fix:** reword §6.1 as "select the record whose first tag is a valid
version tag with value APERTOID1", not a byte-prefix match.

---

# Phase 2 findings (verification procedure, for -02)

> These surfaced while implementing the end-to-end verification procedure
> (`verify_apertoid`, §11.2 + §8), not the record parser. They concern the
> ALGORITHM's ordering and limits rather than the record grammar. The draft
> XML/TXT is NOT modified for these; they are flagged for a future -02.

## P1 — revocation of an include= delegation target is unspecified (SECURITY, MEDIUM)

**§11.2 / §8 / §10.1:** the numbered algorithm checks `status=revoked` at
**step 7**, on the **original** agent declaration record, BEFORE following
`include=` at **step 8**. §10.1 says a verifier "MUST check for
`status=revoked` BEFORE performing any other verification steps" and MUST treat
a revoked agent as unauthorized. But the algorithm never re-runs step 7 on a
record reached **through** an `include=` delegation. So if
`a._apertoid.example.com` delegates via `include=` to
`b._apertoid.thirdparty.com`, and the **third party** revokes `b` (publishes
`v=APERTOID1; status=revoked` at that name), a literal reading of §11.2
would: resolve the include (step 8), then proceed to steps 9-12 on the
delegated record — which, being a revocation record, has no `url`/`pk`/`exp`,
so the outcome is an incidental `permerror`/`url_mismatch` rather than the
intended `revoked`. The delegated party's revocation is not honored as a
revocation.

**Implementation behavior (decision F-2, the safe choice):**
`_follow_includes` re-checks `status=revoked` on **every** resolved record,
including each `include=` target. A revoked target immediately stops the chain
and returns `revoked` (step id `11.2#7-via-include`). This means a third party
can revoke its own delegated agent and have that revocation actually enforced —
the security-preserving interpretation.

**Proposed fix for -02:** state explicitly that step 7's revocation check
applies to EACH resolved record, including every `include=` target, not only
the original. Equivalently: after following an `include=` (step 8), re-enter
the revocation check before steps 9-12.

## P2 — "maximum delegation depth is 2" parenthetical vs. hop count (LOW, ambiguous)

**§8:** "The maximum delegation depth is 2 (i.e., the original record plus one
level of `include`)." The number "2" read as a hop count allows **two** `include`
hops (A→B→C). But the parenthetical "the original record plus one level of
`include`" reads as a chain of **two records** — the origin and one delegated
target — i.e. exactly **one** `include` hop (A→B). The two phrasings disagree by
one level, so the intended limit is genuinely ambiguous in -01.

**Resolution (-02): TWO include hops, keeping what -01 already permitted.**
`DEFAULT_MAX_INCLUDE_DEPTH = 2`: a verifier follows the original record plus up to
**two** delegated targets. So A→B (B has `url`) → PASS; A→B→C → PASS; A→B→C→D (a
**third** hop) → `temperror` (11.2#8, "depth exceeded"). The reasoning is
deliberately NOT the earlier "narrow to one hop" reading: -01 already published
"depth 2", so cutting to one hop in -02 would REMOVE a capability already given
(a breaking restriction on existing deployments). Instead the depth stays at two
and is made **safe** by the other §8 limits, all unchanged: the per-hop
revocation re-check (P1 / F-2), circular-reference detection, and the hard cap of
**10** total DNS queries per attempt. "Wider but safe": secure the depth that -01
gave rather than reduce it. The `max_include_depth` keyword argument still lets a
chain of a different length be exercised in tests.

**Proposed fix for -02:** state the depth rule unambiguously as two hops and drop
the "2" vs "one include" contradiction — e.g. "A verifier MUST follow at most two
`include=` delegations (the original record plus up to two delegated targets); a
chain requiring a third `include` hop MUST result in `temperror`." The
total-lookup cap (10), per-hop revocation, and cycle detection are what bound the
risk at this depth.

## P3 — "trailing slashes are normalized" is under-specified (LOW, ambiguous)

**§11.4:** "trailing slashes are normalized". The rule does not say:

- **singular vs plural:** does it strip one trailing slash or all of them
  (`/x//` vs `/x/` vs `/x`)?
- **which side:** the declared url=, the presented url, or both?
- **root path:** does normalization make root `/` equal to an empty path ``,
  so `https://h` and `https://h/` match?

Every other §11.4 clause (https-only, host case-insensitive, path
case-sensitive, query/fragment ignored, port with 443 default) is precise; only
this one leaves the exact operation open.

**Implementation behavior:** `_normalize_path` strips **all** trailing `/` from
**both** paths before the case-sensitive comparison (`str.rstrip("/")`), so
`/x`, `/x/` and `/x//` all compare equal, and root `/` normalizes to `` (so
`https://h` matches `https://h/`). This is the most permissive-yet-safe reading:
it never causes a security-relevant false match (the significant path segments
must still match exactly, case-sensitively), it is symmetric, and it is
idempotent. It does NOT collapse internal slashes (`/a//b` is left intact) or
touch anything but the trailing run.

**Proposed fix for -02:** state the operation precisely, e.g. "before
comparison, remove any trailing '/' characters from the path component of both
URLs (so an empty path and '/' are equivalent); interior slashes are not
altered." Confirm whether root-vs-empty equivalence is intended (this
implementation assumes yes).

## P4 — a signed request to a keyless (url-only) agent is unspecified by the -sig draft (MEDIUM, cross-draft gap)

This is a cross-draft finding surfaced by wiring the two layers together in
`verify_request` (also noted in [`FINDINGS-sig.md`](FINDINGS-sig.md)).

**The case:** an `ApertoID-Signature` header is present on a request, and the
resolved Agent Declaration Record is **url-only** -- it carries `url=` but no
`pk=`. This record is fully legal: DNS draft §7.3 says "A record MAY legitimately
carry neither 'k' nor 'pk': for example, the 'url'-only deployment stage described
in Section 12.1", and §12.1 makes url-only deployment **stage (2)**, with keys
added at **stage (4)**.

**What each draft says:**

- **DNS draft (-dnsop) specifies the DNS-layer verdict.** The key check is
  explicitly OPTIONAL: §4 step 4 ("...and **optionally** that the agent's presented
  key matches"), §11.2 step 11 ("If record contains a pk= tag **AND** agent_pubkey
  is provided"), §11.3 pass ("...and, **if applicable**, the cryptographic key
  matches"), §11.1 (agent_pubkey received "optionally"). So on the DNS layer a
  url-only record is a `pass`; the key/signature check is simply skipped.
- **-sig draft (§4) does NOT specify the keyless case.** Step 5 says
  unconditionally "Extract pk= (public key) and check exp=", and step 8 says
  "Verify Ed25519 signature sig= ... using public key pk= from DNS record" -- both
  assume a `pk=` exists. §4.1's result values (`malformed`, `timestamp_invalid`,
  `nonce_reused`, `sig_invalid`) contain nothing for "a signature is present but the
  resolved record has no key to check it against." The algorithm has no branch for
  it.

**Gap:** neither draft states whether, when a signature is present but the resolved
record is keyless, the signature is (a) ignored -> accept on URL authorization,
(b) required -> reject, or (c) an error.

**Implementation behavior (decision, following the DNS draft):** `verify_request`
returns the DNS-layer `pass` (option (a)) -- authorized by URL match -- but sets a
new `VerificationResult.signature_verified` flag to **False** and records in
`detail` that the signature was not cryptographically verified. `sig.verify` is not
called (there is no key). This gives the caller the pass without false cryptographic
assurance. (Before this fix, the bridge mislabeled the case as `malformed`, which is
wrong under both drafts: the header is not unparseable.)

**Proposed fix for -02:** -sig §4 should explicitly handle the keyless resolved
record: after step 5, "If the resolved Agent Declaration Record contains no `pk=`,
the request is authorized on the basis of the DNS-layer verification alone (the
`url`-only deployment stage); the signature is not cryptographically verified, and
the verifier MUST NOT report a cryptographically-verified result." A companion note
in §11.3 pass could clarify that a `pass` covers URL-only authorization.

---

# Post-implementation review findings (for a future revision)

> These arose after -02 was published, from measurement and from external
> review, not from implementing the verifier. -02 is the currently published
> revision; the draft XML/TXT is NOT modified for these — they are flagged for a
> future revision. P5 and P6 originate from external review (attributed inline);
> P7 is external review, verified against its cited source; P8 is a measurement.

## P5 — Enumeration surface is concentrated in the names (DNS §13.5) — external review

**Source:** external review by Blake Morrison (author of
draft-morrison-mcp-dns-discovery), by email, 13 August 2026. This is his
observation, not something found in this repository.

**Current §13.5 (verbatim):** "An adversary may attempt to enumerate a domain's
agents by querying common selector names. Domain owners who wish to limit
enumeration SHOULD use non-predictable selector names. DNSSEC-signed zones using
NSEC3 [RFC5155] provide resistance against zone walking."

**The observation (his words):** because ApertoID places each subject at its own
name (`<selector>._apertoid.<domain>`), the RRset never accumulates, so record
size is not a constraint — but "the names are the roll, so NSEC3 carries the
whole enumeration surface there rather than half of it".

**What a future revision should say (analysis):** make explicit that the
one-agent-per-name design concentrates the ENTIRE enumeration surface in the DNS
names. Unlike designs that split subjects between names and RRset contents, here
there is nothing to enumerate but the names, so unpredictable selectors and NSEC3
are not partial mitigations but carry the whole of it. §13.5 should state this
consequence of the naming design rather than presenting NSEC3 as covering only
"zone walking" in the general sense.

## P6 — No comparison entry for MCP DNS Discovery (DNS §2) — external contribution

**Source:** paragraph supplied by Blake Morrison by email, 13 August 2026,
offered for inclusion in whatever form fits, with attribution.

**Gap:** §2 "Comparison with Existing Approaches" does not cover
draft-morrison-mcp-dns-discovery.

**Text supplied (verbatim, as offered):** "MCP DNS Discovery
[I-D.morrison-mcp-dns-discovery] publishes an Ed25519 key inline in a TXT record
under an underscore label, so a relying party learns the key from DNS rather than
fetching it from the endpoint. It binds to an MCP endpoint rather than to an agent
under a domain policy."

**Reference metadata (verified from the IETF datatracker, 13 August 2026):**

- full name / current revision: `draft-morrison-mcp-dns-discovery-05`
- title: "Discovery of Model Context Protocol Servers via DNS TXT Records"
- author: Blake Morrison
- date: July 2026

**Caveat (important before publishing this as our text):** the technical claims
in the supplied paragraph — inline Ed25519 key, underscore label, "learns the key
from DNS rather than fetching it from the endpoint", "binds to an MCP endpoint
rather than to an agent under a domain policy" — are the AUTHOR's characterisation
of his own draft. They have NOT been read against the document. A future revision
MUST verify them against `draft-morrison-mcp-dns-discovery-05` before publishing
the paragraph as our own comparison text.

**What a future revision should do:** add the supplied paragraph as a `<dt>` entry
in §2 (once verified per the caveat) and add the corresponding Informative
reference entry using the verified metadata above, so the revision does not have
to re-derive it.

## P7 — Erasure bound for a withdrawn signed RRset (DNS §13.7 threat model) — external review, VERIFIED

**Source:** raised by Blake Morrison by email, 13 August 2026, citing
draft-ranjbar-dane-did.

**Current threat-model text (§13.7)** treats a published record as
non-retractable in the general case (the domain-expiry / residual-risk paragraph
states, qualitatively, that a published record cannot be recalled).

**The claim:** a withdrawn DNSSEC-signed RRset stays replayable until the larger of
its TTL and its remaining signature validity, because a signed RRset cannot be
securely revoked before its signatures expire.

**Verification:** VERIFIED against Section 9 ("Revocation") of
`draft-ranjbar-dane-did-01`, read from the IETF datatracker on 13 August 2026,
which states (verbatim): "a withdrawn RRset remains replayable to any verifier not
querying the authoritative path until the RRSIG validity period ends";
"revocation latency under this profile is therefore bounded by the larger of the
record's TTL and the remaining signature validity"; and "a DNSSEC-signed RRset
cannot be securely revoked before its signatures expire." (I read the `-01`
revision as cited; I did not check whether a later revision renumbers the section.
Quotes are from the datatracker HTML rendering.)

**What a future revision should say (analysis):** turn the qualitative "a published
record cannot be recalled" into a stated interval — a withdrawn or revoked record
can remain replayable, to any verifier not querying the authoritative path, for up
to the larger of its TTL and its remaining RRSIG validity. This bounds the
revocation window in §10.1 / §13.7 with a concrete figure rather than an
open-ended statement.

## P8 — §7.4 record-size figure is a loose over-estimate (DNS §7.4) — measurement

**Source:** measured in this repository, 13 August 2026.

**Current §7.4 (verbatim):** "A typical Agent Declaration Record with all
recommended fields is approximately 170 bytes, fitting comfortably within a single
255-byte TXT character-string and well within the practical UDP DNS response size
limit."

**Measured:** the §7.2 worked example carries all six fields (`v`, `url`, `k`, `pk`,
`exp`, `type`):

```
v=APERTOID1; url=https://agent.example.com/mcp; k=ed25519; pk=2TmyMjizLUEeS0F9GJvGedF4syZFYvrWl+oFHv56VSY; type=ai; exp=1759276800
```

It measures **130 octets** as written (single space after each `;`), or 125
without the optional spaces after each `;`.

**Assessment (analysis):** "approximately 170 bytes" is a loose over-estimate, not
an error — the conclusion it supports (fits comfortably in one 255-octet
character-string) holds either way, since 130 is about half the limit. A future
revision could replace "approximately 170 bytes" with the measured figure, or keep
the qualitative claim without a specific number.

---

## Summary table

| ID  | Section(s)         | Severity | One-liner |
|-----|--------------------|----------|-----------|
| F1  | 5.1, 7.3, 9.1, 10.2| CRITICAL | 44/88 (padded) vs "unpadded" (43/86) — impossible to satisfy both |
| F2  | 7.2, 8, 10.2, A.* | CRITICAL | Every example pk/prev is wrong length and/or SPKI-wrapped, not raw |
| F3  | 5.1               | HIGH     | `;` legal in values/URIs but is the separator; no escaping ⇒ silent misparse |
| F4  | 5.1               | MEDIUM   | Whitespace ABNF (`[WSP]` after `;`) narrower than "ignore whitespace around ;" prose |
| F5  | 8, 10.1, A.3      | HIGH     | Revocation record has neither url nor include, violating §8's MUST |
| F6  | 6.1, 7.1          | MEDIUM   | Record type is name-scoped only; undecidable from body |
| F7  | 5.1               | MEDIUM   | `URI-CHAR` omits `%`; percent-encoded URLs are ungrammatical |
| F8  | 5.1, 16           | LOW      | `email-address` ABNF loose; wrong RFC citation (5321 vs 5322) |
| F9  | 5.1, 8, A.2       | HIGH     | `domain-name` forbids leading `_`; can't express `_apertoid` include targets |
| F10 | 7.3, 12.1         | LOW      | pk-without-k direction unstated; exp optionality on url-only records unclear |
| F11 | (absent)          | LOW      | Duplicate-tag handling undefined |
| F12 | 6.1               | LOW      | "begins with v=APERTOID1" conflicts with case-insensitive tag + whitespace |
| P1  | 11.2, 8, 10.1     | MEDIUM   | Revocation of an `include=` target unspecified; impl re-checks per hop (F-2) |
| P2  | 8                 | LOW      | "max depth 2" vs "(original + one include)" ambiguous; -02 resolves as 2 include hops (keep -01 capability, safe via per-hop revocation + cycle + ≤10 budget) |
| P3  | 11.4              | LOW      | "trailing slashes are normalized" under-specified (how many / which side / root≡empty) |
| P4  | -sig §4; 7.3, 12.1 | MEDIUM  | Signed request to a keyless (url-only) agent unspecified by -sig §4; impl passes on URL auth, signature_verified=False |
| P5  | 13.5              | —        | External review (Morrison): one-agent-per-name concentrates the whole enumeration surface in the names; NSEC3/unpredictable selectors carry all of it |
| P6  | 2                 | —        | External contribution (Morrison): add comparison + reference for draft-morrison-mcp-dns-discovery-05; verify its technical claims before publishing as our text |
| P7  | 13.7, 10.1        | —        | External review (Morrison), VERIFIED vs draft-ranjbar-dane-did-01 §9: withdrawn signed RRset replayable up to max(TTL, remaining RRSIG validity) |
| P8  | 7.4               | —        | Measured: §7.2 example is 130 octets, not the "~170 bytes" §7.4 states; loose over-estimate, not an error |
