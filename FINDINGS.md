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
