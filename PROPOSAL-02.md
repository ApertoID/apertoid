# -02 Normative Wording Proposal (P1-P4)

> REVIEW DOCUMENT ONLY. Nothing in `spec/` has been edited; the drafts are still
> `-01` (the published versions). This proposes the exact normative text for the
> four Phase-2 findings so the author can approve wording BEFORE any `-02` edit.
> No datatracker submission — repo `-02` preparation only, later.

Authoritative source is the XML; the `.txt` renders from it. Section numbers below
are the rendered `-01` numbers; anchors are the XML anchors.

---

## P1 — DNS §8 (`delegation`) + §11.2 (`verification-algorithm`): re-check revocation on every include target

**Finding:** §11.2 checks `status=revoked` at step 7 on the *origin* record only,
then follows `include=` at step 8. A delegated (include-target) record that is
itself `status=revoked` is never re-checked, so a third party revoking its own
delegated agent is not honored as a revocation. The impl already re-checks per hop
(decision F-2); this makes it normative.

### (a) Current text

§11.2 algorithm (XML lines 319-324):
```
  7. If status=revoked:
       Return result="revoked", apply policy p=
  8. If record contains include= tag:
       Follow delegation (max depth 2, max 10 total lookups)
       If delegation fails: Return result="temperror"
       Continue verification with resolved record
```

§8 prose (XML line 247): "Verifiers MUST follow "include" references to resolve the
final Agent Declaration Record. To prevent abuse and excessive DNS lookups:" +
the three `<li>` limits.

### (b) Proposed text

**Change §11.2 step 8** to make revocation re-checking explicit at each hop:
```
  8. If record contains include= tag:
       Follow delegation (see Section 8). For EACH record resolved
       through an include= reference, re-apply step 7: if a resolved
       record has status=revoked, Return result="revoked", apply
       policy p= (a revoked delegation target stops the chain).
       If delegation otherwise fails: Return result="temperror".
       Continue verification with the final resolved record.
```

**Add one `<li>` to the §8 list** (after the circular-reference bullet):
```
The revocation check of Section 10.1 MUST be applied to EACH record
resolved through an "include" reference, not only the original Agent
Declaration Record. If any record in the delegation chain carries
"status=revoked", the verifier MUST treat the agent as unauthorized
(result "revoked") and MUST NOT continue following the chain.
```

### (c) Where
DNS draft, `draft-ferro-dnsop-apertoid`, §11.2 (`verification-algorithm`) and §8
(`delegation`).

---

## P2 — DNS §8 (`delegation`): unambiguous two-hop delegation limit

**Finding:** "The maximum delegation depth is 2 (i.e., the original record plus one
level of include)" reads two ways — "2" as a hop count (A→B→C, two hops) vs the
parenthetical "original + one include" (A→B, one hop). The two disagree by one
level, so -01's intended limit is ambiguous. Make the prose say exactly one thing.

### (a) Current text

§8, first `<li>` (XML line 249):
```
The maximum delegation depth is 2 (i.e., the original record plus one level of "include").
```

Also §11.2 step 8 (XML line 322) mentions "max depth 2":
```
       Follow delegation (max depth 2, max 10 total lookups)
```

### (b) Proposed text

Resolve the ambiguity in favour of **two** include hops — the reading that keeps
what -01's "depth 2" already permitted, rather than narrowing it (which would be a
breaking restriction on deployments relying on the published -01). Replace the §8
`<li>` with:
```
A verifier MUST follow at most TWO "include" delegations: the original
Agent Declaration Record plus at most two delegated target records. A
chain requiring a third "include" hop MUST be treated as a verification
failure (result "temperror").
```

And in §11.2 step 8, drop the numeric "max depth 2": the merged step 8 (rewritten
by P1 above) says "see Section 8 for the limits" and no longer repeats a number, so
the depth lives only in §8 — single source of truth, no drift.

### (c) Where
DNS draft, §8 (`delegation`); cross-referenced from §11.2 step 8.

> NOTE (author decision): two hops is the "wider but safe" choice — it preserves
> the -01 capability rather than removing it. The risk at this depth is bounded not
> by reducing depth but by the other §8 limits, all kept unchanged: the per-hop
> revocation re-check (P1), circular-reference detection, and the ≤10 total-lookup
> cap. This REVERSES an earlier one-hop proposal; the final decision is two hops.

---

## P3 — DNS §11.4 (`url-matching`): specify trailing-slash normalization exactly

**Finding:** "trailing slashes are normalized" does not say how many, which side, or
whether root `/` equals empty path. Specify it as implemented.

### (a) Current text

§11.4 (XML line 358), single paragraph:
```
When comparing the agent's URL against the declared URL: the scheme MUST be "https"
(HTTP MUST NOT be accepted); host comparison is case-insensitive per [RFC3986];
path comparison is case-sensitive; trailing slashes are normalized; query strings
and fragments are ignored; port numbers, if present, MUST match (default HTTPS port
443 is assumed when absent).
```

### (b) Proposed text

Replace the "trailing slashes are normalized" clause (keep the rest of the sentence
verbatim) with:
```
... path comparison is case-sensitive; before the path comparison, any
trailing "/" characters are removed from the path component of BOTH URLs
(so "/x", "/x/" and "/x//" compare equal, and a root path "/" compares
equal to an empty path), while interior "/" characters are left
unchanged; query strings and fragments are ignored; ...
```

So the full replacement paragraph reads:
```
When comparing the agent's URL against the declared URL: the scheme MUST be "https"
(HTTP MUST NOT be accepted); host comparison is case-insensitive per [RFC3986];
path comparison is case-sensitive; before the path comparison, any trailing "/"
characters are removed from the path component of both URLs (so "/x", "/x/" and
"/x//" compare equal, and a root path "/" compares equal to an empty path), while
interior "/" characters are left unchanged; query strings and fragments are ignored;
port numbers, if present, MUST match (default HTTPS port 443 is assumed when absent).
```

### (c) Where
DNS draft, §11.4 (`url-matching`).

---

## P4 / S16 — -sig §4 (`verification`): handle the keyless (url-only) agent

**Finding:** §4 step 5 ("Extract pk= ... and check exp=") and step 8 ("Verify ...
using pk= from DNS record") assume a `pk=` always exists. But a url-only agent
record (legal per [APERTOID-DNS] §7.3, deployment stage 2) has no key. §4 has no
branch: no key to run step 8 against, and no result value for it. The impl returns
the DNS-layer PASS (authorized by URL) with `signature_verified=False`.

### (a) Current text

§4 algorithm (XML lines 220-234):
```
  5. Perform DNS verification per [APERTOID-DNS]:
     Query "_apertoid.<d>" for policy record
     Query "<s>._apertoid.<d>" for agent declaration
     Extract pk= (public key) and check exp=
  6. If DNS verification fails:
     Apply policy p= from policy record
     Return DNS verification result
  7. Reconstruct signing_input from: ...
  8. Verify Ed25519 signature sig= against signing_input
     using public key pk= from DNS record
```

### (b) Proposed text

**Insert a new step 6a** (between the DNS-fail check and signing-input
reconstruction), and add a sentence to the intro prose + a result-value note:

New step 6a in the algorithm:
```
  6a. If DNS verification passed but the resolved Agent Declaration
      Record contains no pk= (a url-only agent, legal per
      [APERTOID-DNS] Section 7.3), the request is authorized on the
      basis of the DNS-layer verification alone: the URL matched and
      the domain declares the agent, but there is no published key to
      verify the signature against. The verifier MUST NOT
      cryptographically verify the signature in this case, MUST NOT
      report a cryptographically-verified result, and returns the
      DNS-layer "pass". Steps 7-9a are skipped.
```

Add to the §4 result-value list (a `<dt>/<dd>` or a note under "pass"):
```
A "pass" indicates the agent is authorized by the domain. When the
resolved record publishes a pk= and steps 7-9a ran, the signature was
also cryptographically verified for this specific request. When the
resolved record is url-only (no pk=), the "pass" reflects DNS-layer
authorization only; implementations SHOULD expose to the caller whether
the signature was cryptographically verified.
```

### (c) Where
-sig draft, `draft-ferro-httpbis-apertoid-sig`, §4 (`verification`).

> NOTE (author decision): this encodes decision V1 — url-only + signed request →
> `pass`, signature NOT verified. The alternative readings (reject, or a distinct
> error) were considered and rejected in review. Approve the "authorized on
> DNS-layer alone, MUST NOT report cryptographically-verified" wording.

---

## After approval (NOT done yet — for the eventual -02 edit)

Once you approve the wording above, the `-02` edit will also need (mechanical,
following the established -01 process):
- `git mv` all four files `-01.{xml,txt}` → `-02.{xml,txt}`; bump `docName`,
  `seriesInfo`, date, Expires (+6mo via xml2rfc).
- Add a "Changes from -01" entry to each "Changes from ..." appendix listing P1-P4.
- Regenerate `.txt`: -sig regenerates 0-diff; DNS `.txt` repaginates under this
  xml2rfc — fine for a repo -02 (XML is source of truth), or hand-edit surgically.
- Update FINDINGS.md/FINDINGS-sig.md to mark P1-P4/S16 as resolved-in-02.
- Update test DRAFT paths -01 → -02; run full suite (195) + idnits.

None of this happens until the wording is approved.
