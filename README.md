# ApertoID reference implementation — Layer 1: record parser

Python reference parser for **ApertoID** DNS TXT records, implemented strictly
from [`draft-ferro-dnsop-apertoid-00`](spec/draft-ferro-dnsop-apertoid-00.txt),
Section 5 (Record Syntax).

This is **Layer 1 only**: it parses and validates a single record string. It
does **not** do DNS lookups, `include=` delegation resolution, `exp` expiry
checks against wall-clock time, URL matching, or Ed25519 signature
verification. Those belong to the Section 11 verification algorithm (Layer 2)
and are intentionally not built yet.

## Method

The parser is implemented **from the spec, not from intuition**. Where the
Section 5.1 ABNF and the surrounding prose disagree, the parser follows the
**ABNF as literally written** and emits a diagnostic pointing at the
contradiction, rather than silently reconciling it. Surfacing these
contradictions is a goal — see **[FINDINGS.md](FINDINGS.md)**.

## Layout

```
src/apertoid/parser.py    the parser (parse_record, validate_selector)
tests/test_draft_examples.py   every example record in the draft
tests/test_rules.py            targeted MUST-rule / value-format tests
spec/                          the draft text this was built from
FINDINGS.md                    12 spec ambiguities/contradictions found
```

## Usage

```python
from apertoid import parse_record

rec = parse_record("v=APERTOID1; p=reject; rua=mailto:apertoid@example.com")
print(rec.record_type)   # RecordType.POLICY
print(rec.is_valid)      # True
print(rec.get("p"))      # "reject"
for d in rec.diagnostics:
    print(d)             # [severity:code] message
```

`parse_record` never raises on malformed input; it returns a `ParsedRecord`
whose `.errors` / `.warnings` / `.is_valid` describe the outcome. This mirrors
the spec's `permerror` posture (malformed syntax is a result, not a crash).

## Running

```bash
python3 -m venv .venv && .venv/bin/pip install pytest
.venv/bin/python -m pytest -q                 # full suite (47 tests)
.venv/bin/python tests/test_draft_examples.py # human-readable draft-example table
```

## Draft-example results

All 13 example records across §6.2, §7.2, §8, §10.1, §10.2, and Appendix
A.1/A.2/A.3 parse **as the spec text dictates**. Notably, the parser reports
that:

- **Every `pk=` and `prev=` value in the draft is invalid** — wrong length
  and/or SPKI-wrapped rather than the raw 32-byte key §9.1 requires
  (FINDINGS **F1**, **F2**).
- **Both `include=` delegation targets in the draft fail the `domain-name`
  ABNF**, because `_apertoid` starts with an underscore, which `label` forbids
  (FINDINGS **F9**).
- The **revocation record** (`v=APERTOID1; status=revoked`) has neither `url`
  nor `include`, contradicting §8's "MUST contain either" (FINDINGS **F5**).

The policy records (§6.2, A.1, A.2) are the only fully conforming examples in
the draft.

## Status

Layer 1 complete. Not committed. Layers 2+ (verification, delegation, signing)
not started.
