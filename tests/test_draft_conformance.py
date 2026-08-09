"""Prove every ApertoID record example in the ACTUAL draft parses as conforming.

Unlike test_draft_examples.py (which hardcodes record strings), this harness
extracts the record examples *directly from the draft source* -- the .txt
rendering of draft-ferro-dnsop-apertoid-01 -- reassembles each multi-line
"...IN TXT" record into its single logical TXT string, and runs the Layer 1
parser over it. It is the end-to-end check for FINDINGS F1/F2: after the fix,
NO agent-declaration example may fail to parse.

This reads the published draft committed in the repo (spec/), the source of
truth the edits were applied to, so it can drift only if the draft drifts.
"""

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from apertoid import parse_record, RecordType  # noqa: E402

DRAFT_TXT = (
    Path(__file__).resolve().parents[1] / "spec" / "draft-ferro-dnsop-apertoid-01.txt"
)


def extract_records(text: str) -> list[str]:
    """Pull every quoted TXT record body out of the draft's example blocks.

    A record example looks like:
        <owner>. <ttl> IN TXT
          "v=APERTOID1; ... ;
           ... ;
           ..."
    i.e. a double-quoted string that may span several physical lines. We find
    each `IN TXT` line, then capture the balanced double-quoted block that
    follows, and collapse internal whitespace runs to a single space (the draft
    says multi-line records are one logical string; §5.1 says whitespace around
    ';' is ignored).
    """
    records = []
    # Find `IN TXT` then the following one-or-more quoted character-strings.
    # A record may be split across multiple TXT character-strings (RFC 1035
    # Section 3.3.14) when it exceeds 255 octets (e.g. records carrying a
    # "prev" signature); DNS concatenates the character-strings with NO
    # separator to form the single logical record, so we do the same. Each
    # character-string may itself wrap across physical lines with indentation.
    for m in re.finditer(r'IN\s+TXT\s*\n((?:\s*"(?:[^"]*)"\s*)+)', text):
        block = m.group(1)
        # Concatenate every quoted character-string in the block, verbatim
        # (no separator between strings, per RFC 1035 Section 3.3.14).
        parts = re.findall(r'"([^"]*)"', block)
        body = "".join(parts)
        # A single character-string may not span physical lines in the master
        # file, but our examples indent for readability; collapse internal
        # whitespace runs (Section 5.1: whitespace around ';' is ignored).
        body = re.sub(r"\s+", " ", body).strip()
        records.append(body)
    return records


def load_records() -> list[str]:
    assert DRAFT_TXT.exists(), f"draft not found: {DRAFT_TXT}"
    return extract_records(DRAFT_TXT.read_text())


def run_report() -> int:
    records = load_records()
    print(f"Extracted {len(records)} record examples from {DRAFT_TXT.name}\n")
    failures = 0
    for i, raw in enumerate(records, 1):
        rec = parse_record(raw)
        status = "CONFORMS" if rec.is_valid else "FAILS   "
        if not rec.is_valid:
            failures += 1
        # show a trimmed view of the record
        shown = raw if len(raw) <= 78 else raw[:75] + "..."
        print(f"[{i:02d}] {status} type={rec.record_type.value:<7} {shown}")
        for d in rec.errors:
            print(f"       ERROR {d}")
        for d in rec.warnings:
            print(f"       warn  {d}")
    print(f"\n{len(records)} records, {failures} FAILED to conform")
    return failures


# ---- pytest ----
def test_no_f1_f2_errors_remain():
    """F1/F2 scope: NO pk/prev length or format errors anywhere in the draft."""
    offenders = []
    for raw in load_records():
        rec = parse_record(raw)
        for d in rec.errors:
            if d.code in ("pubkey-format", "prev-format"):
                offenders.append((raw, str(d)))
    assert not offenders, "F1/F2 not resolved:\n" + "\n".join(
        f"  {r}\n    {e}" for r, e in offenders
    )


def test_every_draft_record_conforms():
    """After F1/F2, F9, AND F5, EVERY example record in the draft must parse
    with ZERO diagnostics -- not merely no ERRORs, but no warnings either.
    The include= records parse thanks to the F9 underscore-label fix; the
    revocation records are clean thanks to the F5 exception.
    """
    records = load_records()
    assert records, "no records extracted -- extraction regex broke"
    bad = []
    for raw in records:
        rec = parse_record(raw)
        if rec.diagnostics:
            bad.append((raw, [str(d) for d in rec.diagnostics]))
    assert not bad, "records with remaining diagnostics:\n" + "\n".join(
        f"  {r}\n    {diags}" for r, diags in bad
    )


def test_include_targets_are_grammatical():
    """F9 pin: underscore-scoped include targets must parse cleanly."""
    for raw in load_records():
        if "include=" in raw:
            rec = parse_record(raw)
            assert rec.is_valid, (
                f"include record should conform post-F9: "
                f"{[str(d) for d in rec.errors]}"
            )


def test_revocation_records_have_no_diagnostics():
    """F5 pin: bare revocation records conform with zero diagnostics."""
    found = False
    for raw in load_records():
        if "status=revoked" in raw:
            found = True
            rec = parse_record(raw)
            assert rec.diagnostics == [], [str(d) for d in rec.diagnostics]
    assert found, "no revocation record found in draft -- extraction broke"


def test_pk_values_are_43_unpadded():
    """Directly assert every pk= in the draft is 43 chars, no '=' padding."""
    for raw in load_records():
        for m in re.finditer(r"pk=([^;]+)", raw):
            pk = m.group(1).strip()
            assert len(pk) == 43, f"pk not 43 chars: {pk!r} ({len(pk)})"
            assert "=" not in pk, f"pk contains padding: {pk!r}"


def test_prev_sigs_are_86_unpadded():
    for raw in load_records():
        for m in re.finditer(r"prev=sig:([^;]+)", raw):
            sig = m.group(1).strip()
            assert len(sig) == 86, f"prev sig not 86 chars: {sig!r} ({len(sig)})"
            assert "=" not in sig, f"prev sig contains padding: {sig!r}"


if __name__ == "__main__":
    sys.exit(1 if run_report() else 0)
