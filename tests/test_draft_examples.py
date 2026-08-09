"""Parse every example record in draft-ferro-dnsop-apertoid-00.

Each example is reproduced verbatim (whitespace-joined into the single TXT
string the draft says it really is). The test asserts what the parser does and
records WHY, so the pass/fail table maps directly onto spec findings.

Run: python -m pytest tests/test_draft_examples.py -v
Or:  python tests/test_draft_examples.py   (prints the report table)
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from apertoid import parse_record, RecordType, Severity  # noqa: E402


def _join(*lines: str) -> str:
    """Join the multi-line draft presentation into one TXT string.

    The draft (Section 7.2 note) says records shown on multiple lines are a
    single string in practice. The lines are joined with a single space,
    matching how the continuation whitespace appears in the source.
    """
    return " ".join(part.strip() for part in lines)


# Each entry: (id, description, raw, expectation dict)
# expectation: expect_valid (no ERROR diagnostics), record_type, notes
EXAMPLES = [
    # ----- Section 6.2: Policy Record example -----
    dict(
        id="6.2",
        desc="Policy record (reject)",
        raw="v=APERTOID1; p=reject; rua=mailto:apertoid@example.com",
        expect_valid=True,
        expect_type=RecordType.POLICY,
    ),
    # ----- Section 7.2: Agent Declaration example -----
    dict(
        id="7.2",
        desc="Agent declaration w/ real 43-char pk (post-F1)",
        raw=_join(
            "v=APERTOID1; url=https://agent.example.com/mcp;",
            "k=ed25519; pk=2TmyMjizLUEeS0F9GJvGedF4syZFYvrWl+oFHv56VSY;",
            "type=ai; exp=1759276800",
        ),
        expect_valid=True,  # F1 fixed: real raw 32-byte key, unpadded = 43 chars
        expect_type=RecordType.AGENT,
    ),
    # ----- Section 8: Delegation (two records) -----
    dict(
        id="8-delegator",
        desc="Delegation: include record",
        raw="v=APERTOID1; include=agent1._apertoid.salesforce.com",
        expect_valid=True,  # F9 fixed: underscore-scoped label now grammatical
        expect_type=RecordType.AGENT,
    ),
    dict(
        id="8-delegate",
        desc="Delegation: salesforce actual declaration (post-F1)",
        raw=_join(
            "v=APERTOID1; url=https://agents.salesforce.com/crm;",
            "k=ed25519; pk=Hr4Z0cjlqCxFhRYKi2uEOkznCCXMELANsOif7KRkhJk;",
            "type=ai; exp=1759276800",
        ),
        expect_valid=True,  # F1 fixed: real 43-char pk
        expect_type=RecordType.AGENT,
    ),
    # ----- Section 10.1: Immediate revocation -----
    dict(
        id="10.1",
        desc="Revocation record",
        raw="v=APERTOID1; status=revoked",
        expect_valid=True,  # F5 resolved: bare revocation record is conforming
        expect_type=RecordType.AGENT,
    ),
    # ----- Section 10.2: Key rotation -----
    dict(
        id="10.2",
        desc="Key rotation w/ real 43-char pk + 86-char prev (post-F1)",
        raw=_join(
            "v=APERTOID1; url=https://agent.example.com/mcp;",
            "k=ed25519; pk=QV8LAsXQn7cwPMrfpSs/1CbTXO6uTPdq0y9IOUGpAIQ;",
            "prev=sig:bxX1qXatIGHLYDyXAZw6T2VIAWGBuwkNxGHyYJO+UPO2uWPI35gzIdsi9tg1xa6Y0lUW3PDcZJ9b6OYPMjEgDQ;",
            "type=ai; exp=1762000000",
        ),
        expect_valid=True,  # F1 fixed: real key + real 86-char signature
        expect_type=RecordType.AGENT,
    ),
    # ----- Appendix A.1: Basic deployment (two records) -----
    dict(
        id="A.1-policy",
        desc="A.1 policy (warn)",
        raw="v=APERTOID1; p=warn; rua=mailto:apertoid@example.com",
        expect_valid=True,
        expect_type=RecordType.POLICY,
    ),
    dict(
        id="A.1-agent",
        desc="A.1 agent (MCP w/ real 43-char key, post-F1)",
        raw=_join(
            "v=APERTOID1; url=https://mcp.example.com/agent;",
            "k=ed25519; pk=22A9MAOrna2yu63pTR/MtR7E6ZvNr0VpuFf3iz0ZqCw;",
            "type=ai; exp=1761955200",
        ),
        expect_valid=True,  # F1 fixed
        expect_type=RecordType.AGENT,
    ),
    # ----- Appendix A.2: Third-party delegation (three records) -----
    dict(
        id="A.2-policy",
        desc="A.2 policy (reject)",
        raw="v=APERTOID1; p=reject; rua=mailto:sec@example.com",
        expect_valid=True,
        expect_type=RecordType.POLICY,
    ),
    dict(
        id="A.2-agent",
        desc="A.2 own agent (real 43-char key, post-F1)",
        raw=_join(
            "v=APERTOID1; url=https://agents.example.com/leadhunter;",
            "k=ed25519; pk=zud6BDQnS2LuF3Lea1WJdhfo/TssKNIRHXP7N3I3Rwk;",
            "type=ai; exp=1761955200",
        ),
        expect_valid=True,  # F1 fixed
        expect_type=RecordType.AGENT,
    ),
    dict(
        id="A.2-delegation",
        desc="A.2 delegated third-party",
        raw="v=APERTOID1; include=client42._apertoid.salesforce.com",
        expect_valid=True,  # F9 fixed: underscore-scoped label now grammatical
        expect_type=RecordType.AGENT,
    ),
    # ----- Appendix A.3: Emergency revocation + rotation (two records) -----
    dict(
        id="A.3-revoke",
        desc="A.3 revoke",
        raw="v=APERTOID1; status=revoked",
        expect_valid=True,
        expect_type=RecordType.AGENT,
    ),
    dict(
        id="A.3-rotate",
        desc="A.3 new key w/ real rotation proof (post-F1)",
        raw=_join(
            "v=APERTOID1; url=https://agents.example.com/leadhunter;",
            "k=ed25519; pk=SDjyggr4hJnmqHN7KakFCGg63jFIwb7tS3jEMcrDIq0;",
            "prev=sig:ixwPd0LIcPSCoBzCFpBui04VPn2p6Hx3BKbNKEMw6q6MFVzp7p6PF97pkhKocsh7R/kZXSlWXNvkrXayHNi7AQ;",
            "type=ai; exp=1764547200",
        ),
        expect_valid=True,  # F1 fixed
        expect_type=RecordType.AGENT,
    ),
]


def run_report() -> int:
    """Print a human-readable table. Returns number of expectation mismatches."""
    mismatches = 0
    print(f"{'ID':<15} {'valid?':<7} {'exp':<5} {'type':<8} notes")
    print("-" * 100)
    for ex in EXAMPLES:
        rec = parse_record(ex["raw"])
        valid = rec.is_valid
        ok_valid = valid == ex["expect_valid"]
        ok_type = rec.record_type == ex["expect_type"]
        if not (ok_valid and ok_type):
            mismatches += 1
        flag = "OK " if (ok_valid and ok_type) else "!! "
        err_codes = ",".join(sorted({d.code for d in rec.errors})) or "-"
        print(f"{flag}{ex['id']:<12} {str(valid):<7} "
              f"{str(ex['expect_valid']):<5} {rec.record_type.value:<8} "
              f"errors=[{err_codes}]")
        # detail lines
        for d in rec.diagnostics:
            print(f"      {d}")
    print("-" * 100)
    print(f"{len(EXAMPLES)} examples, {mismatches} expectation mismatch(es)")
    return mismatches


# ---- pytest hooks (only defined if pytest is importable) ----

try:
    import pytest
except ImportError:  # allow running the report standalone without pytest
    pytest = None


if pytest is not None:
    @pytest.mark.parametrize("ex", EXAMPLES, ids=[e["id"] for e in EXAMPLES])
    def test_example_validity(ex):
        rec = parse_record(ex["raw"])
        assert rec.is_valid == ex["expect_valid"], (
            f"{ex['id']}: expected valid={ex['expect_valid']}, got {rec.is_valid}; "
            f"errors={[str(d) for d in rec.errors]}"
        )

    @pytest.mark.parametrize("ex", EXAMPLES, ids=[e["id"] for e in EXAMPLES])
    def test_example_type(ex):
        rec = parse_record(ex["raw"])
        assert rec.record_type == ex["expect_type"], (
            f"{ex['id']}: expected type={ex['expect_type']}, got {rec.record_type}"
        )


if __name__ == "__main__":
    sys.exit(1 if run_report() else 0)
