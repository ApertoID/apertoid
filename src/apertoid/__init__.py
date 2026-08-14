"""ApertoID reference implementation.

Layer 1 (parser): draft-ferro-dnsop-apertoid-01 Section 5 record syntax.
Layer 2 (verify): draft-ferro-dnsop-apertoid-01 Section 11 verification +
                  draft-ferro-httpbis-apertoid-sig-01 Section 4 sig<->DNS bridge.
Layer 3 (sig):    draft-ferro-httpbis-apertoid-sig-01 signing/verification.
"""

from . import sig
from .parser import (
    Diagnostic,
    ParsedRecord,
    RecordType,
    Severity,
    parse_record,
    validate_selector,
)
from .resolver import (
    DnsPythonResolver,
    LookupStatus,
    Resolver,
    StaticResolver,
    TxtLookup,
)
from .verify import (
    Outcome,
    Policy,
    VerificationResult,
    verify_apertoid,
    verify_request,
)

__all__ = [
    # Layer 1: record parsing
    "parse_record",
    "validate_selector",
    "ParsedRecord",
    "RecordType",
    "Diagnostic",
    "Severity",
    # Layer 2: verification
    "verify_apertoid",
    "verify_request",
    "VerificationResult",
    "Outcome",
    "Policy",
    # DNS transport
    "Resolver",
    "StaticResolver",
    "TxtLookup",
    "LookupStatus",
    "DnsPythonResolver",
    # Layer 3: HTTP signatures
    "sig",
]

__version__ = "0.2.0"
