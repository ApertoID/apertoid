"""ApertoID reference implementation.

Layer 1 (parser): draft-ferro-dnsop-apertoid-00 Section 5 record syntax.
Layer 3 (sig):    draft-ferro-httpbis-apertoid-sig-00 signing/verification.
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

__all__ = [
    "parse_record",
    "validate_selector",
    "ParsedRecord",
    "RecordType",
    "Diagnostic",
    "Severity",
    "sig",
]

__version__ = "0.1.0"
