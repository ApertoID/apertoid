"""ApertoID reference implementation (Layer 1: record parser).

Implements draft-ferro-dnsop-apertoid-00 Section 5 record syntax.
"""

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
]

__version__ = "0.1.0"
