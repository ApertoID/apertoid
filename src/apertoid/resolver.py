"""DNS transport for the ApertoID verification procedure (Phase 2, Block 1).

The verification algorithm of draft-ferro-dnsop-apertoid-01 Section 11.2 begins
with "Query TXT record at _apertoid.<domain>". This module is the *only* place
that talks to DNS, behind an injectable interface, so that the verification core
(verify.py, built next) and its entire test suite run against a deterministic
in-memory resolver with no live network.

TYPED OUTCOMES (decision F-3). A TXT lookup resolves to exactly one of:

  FOUND     one or more logical TXT records were returned.
  EMPTY     the name does not exist (NXDOMAIN) OR exists with no TXT records.
            Section 11.2 steps 2 and 5 treat both the same: "no record".
  TEMPFAIL  a transient failure (timeout, SERVFAIL, no reachable nameserver).
            Section 11.2 maps this to "temperror".

CHARACTER-STRING CONCATENATION. A single logical TXT record may be split across
several character-strings when it exceeds 255 octets (RFC 1035 Section 3.3.14),
as the draft's rotation example is (the "prev" signature pushes it over 255).
DNS concatenates those character-strings with NO separator to form one logical
record. The resolver performs this join before returning, so every entry in
TxtLookup.records is one already-reassembled logical record. This mirrors the
extract_records() harness in tests/test_draft_conformance.py.

SCOPE: transport only. Multi-record selection among several logical records at a
name (Section 6.1) is a verification concern and lives in verify.py, not here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable, Mapping, Protocol, Sequence, runtime_checkable


class LookupStatus(str, Enum):
    """Outcome of a single TXT lookup (see module docstring)."""

    FOUND = "found"
    EMPTY = "empty"        # NXDOMAIN or name-exists-but-no-TXT -> "no record"
    TEMPFAIL = "tempfail"  # timeout / SERVFAIL / no nameserver -> temperror


@dataclass(frozen=True)
class TxtLookup:
    """The result of Resolver.txt().

    records: each entry is ONE logical TXT record, with any RFC 1035
    Section 3.3.14 character-strings already concatenated (no separator).
    Non-empty iff status is FOUND.
    """

    status: LookupStatus
    records: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.status is LookupStatus.FOUND and not self.records:
            raise ValueError("FOUND lookup must carry at least one record")
        if self.status is not LookupStatus.FOUND and self.records:
            raise ValueError(f"{self.status.value} lookup must carry no records")


@runtime_checkable
class Resolver(Protocol):
    """Injectable DNS TXT resolver. verify.py depends only on this protocol."""

    def txt(self, name: str) -> TxtLookup:
        """Look up all TXT records at `name` and return a typed outcome."""
        ...


def join_character_strings(strings: Iterable[str]) -> str:
    """Concatenate the character-strings of one TXT record per RFC 1035 3.3.14.

    No separator between strings; the split point carries no semantics (the
    draft splits mid-Base64 inside the "prev" signature).
    """
    return "".join(strings)


class StaticResolver:
    """In-memory resolver for tests and offline verification.

    Construct from a mapping of DNS name -> record specification. Names are
    matched case-insensitively (DNS labels are case-insensitive) with a single
    trailing dot tolerated on either side. A record specification is one of:

      * a TxtLookup                 -- used verbatim
      * a str                       -- one logical record (FOUND)
      * a sequence of str           -- several logical records at that name (FOUND)
      * a sequence of sequence[str] -- several records, each given as its
                                       character-strings to be concatenated

    Names absent from the mapping resolve to EMPTY (NXDOMAIN). To simulate a
    transient failure, map the name to TxtLookup(LookupStatus.TEMPFAIL).
    """

    def __init__(self, mapping: Mapping[str, object] | None = None) -> None:
        self._map: dict[str, TxtLookup] = {}
        for name, spec in (mapping or {}).items():
            self._map[_normalize(name)] = _coerce_spec(spec)

    def set(self, name: str, spec: object) -> None:
        """Add or replace the record specification at `name` (see class doc)."""
        self._map[_normalize(name)] = _coerce_spec(spec)

    def txt(self, name: str) -> TxtLookup:
        return self._map.get(_normalize(name), TxtLookup(LookupStatus.EMPTY))


def _normalize(name: str) -> str:
    return name.rstrip(".").lower()


def _coerce_spec(spec: object) -> TxtLookup:
    """Turn a StaticResolver record specification into a TxtLookup."""
    if isinstance(spec, TxtLookup):
        return spec
    if isinstance(spec, str):
        return TxtLookup(LookupStatus.FOUND, (spec,))
    if isinstance(spec, Sequence):
        records: list[str] = []
        for entry in spec:
            if isinstance(entry, str):
                records.append(entry)
            elif isinstance(entry, Sequence):
                # a record given as its RFC 1035 3.3.14 character-strings
                records.append(join_character_strings(entry))
            else:
                raise TypeError(f"invalid record entry: {entry!r}")
        if not records:
            return TxtLookup(LookupStatus.EMPTY)
        return TxtLookup(LookupStatus.FOUND, tuple(records))
    raise TypeError(f"invalid record specification: {spec!r}")


# ---------------------------------------------------------------------------
# Optional live-DNS resolver (dnspython). NOT imported at module load.
# ---------------------------------------------------------------------------

def classify_dns_exception(exc: BaseException) -> LookupStatus:
    """Map a dnspython exception to a LookupStatus (F-3).

    NXDOMAIN / NoAnswer  -> EMPTY    (no record)
    Timeout / SERVFAIL /
      NoNameservers      -> TEMPFAIL (temperror)

    Factored out so the mapping is unit-testable without a live network: the
    tests construct the dnspython exception objects directly and assert the
    classification, never touching a real resolver.
    """
    name = type(exc).__name__
    if name in ("NXDOMAIN", "NoAnswer"):
        return LookupStatus.EMPTY
    if name in ("Timeout", "NoNameservers", "LifetimeTimeout"):
        return LookupStatus.TEMPFAIL
    # SERVFAIL surfaces as dns.resolver.NoNameservers in dnspython; other
    # unexpected transport errors are treated conservatively as transient.
    return LookupStatus.TEMPFAIL


class DnsPythonResolver:
    """Live DNS resolver backed by dnspython.

    dnspython is an OPTIONAL dependency: it is imported lazily inside methods,
    so importing this class (and the rest of apertoid) never requires it. Only
    instantiating or calling .txt() needs the package installed.
    """

    def __init__(self, *, lifetime: float = 5.0) -> None:
        self._lifetime = lifetime
        self._resolver = self._make_resolver()

    @staticmethod
    def _make_resolver():
        try:
            import dns.resolver  # noqa: F401  (lazy optional dependency)
        except ImportError as exc:  # pragma: no cover - exercised via message
            raise ImportError(
                "DnsPythonResolver requires the optional 'dnspython' package. "
                "Install it with: pip install dnspython"
            ) from exc
        return dns.resolver.Resolver()

    def txt(self, name: str) -> TxtLookup:
        import dns.resolver  # lazy

        try:
            answer = self._resolver.resolve(
                name, "TXT", lifetime=self._lifetime
            )
        except dns.resolver.NXDOMAIN:
            return TxtLookup(LookupStatus.EMPTY)
        except dns.resolver.NoAnswer:
            return TxtLookup(LookupStatus.EMPTY)
        except (dns.resolver.Timeout, dns.resolver.NoNameservers) as exc:
            return TxtLookup(classify_dns_exception(exc))

        records = tuple(_rdata_to_record(rdata) for rdata in answer)
        if not records:
            return TxtLookup(LookupStatus.EMPTY)
        return TxtLookup(LookupStatus.FOUND, records)


def _rdata_to_record(rdata: object) -> str:
    """Concatenate a TXT rdata's character-strings into one logical record.

    dnspython exposes the character-strings as `rdata.strings` (a list of
    bytes). Per RFC 1035 3.3.14 they join with no separator. Decoded as
    latin-1 to preserve every byte 1:1 (ApertoID records are ASCII, but this
    never raises on stray bytes).
    """
    parts = getattr(rdata, "strings", None)
    if parts is None:  # pragma: no cover - defensive
        return str(rdata)
    return join_character_strings(
        p.decode("latin-1") if isinstance(p, (bytes, bytearray)) else str(p)
        for p in parts
    )
