# Changelog

All notable changes to the `apertoid` package are recorded here. This project
uses semantic versioning; while below 1.0.0, minor releases may carry small,
bounded breaking changes, called out explicitly.

## 0.2.0 - 2026-08-14

### Breaking

- `sig.verify()` (and `verify_request()`) now reject a validity `window` outside
  60 to 600 seconds with a `ValueError`, raised at call time. Affects callers who
  pass a `window` outside that range; 0.1.0 accepted any integer. Callers using
  the default (300) or any value in range are unaffected. This is the only
  breaking change in this release.

### Added

- End-to-end verification (`apertoid.verify`): `verify_apertoid()` implements the
  DNS verification procedure (record lookup and Section 6.1 selection, revocation
  checked first, `include=` delegation with the Section 8 DoS limits, `exp`
  expiry, and URL matching), and `verify_request()` is the signature-to-DNS
  bridge that resolves the agent's key from DNS and then verifies the request
  signature. Both return a `VerificationResult` (`.outcome`, `.step`, `.policy`,
  `.pk`, `.signature_verified`).
- DNS transport (`apertoid.resolver`): the injectable `Resolver` protocol,
  `StaticResolver` (offline, for tests and self-contained use), `DnsPythonResolver`
  (live DNS, requires the optional `dnspython` package), and the `TxtLookup` /
  `LookupStatus` types.
- New exported symbols: `verify_apertoid`, `verify_request`, `VerificationResult`,
  `Outcome`, `Policy`, `Resolver`, `StaticResolver`, `TxtLookup`, `LookupStatus`,
  `DnsPythonResolver`.
- `sig.verify()` gained an optional `max_body_size` parameter: when set, a request
  body larger than the limit is rejected (new result value `body_too_large`)
  before the body is hashed, closing a body-hash denial-of-service vector. The
  result value only occurs when the parameter is set; existing callers are
  unaffected.
- Optional packaging extra `dns` (`pip install "apertoid[dns]"`) pulling in
  `dnspython` for `DnsPythonResolver`.

### Fixed

- Nonce-cache ordering: a request whose signature does not verify no longer
  inserts its nonce into the caller's replay cache. The nonce is checked
  read-only until the signature verifies, then inserted, so an unauthenticated
  request cannot burn a victim's nonce or flood the cache.

### Tests

- Added negative/adversarial cryptographic tests (tampered body/method/target,
  wrong key, expired and future timestamps, nonce reuse, flipped signature),
  body-size-guard tests, and validity-window-range tests.

### Notes

- No change to the parser's public API, diagnostic codes, or diagnostic message
  text since 0.1.0 (verified by comparison against the 0.1.0 tag).

## 0.1.0 - 2026-08-10

- Initial release: DNS TXT record parsing and validation (`apertoid.parser`) and
  HTTP request signing and local verification (`apertoid.sig`).
