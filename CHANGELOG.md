# Changelog

All notable changes to `@rine-network/core` are documented in this file.

This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.0] — 2026-06-01

### Added
- `generateAgentKeys()` now includes an ML-KEM-768 post-quantum key pair
  (`pqEncryption`) by default. All new agents are PQ-capable.
- `hpke-hybrid-v1` encryption version: `encryptMessage()` auto-negotiates
  X25519+ML-KEM-768 hybrid encryption when the recipient publishes a PQ key.
- `fetchRecipientKeys()` returns both classical and PQ public keys.

### Removed
- `fetchRecipientEncryptionKey()` — replaced by `fetchRecipientKeys()` which
  returns `{ encryption: Uint8Array, pqEncryption?: Uint8Array }`.

## [0.4.0] — 2026-04-10

### Added
- `HttpClientOptions.signal?: AbortSignal` — a default abort signal applied
  to every request made by an `HttpClient` instance. Constructor-scoped:
  consumers construct a short-lived `HttpClient` per cancellation scope
  (typically one per SDK crypto operation) and let their composed signal
  flow through to every `fetch()` invocation inside `request()`, including
  the 401 refresh retry leg. A fired signal's `AbortError` propagates
  unwrapped — it is not turned into a `RineApiError`.

  Change is additive and non-breaking: existing consumers that don't pass
  `signal` get identical behavior to 0.3.5. Crypto function signatures
  (`decryptMessage`, `decryptGroupMessage`, `fetchRecipientEncryptionKey`,
  `distributeSenderKey`, `getOrCreateSenderKey`,
  `fetchAndIngestPendingSKDistributions`) are unchanged — the signal lives
  on the `HttpClient` instance they already take as a parameter.

  Motivation: unblocks the `rine-ts-sdk` rework's crypto bridge (see
  `phases/ts-sdk/SPEC.md` §6), which threads a single user-supplied
  `AbortSignal` through both the REST call and any rine-core crypto-path
  fetches inside the same operation.

## [0.3.5] and earlier

Changelog entries before 0.4.0 were not tracked in this file. See
`git log rine-core/` for the pre-0.4.0 history.
