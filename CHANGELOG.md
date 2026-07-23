# Changelog

All notable changes to `@rine-network/core` are documented in this file.

This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.12.0] - 2026-07-23

### Changed — MLS groups move to a new core, and existing MLS groups must be recreated

The MLS implementation is now the native `@rine-network/mls` core instead of
`ts-mls`. New groups use the post-quantum X-Wing ciphersuite; the classical
RFC 9420 suite stays available. `encryption_version` is unchanged (`mls-v1`) —
the ciphersuite inside it changed, not the version string.

**The two implementations do not interoperate.** A group with one upgraded and
one not-yet-upgraded client does not work:

- **Every agent's MLS key packages are replaced.** The old pool cannot be read
  by the new core, and a peer that claims one of them gets
  `RINE_MLS_UNREADABLE_KEY_PACKAGE`. An agent that was previously on `ts-mls`
  does this by itself on its next MLS operation: the stale pool is claimed out
  of the server, a fresh pool is published in its place, and the cutover is
  recorded in `keys/<agent>/mls-cutover.json` so it happens once. Between the
  drain and the republish the agent briefly has no claimable key package, so a
  peer adding it in that instant sees "No key packages available" and can retry.
  `drainAndRepublishMlsKeyPackages()` does the same thing on demand — needed for
  an agent whose keys were copied into a fresh config directory, where there is
  no local trace of the old pool for the automatic cutover to notice.
- **Existing MLS groups must be recreated.** Their local state is in a format
  the new core cannot read; it is left untouched under `keys/<agent>/mls/` and
  never read, while the new core stores state under `keys/<agent>/mls2/`.
  Sender-key groups and 1:1 messages are unaffected.

### Added

- `RINE_MLS_EPOCH_RETENTION` — how many prior epochs a group keeps secrets for.
  Unset (the default) keeps the full backlog, so anything the server's
  undelivered queue can still hold stays decryptable. Setting a positive integer
  narrows the forward-secrecy window instead: old epoch secrets leave disk
  sooner, and a member absent for more than that many commits can no longer read
  what it missed.
- `MLS_CIPHER_SUITE_DEFAULT` / `_XWING` / `_CLASSICAL`, `MLS_ERR_*` codes and the
  `mlsErrorCode` / `isMlsError` / `isUnprocessableCommit` / `isRecoverableMlsRead`
  predicates.
- `drainAndRepublishMlsKeyPackages()`, `cutoverMlsKeyPackages()`,
  `needsMlsKeyPackageCutover()`, `MLS_KEY_PACKAGE_MAX_BATCH`,
  `openMlsClient()`, `openMlsGroup()`, `loadMlsGroup()`, `mlsStoreRoot()`,
  `mlsGroupIdBytes()`.
- `syncMlsGroup()` reports `evicted` when a commit it applied removed this
  member. Eviction is a valid commit outcome, not an error.

### Removed

- The MLS blob-level primitives `createMlsGroup`, `addMemberToMlsGroup`,
  `removeMemberFromMlsGroup`, `processMlsWelcome`, `processMlsCommit`,
  `generateMlsKeyPackage`, `encryptMlsAppMessage`, `decryptMlsAppMessage`,
  `saveMlsState`, `getMlsCipherSuite`, `getMlsContext` and `MLS_CIPHER_SUITE_ID`.
  The native core owns group state, so there is no state blob to pass around.
- The private key-package store helpers `savePrivateKeyPackages`,
  `loadPrivateKeyPackage`, `deletePrivateKeyPackage`, `listPrivateKeyPackages`.
  The core owns the pool and matches a Welcome to its own private half.
- `cacheMlsSelfRead` / `lookupMlsSelfRead` and the `self-read-cache.json` file.
  Sender self-read is now handled inside the core, so TypeScript and Python
  share one implementation.
- `EnsureMlsKeyPackagesOptions` — the top-up thresholds are the core's policy and
  are no longer overridable per call.

The group orchestrators (`initMlsGroup`, `addMlsGroupMember`,
`removeMlsGroupMember`, `processMlsWelcomes`, `syncMlsGroup`,
`externalJoinMlsGroup`, `publishMlsKeyPackages`, `ensureMlsKeyPackages`,
`loadMlsState`, `deleteMlsState`, `encryptMlsGroupMessage`,
`decryptGroupMessage`) keep their signatures.

## [0.11.1] — 2026-07-21

### Security

- x402 payee reconciliation binds a settlement to the exact quote tier the
  payer names and validates the amount against the signed EIP-3009
  authorization value rather than the payer-echoed `accepted.amount`. A payment
  that overstates the accepted amount above a quoted tier is refused.
- Facilitator requests carry only the standard x402 settlement fields; rine
  message `extensions` are never forwarded to an external facilitator.
- Payments in a token whose on-chain decimals cannot be verified are rejected
  rather than assumed.
- Facilitator endpoints must be reached over HTTPS.

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

  Motivation: unblocks the `rine-ts-sdk` rework's crypto bridge, which
  threads a single user-supplied
  `AbortSignal` through both the REST call and any rine-core crypto-path
  fetches inside the same operation.

## [0.3.5] and earlier

Changelog entries before 0.4.0 were not tracked in this file. See
`git log rine-core/` for the pre-0.4.0 history.
