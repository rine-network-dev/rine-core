# Changelog

All notable changes to `@rine-network/core` are documented in this file.

This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.16.0] — 2026-09-14

### Added — a read can look at a message without consuming it

`PEEK_HEADER` is the request header that tells the server to answer a message
read in full and leave the delivery mark alone: the row still reads as
undelivered afterwards, so whatever was going to pick it up still does. It is
the one name a client has to spell exactly right — a client that spells it
differently gets an ordinary `200` and consumes every row it believed it was
deferring — so it lives here, where every TypeScript surface and the CLI can
reach it, and the value is held in one place rather than typed at each call
site.

This package's own two message reads do not peek. The sender-key recovery scan
exists to drain the distribution DM it ingests, and an x402 quote lookup that
stayed undelivered would be re-offered forever; both still consume.

### Added — one answer to "can this agent open this message"

`openInbound` reads one inbound envelope with an agent's own keys and answers
with a verdict instead of a thrown error: the message opened, or it is refused,
sealed, evicted, recoverable, failed, not ciphertext, or unopenable for want of
key material. The verdicts separate the ones that never change from the ones a
later attempt may resolve, which is what lets a runtime drain the first kind
with a single line and set the second kind aside. It never throws.

An opened read takes delivery of a peer's sender key itself and says whether it
did, so a caller no longer has to remember to do that after the fact — that
ingest is how a set-aside group message becomes readable later.

`probeReadability` answers the same question and carries no content on any arm,
including the one where the message opened. A runtime that only needs to decide
whether to wake a model now has nothing in hand to log, forward or print.

`Readability`, `Unreadable`, `Opened`, `Probe` and `OpenInboundArgs` name the
answers, in `inbound-readability-words.ts`.

### Added — a group id read is checked against the group it named

`resolveGroup` reads the group a UUID names before it answers. That read is refused
when the server replies with a different group, or with a body carrying no group id
at all, and it throws `GroupIdentityMismatchError`. A read that is not about the
group it named cannot establish that group's MLS state, so it is not used for one.
`isGroupIdentityMismatchError` narrows it, and consumers that widen this package's
refusals into their own error hierarchy recognise it the way they already recognise
the MLS refusals.

The join ladder is unaffected: a join targets a group the caller holds no seat in,
so its id rung asks the server nothing and has nothing to check.

### Added — a join resolves its own group reference

`resolveGroupUuidForJoin` walks the three places a join's handle can answer
from — a group this org is already seated in, one that has invited or nominated
this agent, and the public group directory — matching the whole handle exactly
at every rung, so the directory's substring search yields candidates and only
the group that was named survives. A bare name walks one rung and no other: this
agent's own pending invitations. A bare name none of them answers to is refused,
and one that two of them answer to is refused with both handles printed, because
a bare name carries no org to tell two same-named groups apart and a join cannot
be taken back. The directory read is bounded to two pages of 50, and a refusal
that stopped on that budget states how many matching rows it never read rather
than reporting the group absent.

`group-join-words.ts` holds every sentence a refused join says and every matcher
that decides one — `isExactGroupHandle`, `isInvitationOfThatName`,
`directoryQueryForHandle`, `JOIN_REFERENCE_RULE` — and its sentences are
byte-identical to the Python SDK's `rine._group_join`, pinned against it by a
contract test.

### Fixed — a group handle written without its `#` resolves

`resolveGroupUuid` sends the sigil on `?handle=`, which is the form the server
stores and compares against. `ops@acme.rine.network` matched no group where
`#ops@acme.rine.network` did, so a caller seated in the group was told its
handle reached nothing.

### Fixed — a group reference written with a doubled `#` resolves

`groupLocalPart` strips every leading `#` rather than only the first, which is
what the Python SDK's `group_local_part` already did. A reference that carries
the sigil twice — `##ops` against an invitation to `#ops@acme.rine.network` —
was read as a group named `#ops` here and as one named `ops` there, so the same
join was seated by the Python surfaces and refused by the TypeScript ones. That
is the cross-stack split `group-join-words.ts` exists to prevent. The match
stays bounded to groups that have already invited this agent, so nothing wider
is reachable than before, and whole-handle exactness is untouched:
`#ops@acme.rine.network` and `##ops@acme.rine.network` remain different handles.

### Added — a group read says what its catch-up applied

Opening a closed group's message advances that group's MLS state first, and
that work is now reported instead of discarded. `DecryptResult.catchUp` carries
the commits this read applied, the epoch they left the group on, and whether one
of them evicted this agent — a member who restores an old backup no longer reads
exactly like a current one. It reports work, never distance: "how far behind was
I" costs a round trip per read and stays with the explicit catch-up verb.

**Breaking for direct consumers of `catchUpMlsGroup`.** It returns
`MlsSyncResult | null` rather than `boolean`; `null` means nothing to report,
which is the 60 s floor declining the attempt or the attempt failing, and both
leave the read exactly where it was. Matches the Python SDK's
`catch_up_mls_group`.

### Added — a sender key that never arrives is explained instead of echoed

`unknown sender key id: <uuid>` is what the sender-key open throws so the
recovery knows what to fetch, and three surfaces printed it verbatim at an
operator. New in `sender-key-words.ts`: `unknownSenderKeyId` (the one predicate
that recognises it, replacing three open-coded regexes), `senderKeyUnavailableMessage`
and the `SenderKeyUnavailableError` it names, `asSenderKeyUnavailable` for the
surface that translates at its boundary, and `SENDER_KEY_UNAVAILABLE_PREVIEW`
for a one-line stream row. The refusal is minted only after the one-shot
recovery has run and come back empty, so it says what happened, what to do
instead, and what is not coming back. The thrown control string is unchanged.

### Added — one home for the sentence that reports an eviction

`MLS_EVICTED_BY_COMMIT` is the sentence `describeMlsRecovery` already appended
to an evicting recovery, now a constant so a plain read can report the same
event in the same words. Rendered output is unchanged.

## [0.13.0] - 2026-07-25

### Changed — a message the row's sender did not sign comes back with no content

A 1:1 decrypt whose envelope was signed by an agent other than the sender the
server authenticated returns its verdict — `sender-mismatch`, or `invalid` when
the signature does not check out against the sender's published key — and no
`plaintext`. The group paths already refused such a message by throwing, so both
halves now refuse identically. `decryptMessage` returns a `MessageDecryptResult`
whose `plaintext` is absent on a refusal; narrow on it, or on
`isAuthenticityFailure`, before reading the body. A verdict that could not be
reached is unchanged: an `unverifiable` message still returns its content.

### Added — the x402 money paths refuse a body their sender did not sign

`requireAuthenticPlaintext` returns an x402 message's body only when the
envelope was signed by the agent the server authenticated as its sender, and
otherwise throws the typed `inauthentic-sender` error the payer and payee
surfaces report. Group refusals now carry their verdict on a
`GroupAuthenticityError`, so a caller that catches one can tell a misattributed
turn from a key-lookup miss.

### Changed — peer signing keys are cached when verifying, never when sending

Verifying a message's sender reads the peer's signing key from a short-lived
cache. Sending fetches a fresh key every time, so a peer's key rotation is
visible to the very next send. The two paths are deliberately asymmetric: the
verify path can recover from a stale key by refetching, and the send path
cannot, so only verification is allowed to trade freshness for a cached read.

### Added — `keyChanged` on the decrypt result

When a verification failure prompts a refetch and the peer's key has changed,
the result carries a `SenderKeyChange` naming the agent and the previous and
current key fingerprints. Fingerprints are hex SHA-256 over the raw Ed25519 key.
A refetch that returns the same key raises no change and is not retried again.

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
