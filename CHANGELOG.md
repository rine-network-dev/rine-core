# Changelog

All notable changes to `@rine-network/core` are documented in this file.

This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.17.0] - 2026-10-29

An org is now built from one secret, the **org root**, and `client_secret` no longer
exists. This is a breaking release. Every key an org uses derives from the root; the
server stores only public keys and certificates; and a 24-word recovery phrase rebuilds
the whole org on a new machine. Every 1:1 message is post-quantum, every closed group
uses the post-quantum MLS suite only, and the org that owns an agent can read what that
agent reads. Packages older than 0.17.0 cannot sign in to a server that runs this release,
and every org registered before it is retired.

**What you will see differently:**

- Onboarding creates a 32-byte org root and shows a 24-word recovery phrase. Losing both
  `root.key` and the phrase loses the org for good; anyone who reads either one controls
  the org permanently. The phrase does not restore wallet keys.
- `client_id` and `client_secret` are gone, and so are the `RINE_CLIENT_ID` and
  `RINE_CLIENT_SECRET` variables: they are ignored and nothing replaces them. A token
  comes from a short-lived signed assertion (`private_key_jwt`). A clock more than 30
  seconds ahead cannot sign in, and the error names clock skew.
- `credentials.json` is replaced by `profiles.json`, which holds the principal, agent id
  and poll URL and no secret. `root.key` and the phrase live in a separate owner
  directory (`RINE_OWNER_DIR`, default `~/.config/rine-owner`) that the library refuses to
  place inside a git checkout or the config directory. An agent runtime holds only its
  own leaf keys.
- Only `hpke-hybrid-v2` (1:1), `sender-key-v1` and `mls-v1` messages exist. A message
  sealed as `hpke-v1` or `hpke-hybrid-v1` is refused, and an agent without a
  post-quantum key cannot be created.
- Org ids are derived from the org's keys, so a recovered org keeps its id. Every agent's
  verification words change with its new keys, and an org has eight verification words of
  its own.
- Reading a closed or open group is no longer limited to the member agents: the root of
  every member org reads what the group's other members said in the epochs its own agents
  held. Say nothing in a shared group that you would not let those orgs read.
- Rotating an agent's keys needs the org root or a branch key. After a rotation the
  holder of the root can still read the older generations' 1:1 traffic.

### Added

- **Derivation, phrase and org id.** `deriveOrg`, `deriveBranch`, `deriveAgent`,
  `deriveMessageKey`, `orgIdFromKeys`, `orgWords`, `phraseFromEntropy`,
  `entropyFromPhrase`, and the owner-directory helpers `saveRoot`, `loadRoot`,
  `restoreOwnerFromPhrase` and `readOwnerPhrase`.
- **Signed assertions and certificates.** `buildAssertion` and the JWS and certificate
  family (`signJws`, `verifyJws`, `issueAgentCert`, `issueBranchCert`, `verifyAgentCert`,
  `verifyBranchCert`). Every key a client accepts from the server is checked against its
  certificate chain (`verifyKeyChain`), and `KeyPins` pins the own org, each agent's
  org and its highest key generation.
- **Branches.** A branch is a named subtree of the org that a partner can hold; an agent
  or branch principal can sign in with narrower authority than the org. `revokeBranch`
  takes a `confirm` flag: the server refuses to revoke `main` or the org's last live branch
  without it.
- **Group read escrow.** Each member agent seals the read secrets of every closed-group
  epoch it holds to its branch's escrow key and uploads them (`sealEscrow`, `drainEscrow`,
  `startupEscrowSweep`, `postWithEscrowRetry`). A post into a new epoch waits for its
  escrow, and a refused post (`escrow_missing`) uploads and retries. `listGapMarkers` and
  `describeEscrowGaps` name the epochs that could not be escrowed.
- **Reader signers.** `orgReaderSigner` and `branchReaderSigner` give a GET-only
  credential that reads and signs nothing else.
- **`@rine-network/core/testing`** exports a self-consistent test org with real
  derivation and real certificates, for tests that need a peer whose key chain verifies.
  It is test-only and not part of the root entry.
- `isA2aCleartext`, `markA2aCleartext` and `A2A_CLEARTEXT_NOTICE`: the one marking an A2A
  message gets when it arrived without end-to-end encryption, and `a2aCleartextPlaintext` and
  `a2aCleartextPayload`, which decode the parts it carried from the wire's base64url. `a2aCleartextMark`
  returns the typed flag and the sentence for such a row, and `A2A_MESSAGE_TYPE` and
  `CLEARTEXT_ENCRYPTION_VERSION` name the two wire values that identify it.
- `withA2aCleartextNotice`: a body shown for an A2A cleartext message, led by the notice in
  brackets, for a renderer that shows or hands a model one string. Any other row is unchanged.
- **Seat self-update on rotation.** `rotateAgentWithSeats` rotates an agent's keys and then
  moves the agent's own leaf in every closed group it sits in, with no removal and no
  re-invite. `settleRotation` finishes that work later (the heartbeat runs it before the
  key-package top-up) and `selfUpdateGroup` is the per-group step, and each seat reports
  `updated`, `current`, `deferred` or `failed` with a reason. A self-update stays pending
  until the server confirms it; while it is pending the agent's own other commits in that
  group are refused and its sync applies and ACKs nothing, though reads and sends carry on,
  and a commit the group did not take is dropped and tried again. A key package that names a
  key the chain does not publish is skipped when a member is added. A background settle that
  keeps failing backs off, from one minute up to an hour, instead of retrying every beat.

### Changed

- 1:1 messages seal with `hpke-hybrid-v2`: an X-Wing-style SHA3-256 combiner that binds
  the ciphertext and both public keys, with the associated data fixed by a closed
  `SealContext` (`AgentMessage`, `BranchBundle`, `MlsEscrow`) rather than a free label.
- Every message signature signs a fixed prefix, the recipient or group id and the
  payload, so a signature made for one purpose can never verify as another.
- One strict Ed25519 verifier is used everywhere: small-order and non-canonical keys are
  refused.
- MLS opens with an allowed set of chain-verified `(agent id, leaf key)` pairs instead of
  accepting any credential. The leaf key derives from the branch signing key, so recovery
  keeps the agent's seats. Suite `0xF057` is the only suite. Requires
  `@rine-network/mls` 0.2.0.
- Funnel hostnames, poll URLs and webhooks follow the new agent ids; register them again.
- The `@hpke/core` and `@hpke/dhkem-x25519` dependencies are dropped.

### Removed

- `loadCredentials`, `getCredentialEntry` and the rest of the credentials-file helpers.
- `MLS_CIPHER_SUITE_CLASSICAL` and the classical MLS suite.
- The `hpke.ts` exports that `crypto/index.ts` re-exported, and `signPayload` as an
  unprefixed signer.
- Reading or writing `client_secret`, the `RINE_CLIENT_*` variables and `hpke-v1` anywhere.
- `generateAgentKeys`, `generateSigningKeyPair`, `generateEncryptionKeyPair` and
  `generatePqKeyPair`. They made random keys with no org root above them, so nothing a
  server would accept came out of them. External callers lose these functions; derive an
  agent's keys from the org root with `deriveOrg`, `deriveBranch` and `deriveAgent`, then
  `agentKeysFromDerived`.

### Changed — internal

- The per-Welcome install and the external join move out of `mls-ops-join.ts` into their
  own modules. No export changes. The Welcome install invalidates the local state memo right
  after the join, before the refusal check, as the Python SDK does.

### Fixed — an unreadable x402 spend journal refuses payment

A spend journal that cannot be read (not JSON, a missing day, a malformed total or
paid-id list) raises `CorruptSpendJournalError`, names the file and leaves it as it is;
it used to read as a fresh day with nothing spent. A journal dated tomorrow (UTC) keeps
its spend, because the clock moved back across midnight. One dated two or more days
ahead refuses payments with the same error, which names the file and says to check the
system clock.

**What you will see differently:** a clock set back by two or more days stops x402
payments until the clock is right or the journal is repaired.

### Fixed — a Welcome naming a member the roster no longer lists installs

A Welcome whose group holds a member added or removed since the agent read the
roster is no longer discarded as unjoinable. The welcome pass chain-verifies
each member the native core refuses by name, once per member, and opens the same
Welcome again, so it installs. A Welcome naming a member that does not verify is
still discarded, with its key package released, as is one that names more than 64
such members. A failed verification read keeps the Welcome on the spool for the
next pass. An ordinary pass makes no extra request.

**What you will see differently:** a join that used to be discarded as unjoinable
now installs. An agent re-invited to a group it still holds old state for no longer
sees that group reported as joined when the new Welcome is refused for a member
that does not verify: the group is absent from `groupIds`, the Welcome counts in
`discarded`, and its key package is released.

### Fixed — a member that missed a commit catches up through it

A member that was offline while a peer was added and then removed could not
apply the Add: the native core refuses a leaf it has not admitted, and the
peer was already off the roster the sync read. Sync, resync, the recovery
reseat, removal and orphan removal now chain-verify each agent the core names
in a refusal, once, and retry the same input. A leaf that does not verify, or
whose key is not the verified one, is refused as before: the commit is NACKed
once and the call throws with the stable code `RINE_MLS_PEER_NOT_ADMITTED`, so
recovery can resync past it. A failed verification read surfaces as itself and
earns no NACK. An ordinary sync makes no extra request.

### Fixed — escrow gaps belong to the fork that lost them

A gap the drain reports, and the epochs of a parked snapshot that can no longer
be opened, are filed under their fork (`<epoch>-<fp>.gap`), so losing fork A at
an epoch no longer blocks a send on fork B at the same epoch. The parked
snapshot's sidecar records each queued epoch's fork under `fps`; a sidecar
without it still reads, and names no fork.

### Fixed — the escrow head follows a fork switch

A resync or reseat that seats the member on another fork at a lower epoch now
moves the escrow head there, instead of leaving it on the fork the group left.

### Fixed — a Welcome dropped unopened gives back its key package

A Welcome that ages out, is evicted, belongs to a group that is gone, cannot be
joined or is finally refused releases the key package it was sealed to, so the
local inventory no longer over-counts. An installed or retained Welcome never
does.

### Fixed

- A cleartext A2A turn shows in `decryptThreadRows` with the notice and as `unverifiable`,
  where it used to render as `[unavailable]`. The thread a CLI or MCP caller prints now matches
  the one the SDKs print.
- **A wrong clock no longer reads as a wrong phrase.** When recovery is refused because
  this machine's clock is outside the window the server accepts, the error now says the
  clock is off instead of "no org matches this phrase". The token error carries the
  server's `reason` on `RineApiError.body`.
- **A read escrow with an impossible tree size is refused before sealing.** A leaf count
  that is zero, not a power of two or above 2048 is rejected up front.

### Removed — the root export is an explicit list

The package root exports named values and types instead of `export *` from every module, and 335 names (290 values,
45 types) that nothing outside the package used left it. Code that imported one of them from `@rine-network/core`
stops compiling or resolves to `undefined`; the removed names are internal helpers of the crypto, MLS, funnel, x402
and key-derivation modules. They include `getAgentPublicKeys` (deleted: it built the calling agent's own public-key
JWKs from its local key files, and no root export replaces it whole; `loadAgentKeys` and `signingPublicKeyToJWK`
remain, and `fetchRecipientKeys` reads another agent's published keys), the low-level MLS wrappers (`mlsInit`,
`mlsCommit`, `mlsAck`, `mlsNack`, `mlsHeartbeat`), the escrow, branch and certificate helpers (`sealEscrow`,
`issueBranchCert`, `verifyBranchCert`, `loadRoot`, `saveBranchSecrets`), the funnel ACME and mux internals
(`createMuxClient`, `buildAcmeClient`, `encodeFrame`, `decodeFrame`), the x402 helpers (`recordSpend`,
`withSpendLock`, `parseAtomicAmount`, `signDigest`), and the test-only reset hooks `resetMlsCatchUpGate` and
`resetKeyPackageRescueGate`.
The full list is below.

New on the root: `sealForAgent` (the one 1:1 seal that the CLI, MCP and SDK share), `createAtomicExclusive`,
`SENDER_KEY_DISTRIBUTION_TYPE`, `isControlFrameType` and `controlFrameReplyRefusal` (the sentence a reply path gives
a control frame). `GROUP_INVITE_TYPE` keeps its root name.

**What you will see differently:**

- `writeAtomic(path, content)` has no third `exclusive` parameter and returns nothing. Create a file that must not
  already exist with `createAtomicExclusive(path, content)`, which returns `false` when the file is there.
- A TypeScript consumer of a removed name fails at build time with "has no exported member".

**Removed values:** accountKeyPath, acmeDirectoryUrl, ACQUIRE_TIMEOUT_MS, actorLabel, addProfileIfAbsent, admitTree,
admitWelcomePeers, advanceChain, agentKeyBody, AgentOnlyOwnerDirError, agentWildcardFqdn, ALREADY_A_MEMBER_CODE,
ambiguousInvitationJoinRefusal, assertEpochReadSecrets, assertFreshOwnerDir, assertionClaims, assertOwnerDirAllowed,
assertStrictEd25519PublicKey, BARE_NAME_IS_ONLY_AN_INVITATION, branchCertClaims, BranchEscrowKeyError,
branchFromSecrets, BRANCH_NAME_RE, branchPublication, branchReaderSigner, branchSigner, buildAcmeClient,
buildExpectedRequirement, bytesToUuid, cachedEscrowKey, canonicalAgentLabelId, CANONICAL_DECIMALS, canonicalize,
canonicalUuid, CANONICAL_UUID_RE, chainIdFromCaip2, claimKeyPackages, claimKeyPackagesBatch, CLOCK_SKEW_REASON,
compareVerificationWords, composeGroupRefusal, CONTROL_CONN_ID, createMuxClient, decodeEnvelope, decodeFrame,
decryptThreadRow, deriveEvmAddress, deriveMessageKey, DIRECTORY_HELD_MORE_THAN_THIS_JOIN_READ,
DIRECTORY_PAGE_LIMIT, DIRECTORY_PAGES_FOR_A_JOIN, directoryQueryForHandle, domainSeparator, dropEscrowKeys,
eip3009Digest, encodeEnvelope, encodeFrame, encryptionPublicKeyToJWK, ensureDir, entropyFromPhrase,
EPOCH_READ_SECRETS_VERSION, ESCROW_CIPHER_SUITE, ESCROW_KEY_REVOKED, ESCROW_MISSING_CODE, escrowSealContext,
escrowSigningInput, FACILITATOR_TIMEOUT_MS, fetchHandshakes, fetchPeerCardWords, fetchWelcomes, forgetEscrowKey,
FrameError, fullJitterBackoffMs, funnelCacheDir, generateCertKeypairAndCsr, generateWalletKey, getAgentPublicKeys,
groupLocalPart, GROUP_READ_MAX_BYTES, GROUP_READ_MAX_ENTRIES, handleCacheDir, handleConnection,
hashTransferWithAuthorization, HEADER_LEN, hkdfDerive, HOOK_NAME_MIN_LENGTH, HTTP_204, HTTP_400, HTTP_500,
ignoredActorWarning, instantMicros, isAssetAllowed, isBareReference, isCanonicalText, isEscrowMissing,
isExactGroupHandle, isInventoryFull, isInvitationOfThatName, isMlsError, isMlsKeyNotCurrent, isRenewalDue,
isSigilGroupReference, issueAgentCert, issueBranchCert, issueCert, isTerminalAcmeError, isUnprocessableCommit,
isValidHookName, joinLines, joinSentences, JOIN_TAKES_A_HANDLE_OR_AN_ID, JwsError, keyPackageTopUpLine,
KNOWN_ASSETS, liftRetirementIfMember, loadAttemptLedger, loadBranchSecrets, loadCachedCert, loadReferencedQuote,
loadRoot, localAgentIds, localAllowedIdentities, lookupAsset, lookupGroupRead, MAIN_BRANCH, makeAcmeClientDeps,
makeDnsPost, markSenderKeysRetired, MAX_AUTHORIZATION_TTL_SECONDS, MAX_ESCROW_CONTEXT_LENGTH, MAX_LISTED_GROUPS,
MAX_RETRY_WAIT_MS, messageSigningInput, MLKEM_CT_SIZE, mlsAck, MLS_CATCHUP_MIN_INTERVAL_MS, mlsCommit,
MLS_ERR_ALLOWED_GENERATION_CONFLICT, MLS_ERR_COMMIT_PENDING, MLS_ERR_KEY_NOT_CURRENT, MLS_ERR_NO_SEAT_TO_REPLACE,
MLS_ERR_PANIC, MLS_ERR_PEER_NOT_ADMITTED, MLS_ERR_POISONED, MLS_ERR_RESYNC_CHANGES_KEY, MLS_ERR_ROTATED_LEAF,
MLS_ERR_SELF_MESSAGE_NOT_CACHED, MLS_ERR_SIGNER_LEAF_MISMATCH, MLS_ERR_UNREADABLE_KEY_PACKAGE, mlsFromBase64,
mlsGroupIdBytes, mlsHeartbeat, MLS_HEARTBEAT_MIN_INTERVAL_MS, mlsInit, MlsKeyNotCurrentError,
MLS_KEY_PACKAGE_LOW_WATER, MLS_KEY_PACKAGE_MAX_BATCH, MLS_KEY_PACKAGE_TARGET, mlsNack, MLS_NEVER_FOUNDED_NOTE,
MLS_REMOVAL_COMMIT_REQUIRED, MLS_RESYNC_REQUIRED_CODE, MLS_RESYNC_UNAVAILABLE_CODE, mlsToBase64, nameOneOfThem,
namesClockSkew, needsRotation, NO_KEY_PACKAGE_TOP_UP, NO_ORG_FOR_PHRASE, normalizeGroupRef, NO_SUCH_GROUP_TO_JOIN,
notAConversationUuidRefusal, noteMlsStateChanged, openGroup, openHybrid, openInbound, ORG_CLAIM_MISMATCH,
orgIdFromKeys, orgWords, OWNER_DIR_ENV, parseAtomicAmount, parseAtomicUnits, parseHttpRequest, parsesAsUuid,
parseUnits, PER_CONN_INFLIGHT_CAP, PhraseError, phraseFromEntropy, POLL_MS, pqKeyPairFromSeed, pqPublicKeyToJWK,
pqSigningPublicKeyToJWK, recordGroupRead, recordSpend, recoverAddress, RECOVERY_LEFT_ON_REMEDY, RECOVERY_NOTES,
refuseIfABareAgentName, registerPopClaims, removeOwnerFiles, renderThreadText, requirementCanonicalAmount,
reseatGroup, resetKeyPackageRescueGate, resetMlsCatchUpGate, resolveBareRecipientGroup, resolveDecimals,
resolveGroupByName, resolveGroupUuid, resolveTokenExtra, retakeSeat, retryAfterMsFromError,
retryAfterMsFromResponse, revokeAndWipeCache, RevokedCode, revokedErrorFor, revokedScope, rineErrorFromResponse,
ROOT_KEY_FILE, sameWords, saveAttemptLedger, saveBranchSecrets, saveCert, saveMeta, saveOwnerIdentity,
savePqEncryptionKey, saveWalletKey, scaleToDecimals, sealContextAad, sealEscrow, sealEscrowWith, sealGroup,
sealHybrid, sealHybridWith, seatedGroupByHandle, selfUpdateGroup, senderKeysRetired, sharePins, SiblingIssuanceInProgress,
sigiledGroupRef, signDigest, signedWithinValidity, signingKid, signMessage, solveTimeLock, spendLockPath,
SPIFFE_ENDPOINT_SOCKET_ENV, STALE_MS, tagLeRateLimit, takeAndSeal, toChecksumAddress, toDrainGap,
TOKEN_RETRY_MAX_ATTEMPTS, topUpFromServerCount, topUpKeyPackages, TunnelBindError, TWO_INVITATIONS_OF_THAT_NAME,
UnpersistedSenderKeyStateError, unretireSenderKeys, unseatedGroupSendRefusal, UPGRADE_DETAIL, uploadKeyPackages,
uuidFromBytes, uuidToBytes, validatePathId, validatePolicy, verificationWordsForJwk, verifyAgentCert,
verifyBatchKeys, verifyBranchCert, verifyBranchEscrowKey, verifyEd25519Strict, verifyEnvelopeSender,
verifyEscrowUploaderSig, verifyJws, verifyKeyChain, verifyMessageSignature, VERSION_HYBRID_V2, VERSION_MLS,
waitForTxtPropagation, WEBHOOK_CONTENT_TRUST, WEBHOOK_MESSAGE_TYPE, WELCOME_REFUSED_CODE, wipeHandleCache,
withAgentIssuanceLock, withSpendLock, x402Marker, x402MarkerMetadata, X402_PAYLOAD_SCHEMA, X402_SUPPORTED_SCHEMES.

**Removed types:** AssertionClaims, AttemptLedger, BatchKeysResponse, BranchCertClaims, BranchEscrowKeyResponse,
CachedCert, Eip712Domain, EscrowSlot, EscrowUploader, GroupRefusalParts, HeldSigningKey, InnerEnvelope,
KeypairAndCsr, KnownAsset, MarkDeliveredResponse, MlsAckResponse, MlsActor, MlsCommitBody, MlsCommitResponse,
MlsHandshakeEntry, MlsHeartbeatPace, MlsInitResponse, MlsKeyPackageClaim, MlsNackResponse, MlsWelcomeEntry,
MuxClient, MuxClientArgs, MuxWs, Opened, OwnIdentity, ParseResult, PhraseFault, PublishedKeys, Readability,
ReferencedQuote, RefusalCandidates, RefusalLead, RegisterPopClaims, SealContext, SealedEscrow, SenderVerification,
SigContext, SpendLockClock, WelcomeAdmission, X402Scheme.

### Added — hook creation, vote eligibility words and shared timing helpers

- `createHook` creates a funnel hook and keeps its secret in step with the server. A create that fails over an
  existing hook name keeps the secret that hook already uses, and a refused create for a new name leaves no secret
  on disk.
- `describeVoteEligibility`, `VOTE_ELIGIBILITY_CLAUSES`, `sleep`, `fetchGroupMembers` and `isDecryptableVersion`
  are new root exports. With `jitteredDelayMs` and `nextReconnectBackoffSeconds`, which were root exports already,
  they are what the CLI, MCP and SDK now share instead of carrying copies.
- Also new at the root: `agentKeysFromPrivate` and `AgentPrivateKeys`; `ENCRYPTION_VERSIONS`, `EncryptionVersion`,
  `GroupEncryptionVersion` and `isGroupEncryptionVersion`; `impliedVoteEligibilityReason`,
  `VoteEligibilityClauseReason` and `VoteEligibilityFallbacks`; `HookCreateResult`, what `createHook` returns; and
  `AlreadyAMemberJoin`, `seatedMemberAfterConflict`, `reportFailedSetup` and `MlsSetupFailureSink`.
- `CorruptProfilesError`, `CorruptSpendJournalError` and `seedOwnPins` are root exports.

### Fixed — files written under the config directory

- Agent key files, the MLS cutover marker and peer-verification records are 0600 from creation and written
  atomically. A symlink left at one of those paths is replaced, not written through. A funnel certificate, cert key,
  `meta.json`, attempt ledger or ACME account key written beside a `.tmp` file or symlink someone left there is no
  longer written through or reused.
- A `profiles.json` that is not valid makes `register`, `onboard`, `auth`, agent create and owner recovery fail with
  "<path> is not a valid profiles file; repair or remove it, then retry". Before, they replaced it with a file that
  held only the new entry, and onboarding failed only after the registration and the `root.key` write. Read
  commands still treat a corrupt file as having no profiles. A `profiles.json` that holds `null` reads as empty.
- Two runs that write profiles at once no longer lose an entry: profile writes take `profiles.json.lock`, and a
  writer that outwaits a live holder fails after 10 seconds. A second `saveRoot` that races the first fails instead
  of overwriting `root.key`. A funnel relay that cannot create its issuance lock for a reason other than a held
  lock (a permission error, say) fails that attempt instead of waiting for a sibling that does not exist.
- A spend journal that is not valid UTF-8 refuses payments with `CorruptSpendJournalError`; invalid bytes inside a
  JSON string used to be replaced and the journal parsed. An unreadable journal (permissions) refuses as well.
- A pending-escrow file whose epoch has a leading zero (`01-<hex>.bin`, which only a hand edit makes) is no longer
  read; the 15-digit epoch limit that gap files already had applies to it.
- `isInventoryFull` recognises a refusal that carries the `key_package_inventory_full` code, whatever its prose says.

### Changed (since the release candidate)

**What you will see differently:**

- `requireAuthenticPlaintext` is gone from the exports. `requireVerifiedSender` and `requireVerifiedPlaintext`
  replace it, and only a `verified` sender passes. Code that imported the old name must switch.
- A sender whose signing key could not be read is refused with the new `X402_ERROR.SENDER_UNVERIFIABLE`
  (`sender-unverifiable`). It is retryable: nothing was paid or settled, and the same message passes once the key
  lookup works. `INAUTHENTIC_SENDER` is kept for a signature that does not check out, a re-sealed message, a
  verified message with no body, a row that failed to decrypt or has no authenticated sender, and a cleartext A2A message.
- A signing key id that does not parse is a `sender-mismatch` verdict, with no key fetch.
- Requests to a payment facilitator no longer follow redirects.
- The EIP-712 domain for Base mainnet USDC is `USD Coin`, version `2`, as the contract reports it.
- The webhook request framer refuses a body over 94 KiB with HTTP 413 Payload Too Large, and a head over 16 KiB
  with HTTP 400, then drops a connection that keeps sending. 94 KiB is the largest webhook the relay can
  encrypt and post within the server's 128 KiB ciphertext limit; a larger body was acknowledged with a 204 and
  never delivered. The shared-edge broker still refuses a body over 128 KiB first, so a shared-edge body between
  94 KiB and 128 KiB now gets the relay's 413.
- The relay answers a verified webhook it could not post (key lookup or `POST /messages` failed) with HTTP 502
  Bad Gateway instead of 204, so the sender can mark the delivery failed and redeliver. A replay and an HMAC
  rejection still answer 204. `TlsListenerArgs.onRequest` and `EdgePipeArgs.onRequest` now resolve with the
  relay's `RelayResult`, which picks the response.
- `rotateAgentKeys` checks the key it reads against the org's chain: a key set from another org or with a lower
  generation than this device holds is refused.

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
