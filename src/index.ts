// `mls-self-update.js` registers the group re-seat a key-rotation settlement
// runs (see `mls-settle-guard.ts`) when it loads, and none of its names is
// public, so the package entry point imports it for that effect.
import "./mls-self-update.js";

export { ackFailureNotice, createAckBatcher, markDeliveredAs } from "./ack-batcher.js";
export type { AckBatcher, AckBatcherOptions } from "./ack-batcher.js";
export {
	AGENT_ID_MISMATCH_CODE,
	AgentIdMismatchError,
	ESCROW_GAP_CODE,
	EscrowGapError,
	GROUP_IDENTITY_MISMATCH_CODE,
	GroupIdentityMismatchError,
	ORG_MISMATCH_CODE,
	OrgMismatchError,
	PrincipalRevokedError,
	RevokedScope,
	SENDER_KEY_UNDELIVERED_CODE,
	SENDER_KEY_UNDELIVERED_REFUSAL,
	SenderKeyUndeliveredError,
	RineApiError,
	formatError,
	isAgentIdMismatchError,
	isEscrowGapError,
	isGroupIdentityMismatchError,
	isOrgMismatchError,
	isPrincipalRevokedError,
	needsRemovalCommit,
	rejectedAgents,
	scopeOfRevokedCode,
} from "./errors.js";
export type { RejectedAgent, RineErrorBody } from "./errors.js";
export { GovernanceRefusal, HoldCode, holdOf } from "./errors-suspended.js";
export type {
	ApiError,
	CachedToken,
	ProfileEntry,
	Profiles,
	TokenCache,
} from "./types.js";
export { FUNNEL_TIERS } from "./api-types.js";
export type {
	AgentKeysResponse,
	AgentRead,
	FunnelTier,
	GroupMemberRead,
	GroupRead,
	HookCreated,
	HookListResponse,
	HookRead,
	JoinRequestRead,
	ListResponse,
	MessageRead,
	OrgRead,
	PaginatedResponse,
	VoteResponse,
	WebhookDeliveryRead,
	WebhookRead,
	WhoAmIRead,
} from "./api-types.js";
export { TtlCache } from "./cache.js";
export {
	DEFAULT_API_URL,
	PROFILES_FILE,
	cacheToken,
	createAtomicExclusive,
	loadTokenCache,
	resolveApiUrl,
	resolveConfigDir,
	saveTokenCache,
	writeAtomic,
} from "./config.js";
export { isRefusalStatus, isUnavailableStatus, jitteredRefreshMargin, retryAfterMsFromError } from "./retry.js";
export {
	HttpClient,
	fetchOAuthToken,
	getOrRefreshToken,
	seedOwnPins,
} from "./http.js";
export type { HttpClientOptions, TokenFn } from "./http.js";
export {
	UUID_RE,
	normalizeHandle,
	resolveHandleViaWebFinger,
} from "./resolve-handle.js";
export {
	handleCompletionNote,
	handleCompletionNotes,
} from "./handle-completion.js";
export {
	ACTING_AGENT_ENV,
	ACTING_AGENT_HEADER,
	ACTOR_SURFACES,
	actorFromEnv,
	actorNote,
	actorRefusal,
	ambiguousActorRefusal,
	normalizeActor,
	singleActorValue,
	unknownActorRefusal,
	unknownHandleRefusal,
} from "./actor.js";
export type { ActorOrigin, ActorSurface, ResolvedActor } from "./actor.js";
export {
	fetchAgents,
	invalidAgentIdentifierRefusal,
	resolveActor,
	resolveAgent,
	resolveToUuid,
} from "./resolve-agent.js";
export {
	EVICTION_POINTER_TAIL,
	GROUP_NOT_FOUND_LEAD,
	GROUP_ROSTER_LEAD,
	NEITHER_NAMESPACE_LEAD,
	NO_GROUPS_IN_ORG,
	matchGroupByName,
	recipientGroupForBareName,
	unknownGroupRefusal,
	withEvictionPointer,
} from "./group-ref.js";
export {
	readableGroupById,
	resolveGroup,
	resolveGroupByHandle,
	resolveGroupRef,
} from "./resolve-group.js";
export { GROUP_HANDLE_PARTS } from "./handle-words.js";
export {
	JOIN_REFERENCE_RULE,
	bareNameJoinRefusal,
	unresolvedHandleJoinRefusal,
} from "./group-join-words.js";
export { resolveGroupUuidForJoin } from "./resolve-group-join.js";
export {
	REF_CLASS,
	classifyReference,
	resolveGroupForJoin,
	resolveRecipient,
} from "./recipient-resolution.js";
export type {
	GroupTarget,
	RecipientTarget,
	RefClass,
	ResolveOptions,
	SeatedGroupTarget,
} from "./recipient-resolution.js";
export {
	THREAD_REF_SURFACES,
	resolveThreadRef,
	threadRefRequiredRefusal,
} from "./thread-ref.js";
export type { ThreadRef, ThreadRefSurface } from "./thread-ref.js";
export {
	conversationTranscriptPath,
	groupTranscriptPath,
	readThreadPage,
} from "./thread-read.js";
export type { ReadThreadOptions, ThreadPage } from "./thread-read.js";
export { solveTimeLockWithProgress } from "./timelock.js";
export {
	decryptGroupMessageWithRecovery,
	deleteSenderKey,
	distributeSenderKey,
	fetchAndIngestPendingSKDistributions,
	getOrCreateSenderKey,
} from "./sender-key-ops.js";
export type { DistributeResult } from "./sender-key-ops.js";
export {
	GROUP_ADMISSION_SKIP_REASONS,
	admissionHeadline,
	admittedAgentIds,
	groupAdmissionSkipSentence,
	mlsAdmissionSkipSentence,
} from "./group-admission.js";
export type {
	GroupAdmissionEntry,
	GroupAdmissionReport,
	GroupAdmissionSkipReason,
} from "./group-admission.js";
export { VOTING_ENROLLMENT_POLICIES, inviteNominates } from "./group-enrollment.js";
export { encryptionLine, groupEncryption } from "./group-format.js";
export { GroupPostingRefusedError, PostingRefusal, assertGroupPostable, isGroupPostingRefusedError, postingLine, unreadableByOrgsSentence } from "./group-postable.js";
export { isCached } from "./sender-key-negative-cache.js";
export type { GroupEncryption, RenderableGroup } from "./group-format.js";
export {
	MLS_FOUNDING_FAILED_MODE,
	MLS_FOUNDING_FAILED_NOTE,
	createdGroupMls,
} from "./group-create-format.js";
export type {
	CreatedGroupMls,
	CreatedGroupMlsFields,
} from "./group-create-format.js";
export {
	GROUP_INVITE_TYPE,
	HIDDEN_CONTROL_FRAME_READ,
	OPERATOR_CONTENT_NOTICE,
	OPERATOR_HISTORY_NOTICE,
	SENDER_KEY_DISTRIBUTION_TYPE,
	UNTRUSTED_CONTENT_NOTICE,
	controlFrameReplyRefusal,
	groupInviteNotice,
	isControlFrameType,
	isGroupInvite,
	isHiddenFromModel,
	withoutHiddenFrames,
} from "./control-frames.js";
export {
	OPERATOR_COMMAND_PURPOSE, OPERATOR_FUTURE_SKEW_MS, OPERATOR_STATEMENT_KEY, OPERATOR_WINDOW_MS,
	parseOperatorStatement, stripOperatorStatement, type OperatorStatement,
} from "./operator-statement.js";
export {
	cleanHandle, looksLikeSeat, pinMatchesKey, pinMatchesSender, type OperatorPin,
} from "./operator-pin.js";
export { updateLedger, type LedgerEntry, type LedgerLoc } from "./operator-ledger.js";
export {
	UNOPENED_VERDICT, classifyOperatorRow, type ClassReason, type OperatorContext,
	type OperatorRowInput, type OperatorVerdict, type SenderClass,
} from "./operator-classify.js";
export { classifyShown, frameRow, noticeForClass, type FramedRow } from "./operator-frame.js";
export {
	NEUTRALISED_NOTICE,
	neutraliseNotices,
	randomDelimiter,
	wrapThirdPartyText,
} from "./operator-quote.js";
export {
	listMyInvites,
	sendGroupInviteNotification,
} from "./group-invite-ops.js";
export type { GroupInvitePayload } from "./group-invite-ops.js";
export {
	VOTE_DURATION_DEFAULT_HOURS,
	VOTE_DURATION_MAX_HOURS,
	VOTE_DURATION_MIN_HOURS,
	VOTE_DURATION_RULE,
	VOTE_ELECTORATE_RULE,
	VOTE_ELIGIBILITY_CLAUSES,
	describeVoteEligibility,
	impliedVoteEligibilityReason,
} from "./vote-words.js";
export type {
	VoteEligibilityClauseReason,
	VoteEligibilityFallbacks,
} from "./vote-words.js";
export { GROUPS_KEY_SCOPE } from "./key-scope-words.js";
export {
	NOT_A_MEMBER_CLAUSE,
	SEATED_SIBLING_CLAUSE,
	namesASeatedSibling,
} from "./group-words.js";
export {
	A2A_CLEARTEXT_NOTICE,
	A2A_MESSAGE_TYPE,
	CLEARTEXT_ENCRYPTION_VERSION,
	a2aCleartextMark,
	a2aCleartextPayload,
	a2aCleartextPlaintext,
	isA2aCleartext,
	markA2aCleartext,
	withA2aCleartextNotice,
} from "./a2a-cleartext.js";
export type { A2aCleartextMark } from "./a2a-cleartext.js";
export { GROUP_READERS_NOTICE } from "./group-readers-notice.js";
export {
	SENDER_KEY_NOT_RECOVERED_PREVIEW,
	SENDER_KEY_UNAVAILABLE_CODE,
	SENDER_KEY_UNAVAILABLE_PREVIEW,
	SINGLE_MESSAGE_READ_REMEDY,
	SenderKeyUnavailableError,
	UNKNOWN_SENDER_KEY_CLAUSE,
	asSenderKeyUnavailable,
	senderKeyNotRecoveredMessage,
	senderKeyUnavailableMessage,
	unknownSenderKeyId,
} from "./sender-key-words.js";
export {
	senderKeyExplainer,
	senderKeyExplanation,
} from "./sender-key-explain.js";
export type {
	SenderKeyExplained,
	SenderKeyExplainer,
	SenderKeyRefusedRow,
} from "./sender-key-explain.js";
export {
	deleteGroupMember,
	evictionMessage,
	isSelfLeave,
	retireLocalGroupState,
	retirementMessage,
} from "./group-removal-ops.js";
export type { LocalStateRetirement } from "./group-removal-ops.js";
export {
	MLS_EVICTED_BY_COMMIT,
	describeMlsReclamation,
	describeMlsRecovery,
	mlsInitInFlightSync,
	mlsNeverFoundedSync,
	notAnMlsGroupResume,
	unfoundedGroupNote,
} from "./mls-recovery-format.js";
export type { UnfoundedGroupRepair } from "./mls-recovery-format.js";
export {
	cliSyncRemedy,
	mlsReadRefusal,
	sdkSyncRemedy,
} from "./mls-read-refusal.js";
export { PEEK_HEADER, withPeekHeader } from "./message-words.js";
export {
	ackAfterRead,
	isDirectEnvelope,
	isGroupEnvelope,
	isSettledRow,
} from "./read-ack.js";
export type { AckDecision, AckRow } from "./read-ack.js";
export {
	groupAuthenticityStatus,
	isPermanent,
	openInbound,
	probeReadability,
} from "./inbound-readability.js";
export type {
	OpenInboundArgs,
	Opened,
	Probe,
	Readability,
	Unreadable,
} from "./inbound-readability.js";
export {
	fetchAgentKeys,
	fetchRecipientKeys,
	sameAgentId,
} from "./crypto/agent-keys.js";
export { agentCertClaims } from "./crypto/certs.js";
export {
	assertBranchName,
	deriveAgent,
	deriveBranch,
	deriveOrg,
} from "./crypto/derive.js";
export {
	DOWNGRADE_REFUSED_CODE,
	MlsDowngradeError,
	isMlsDowngradeError,
} from "./crypto/downgrade-error.js";
export {
	groupAcceptsMlsSendOnly,
	groupIsMls,
	groupMlsInitInFlight,
	groupMlsNeverFounded,
} from "./crypto/group-predicates.js";
export { deleteGroupReadCache } from "./crypto/group-read-cache.js";
export { ENCRYPTION_VERSION_HYBRID_V2 } from "./crypto/hybrid.js";
export { ingestSenderKeyDistribution } from "./crypto/ingest.js";
export { JwsTyp, signJws } from "./crypto/jws.js";
export { KeyChainError } from "./crypto/key-chain.js";
export { KeyPins, pinsFor } from "./crypto/key-pins.js";
export {
	agentKeysExist,
	agentKeysFromDerived,
	agentKeysFromPrivate,
	fromBase64Url,
	isPathSafeId,
	jwkToPqPublicKey,
	jwkToPublicKey,
	loadAgentKeys,
	parseSigningKid,
	saveAgentKeys,
	signingPublicKeyToJWK,
	toBase64Url,
	validateEncryptionKey,
	validateSigningKey,
} from "./crypto/keys.js";
export {
	GroupAuthenticityError,
	decryptMessage,
	encryptMessage,
	isAuthenticityFailure,
	isRefusedDecrypt,
	sealForAgent,
} from "./crypto/message.js";
export { fetchGroupInfo } from "./crypto/mls-api.js";
export { assertNoMlsDowngrade } from "./crypto/mls-downgrade.js";
export {
	MLS_ERR_GROUP_INACTIVE,
	MLS_ERR_PROTOCOL,
	MLS_ERR_STORE,
	mlsErrorCode,
} from "./crypto/mls-errors.js";
export {
	MLS_INIT_IN_FLIGHT_CODE,
	MLS_PENDING_SELF_CLEAR_SECONDS,
	MlsInitInFlightError,
	isMlsInitInFlightError,
} from "./crypto/mls-init-in-flight.js";
export { KEY_NOT_CURRENT_MESSAGE } from "./crypto/mls-key-not-current.js";
export {
	deleteMlsState,
	holdsMlsState,
	loadMlsState,
} from "./crypto/mls-state.js";
export { holdsAnyMlsState } from "./crypto/mls-store-probe.js";
export {
	MLS_CIPHER_SUITE_XWING,
	isNoMlsStateError,
	isRecoverableMlsRead,
	isUnopenableGroupRead,
	loadMlsGroup,
	mlsStoreRoot,
	noMlsStateError,
	openMlsClient,
	openMlsGroup,
} from "./crypto/mls.js";
export {
	RECIPIENT_KEY_BYTES,
	parseRecipientKey,
	recipientKeyWords,
	sealBranchBundle,
} from "./crypto/recipient-key.js";
export { encryptGroupMessage } from "./crypto/sender-key-seal.js";
export {
	loadSenderKeyStates,
	saveSenderKeyState,
	senderKeyStateExists,
} from "./crypto/sender-keys-helpers.js";
export { generateSenderKey } from "./crypto/sender-keys.js";
export { THREAD_UNAVAILABLE } from "./crypto/thread-row.js";
export { decryptThreadRows } from "./crypto/thread.js";
export { verificationWordsForKey } from "./crypto/verification-words.js";
export {
	createWallet,
	getWalletAddress,
	loadWalletKey,
	walletKeyExists,
} from "./crypto/wallet.js";
export type { MlsGroup } from "./../../rine-mls/crates/rine-mls-node/index.d.js";
export type { RecipientKeys, SenderKeyChange } from "./crypto/agent-keys.js";
export type { AgentCertClaims } from "./crypto/certs.js";
export type { AgentDerivedKeys, BranchKeys, OrgKeys } from "./crypto/derive.js";
export type { VerifiedEscrowKey } from "./crypto/escrow.js";
export type {
	GroupRegimeFields,
	MlsGroupFields,
} from "./crypto/group-predicates.js";
export type { JcsObject, JcsValue } from "./crypto/jws.js";
export type { KeyChainFault, VerifiedAgentKeys } from "./crypto/key-chain.js";
export type {
	AgentKeys,
	AgentPrivateKeys,
	JWK,
	KeyPair,
	PqJWK,
	PqKeyPair,
} from "./crypto/keys.js";
export type {
	DecryptResult,
	EncryptResult,
	MessageDecryptResult,
	RefusedDecrypt,
	VerificationStatus,
} from "./crypto/message.js";
export type { MlsGroupInfoResponse } from "./crypto/mls-api.js";
export type { MlsGroupState } from "./crypto/mls-state.js";
export type { OpenMlsClientOptions } from "./crypto/mls.js";
export type { RecipientKey } from "./crypto/recipient-key.js";
export type { SenderKeyState } from "./crypto/sender-keys.js";
export type { ThreadRow, ThreadRowEntry } from "./crypto/thread-row.js";
export type {
	VerificationWordsComparison,
	VerificationWordsStatus,
} from "./crypto/verification-words.js";
export { decryptGroupMessage } from "./message-group.js";
export { encryptMlsGroupMessage } from "./message-mls.js";
export { requirementAmount } from "./x402/assets.js";
export { X402Error, X402_ERROR } from "./x402/errors.js";
export {
	parseFacilitatorHeaders,
	resolveFacilitatorConfig,
} from "./x402/facilitator-resolve.js";
export {
	FACILITATOR_PRESET,
	X402FacilitatorError,
	facilitatorRequestBody,
	settlePayment,
	verifyPayment,
} from "./x402/facilitator.js";
export { readX402Marker } from "./x402/marker.js";
export {
	X402_CONTENT_TYPE,
	X402_MESSAGE_TYPE,
	isX402MessageType,
} from "./x402/message-types.js";
export {
	buildPaymentMessage,
	buildPaymentRequiredMessage,
	buildReceiptMessage,
} from "./x402/messages.js";
export { parseX402Payload } from "./x402/parse.js";
export { buildPaymentPayload, selectRequirement } from "./x402/pay.js";
export { matchedQuoteToWire, sendReceipt } from "./x402/payee-receipt.js";
export {
	refusalReceiptBody,
	resolvePayeeRequirement,
	settleToReceipt,
} from "./x402/payee-settle.js";
export {
	enforcePolicy,
	isAutoPayable,
	loadPolicy,
	savePolicy,
} from "./x402/policy.js";
export { reconcilePayment } from "./x402/reconcile.js";
export {
	requireVerifiedPlaintext,
	requireVerifiedSender,
} from "./x402/sender-guard.js";
export {
	CorruptSpendJournalError,
	readDailySpent,
	reserveSpend,
} from "./x402/spend-journal.js";
export { x402ThreadStatus } from "./x402/thread-state.js";
export {
	X402_METADATA_KEY,
	X402_MODE,
	X402_QUOTE_REF_KEY,
	X402_RAIL,
	X402_STATUS,
	X402_VERSION,
} from "./x402/types.js";
export type { X402ErrorCode } from "./x402/errors.js";
export type {
	FacilitatorCallOptions,
	FacilitatorConfig,
	VerifyResponse,
} from "./x402/facilitator.js";
export type { X402MarkerMetadata } from "./x402/marker.js";
export type { X402MessageType } from "./x402/message-types.js";
export type { BuildX402Options, BuiltX402Message } from "./x402/messages.js";
export type { X402Payload } from "./x402/parse.js";
export type { BuildPaymentOptions } from "./x402/pay.js";
export type { MatchedQuoteWire } from "./x402/payee-receipt.js";
export type {
	ExpectedTermsInput,
	FulfillReceipt,
	FulfillSettleStatus,
	MatchedQuote,
	ResolvedPayeeRequirement,
} from "./x402/payee-settle.js";
export type { ReserveSpendOptions } from "./x402/spend-journal.js";
export type { X402ThreadEntry } from "./x402/thread-state.js";
export type {
	Eip3009Authorization,
	Eip3009Signed,
	PaymentPayload,
	PaymentPolicy,
	PaymentRequired,
	PaymentRequirements,
	SettlementResponse,
	X402Marker,
	X402Mode,
	X402Resource,
	X402Status,
	X402TokenExtra,
} from "./x402/types.js";
export { buildIssueCertDeps } from "./funnel/acme.js";
export { nextBackoffDelayMs, renewalDueWithJitter } from "./funnel/backoff.js";
export { loadMeta } from "./funnel/cert-cache.js";
export { ensureCert } from "./funnel/cert.js";
export { agentLabel } from "./funnel/csr.js";
export { makeEdgePipeFactory } from "./funnel/edge-pipe.js";
export {
	deleteHookSecret,
	funnelSecretDir,
	generateHookSecret,
	hookNameError,
	hookSecretPath,
	loadHookSecret,
	saveHookSecret,
} from "./funnel/hook-key-store.js";
export { IdempotencyStore } from "./funnel/idempotency-store.js";
export { nextReconnectBackoffSeconds } from "./funnel/mux-client.js";
export { FrameType } from "./funnel/mux-codec.js";
export { handleWebhookRequest } from "./funnel/relay-adapter.js";
export { startTlsListener } from "./funnel/tls-listener.js";
export { BindNakReason, CLOSE_SUSPENDED, TunnelBindError, connectTunnel } from "./funnel/tunnel.js";
export type { AcmeOptions, CertMeta } from "./funnel/cert-cache.js";
export type { EnsureCertResult } from "./funnel/cert.js";
export type { EdgePipeArgs } from "./funnel/edge-pipe.js";
export type { IssueCertDeps, IssuedCert } from "./funnel/issue.js";
export type { LocalPipe } from "./funnel/mux-client.js";
export type { Frame } from "./funnel/mux-codec.js";
export type {
	RelayAdapterDeps,
	RelayResult,
	WebhookRequest,
} from "./funnel/relay-adapter.js";
export type { TlsListener, TlsListenerArgs } from "./funnel/tls-listener.js";
export type {
	ConnectTunnelArgs,
	TunnelCaps,
	TunnelClose,
	TunnelHandle,
} from "./funnel/tunnel.js";
export {
	MlsWelcomeRefusedError,
	addMlsGroupMember,
	addMlsGroupMembers,
	catchUpMlsGroup,
	cutoverMlsKeyPackages,
	drainAndRepublishMlsKeyPackages,
	ensureMlsKeyPackages,
	externalJoinMlsGroup,
	fetchMlsIdentities,
	initMlsGroup,
	isMlsWelcomeRefusedError,
	isSeated,
	needsMlsKeyPackageCutover,
	orphanLeaves,
	processMlsWelcomes,
	publishMlsKeyPackages,
	reclaimOrphanLeaves,
	removeMlsGroupMember,
	replenishMlsKeyPackages,
	resumeMlsGroupAdmission,
	syncMlsGroup,
} from "./mls-ops.js";
export type {
	MlsAdmissionOutcome,
	MlsAdmissionResult,
	MlsAdmissionSkipReason,
	MlsCutoverResult,
	MlsKeyPackageStatus,
	MlsReclamationDecline,
	MlsReclamationDeclineReason,
	MlsReclamationResult,
	MlsRemovalCommit,
	MlsSyncResult,
	OrphanLeaf,
	WelcomeRefusalReason,
} from "./mls-ops.js";
export {
	MlsResyncUnavailableError,
	isMlsResyncRequired,
	isMlsResyncUnavailable,
	recoverMlsGroup,
} from "./mls-ops-resync.js";
export type { MlsRecoveryResult, MlsRecoveryRung } from "./mls-ops-resync.js";
export {
	MlsEstablishStep,
	MlsMembershipOutcome,
	establishAfterAlreadyAMember,
	establishMlsMembership,
	isAlreadyAMember,
	mlsStateEstablished,
} from "./mls-join-establish.js";
export type { MlsMembershipResult } from "./mls-join-establish.js";
export {
	reportFailedSetup,
	seatedMemberAfterConflict,
} from "./mls-join-seat.js";
export type {
	AlreadyAMemberJoin,
	MlsSetupFailureSink,
} from "./mls-join-seat.js";
export { MlsRotatedLeafError, isMlsRotatedLeaf } from "./mls-rotated-leaf.js";
export type {
	KeyPackageTopUp,
	KeyPackageTopUpOutcome,
} from "./mls-keypackage-topup.js";
export {
	KeyPackageRotation,
	SeatDeferReason,
	SeatFailReason,
	SeatUpdateStatus,
} from "./mls-seat-update.js";
export type { RotationSettlement, SeatUpdate } from "./mls-seat-update.js";
export { seatUpdateLine } from "./mls-seat-sentences.js";
export { settleRotation } from "./mls-seat-sweep.js";
export { rotateAgentWithSeats } from "./agent-rotate-seats.js";
export type { RotationReport } from "./agent-rotate-seats.js";
export { recoverGroup } from "./group-recovery.js";
export type {
	GroupRecoveryResult,
	SenderKeyRecoveryResult,
} from "./group-recovery.js";
export {
	compareVerificationWordsForAgent,
	peerVerificationLines,
	verificationWordsLines,
} from "./verification-display.js";
export {
	buildPeerVerification,
	loadPeerVerification,
	recordPeerVerification,
} from "./verification-confirm.js";
export type {
	PeerCardWords,
	PeerVerificationRecord,
	PeerVerificationState,
} from "./verification-confirm.js";
// A surface reporting a refused commit has to be able to recognise the one
// refusal that has a remedy, or it drops to `RineApiError`'s own `409: …` —
// which is the only place the group commands quote a status code at an
// operator. Exported here rather than through `mls-ops.js` because it belongs
// to `mls-commit.js`, whose surface reaches the barrel directly: it is a
// predicate over an error, not a verb, and the verbs are what `mls-ops.js`
// gathers.
export { isEpochConflict } from "./mls-commit.js";
export { PrincipalKind, parsePrincipal, principalString } from "./principal.js";
export type { Principal } from "./principal.js";
export {
	agentSigner,
	buildAssertion,
	orgReaderSigner,
	orgSigner,
	delegateSigner,
} from "./assertion.js";
export type { AssertionSigner } from "./assertion.js";
export {
	CorruptProfilesError,
	addProfileIfAbsent,
	DEFAULT_PROFILE,
	getProfile,
	loadProfiles,
	saveProfiles,
} from "./profiles.js";
export {
	PHRASE_FILE,
	PHRASE_INSTRUCTION,
	hasRoot,
	ownerDirNotice,
	readOwnerPhrase,
	resolveOwnerDir,
	saveRoot,
} from "./owner.js";
export { loadCustody, loadOrgFromOwner } from "./custody.js";
export type { Custody, CustodyDirs } from "./custody.js";
export { AGENT_ONLY_OWNER_DIR, resolveAuth } from "./auth-resolve.js";
export type { AgentOnlyDirs, AuthDirs, ResolvedAuth } from "./auth-resolve.js";
export { agentCreateRequest, agentRotateRequest } from "./agent-body.js";
export type {
	AgentCreateBody,
	AgentCreateParams,
	AgentKeyBody,
	AgentRequest,
} from "./agent-body.js";
export { performAgentCreation, persistCreatedAgent } from "./agent-create.js";
export type { CreatedAgent } from "./agent-create.js";
export { performKeyRotation } from "./agent-rotate.js";
export type { ApiGetPoster } from "./agent-rotate.js";
export { performRegistration, validateSlug } from "./onboard.js";
export type { RegistrationResult } from "./onboard.js";
export { createBranch, revokeBranch } from "./org-branch.js";
export { loadDelegateSeed, saveDelegateSeed } from "./delegate-files.js";
export { JcsError, canonicalize as jcsCanonicalize } from "./crypto/jcs.js";
export type { JcsJson } from "./crypto/jcs.js";
export {
	createDelegate,
	fetchOrgEvents,
	freezeOrg,
	getSuspension,
	listAgentStates,
	listDelegates,
	newDelegateKey,
	pickAgent,
	resumeAgent,
	resumeBranch,
	revokeDelegate,
	suspendAgent,
	suspendBranch,
	unfreezeOrg,
} from "./org-governance.js";
export {
	DelegateScope, type AgentHold, type AgentHoldView, type AgentStateView,
	type BranchHoldView, type CounterpartiesPage, type CounterpartyView, type CrossOrgGroup,
	type DelegateView, type EventHead, type HeadKey, type HeadKeyList, type LogSettings,
	type MessageMetadata, type MetadataPage, type OrgEvent, type OrgEventsPage,
	type OrgFreezeView, type RetentionFloor, type SuspensionView,
} from "./org-governance-types.js";
export {
	HEAD_DOMAIN, HeadFault, headMessage, verifyHead, type HeadVerdict,
} from "./org-event-head.js";
export { SignalClass, signalClass } from "./org-event-signals.js";
export {
	RecordRefusal, fetchCounterparties, fetchCounterpartyGroups, fetchHeadKeys, fetchLogSettings,
	fetchOrgEventHead, fetchOrgMetadata, forkPointOf, putLogSettings, type ForkPoint,
} from "./org-governance-record.js";
export { orgWords } from "./crypto/org-words.js";
export { PRESETS, Preset, Surface, aboveCeiling, capTo, exposureDiff, hidesDid, invalidSurfaces, isNamedPreset, presetOf } from "./agent-exposure.js";
export type { ExposureInput, ExposurePlanView, ExposureSet, ExposureView, NamedPreset, OrgExposureView } from "./agent-exposure.js";
export { getExposure, getOrgExposure, previewExposure, putExposure } from "./agent-exposure-api.js";
export { EXPOSURE_COPY, aboveCeilingLine, cappedLine, ceilingLine, createdPrivateLine, orgSummaryLine, presetLine, previewLines, refusedLine, summaryLine, switchLines } from "./agent-exposure-words.js";
export {
	Decision, MessageDefault, PolicyRule, RULE_MODES,
	RuleDirection, RuleMode, RuleRefusal, ScopeKind, TypeClass,
	type ActingAsRule, type ExistingCounts, type ExistingPreview, type GroupsPreview, type ListingRule, type MessagePreview,
	type MessageRule, type ModeRule, type PolicyPreview, type PolicyView, type PreviewCounterparty,
	type RuleSet, type RulesPatch, type StopExistingResult, type WebhookHostsRule,
} from "./org-rules-types.js";
export { getPolicy, patchRules, previewRule, stopExisting } from "./org-rules.js";
export {
	DomainStatus, addDomain, deleteAllow, fetchAllAllow, fetchAllowPage, listDomains,
	lookupCounterparty, putAllow, removeDomain, verifyDomain,
	type AllowEntry, type AllowPage, type AllowWrite, type CounterpartyLookup, type DomainView,
} from "./org-allow.js";
export { AgentRecoveryStatus, performRecovery } from "./recover.js";
export type { AgentRecovery, RecoveryReport } from "./recover.js";
export { restoreOwnerFromPhrase } from "./recover-owner.js";
export { ReseatStatus, reseatClosedGroups } from "./recover-reseat.js";
export type { GroupReseat } from "./recover-reseat.js";
export {
	orgIdOfAgent,
	ownIdentityFor,
	pinOwnIdentity,
} from "./own-identity.js";
export {
	admitPeers,
	allowedFor,
	openPeerMlsClient,
	openPeerMlsGroup,
} from "./mls-allowed.js";
export type { AdmitPeersOptions, PeerActor } from "./mls-allowed.js";
export { admitGroupPeers } from "./mls-allowed-tree.js";
export { drainEscrow } from "./mls-escrow-drain.js";
export type { DrainOutcome } from "./mls-escrow-drain.js";
export { BranchRevokedError, resolveEscrowKey } from "./mls-escrow-key.js";
export { settleEscrow } from "./mls-escrow-settle.js";
export {
	EscrowUnavailableError,
	postWithEscrowRetry,
	prepareEscrowForSend,
} from "./mls-escrow-send.js";
export { sealAndPostMlsGroupMessage } from "./mls-group-send.js";
export type { MlsSealedFields } from "./mls-group-send.js";
export { inBackground, startupEscrowSweep } from "./mls-escrow-sweep.js";
export { describeEscrowGaps } from "./mls-escrow-report.js";
export type { EscrowReport } from "./mls-escrow-report.js";
export { EscrowLoss } from "./mls-escrow-gap.js";
export type { DrainGap, GapReason } from "./mls-escrow-gap.js";
export { describeGapMarkers, listGapMarkers } from "./mls-escrow-gap-list.js";
export type { GapMarker } from "./mls-escrow-gap-list.js";
export {
	SpiffeVerificationError,
	hasSpiffeEndpoint,
	verifyIdentitySpiffe,
	verifyNewAgent,
} from "./spiffe.js";
export type {
	ApiPoster,
	VerifyIdentityResult,
	VerifyIdentitySpiffeOptions,
} from "./spiffe.js";
export { DeadlineError, jitteredDelayMs, sleep, sleepWithSignal, raceDeadline } from "./timing.js";
export {
	ENCRYPTION_VERSIONS,
	isDecryptableVersion,
	isGroupEncryptionVersion,
} from "./encryption-versions.js";
export type {
	EncryptionVersion,
	GroupEncryptionVersion,
} from "./encryption-versions.js";
export { fetchGroupMembers } from "./group-members.js";
export { createHook } from "./funnel/hook-create.js";
export type { HookCreateResult } from "./funnel/hook-create.js";
export { ReadGapReason, findingKey, findingToJson, gapKey, gapToJson } from "./org-reader/gaps.js";
export type { ReadFinding, ReadGap } from "./org-reader/gaps.js";
export { ReadKey } from "./org-reader/keys.js";
export { messageToJson } from "./org-reader/page.js";
export type { ReadMessage, ReadPage } from "./org-reader/page.js";
export { OrgReader } from "./org-reader/reader.js";
export type {
	OrgPage,
	OrgReaderOptions,
} from "./org-reader/reader.js";
export type { Direction, Party, Row } from "./org-reader/rows.js";
export {
	ESCROW_MAX_PAGES,
	ESCROW_MAX_ROWS,
	ReaderClient,
} from "./org-reader/client.js";
export type {
	ActivityQuery,
	ReaderClientOptions,
} from "./org-reader/client.js";
export { MalformedPageError } from "./org-reader/page-envelope.js";
export type { OrgSummary } from "./org-reader/org-summary.js";
export type { ActivityPage } from "./org-reader/page-envelope.js";
export { isKeysUnavailable } from "./org-reader/key-errors.js";
export {
	ReaderNetworkError,
	TokenBucket,
	createBudgetedFetch,
} from "./org-reader/fetch-budget.js";
export type {
	BudgetedFetchOptions,
	TokenBucketOptions,
} from "./org-reader/fetch-budget.js";
export {
	agentReadKeys,
	deriveOrgRead,
	escrowReadKeys,
} from "./crypto/derive-read.js";
export type {
	AgentReadKeys,
	EscrowReadKeys,
	OrgReadKeys,
} from "./crypto/derive-read.js";
export {
	clipToWidth,
	clipWithEllipsis,
	clusterWidth,
	displayWidth,
	graphemes,
} from "./terminal-width.js";
export { safeBlock, scrub } from "./terminal-text.js";
export { displayHandle, identityHandle } from "./display-handle.js";
export { humanTime } from "./human-time.js";
export { fitFromTo, fitGroupSender, fitHandle } from "./fit-party.js";
export type { Block, Scrubbed } from "./terminal-text.js";
export { holdsBranchKeys } from "./branch-files.js";
