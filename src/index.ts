export * from "./errors.js";
export * from "./types.js";
export * from "./api-types.js";
export * from "./cache.js";
export * from "./config.js";
export * from "./retry.js";
export * from "./http.js";
export * from "./resolve-handle.js";
export * from "./handle-completion.js";
export * from "./actor.js";
export * from "./resolve-agent.js";
export * from "./group-ref.js";
export * from "./resolve-group.js";
export * from "./handle-words.js";
export * from "./group-join-words.js";
export * from "./resolve-group-join.js";
export * from "./recipient-refusal.js";
export * from "./recipient-resolution.js";
export * from "./thread-ref.js";
export * from "./thread-read.js";
export * from "./timelock.js";
export * from "./sender-key-ops.js";
export * from "./group-admission.js";
export * from "./group-enrollment.js";
export * from "./group-format.js";
export * from "./group-create-format.js";
export * from "./group-invite-ops.js";
export * from "./vote-words.js";
export * from "./group-words.js";
export * from "./sender-key-words.js";
export * from "./sender-key-explain.js";
export * from "./group-removal-ops.js";
export * from "./mls-recovery-format.js";
export * from "./mls-read-refusal.js";
export * from "./crypto/index.js";
export * from "./x402/index.js";
export * from "./funnel/index.js";
export * from "./mls-ops.js";
export * from "./mls-ops-resync.js";
export * from "./mls-keypackage-topup.js";
export * from "./group-recovery.js";
export * from "./verification-display.js";
export * from "./verification-confirm.js";
// Resolve the name clash: both the low-level crypto primitive and the
// high-level orchestrator are named externalJoinMlsGroup. Surfaces consume the
// orchestrator, so it wins at the package root.
export { externalJoinMlsGroup } from "./mls-ops.js";
// A surface reporting a refused commit has to be able to recognise the one
// refusal that has a remedy, or it drops to `RineApiError`'s own `409: …` —
// which is the only place the group commands quote a status code at an
// operator. Exported here rather than through `mls-ops.js` because it belongs
// to `mls-commit.js`, whose surface reaches the barrel directly: it is a
// predicate over an error, not a verb, and the verbs are what `mls-ops.js`
// gathers.
export { isEpochConflict } from "./mls-commit.js";
export {
	performRegistration,
	performAgentCreation,
	validateSlug,
	verifyIdentitySpiffe,
	hasSpiffeEndpoint,
	SpiffeVerificationError,
	SPIFFE_ENDPOINT_SOCKET_ENV,
} from "./onboard.js";
export type {
	VerifyIdentityResult,
	VerifyIdentitySpiffeOptions,
} from "./onboard.js";
