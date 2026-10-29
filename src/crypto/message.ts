/**
 * The 1:1 message path and the result types every message path shares.
 *
 * A leaf of the crypto layer: nothing here imports the ops modules above it at
 * runtime (one result type is borrowed from `mls-ops-sync.ts`, type-only). The
 * group decrypt lives one layer up, in `message-group.ts` and `message-mls.ts`,
 * because opening a group row can run a catch-up, a Welcome install or an
 * external join. The sender-key seal is `sender-key-seal.ts`.
 */
import type { HttpClient } from "../http.js";
import type { MlsSyncResult } from "../mls-ops-sync.js";
import {
	type RecipientKeys,
	type SenderKeyChange,
	fetchRecipientKeys,
	verifyEnvelopeSender,
} from "./agent-keys.js";
import { decodeEnvelope, encodeEnvelope } from "./envelope.js";
import {
	ENCRYPTION_VERSION_HYBRID_V2,
	openHybrid,
	sealHybrid,
} from "./hybrid.js";
import {
	fromBase64Url,
	loadAgentKeys,
	signingKid,
	toBase64Url,
} from "./keys.js";
import { type SigContext, signMessage } from "./sign.js";

export interface EncryptResult {
	encrypted_payload: string;
	encryption_version: string;
	sender_signing_kid: string;
	/**
	 * A second ciphertext of the same signed envelope, sealed to the SENDER's own
	 * encryption key(s), enabling sender self-read of 1:1 messages. Only produced
	 * by {@link encryptMessage} (1:1 `hpke-hybrid-v2`); the group encrypt paths
	 * leave it `undefined` (groups already self-read via client caches). It seals
	 * the recipient's own signed envelope to the sender's keys, so both copies
	 * carry one signature scoped to the recipient.
	 */
	self_encrypted_payload?: string;
}

/**
 * Outcome of checking a message's inner envelope.
 *
 * - `verified` — signed by the agent the server says sent the message.
 * - `invalid` — the signature does not check out against that agent's key.
 * - `sender-mismatch` — the signature is well-formed but names a different agent
 *   than the one the server authenticated as the sender.
 * - `unverifiable` — the verdict could not be reached (key lookup failed, or no
 *   server-authenticated sender was available for the row).
 */
export type VerificationStatus =
	"verified" | "invalid" | "sender-mismatch" | "unverifiable";

/**
 * True when the status means the content must not be trusted as authentic:
 * either the bytes do not match the signature, or they are attributed to the
 * wrong agent. `unverifiable` is deliberately excluded — it is a transient
 * lookup outcome, not a verdict, and callers surface it as such.
 *
 * Every authenticity comparison goes through this predicate; an equality check
 * against a single member silently accepts the others.
 */
export function isAuthenticityFailure(status: VerificationStatus): boolean {
	return status === "invalid" || status === "sender-mismatch";
}

/**
 * A group message refused because its author cannot be trusted, carrying the
 * verdict that produced it. A group decrypt throws where the 1:1 path degrades,
 * so without the verdict on the error a caller's `catch` cannot tell an active
 * misattribution from a transient key-lookup miss. The message text tells the
 * two authenticity failures apart for an operator reading a log.
 */
export class GroupAuthenticityError extends Error {
	constructor(public readonly verificationStatus: VerificationStatus) {
		super(
			verificationStatus === "sender-mismatch"
				? "Envelope sender does not match the message sender"
				: "Sender signature verification failed",
		);
		this.name = "GroupAuthenticityError";
	}
}

export interface DecryptResult {
	plaintext: string;
	senderKid: string;
	verified: boolean;
	verificationStatus: VerificationStatus;
	/**
	 * Set when the sender's published signing key no longer matches the copy this
	 * client had cached — a rotation the recipient may want to notice rather than
	 * silently accept.
	 */
	keyChanged?: SenderKeyChange;
	/**
	 * What the MLS catch-up behind this read actually did: the epoch it left
	 * this agent on, the commits it applied to get there, and whether one of
	 * them evicted this agent.
	 *
	 * Present only on an MLS row whose read ran a sync — absent on a 1:1 row, a
	 * sender-key row, a replay served from the read cache, and a read whose
	 * catch-up the 60 s floor declined or whose sync failed. Absent therefore
	 * means "nothing was done", never "you are current".
	 *
	 * It reports the work, not the distance: asking how far behind this agent
	 * still is costs a round trip per read, and the explicit catch-up verb is
	 * where that question is asked.
	 */
	catchUp?: MlsSyncResult;
}

/**
 * A decrypt that withheld its own content because the envelope's author cannot
 * be trusted. The verdict and the kid the envelope named still come back — an
 * operator has to be able to say WHY a row is closed — but the text does not, so
 * bytes attributed to an agent that did not sign them never reach a transcript,
 * a model or a payment decision.
 */
export interface RefusedDecrypt extends Omit<DecryptResult, "plaintext"> {
	plaintext?: undefined;
}

/**
 * What the 1:1 decrypt returns: the opened message, or a refusal carrying the
 * verdict in place of the text. Narrow with {@link isRefusedDecrypt} before
 * reading content — the group paths refuse the same content by throwing, so this
 * union is where the 1:1 half of that one refusal shows up in the type system.
 */
export type MessageDecryptResult = DecryptResult | RefusedDecrypt;

/**
 * True when a 1:1 decrypt refused to hand back its content: the author is one of
 * the {@link isAuthenticityFailure} verdicts, or the text is absent for any other
 * reason. Narrowing on this predicate is how a caller reaches `plaintext` as a
 * `string` — writing the two terms out by hand at each site is how one of them
 * gets dropped, which is the same trap {@link isAuthenticityFailure} exists to
 * close one level down.
 */
export function isRefusedDecrypt(
	result: MessageDecryptResult,
): result is RefusedDecrypt {
	return (
		isAuthenticityFailure(result.verificationStatus) ||
		result.plaintext === undefined
	);
}

/**
 * Seal a 1:1 message to `recipientAgentId`'s chain-verified keys. The signature
 * is scoped to the recipient, and the same envelope is sealed twice: once to the
 * recipient and once to the sender's own keys, each under its own holder's seal
 * context. Both copies therefore decrypt to byte-identical envelopes, which is
 * what the equivocation check compares. A sender re-reading
 * its own copy passes the recipient as `scopeAgentId` to {@link decryptMessage}.
 */
export async function encryptMessage(
	configDir: string,
	senderAgentId: string,
	recipientAgentId: string,
	recipientKeys: RecipientKeys,
	payload: unknown,
): Promise<EncryptResult> {
	const keys = loadAgentKeys(configDir, senderAgentId);
	const plaintext = new TextEncoder().encode(JSON.stringify(payload));
	const kid = signingKid(senderAgentId, keys.keyGen);
	const signature = signMessage(
		keys.signing.privateKey,
		{ kind: "MessageSig", recipientAgentId },
		plaintext,
	);
	const envelope = encodeEnvelope(kid, signature, plaintext);
	const sealFor = (
		toAgentId: string,
		encryptionPk: Uint8Array,
		pqEncryptionPk: Uint8Array,
	): string =>
		toBase64Url(
			sealHybrid(encryptionPk, pqEncryptionPk, envelope, {
				kind: "AgentMessage",
				recipientAgentId: toAgentId,
			}),
		);
	return {
		encrypted_payload: sealFor(
			recipientAgentId,
			recipientKeys.encryption,
			recipientKeys.pqEncryption,
		),
		encryption_version: ENCRYPTION_VERSION_HYBRID_V2,
		sender_signing_kid: kid,
		self_encrypted_payload: sealFor(
			senderAgentId,
			keys.encryption.publicKey,
			keys.pqEncryption.publicKey,
		),
	};
}

/**
 * Seal `payload` for one agent: fetch the recipient's chain-verified keys, then
 * {@link encryptMessage}. The result spreads straight into a `POST /messages`
 * or reply body; it is the 1:1 half of every direct send on every surface.
 *
 * The two agent IDs are named, not positional: both are strings, so a swapped
 * pair would type-check and seal to the wrong key.
 */
export async function sealForAgent(
	client: Pick<HttpClient, "get">,
	configDir: string,
	{
		senderAgentId,
		recipientAgentId,
	}: { readonly senderAgentId: string; readonly recipientAgentId: string },
	payload: unknown,
): Promise<EncryptResult> {
	const recipientKeys = await fetchRecipientKeys(client, recipientAgentId);
	return encryptMessage(
		configDir,
		senderAgentId,
		recipientAgentId,
		recipientKeys,
		payload,
	);
}

/**
 * Open a 1:1 ciphertext with the recipient's own keys and report on its sender.
 *
 * `scopeAgentId` is the recipient the sender signed for, when that is not the
 * opener: a sender reading its own self-sealed copy passes the message's
 * `to_agent_id`.
 *
 * `createdAt` is the row's server `created_at`. A signature under a sender key
 * generation the sender has since rotated away verifies only for a row stamped
 * before that rotation; without it such a message is `"invalid"`.
 *
 * `fromAgentId` is the server-authenticated `from_agent_id` of the row being
 * opened — for a self-sealed blob a sender re-reads, that is the caller's own
 * agent id. It must never be taken from the envelope, the plaintext or a
 * client-supplied header: those are the inputs the check exists to distrust.
 *
 * Authenticity is reported rather than thrown, but it is never returned as
 * readable content: an envelope signed by an agent other than the one the server
 * attributes the row to comes back as
 * `{ verified: false, verificationStatus: "sender-mismatch" }` with NO
 * `plaintext`, so a caller renders a closed row and says why. The group paths
 * refuse the same content by throwing; both derive the refusal from
 * {@link isAuthenticityFailure}, so gate on that rather than on a single status
 * value.
 */
export async function decryptMessage(
	configDir: string,
	recipientAgentId: string,
	encryptedPayloadB64: string,
	client: HttpClient,
	fromAgentId: string,
	scopeAgentId: string = recipientAgentId,
	createdAt?: string,
): Promise<MessageDecryptResult> {
	const keys = loadAgentKeys(configDir, recipientAgentId);
	const encrypted = fromBase64Url(encryptedPayloadB64);

	const ctx: SigContext = { kind: "MessageSig", recipientAgentId: scopeAgentId };
	const envelopeBytes = openHybrid(
		keys.encryption.privateKey,
		keys.pqEncryption.privateKey,
		encrypted,
		{ kind: "AgentMessage", recipientAgentId },
	);
	const decoded = decodeEnvelope(envelopeBytes);

	const verification = await verifyEnvelopeSender(
		decoded,
		client,
		fromAgentId,
		ctx,
		createdAt,
	);
	// Withhold before decoding: content whose author cannot be trusted is not
	// content, so the caller gets the verdict and nothing to render.
	if (isAuthenticityFailure(verification.verificationStatus)) {
		return { senderKid: decoded.kid, ...verification };
	}

	const plaintext = new TextDecoder("utf-8", { fatal: true }).decode(
		decoded.payload,
	);
	return { plaintext, senderKid: decoded.kid, ...verification };
}
