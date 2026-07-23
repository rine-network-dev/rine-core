// rine Funnel per-request relay adapter. Given
// the plaintext HTTP request the local TLS listener produced from one mux conn,
// it (a) HMAC-verifies the RAW body, (b) on success runs the EXISTING client send
// path — fetchRecipientKeys → encryptMessage (hpke-v1) → self-send POST /messages
// with type "rine.v1.webhook" — and (c) on failure drops the conn.
//
// FROZEN-CONTRACT (a violation is a build defect):
//  - The relay uses the existing send path; encryption_version stays "hpke-v1"
//    (or "hpke-hybrid-v1" when the agent publishes a PQ key). NO new
//    encryption_version, NO server-sealed branch, NO server crypto. type is
//    EXACTLY "rine.v1.webhook" and the message is self-addressed (from==to==agent,
//    the D8 type-literal self-send exception) so it verifies as the agent.
//  - VERIFIED SENDER, UNTRUSTED CONTENT (T2): the self-send is genuinely
//    signature-valid (it IS the agent's own send), so the *sender* trust signal is
//    true — but the body is attacker-influenceable external webhook input, NOT a
//    peer message. The metadata therefore carries `rine.content_trust:
//    "untrusted-external"` so agentic consumers distinguish webhook content from
//    peer-to-peer messages and never treat "signature verified" as content trust.
//    This marker is part of the contract; type/addressing/encryption are unchanged.
//  - No-body-log: NEVER log the raw body, the decrypted payload, the HMAC secret,
//    or the signature value — only the verify outcome + counters/IDs.
//  - Replay de-dup (T8): the HMAC authenticates the BODY only, so a captured signed
//    webhook replays forever. With an `idempotency` store, a duplicate delivery is
//    DROPPED after verify (no encrypt/self-send). Client-side only; wire unchanged
//    (see idempotency-store.ts). HMAC verify, not the store, is the authenticator.

import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import { encryptMessage, fetchRecipientKeys } from "../crypto/message.js";
import type { HttpClient } from "../http.js";
import type { IdempotencyStore } from "./idempotency-store.js";

export const WEBHOOK_MESSAGE_TYPE = "rine.v1.webhook";
/** Content-trust marker (T2): the self-send sender is verified, the BODY is not. */
export const WEBHOOK_CONTENT_TRUST = "untrusted-external";

/** A single inbound webhook request as the local TLS listener parsed it. */
export interface WebhookRequest {
	headers: Record<string, string>;
	rawBody: Uint8Array;
}

export interface RelayAdapterDeps {
	configDir: string;
	agentId: string;
	hookName: string;
	secret: string;
	client: Pick<HttpClient, "get" | "post">;
	/** Lifecycle sink (stream.ts shape). NEVER receives body/secret/signature. */
	emitLifecycle?(ev: Record<string, unknown>): void;
	/**
	 * Optional bounded replay-de-dup store (T8). When present, a duplicate
	 * delivery is dropped after verify (no encrypt/self-send). One store should be
	 * shared across requests for a single agent/hook so its keyspace is per-hook.
	 */
	idempotency?: IdempotencyStore;
}

export interface RelayResult {
	verified: boolean;
	relayed: boolean;
	/** True when verify passed but the delivery was a dropped replay (T8). */
	duplicate: boolean;
}

/** Parse `sha256=<hex>` (X-Hub-Signature-256) or a bare hex (X-Hook-Signature). */
function parseSignature(
	headers: Record<string, string>,
): Uint8Array | undefined {
	const raw = headers["x-hub-signature-256"] ?? headers["x-hook-signature"];
	if (!raw) return undefined;
	const hex = raw.startsWith("sha256=") ? raw.slice("sha256=".length) : raw;
	if (!/^[0-9a-fA-F]+$/.test(hex) || hex.length % 2 !== 0) return undefined;
	return Uint8Array.from(Buffer.from(hex, "hex"));
}

/**
 * Constant-time HMAC-SHA-256 verification over the EXACT raw bytes (no JSON
 * re-serialization). A length-mismatched signature fails SAFELY: timingSafeEqual
 * throws on unequal buffers, so we length-guard first.
 *
 * An EMPTY secret fails closed (returns false) BEFORE any HMAC is computed — never
 * `createHmac("sha256", "")`. With an empty key an attacker who controls the body
 * can compute `HMAC("", body)` themselves and forge a "verified" self-send (T1);
 * relay.ts also refuses to start without a secret, this is the defense-in-depth.
 */
function verifyHmac(
	secret: string,
	rawBody: Uint8Array,
	headers: Record<string, string>,
): boolean {
	if (secret.length === 0) return false;
	const received = parseSignature(headers);
	if (!received) return false;
	const computed = createHmac("sha256", secret).update(rawBody).digest();
	if (received.length !== computed.length) return false;
	return timingSafeEqual(received, computed);
}

/**
 * Stable idempotency key for one delivery (T8). Prefers a per-delivery unique id
 * — GitHub's `x-github-delivery` or the standard `Idempotency-Key` — so distinct
 * legitimate deliveries never collide. Absent both, hashes the RAW (HMAC-authed)
 * body: a byte-identical replay is still caught, at the cost that a non-GitHub
 * source re-sending an identical body within the TTL is de-duped (it can send an
 * `Idempotency-Key` to avoid that). Source-prefixed so id/body-hash can't collide.
 */
function idempotencyKey(req: WebhookRequest): string {
	const deliveryId =
		req.headers["x-github-delivery"] ?? req.headers["idempotency-key"];
	if (deliveryId) return `id:${deliveryId}`;
	return `body:${createHash("sha256").update(req.rawBody).digest("hex")}`;
}

/**
 * Verify → de-dup → encrypt → self-send one webhook. Returns the outcome; never
 * throws out (the tunnel must survive a single bad request). Verify failure drops
 * the conn (no post/encrypt); a duplicate delivery drops after verify
 * (`duplicate:true`, no post); a post/key-fetch failure drops with `relayed:false`.
 */
export async function handleWebhookRequest(
	deps: RelayAdapterDeps,
	req: WebhookRequest,
): Promise<RelayResult> {
	const { configDir, agentId, hookName, secret, client, emitLifecycle } = deps;

	if (!verifyHmac(secret, req.rawBody, req.headers)) {
		emitLifecycle?.({
			event: "lifecycle",
			data: { state: "verify_failed", hook_name: hookName },
		});
		return { verified: false, relayed: false, duplicate: false };
	}

	// T8: a verified-but-replayed delivery is dropped before any encrypt/self-send
	// so it never mints a duplicate inbox message. The store keys on the delivery
	// id / body hash only — never the body itself (no-body-log holds).
	if (deps.idempotency?.seen(idempotencyKey(req))) {
		emitLifecycle?.({
			event: "lifecycle",
			data: { state: "duplicate_dropped", hook_name: hookName },
		});
		return { verified: true, relayed: false, duplicate: true };
	}

	try {
		const recipientKeys = await fetchRecipientKeys(
			client as HttpClient,
			agentId,
		);
		// The webhook body is the encrypted payload; the relay decodes it as UTF-8
		// JSON when valid, else passes the raw text through (still E2EE-sealed).
		const payload = decodePayload(req.rawBody);
		const encrypted = await encryptMessage(
			configDir,
			agentId,
			recipientKeys.encryption,
			payload,
			recipientKeys.pqEncryption,
		);
		// NO conversation_id: MessageCreate has no such field (only
		// parent_conversation_id: UUID), so the backend would silently drop it and
		// auto-create a fresh conversation per send anyway (D7 — zero new server
		// machinery). The hook is identified by metadata["rine.hook_name"].
		const body = {
			to_agent_id: agentId,
			type: WEBHOOK_MESSAGE_TYPE,
			metadata: {
				"rine.hook_name": hookName,
				"rine.content_trust": WEBHOOK_CONTENT_TRUST,
			},
			encrypted_payload: encrypted.encrypted_payload,
			encryption_version: encrypted.encryption_version,
			sender_signing_kid: encrypted.sender_signing_kid,
		};
		const result = (await client.post("/messages", body)) as { id?: string };
		emitLifecycle?.({
			event: "lifecycle",
			data: {
				state: "webhook_relayed",
				hook_name: hookName,
				message_id: result?.id,
			},
		});
		return { verified: true, relayed: true, duplicate: false };
	} catch {
		// Key-fetch / encrypt / post failure: drop this conn, keep the tunnel up.
		// The error is intentionally not logged with any request detail.
		emitLifecycle?.({
			event: "lifecycle",
			data: { state: "relay_error", hook_name: hookName },
		});
		return { verified: true, relayed: false, duplicate: false };
	}
}

/** Best-effort JSON decode; fall back to the raw text so any body still relays. */
function decodePayload(rawBody: Uint8Array): unknown {
	const text = new TextDecoder("utf-8").decode(rawBody);
	try {
		return JSON.parse(text);
	} catch {
		return text;
	}
}
