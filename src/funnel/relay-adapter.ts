// rine Funnel per-request relay adapter (REQ-CLI-08/09 + REQ-SEC-15/16). Given
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
//  - No-body-log: NEVER log the raw body, the decrypted payload, the HMAC secret,
//    or the signature value — only the verify outcome + counters/IDs.

import { createHmac, timingSafeEqual } from "node:crypto";
import { encryptMessage, fetchRecipientKeys } from "../crypto/message.js";
import type { HttpClient } from "../http.js";

export const WEBHOOK_MESSAGE_TYPE = "rine.v1.webhook";

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
}

export interface RelayResult {
	verified: boolean;
	relayed: boolean;
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
 */
function verifyHmac(
	secret: string,
	rawBody: Uint8Array,
	headers: Record<string, string>,
): boolean {
	const received = parseSignature(headers);
	if (!received) return false;
	const computed = createHmac("sha256", secret).update(rawBody).digest();
	if (received.length !== computed.length) return false;
	return timingSafeEqual(received, computed);
}

/**
 * Verify → encrypt → self-send one webhook. Returns the outcome; never throws out
 * (the caller's tunnel must survive a single bad request). A verify failure drops
 * the conn with no post and no encrypt; a post/key-fetch failure drops the conn
 * after verify with `relayed:false`.
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
		return { verified: false, relayed: false };
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
			metadata: { "rine.hook_name": hookName },
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
		return { verified: true, relayed: true };
	} catch {
		// Key-fetch / encrypt / post failure: drop this conn, keep the tunnel up.
		// The error is intentionally not logged with any request detail (REQ-SEC-15).
		emitLifecycle?.({
			event: "lifecycle",
			data: { state: "relay_error", hook_name: hookName },
		});
		return { verified: true, relayed: false };
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
