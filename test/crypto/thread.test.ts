import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	generateAgentKeys,
	saveAgentKeys,
	signingPublicKeyToJWK,
	toBase64Url,
} from "../../src/crypto/keys.js";
import type { AgentKeys } from "../../src/crypto/keys.js";
import { encryptMessage } from "../../src/crypto/message.js";
import {
	THREAD_UNAVAILABLE,
	type ThreadRow,
	decryptThreadRow,
	renderThreadText,
} from "../../src/crypto/thread.js";

const SENDER_ID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
const RECIPIENT_ID = "b2c3d4e5-f6a7-8901-bcde-f12345678901";

function makeTmpDir(): string {
	return fs.mkdtempSync(join(tmpdir(), "rine-thread-test-"));
}

function setupAgent(dir: string, agentId: string): AgentKeys {
	const keys = generateAgentKeys();
	saveAgentKeys(dir, agentId, keys);
	return keys;
}

/** Mock client serving the SENDER's public keys for sender-signature verify. */
function clientWith(keys: AgentKeys) {
	return {
		get: vi.fn().mockImplementation((path: string) => {
			if (path.includes("/keys")) {
				return Promise.resolve({
					agent_id: SENDER_ID,
					signing_public_key: signingPublicKeyToJWK(keys.signing.publicKey),
					encryption_public_key: {
						kty: "OKP",
						crv: "X25519",
						x: toBase64Url(keys.encryption.publicKey),
					},
				});
			}
			return Promise.reject(new Error(`Unexpected GET: ${path}`));
		}),
		post: vi.fn(),
	};
}

const baseRow = (over: Partial<ThreadRow>): ThreadRow => ({
	type: "rine.v1.task_request",
	encrypted_payload: "",
	encryption_version: "hpke-v1",
	created_at: "2026-06-20T00:00:00Z",
	...over,
});

describe("decryptThreadRow (shared CLI/MCP helper)", () => {
	let dir: string;
	let senderKeys: AgentKeys;
	let recipientKeys: AgentKeys;

	beforeEach(() => {
		dir = makeTmpDir();
		senderKeys = setupAgent(dir, SENDER_ID);
		recipientKeys = setupAgent(dir, RECIPIENT_ID);
	});
	afterEach(() => fs.rmSync(dir, { recursive: true }));

	it("decrypts the self-blob for a direction:sent 1:1 row", async () => {
		const enc = await encryptMessage(
			dir,
			SENDER_ID,
			recipientKeys.encryption.publicKey,
			{ text: "from me" },
		);
		const row = baseRow({
			direction: "sent",
			sender_handle: "me@org",
			encrypted_payload: enc.encrypted_payload,
			self_encrypted_payload: enc.self_encrypted_payload,
		});
		const entry = await decryptThreadRow(
			dir,
			SENDER_ID,
			row,
			clientWith(senderKeys) as never,
		);
		expect(entry.direction).toBe("sent");
		expect(entry.text).toBe("from me");
		expect(entry.verification_status).toBe("verified");
	});

	it("decrypts encrypted_payload for a direction:received row", async () => {
		const enc = await encryptMessage(
			dir,
			SENDER_ID,
			recipientKeys.encryption.publicKey,
			{ text: "to you" },
		);
		const row = baseRow({
			direction: "received",
			sender_handle: "alice@org",
			encrypted_payload: enc.encrypted_payload,
		});
		const entry = await decryptThreadRow(
			dir,
			RECIPIENT_ID,
			row,
			clientWith(senderKeys) as never,
		);
		expect(entry.direction).toBe("received");
		expect(entry.sender_handle).toBe("alice@org");
		expect(entry.text).toBe("to you");
		expect(entry.verification_status).toBe("verified");
	});

	it("renders [unavailable] for a sent row with no self-blob (legacy)", async () => {
		const enc = await encryptMessage(
			dir,
			SENDER_ID,
			recipientKeys.encryption.publicKey,
			{ text: "legacy" },
		);
		const row = baseRow({
			direction: "sent",
			encrypted_payload: enc.encrypted_payload,
			self_encrypted_payload: null,
		});
		const entry = await decryptThreadRow(
			dir,
			SENDER_ID,
			row,
			clientWith(senderKeys) as never,
		);
		expect(entry.text).toBe(THREAD_UNAVAILABLE);
	});

	it("fails closed to [unavailable] for an undecryptable row", async () => {
		// A received row the caller has no key for: garbage ciphertext → throw → degrade.
		const row = baseRow({
			direction: "received",
			encrypted_payload: "AAAA",
		});
		const entry = await decryptThreadRow(
			dir,
			RECIPIENT_ID,
			row,
			clientWith(senderKeys) as never,
		);
		expect(entry.text).toBe(THREAD_UNAVAILABLE);
		expect(entry.verification_status).toBe("unverifiable");
	});

	it("unwraps the {text} payload shape (parity with the SDK render contract)", async () => {
		const enc = await encryptMessage(
			dir,
			SENDER_ID,
			recipientKeys.encryption.publicKey,
			{ text: "hello world" },
		);
		const row = baseRow({
			direction: "received",
			encrypted_payload: enc.encrypted_payload,
		});
		const entry = await decryptThreadRow(
			dir,
			RECIPIENT_ID,
			row,
			clientWith(senderKeys) as never,
		);
		expect(entry.text).toBe("hello world");
	});
});

describe("renderThreadText (content-type-gated SDK parity)", () => {
	it("unwraps {text} for an application/json body (the default)", () => {
		expect(renderThreadText('{"text":"hi"}')).toBe("hi");
		expect(renderThreadText('{"text":"hi"}', "application/json")).toBe("hi");
		expect(renderThreadText('{"text":"hi"}', null)).toBe("hi");
	});

	it("surfaces a non-JSON content type verbatim, even if it looks like JSON", () => {
		// SDK `autoParsePlaintext` only parses application/json — text/plain is raw.
		expect(renderThreadText('{"text":"hi"}', "text/plain")).toBe('{"text":"hi"}');
		expect(renderThreadText("plain body", "text/plain")).toBe("plain body");
	});

	it("normalizes a JSON object with no text key via JSON.stringify (SDK renderText)", () => {
		// Whitespace is normalized to match the SDK's stringify, not the raw input.
		expect(renderThreadText('{ "a": 1 }')).toBe('{"a":1}');
	});

	it("returns a JSON string scalar unwrapped", () => {
		expect(renderThreadText('"bare"')).toBe("bare");
	});

	it("returns malformed JSON (claimed application/json) as the raw string", () => {
		expect(renderThreadText("{not json")).toBe("{not json");
	});
});
