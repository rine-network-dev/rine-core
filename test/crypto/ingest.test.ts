import * as fs from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ingestSenderKeyDistribution } from "../../src/crypto/ingest.js";
import { loadSenderKeyStates } from "../../src/crypto/sender-keys-helpers.js";
import type { DecryptResult } from "../../src/crypto/message.js";

function makeTmpDir(): string {
	return fs.mkdtempSync(join(tmpdir(), "rine-ingest-test-"));
}

const AGENT_ID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
const SENDER_ID = "b2c3d4e5-f6a7-8901-bcde-f12345678901";
const GROUP_ID = "c3d4e5f6-a7b8-9012-cdef-123456789012";

function makeDistribution(overrides?: Partial<{
	group_id: string;
	sender_key_id: string;
	chain_key: string;
	message_index: number;
	sender_agent_id: string;
}>): string {
	return JSON.stringify({
		group_id: GROUP_ID,
		sender_key_id: "d4e5f6a7-b8c9-0123-defa-234567890123",
		chain_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		message_index: 0,
		sender_agent_id: SENDER_ID,
		...overrides,
	});
}

function makeDecryptResult(opts?: {
	verified?: boolean;
	plaintext?: string;
}): DecryptResult {
	return {
		plaintext: opts?.plaintext ?? makeDistribution(),
		senderKid: `rine:${SENDER_ID}`,
		verified: opts?.verified ?? true,
		verificationStatus: opts?.verified === false ? "invalid" : "verified",
	};
}

describe("ingestSenderKeyDistribution", () => {
	let dir: string;

	beforeEach(() => {
		dir = makeTmpDir();
		// Create the keys directory structure needed by loadSenderKeyStates
		fs.mkdirSync(join(dir, "keys", AGENT_ID, "sender_keys"), { recursive: true });
	});
	afterEach(() => fs.rmSync(dir, { recursive: true }));

	it("returns false for wrong message type", () => {
		const result = ingestSenderKeyDistribution(dir, AGENT_ID, "rine.v1.dm", makeDecryptResult());
		expect(result).toBe(false);
	});

	it("returns false for unverified sender (poisoning prevention)", () => {
		const result = ingestSenderKeyDistribution(
			dir, AGENT_ID, "rine.v1.sender_key_distribution",
			makeDecryptResult({ verified: false }),
		);
		expect(result).toBe(false);
	});

	it("ingests new sender key and returns true", () => {
		const result = ingestSenderKeyDistribution(
			dir, AGENT_ID, "rine.v1.sender_key_distribution",
			makeDecryptResult(),
		);
		expect(result).toBe(true);

		const states = loadSenderKeyStates(dir, AGENT_ID, GROUP_ID);
		expect(states).toHaveLength(1);
		expect(states[0]!.senderKeyId).toBe("d4e5f6a7-b8c9-0123-defa-234567890123");
		expect(states[0]!.senderAgentId).toBe(SENDER_ID);
	});

	it("returns false for duplicate sender key id", () => {
		// Ingest once
		ingestSenderKeyDistribution(
			dir, AGENT_ID, "rine.v1.sender_key_distribution",
			makeDecryptResult(),
		);
		// Try again — should be rejected as duplicate
		const result = ingestSenderKeyDistribution(
			dir, AGENT_ID, "rine.v1.sender_key_distribution",
			makeDecryptResult(),
		);
		expect(result).toBe(false);
		expect(loadSenderKeyStates(dir, AGENT_ID, GROUP_ID)).toHaveLength(1);
	});

	it("ingests multiple different keys for same group", () => {
		ingestSenderKeyDistribution(
			dir, AGENT_ID, "rine.v1.sender_key_distribution",
			makeDecryptResult(),
		);
		ingestSenderKeyDistribution(
			dir, AGENT_ID, "rine.v1.sender_key_distribution",
			makeDecryptResult({
				plaintext: makeDistribution({ sender_key_id: "e5f6a7b8-c9d0-1234-efab-345678901234" }),
			}),
		);
		expect(loadSenderKeyStates(dir, AGENT_ID, GROUP_ID)).toHaveLength(2);
	});

	it("returns false for malformed plaintext", () => {
		const result = ingestSenderKeyDistribution(
			dir, AGENT_ID, "rine.v1.sender_key_distribution",
			makeDecryptResult({ plaintext: "not json" }),
		);
		expect(result).toBe(false);
	});
});
