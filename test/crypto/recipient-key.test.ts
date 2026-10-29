import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { type KeyPair, type PqKeyPair, openHybrid } from "../../src/crypto/index.js";
import { generateEncryptionKeyPair, generatePqKeyPair } from "../helpers/keys.js";
import { toBase64Url } from "../../src/crypto/keys.js";
import {
	RECIPIENT_KEY_BYTES,
	parseRecipientKey,
	recipientKeyWords,
	sealBranchBundle,
} from "../../src/crypto/recipient-key.js";

const VECTOR_PATH = new URL(
	"../../../rine-sdk/tests/fixtures/recipient_key_words_vector.json",
	import.meta.url,
);

const ORG_ID = "11111111-2222-3333-4444-555555555555";

/** A recipient keypair: the X25519 and ML-KEM-768 keys the fleet holds. */
function recipientPair() {
	const x = generateEncryptionKeyPair();
	const pq = generatePqKeyPair();
	return { x, pq };
}

function recipientKeyText(x: KeyPair, pq: PqKeyPair): string {
	const raw = new Uint8Array(RECIPIENT_KEY_BYTES);
	raw.set(x.publicKey, 0);
	raw.set(pq.publicKey, 32);
	return toBase64Url(raw);
}

function branchSecrets(name: string) {
	const bRead = new Uint8Array(32).fill(7);
	const bSign = new Uint8Array(32).fill(9);
	return { name, bRead, bSign };
}

describe("parseRecipientKey", () => {
	it("round-trips a well-formed key", () => {
		const { x, pq } = recipientPair();
		const text = recipientKeyText(x, pq);

		const parsed = parseRecipientKey(text);

		expect(parsed.raw.length).toBe(RECIPIENT_KEY_BYTES);
		expect(parsed.x25519).toEqual(x.publicKey);
		expect(parsed.mlKem).toEqual(pq.publicKey);
	});

	it("trims surrounding whitespace", () => {
		const { x, pq } = recipientPair();
		const parsed = parseRecipientKey(`  ${recipientKeyText(x, pq)}\n`);
		expect(parsed.raw.length).toBe(RECIPIENT_KEY_BYTES);
	});

	it("rejects a key of the wrong length", () => {
		const short = toBase64Url(new Uint8Array(64));
		expect(() => parseRecipientKey(short)).toThrow(
			"recipient key must be 1216 bytes: an X25519 key followed by an ML-KEM-768 key, base64url",
		);
	});
});

describe("recipientKeyWords", () => {
	it("matches the Python SDK's words for the shared golden key", () => {
		// The golden lives with the SDK's cross-language vectors; the SDK suite
		// and the fleet replay the same file, so the three derivations move together.
		const vector = JSON.parse(readFileSync(VECTOR_PATH, "utf-8")) as {
			key_hex: string;
			words: string;
		};
		const raw = Uint8Array.from(Buffer.from(vector.key_hex, "hex"));

		expect(recipientKeyWords(parseRecipientKey(toBase64Url(raw)))).toBe(vector.words);
	});

	it("is five words and stable for a fixed key", () => {
		const { x, pq } = recipientPair();
		const key = parseRecipientKey(recipientKeyText(x, pq));

		const words = recipientKeyWords(key);

		expect(words.split(" ")).toHaveLength(5);
		expect(recipientKeyWords(key)).toBe(words);
	});
});

describe("sealBranchBundle", () => {
	it("opens under the BranchBundle context with the matching private keys", () => {
		const { x, pq } = recipientPair();
		const key = parseRecipientKey(recipientKeyText(x, pq));
		const branch = branchSecrets("partner");

		const sealed = sealBranchBundle(key, ORG_ID, branch);

		const opened = openHybrid(x.privateKey, pq.privateKey, sealed, {
			kind: "BranchBundle",
			orgId: ORG_ID,
			branch: "partner",
		});
		expect(JSON.parse(new TextDecoder().decode(opened))).toEqual({
			org_id: ORG_ID,
			branch: "partner",
			read: toBase64Url(branch.bRead),
			sign: toBase64Url(branch.bSign),
			v: 1,
		});
	});

	it("does not open under a different branch name", () => {
		const { x, pq } = recipientPair();
		const key = parseRecipientKey(recipientKeyText(x, pq));

		const sealed = sealBranchBundle(key, ORG_ID, branchSecrets("partner"));

		expect(() =>
			openHybrid(x.privateKey, pq.privateKey, sealed, {
				kind: "BranchBundle",
				orgId: ORG_ID,
				branch: "other",
			}),
		).toThrow();
	});
});
