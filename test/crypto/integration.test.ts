import { describe, expect, it } from "vitest";
import { decodeEnvelope, encodeEnvelope } from "../../src/crypto/envelope.js";
import { openHybrid, sealHybrid } from "../../src/crypto/hybrid.js";
import { signingKid } from "../../src/crypto/keys.js";
import { generateAgentKeys } from "../helpers/keys.js";
import {
	type SigContext,
	signMessage,
	verifyMessageSignature,
} from "../../src/crypto/sign.js";

const RECIPIENT_ID = "b2c3d4e5-f6a7-8901-bcde-f12345678901";
const SENDER_ID = "00000000-0000-4000-a000-000000000001";
const sigCtx: SigContext = {
	kind: "MessageSig",
	recipientAgentId: RECIPIENT_ID,
};

function open(recipient: ReturnType<typeof generateAgentKeys>, wire: Uint8Array) {
	return openHybrid(
		recipient.encryption.privateKey,
		recipient.pqEncryption.privateKey,
		wire,
		{ kind: "AgentMessage", recipientAgentId: RECIPIENT_ID },
	);
}

function seal(recipient: ReturnType<typeof generateAgentKeys>, bytes: Uint8Array) {
	return sealHybrid(
		recipient.encryption.publicKey,
		recipient.pqEncryption.publicKey,
		bytes,
		{ kind: "AgentMessage", recipientAgentId: RECIPIENT_ID },
	);
}

describe("full E2EE roundtrip", () => {
	it("sender encrypts, recipient decrypts and verifies", () => {
		const sender = generateAgentKeys();
		const recipient = generateAgentKeys();
		const senderKid = signingKid(SENDER_ID, 0);

		const plaintext = new TextEncoder().encode(
			JSON.stringify({ task: "validate", amount: 42 }),
		);
		const signature = signMessage(sender.signing.privateKey, sigCtx, plaintext);
		const envelope = encodeEnvelope(senderKid, signature, plaintext);

		const decoded = decodeEnvelope(open(recipient, seal(recipient, envelope)));

		expect(decoded.kid).toBe(senderKid);
		expect(
			verifyMessageSignature(
				sender.signing.publicKey,
				sigCtx,
				decoded.payload,
				decoded.signature,
			),
		).toBe(true);
		expect(JSON.parse(new TextDecoder().decode(decoded.payload))).toEqual({
			task: "validate",
			amount: 42,
		});
	});

	it("rejects message signed by different sender", () => {
		const sender = generateAgentKeys();
		const impersonator = generateAgentKeys();
		const recipient = generateAgentKeys();

		const plaintext = new TextEncoder().encode("legit message");
		const sig = signMessage(impersonator.signing.privateKey, sigCtx, plaintext);
		const envelope = encodeEnvelope("fake-kid", sig, plaintext);

		const decoded = decodeEnvelope(open(recipient, seal(recipient, envelope)));

		expect(
			verifyMessageSignature(
				sender.signing.publicKey,
				sigCtx,
				decoded.payload,
				decoded.signature,
			),
		).toBe(false);
	});
});
