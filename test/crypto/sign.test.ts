import { describe, expect, it } from "vitest";
import { generateSigningKeyPair } from "../helpers/keys.js";
import {
	type SigContext,
	messageSigningInput,
	signMessage,
	verifyMessageSignature,
} from "../../src/crypto/sign.js";

const ctx: SigContext = {
	kind: "MessageSig",
	recipientAgentId: "6f3a9056-250e-4ae3-baf5-6a5cc54533a5",
};
const encode = (text: string) => new TextEncoder().encode(text);

describe("signMessage + verifyMessageSignature", () => {
	it("roundtrips: sign then verify", () => {
		const kp = generateSigningKeyPair();
		const msg = encode("hello world");
		const sig = signMessage(kp.privateKey, ctx, msg);

		expect(sig).toHaveLength(64);
		expect(verifyMessageSignature(kp.publicKey, ctx, msg, sig)).toBe(true);
	});

	it("rejects wrong public key", () => {
		const sender = generateSigningKeyPair();
		const other = generateSigningKeyPair();
		const sig = signMessage(sender.privateKey, ctx, encode("secret"));

		expect(
			verifyMessageSignature(other.publicKey, ctx, encode("secret"), sig),
		).toBe(false);
	});

	it("rejects tampered message", () => {
		const kp = generateSigningKeyPair();
		const sig = signMessage(kp.privateKey, ctx, encode("original"));

		expect(
			verifyMessageSignature(kp.publicKey, ctx, encode("modified"), sig),
		).toBe(false);
	});

	it("rejects a signature replayed to another recipient", () => {
		const kp = generateSigningKeyPair();
		const msg = encode("pay 42");
		const sig = signMessage(kp.privateKey, ctx, msg);
		const other: SigContext = {
			kind: "MessageSig",
			recipientAgentId: "b2c3d4e5-f6a7-8901-bcde-f12345678901",
		};

		expect(verifyMessageSignature(kp.publicKey, other, msg, sig)).toBe(false);
	});

	it("produces deterministic signatures", () => {
		const kp = generateSigningKeyPair();
		const msg = encode("deterministic");
		const sig1 = signMessage(kp.privateKey, ctx, msg);
		const sig2 = signMessage(kp.privateKey, ctx, msg);

		expect(Buffer.from(sig1).equals(Buffer.from(sig2))).toBe(true);
	});

	it("signs empty payload", () => {
		const kp = generateSigningKeyPair();
		const empty = new Uint8Array(0);
		const sig = signMessage(kp.privateKey, ctx, empty);

		expect(verifyMessageSignature(kp.publicKey, ctx, empty, sig)).toBe(true);
	});

	it("prefixes the payload with the domain and the scope", () => {
		const input = messageSigningInput(ctx, encode("x"));

		expect(new TextDecoder().decode(input)).toBe(
			`rine.v1.msg-sig\0${ctx.recipientAgentId}\0x`,
		);
	});

	it("gives a group signature its own prefix", () => {
		const group: SigContext = { kind: "GroupSig", groupId: ctx.recipientAgentId };
		const input = messageSigningInput(group, encode("x"));

		expect(new TextDecoder().decode(input)).toBe(
			`rine.v1.group-sig\0${ctx.recipientAgentId}\0x`,
		);
	});
});
