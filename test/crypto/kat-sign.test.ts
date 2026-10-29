import { describe, expect, it } from "vitest";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { deriveAgent, deriveBranch, deriveOrg } from "../../src/crypto/derive.js";
import {
	assertStrictEd25519PublicKey,
	verifyEd25519Strict,
} from "../../src/crypto/ed25519-strict.js";
import {
	MLKEM_CT_SIZE,
	type SealContext,
	sealHybrid,
} from "../../src/crypto/hybrid.js";
import { JwsTyp, verifyJws } from "../../src/crypto/jws.js";
import { generateEncryptionKeyPair } from "../helpers/keys.js";
import {
	type SigContext,
	messageSigningInput,
	signMessage,
	verifyMessageSignature,
} from "../../src/crypto/sign.js";
import { hex, kat, unhex } from "./kat-fixture.js";

const encoder = new TextEncoder();
const signatures = kat.signatures;

interface SenderRef {
	root: number;
	agent_id: string;
	branch: string;
	gen: number;
}

function senderKeys(sender: SenderRef) {
	const entropy = unhex(kat.roots.roots[sender.root].entropy);
	const branch = deriveBranch(deriveOrg(entropy), sender.branch);
	return deriveAgent(branch, sender.agent_id, sender.gen);
}

describe("kat.signatures.message_signature", () => {
	const entry = signatures.message_signature;
	const keys = senderKeys(entry.sender);
	const ctx: SigContext = {
		kind: "MessageSig",
		recipientAgentId: entry.recipient_agent_id,
	};
	const payload = encoder.encode(entry.payload_utf8);

	it("builds the golden signing input", () => {
		expect(hex(messageSigningInput(ctx, payload))).toBe(entry.signing_input);
	});

	it("reproduces the golden signature and public key", () => {
		expect(hex(signMessage(keys.ed25519.privateKey, ctx, payload))).toBe(
			entry.signature,
		);
		expect(hex(keys.ed25519.publicKey)).toBe(entry.public_key);
	});

	it("accepts the golden signature", () => {
		expect(
			verifyMessageSignature(
				keys.ed25519.publicKey,
				ctx,
				payload,
				unhex(entry.signature),
			),
		).toBe(true);
	});
});

describe("kat.signatures.group_message_signature", () => {
	const entry = signatures.group_message_signature;
	const keys = senderKeys(entry.sender);
	const ctx: SigContext = { kind: "GroupSig", groupId: entry.group_id };
	const payload = encoder.encode(entry.payload_utf8);

	it("builds the golden signing input", () => {
		expect(hex(messageSigningInput(ctx, payload))).toBe(entry.signing_input);
	});

	it("reproduces the golden signature and public key", () => {
		expect(hex(signMessage(keys.ed25519.privateKey, ctx, payload))).toBe(
			entry.signature,
		);
		expect(hex(keys.ed25519.publicKey)).toBe(entry.public_key);
	});

	it("accepts the golden signature", () => {
		expect(
			verifyMessageSignature(
				keys.ed25519.publicKey,
				ctx,
				payload,
				unhex(entry.signature),
			),
		).toBe(true);
	});
});

describe("kat.signatures.message_signature negatives", () => {
	const entry = signatures.message_signature;
	const keys = senderKeys(entry.sender);
	const ctx: SigContext = {
		kind: "MessageSig",
		recipientAgentId: entry.recipient_agent_id,
	};
	const payload = encoder.encode(entry.payload_utf8);
	const signature = unhex(entry.signature);

	it("refuses a signature under another recipient scope", () => {
		const other: SigContext = {
			kind: "MessageSig",
			recipientAgentId: signatures.group_message_signature.group_id,
		};
		expect(
			verifyMessageSignature(keys.ed25519.publicKey, other, payload, signature),
		).toBe(false);
	});

	it("refuses a changed payload", () => {
		const changed = encoder.encode(`${entry.payload_utf8} `);
		expect(
			verifyMessageSignature(keys.ed25519.publicKey, ctx, changed, signature),
		).toBe(false);
	});

	it("refuses a flipped signature bit", () => {
		const flipped = signature.slice();
		flipped[0] = (flipped[0] ?? 0) ^ 0x01;
		expect(
			verifyMessageSignature(keys.ed25519.publicKey, ctx, payload, flipped),
		).toBe(false);
	});

	it("refuses a signature under another key", () => {
		const other = deriveOrg(
			unhex(kat.roots.roots[entry.sender.root].entropy),
		).ed25519.publicKey;
		expect(verifyMessageSignature(other, ctx, payload, signature)).toBe(false);
	});
});

describe("kat.signatures.cross_domain", () => {
	it("refuses a message signature presented as a JWS", () => {
		const entry = signatures.cross_domain.message_signature_as_jws;
		expect(() =>
			verifyJws(
				entry.compact_jws,
				unhex(entry.verifier_pk),
				entry.expected_typ as JwsTyp,
			),
		).toThrow();
	});

	it("refuses a JWS signing input presented as a message signature", () => {
		const entry = signatures.cross_domain.jws_as_message_signature;
		const ctx: SigContext = {
			kind: "MessageSig",
			recipientAgentId: entry.recipient_agent_id,
		};
		expect(
			verifyMessageSignature(
				unhex(entry.public_key),
				ctx,
				encoder.encode(entry.payload_utf8),
				unhex(entry.signature),
			),
		).toBe(false);
	});
});

describe("kat.signatures.cross_scope", () => {
	const entries: [string, SigContext][] = [
		[
			"message_signature_as_group",
			{ kind: "GroupSig", groupId: signatures.cross_scope.message_signature_as_group.shared_id },
		],
		[
			"group_signature_as_message",
			{
				kind: "MessageSig",
				recipientAgentId: signatures.cross_scope.group_signature_as_message.shared_id,
			},
		],
	];

	it.each(entries)("refuses %s under an equal id", (name, ctx) => {
		const entry = signatures.cross_scope[name];
		expect(
			verifyMessageSignature(
				unhex(entry.public_key),
				ctx,
				encoder.encode(entry.payload_utf8),
				unhex(entry.signature),
			),
		).toBe(false);
	});
});

describe("kat.signatures.ed25519_strict", () => {
	const strict = signatures.ed25519_strict;

	it("accepts the control", () => {
		expect(
			verifyEd25519Strict(
				unhex(strict.control.public_key),
				unhex(strict.control.message),
				unhex(strict.control.signature),
			),
		).toBe(true);
	});

	it("refuses every negative", () => {
		for (const entry of strict.negatives) {
			expect(
				verifyEd25519Strict(
					unhex(entry.public_key),
					unhex(entry.message),
					unhex(entry.signature),
				),
				entry.name,
			).toBe(false);
		}
	});

	it("accepts the control key and throws on every malformed negative key", () => {
		expect(() =>
			assertStrictEd25519PublicKey(unhex(strict.control.public_key)),
		).not.toThrow();
		for (const entry of strict.negatives) {
			if (entry.public_key === strict.control.public_key) continue;
			expect(
				() => assertStrictEd25519PublicKey(unhex(entry.public_key)),
				entry.name,
			).toThrow();
		}
	});
});

describe("kat.signatures.ml_kem_modulus", () => {
	const modulus = signatures.ml_kem_modulus;

	it("encapsulates to the control encapsulation key", () => {
		const { cipherText, sharedSecret } = ml_kem768.encapsulate(
			unhex(modulus.control.ek),
		);
		expect(cipherText).toHaveLength(MLKEM_CT_SIZE);
		expect(sharedSecret).toHaveLength(32);
	});

	it("refuses the non-canonical encapsulation key", () => {
		expect(() => ml_kem768.encapsulate(unhex(modulus.negative.ek))).toThrow();
	});

	it("refuses to seal to the non-canonical encapsulation key", () => {
		const x = generateEncryptionKeyPair();
		const ctx: SealContext = {
			kind: "AgentMessage",
			recipientAgentId: signatures.message_signature.recipient_agent_id,
		};
		expect(() =>
			sealHybrid(
				x.publicKey,
				unhex(modulus.negative.ek),
				new Uint8Array([1]),
				ctx,
			),
		).toThrow();
	});
});
