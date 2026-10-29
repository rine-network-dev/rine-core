import { describe, expect, it } from "vitest";
import { x25519 } from "@noble/curves/ed25519.js";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import {
	MLKEM_CT_SIZE,
	VERSION_HYBRID_V2,
	type SealContext,
	openHybrid,
	sealContextAad,
	sealHybrid,
	sealHybridWith,
} from "../../src/crypto/hybrid.js";
import { generateEncryptionKeyPair, generatePqKeyPair } from "../helpers/keys.js";
import { hex, kat, unhex } from "./kat-fixture.js";

const hybrid = kat.hybrid_v2;
const escrow = kat.mls_escrow;

function ctxFromJson(json: any): SealContext {
	if (json.kind === "AgentMessage") {
		return { kind: "AgentMessage", recipientAgentId: json.recipient_agent_id };
	}
	if (json.kind === "BranchBundle") {
		return { kind: "BranchBundle", orgId: json.org_id, branch: json.branch };
	}
	return {
		kind: "MlsEscrow",
		orgId: json.org_id,
		branch: json.branch,
		groupId: json.group_id,
		epoch: json.epoch,
		uploaderAgentId: json.uploader_agent_id,
		fp: unhex(json.fp),
	};
}

function ctxFromAad(entry: any): SealContext {
	return ctxFromJson({ kind: entry.kind, ...entry.args });
}

function agentKeys(rootIndex: number, agentId: string, gen: number) {
	const root = kat.roots.roots[rootIndex];
	const agent = root.agents.find((entry: any) => entry.id === agentId);
	const generation = agent.gens.find((entry: any) => entry.gen === gen);
	return {
		x25519Pk: unhex(generation.x25519.pk),
		x25519Sk: unhex(generation.x25519.sk),
		mlKemPk: unhex(generation.ml_kem_768.pk),
		mlKemSk: ml_kem768.keygen(unhex(generation.ml_kem_768.seed)).secretKey,
	};
}

function escrowKeys(branchName: string) {
	const branch = kat.roots.roots[0].branches[branchName];
	return {
		x25519Pk: unhex(branch.escrow_x25519.pk),
		x25519Sk: unhex(branch.escrow_x25519.sk),
		mlKemPk: unhex(branch.escrow_ml_kem_768.pk),
		mlKemSk: ml_kem768.keygen(unhex(branch.escrow_ml_kem_768.seed)).secretKey,
	};
}

describe("sealContextAad", () => {
	it("matches every golden AAD", () => {
		for (const entry of hybrid.aad) {
			expect(hex(sealContextAad(ctxFromAad(entry)))).toBe(entry.aad);
		}
	});

	it("rejects ids that are not canonical NUL-free UUIDs or branch names", () => {
		const uuid = "f89b5784-b1da-832f-8db2-4e46a5cec787";
		const bad: SealContext[] = [
			{ kind: "AgentMessage", recipientAgentId: `${uuid}\0x` },
			{ kind: "AgentMessage", recipientAgentId: uuid.toUpperCase() },
			{ kind: "BranchBundle", orgId: uuid, branch: "Not A Branch" },
		];
		for (const ctx of bad) expect(() => sealContextAad(ctx)).toThrow();
	});

	it("rejects a negative epoch", () => {
		const ctx: SealContext = {
			kind: "MlsEscrow",
			orgId: "f89b5784-b1da-832f-8db2-4e46a5cec787",
			branch: "main",
			groupId: "b56ab59d-d286-4c64-9d82-722fc43b948d",
			epoch: -1,
			uploaderAgentId: "8558188f-7713-44e4-824d-c2e060c9c5e1",
			fp: new Uint8Array(16),
		};
		expect(() => sealContextAad(ctx)).toThrow();
	});
});

describe("hybrid_v2 seal KAT", () => {
	const recipient = hybrid.seal.recipient;
	const keys = agentKeys(recipient.root, recipient.agent_id, recipient.gen);
	const ctx = ctxFromJson(hybrid.seal.ctx);

	it("reproduces the golden wire", () => {
		const wire = sealHybridWith(
			keys.x25519Pk,
			keys.mlKemPk,
			new TextEncoder().encode(hybrid.seal.plaintext_utf8),
			ctx,
			unhex(hybrid.seal.ephemeral_sk),
			unhex(hybrid.seal.kem_msg),
		);
		expect(hex(wire)).toBe(hybrid.seal.wire);
	});

	it("opens the golden wire", () => {
		const opened = openHybrid(
			keys.x25519Sk,
			keys.mlKemSk,
			unhex(hybrid.seal.wire),
			ctx,
		);
		expect(new TextDecoder().decode(opened)).toBe(hybrid.seal.plaintext_utf8);
	});

	it("refuses every open negative", () => {
		for (const entry of hybrid.open_negatives) {
			expect(() =>
				openHybrid(
					keys.x25519Sk,
					keys.mlKemSk,
					unhex(entry.wire),
					ctxFromJson(entry.ctx),
				),
			).toThrow();
		}
	});
});

describe("mls_escrow seal KAT", () => {
	const keys = escrowKeys(escrow.seal.escrow_branch);
	const ctx: SealContext = {
		kind: "MlsEscrow",
		orgId: escrow.slot.org_id,
		branch: escrow.slot.branch,
		groupId: escrow.slot.group_id,
		epoch: escrow.slot.epoch,
		uploaderAgentId: escrow.uploader.agent_id,
		fp: unhex(escrow.slot.fp),
	};

	it("reproduces the golden sealed bytes and AAD", () => {
		const sealed = sealHybridWith(
			keys.x25519Pk,
			keys.mlKemPk,
			unhex(escrow.plaintext.bytes),
			ctx,
			unhex(escrow.seal.ephemeral_sk),
			unhex(escrow.seal.kem_msg),
		);
		expect(hex(sealed)).toBe(escrow.seal.sealed);
		expect(hex(sealContextAad(ctx))).toBe(escrow.seal.aad);
	});

	it("refuses every open_under negative", () => {
		for (const entry of escrow.negatives.open_under) {
			expect(() =>
				openHybrid(
					keys.x25519Sk,
					keys.mlKemSk,
					unhex(escrow.seal.sealed),
					ctxFromJson(entry.ctx),
				),
			).toThrow();
		}
	});

	it("opens every bad plaintext under the correct context", () => {
		for (const entry of escrow.negatives.bad_plaintexts) {
			const opened = openHybrid(
				keys.x25519Sk,
				keys.mlKemSk,
				unhex(entry.sealed),
				ctx,
			);
			expect(hex(opened)).toBe(entry.plaintext);
		}
	});
});

describe("hybrid_v2 round trip and framing", () => {
	const x = generateEncryptionKeyPair();
	const pq = generatePqKeyPair();
	const ctx: SealContext = {
		kind: "AgentMessage",
		recipientAgentId: "8558188f-7713-44e4-824d-c2e060c9c5e1",
	};

	it("round trips with fresh randomness", () => {
		const plaintext = new TextEncoder().encode("round trip");
		const wire = sealHybrid(x.publicKey, pq.publicKey, plaintext, ctx);
		expect(wire[0]).toBe(VERSION_HYBRID_V2);
		expect(wire.length).toBe(
			1 + 32 + MLKEM_CT_SIZE + plaintext.length + 16,
		);
		expect(hex(openHybrid(x.privateKey, pq.privateKey, wire, ctx))).toBe(
			hex(plaintext),
		);
	});

	it("refuses a flipped last byte", () => {
		const wire = sealHybrid(x.publicKey, pq.publicKey, new Uint8Array([1]), ctx);
		const last = wire.length - 1;
		wire[last] = (wire[last] ?? 0) ^ 0x01;
		expect(() => openHybrid(x.privateKey, pq.privateKey, wire, ctx)).toThrow();
	});

	it("refuses version bytes 0x03 and 0x01", () => {
		for (const version of [0x03, 0x01]) {
			const wire = sealHybrid(
				x.publicKey,
				pq.publicKey,
				new Uint8Array([1]),
				ctx,
			);
			wire[0] = version;
			expect(() =>
				openHybrid(x.privateKey, pq.privateKey, wire, ctx),
			).toThrow();
		}
	});

	it("refuses a 10-byte wire", () => {
		expect(() =>
			openHybrid(x.privateKey, pq.privateKey, new Uint8Array(10), ctx),
		).toThrow();
	});

	it("keeps generatePqKeyPair sized", () => {
		const kp = generatePqKeyPair();
		expect(kp.publicKey).toHaveLength(1184);
		expect(kp.privateKey).toHaveLength(2400);
		expect(x25519.getPublicKey(x.privateKey)).toHaveLength(32);
	});
});
