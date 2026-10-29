import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { describe, expect, it, vi } from "vitest";
import { bytesToUuid } from "../src/crypto/bytes.js";
import { bytesToUuid as senderKeyUuid } from "../src/crypto/sender-keys-helpers.js";
import { deriveAgent, deriveBranch, deriveOrg } from "../src/crypto/derive.js";
import {
	agentReadKeys,
	deriveOrgRead,
	escrowReadKeys,
} from "../src/crypto/derive-read.js";
import { hex, kat, unhex } from "./crypto/kat-fixture.js";

const mlDsaFault = vi.hoisted(() => ({ fail: false }));
vi.mock("@noble/post-quantum/ml-dsa.js", async (importOriginal) => {
	const actual =
		await importOriginal<typeof import("@noble/post-quantum/ml-dsa.js")>();
	return {
		...actual,
		ml_dsa65: {
			...actual.ml_dsa65,
			keygen: (seed?: Uint8Array) => {
				if (mlDsaFault.fail) throw new Error("boom");
				return actual.ml_dsa65.keygen(seed);
			},
		},
	};
});

describe("derive-read against org-root-v1.json", () => {
	for (const root of kat.roots.roots) {
		const entropy = unhex(root.entropy);

		it(`root ${root.index}: deriveOrgRead matches the vector and deriveOrg`, () => {
			const read = deriveOrgRead(entropy);
			expect(read.orgId).toBe(root.org.org_id);
			expect(read.orgId).toBe(deriveOrg(entropy).orgId);
			expect(hex(read.rRead)).toBe(root.r_read);
			expect(hex(read.reader.privateKey)).toBe(root.org.reader.seed);
			expect(hex(read.reader.publicKey)).toBe(root.org.reader.pk);
		});

		for (const [name, expected] of Object.entries<any>(root.branches)) {
			it(`root ${root.index}: escrowReadKeys for ${name} equals deriveBranch`, () => {
				const branch = deriveBranch(deriveOrg(entropy), name);
				const read = escrowReadKeys(unhex(expected.b_read));
				expect(read).toEqual({
					escrowX25519: branch.escrowX25519,
					escrowMlKem768: branch.escrowMlKem768,
					reader: branch.reader,
				});
			});
		}

		for (const agent of root.agents) {
			for (const gen of agent.gens) {
				it(`root ${root.index}: agentReadKeys for ${agent.id} gen ${gen.gen} equals deriveAgent`, () => {
					const branch = deriveBranch(deriveOrg(entropy), agent.branch);
					const full = deriveAgent(branch, agent.id, gen.gen);
					const read = agentReadKeys(branch.bRead, agent.id, gen.gen);
					expect(read.x25519).toEqual(full.x25519);
					expect(read.mlKem768).toEqual(full.mlKem768);
					expect(hex(read.x25519.privateKey)).toBe(gen.x25519.sk);
				});
			}
		}
	}

	it("agentReadKeys refuses a non-canonical agent id and a bad generation", () => {
		const bRead = new Uint8Array(32);
		expect(() => agentReadKeys(bRead, "not-a-uuid", 0)).toThrow(
			"non-canonical agent id",
		);
		expect(() =>
			agentReadKeys(bRead, "f89b5784-b1da-432f-8db2-000000000000", -1),
		).toThrow("invalid key_gen");
	});
});

describe("deriveOrgRead zeroing", () => {
	it("leaves the root untouched and returns only read material", () => {
		const entropy = unhex(kat.roots.roots[0].entropy);
		const copy = entropy.slice();
		const read = deriveOrgRead(entropy);
		expect(entropy).toEqual(copy);
		expect(Object.keys(read).sort()).toEqual(["orgId", "rRead", "reader"]);
	});

	it("zeroes rSign and both org signing private keys before returning", () => {
		const entropy = unhex(kat.roots.roots[0].entropy);
		const full = deriveOrg(entropy);
		const secrets = new Set(
			[full.rSign, full.ed25519.privateKey, full.mlDsa65.privateKey].map(hex),
		);
		const zeroed = new Set<string>();
		const realFill = Uint8Array.prototype.fill;
		Uint8Array.prototype.fill = function (this: Uint8Array, ...args) {
			const before = hex(this);
			if (args[0] === 0 && secrets.has(before)) zeroed.add(before);
			return realFill.apply(this, args as [number]);
		} as typeof Uint8Array.prototype.fill;
		try {
			deriveOrgRead(entropy);
		} finally {
			Uint8Array.prototype.fill = realFill;
		}
		expect(zeroed).toEqual(secrets);
	});

	it("zeroes the ML-DSA secret key keygen returns", () => {
		const entropy = unhex(kat.roots.roots[0].entropy);
		const full = deriveOrg(entropy);
		const secret = hex(ml_dsa65.keygen(full.mlDsa65.privateKey).secretKey);
		const zeroed = new Set<string>();
		const realFill = Uint8Array.prototype.fill;
		Uint8Array.prototype.fill = function (this: Uint8Array, ...args) {
			if (args[0] === 0) zeroed.add(hex(this));
			return realFill.apply(this, args as [number]);
		} as typeof Uint8Array.prototype.fill;
		try {
			deriveOrgRead(entropy);
		} finally {
			Uint8Array.prototype.fill = realFill;
		}
		expect(zeroed.has(secret)).toBe(true);
	});

	it("zeroes the root-derived secrets when derivation throws", () => {
		const entropy = unhex(kat.roots.roots[0].entropy);
		const full = deriveOrg(entropy);
		const secrets = new Set([full.rSign, full.ed25519.privateKey].map(hex));
		const zeroed = new Set<string>();
		const realFill = Uint8Array.prototype.fill;
		Uint8Array.prototype.fill = function (this: Uint8Array, ...args) {
			const before = hex(this);
			if (args[0] === 0 && secrets.has(before)) zeroed.add(before);
			return realFill.apply(this, args as [number]);
		} as typeof Uint8Array.prototype.fill;
		mlDsaFault.fail = true;
		try {
			expect(() => deriveOrgRead(entropy)).toThrow("boom");
		} finally {
			mlDsaFault.fail = false;
			Uint8Array.prototype.fill = realFill;
		}
		expect(zeroed).toEqual(secrets);
	});
});

describe("bytesToUuid", () => {
	it("is the one formatter for sender keys and org ids", () => {
		expect(senderKeyUuid).toBe(bytesToUuid);
		expect(bytesToUuid(Uint8Array.from({ length: 16 }, (_, i) => i * 17))).toBe(
			"00112233-4455-6677-8899-aabbccddeeff",
		);
	});
});
