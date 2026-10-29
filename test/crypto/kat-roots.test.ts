import { describe, expect, it } from "vitest";
import {
	assertBranchName,
	canonicalAgentLabelId,
	deriveAgent,
	deriveBranch,
	deriveOrg,
	hkdfDerive,
} from "../../src/crypto/derive.js";
import { orgWords } from "../../src/crypto/org-words.js";
import {
	entropyFromPhrase,
	PhraseError,
	phraseFromEntropy,
} from "../../src/crypto/phrase.js";
import { hex, kat, unhex } from "./kat-fixture.js";

describe("kat constants: hkdf", () => {
	for (const vector of kat.constants.hkdf) {
		it(`derives ${vector.label}`, () => {
			const okm = hkdfDerive(unhex(vector.parent), vector.label, vector.length);
			expect(hex(okm)).toBe(vector.okm);
		});
	}
});

describe("kat constants: branch names", () => {
	for (const name of kat.constants.branch_names.accepted) {
		it(`accepts ${JSON.stringify(name)}`, () => {
			expect(assertBranchName(name)).toBe(name);
		});
	}
	for (const vector of kat.constants.branch_names.refused) {
		it(`refuses ${vector.name}`, () => {
			expect(() => assertBranchName(vector.input)).toThrow("invalid branch name");
		});
	}
});

describe("kat constants: canonical agent id", () => {
	for (const id of kat.constants.canonical_agent_id.accepted) {
		it(`accepts ${id}`, () => {
			expect(canonicalAgentLabelId(id)).toBe(id);
		});
	}
	for (const vector of kat.constants.canonical_agent_id.refused) {
		it(`refuses ${vector.name}`, () => {
			expect(() => canonicalAgentLabelId(vector.input)).toThrow(
				"non-canonical agent id",
			);
		});
	}
});

describe("kat roots", () => {
	for (const root of kat.roots.roots) {
		describe(`root ${root.index}`, () => {
			const entropy = unhex(root.entropy);

			it("round-trips the phrase", () => {
				expect(phraseFromEntropy(entropy)).toBe(root.phrase);
				expect(hex(entropyFromPhrase(root.phrase))).toBe(root.entropy);
			});

			it("derives the org words", () => {
				expect(orgWords(root.org.org_id)).toBe(root.org_words);
			});

			it("derives the org keys", () => {
				const org = deriveOrg(entropy);
				expect(hex(org.rRead)).toBe(root.r_read);
				expect(hex(org.rSign)).toBe(root.r_sign);
				expect(hex(org.reader.privateKey)).toBe(root.org.reader.seed);
				expect(hex(org.reader.publicKey)).toBe(root.org.reader.pk);
				expect(hex(org.ed25519.privateKey)).toBe(root.org.ed25519.seed);
				expect(hex(org.ed25519.publicKey)).toBe(root.org.ed25519.pk);
				expect(hex(org.mlDsa65.privateKey)).toBe(root.org.ml_dsa_65.xi);
				expect(hex(org.mlDsa65.publicKey)).toBe(root.org.ml_dsa_65.pk);
				expect(org.orgId).toBe(root.org.org_id);
			});

			for (const [name, expected] of Object.entries<any>(root.branches)) {
				it(`derives branch ${name}`, () => {
					const branch = deriveBranch(deriveOrg(entropy), name);
					expect(branch.name).toBe(expected.name);
					expect(hex(branch.bRead)).toBe(expected.b_read);
					expect(hex(branch.bSign)).toBe(expected.b_sign);
					expect(hex(branch.escrowX25519.privateKey)).toBe(
						expected.escrow_x25519.sk,
					);
					expect(hex(branch.escrowX25519.publicKey)).toBe(
						expected.escrow_x25519.pk,
					);
					expect(hex(branch.escrowMlKem768.privateKey)).toBe(
						expected.escrow_ml_kem_768.seed,
					);
					expect(hex(branch.escrowMlKem768.publicKey)).toBe(
						expected.escrow_ml_kem_768.pk,
					);
					expect(hex(branch.reader.privateKey)).toBe(expected.reader.seed);
					expect(hex(branch.reader.publicKey)).toBe(expected.reader.pk);
					expect(hex(branch.ed25519.privateKey)).toBe(expected.ed25519.seed);
					expect(hex(branch.ed25519.publicKey)).toBe(expected.ed25519.pk);
					expect(hex(branch.mlDsa65.privateKey)).toBe(expected.ml_dsa_65.xi);
					expect(hex(branch.mlDsa65.publicKey)).toBe(expected.ml_dsa_65.pk);
				});
			}

			for (const agent of root.agents) {
				for (const gen of agent.gens) {
					it(`derives agent ${agent.id} gen ${gen.gen}`, () => {
						const branch = deriveBranch(deriveOrg(entropy), agent.branch);
						const derived = deriveAgent(branch, agent.id, gen.gen);
						expect(derived.id).toBe(agent.id);
						expect(derived.gen).toBe(gen.gen);
						expect(derived.branch).toBe(agent.branch);
						expect(hex(derived.x25519.privateKey)).toBe(gen.x25519.sk);
						expect(hex(derived.x25519.publicKey)).toBe(gen.x25519.pk);
						expect(hex(derived.mlKem768.privateKey)).toBe(gen.ml_kem_768.seed);
						expect(hex(derived.mlKem768.publicKey)).toBe(gen.ml_kem_768.pk);
						expect(hex(derived.ed25519.privateKey)).toBe(gen.ed25519.seed);
						expect(hex(derived.ed25519.publicKey)).toBe(gen.ed25519.pk);
						expect(hex(derived.mlDsa65.privateKey)).toBe(gen.ml_dsa_65.xi);
						expect(hex(derived.mlDsa65.publicKey)).toBe(gen.ml_dsa_65.pk);
						expect(hex(derived.mlsEd25519.privateKey)).toBe(
							gen.mls_ed25519.seed,
						);
						expect(hex(derived.mlsEd25519.publicKey)).toBe(gen.mls_ed25519.pk);
					});
				}
			}
		});
	}
});

describe("org words input", () => {
	it("refuses an id that is not 16 bytes of hex", () => {
		expect(() => orgWords("zz")).toThrow();
		expect(() => orgWords("f89b5784-b1da-832f-8db2")).toThrow();
	});
});

describe("kat phrases", () => {
	for (const vector of kat.phrases.accepted) {
		it(`accepts ${vector.name}`, () => {
			expect(hex(entropyFromPhrase(vector.input))).toBe(vector.entropy);
		});
	}
	for (const vector of kat.phrases.refused) {
		it(`refuses ${vector.name}`, () => {
			let thrown: unknown;
			try {
				entropyFromPhrase(vector.input);
			} catch (error) {
				thrown = error;
			}
			expect(thrown).toBeInstanceOf(PhraseError);
			expect((thrown as PhraseError).message.startsWith(vector.error_prefix)).toBe(
				true,
			);
		});
	}
	it("refuses a root that is not 32 bytes", () => {
		expect(() => phraseFromEntropy(new Uint8Array(16))).toThrow();
	});
	it("cuts a phrase at the whitespace Python's split does, and nowhere else", () => {
		const accepted = kat.phrases.accepted[0];
		const joined = accepted.input.split(/\s+/u).join("\x1c");
		expect(hex(entropyFromPhrase(joined))).toBe(accepted.entropy);
	});
	it("has a 2048-word list", () => {
		expect(kat.phrases.wordlist.words).toBe(2048);
	});
});
