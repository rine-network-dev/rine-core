import { describe, expect, it } from "vitest";
import {
	type AgentCertClaims,
	type BranchCertClaims,
	agentCertClaims,
	assertionClaims,
	branchCertClaims,
	issueAgentCert,
	issueBranchCert,
	registerPopClaims,
	verifyAgentCert,
	verifyBranchCert,
} from "../../src/crypto/certs.js";
import {
	type AgentDerivedKeys,
	type BranchKeys,
	type OrgKeys,
	deriveAgent,
	deriveBranch,
	deriveOrg,
} from "../../src/crypto/derive.js";
import {
	BranchEscrowKeyError,
	type BranchEscrowKeyResponse,
	type OwnIdentity,
	verifyBranchEscrowKey,
} from "../../src/crypto/escrow-key.js";
import { JwsTyp, signJws } from "../../src/crypto/jws.js";
import { toBase64Url } from "../../src/crypto/keys.js";
import { kat, unhex } from "./kat-fixture.js";

const KAT = kat.constants.kat;
const BASE_URL: string = KAT.base_url;
const IAT: number = KAT.iat;

interface Root {
	org: OrgKeys;
	branches: Record<string, BranchKeys>;
	agents: Map<string, AgentDerivedKeys>;
}

function deriveRoot(index: number): Root {
	const fixture = kat.roots.roots[index];
	const org = deriveOrg(unhex(fixture.entropy));
	const branches: Record<string, BranchKeys> = {};
	for (const name of Object.keys(fixture.branches)) {
		branches[name] = deriveBranch(org, name);
	}
	const agents = new Map<string, AgentDerivedKeys>();
	for (const agent of fixture.agents) {
		for (const gen of agent.gens) {
			const derived = deriveAgent(branches[agent.branch]!, agent.id, gen.gen);
			agents.set(`${agent.id}#${gen.gen}`, derived);
		}
	}
	return { org, branches, agents };
}

const roots = kat.roots.roots.map((_: unknown, index: number) =>
	deriveRoot(index),
);

const mainAgentOf = (index: number): AgentDerivedKeys => {
	const fixture = kat.roots.roots[index];
	const agent = fixture.agents.find((a: { branch: string }) => a.branch === "main");
	return roots[index]!.agents.get(`${agent.id}#0`)!;
};

describe("kat.certs.roots: builders reproduce the fixture bytes", () => {
	for (const certRoot of kat.certs.roots) {
		const root = roots[certRoot.index]!;
		describe(`root ${certRoot.index}`, () => {
			for (const [name, entry] of Object.entries<any>(
				certRoot.branch_certs,
			)) {
				it(`branch cert ${name}`, () => {
					const branch = root.branches[name]!;
					const claims = branchCertClaims(root.org.orgId, branch, IAT);
					expect(claims).toEqual(entry.payload);
					expect(issueBranchCert(root.org, branch, IAT)).toBe(entry.jws);
				});
			}

			for (const entry of certRoot.agent_certs) {
				it(`agent cert ${entry.agent_id} gen ${entry.gen}`, () => {
					const branch = root.branches[entry.branch]!;
					const agent = root.agents.get(`${entry.agent_id}#${entry.gen}`)!;
					const claims = agentCertClaims(root.org.orgId, agent, IAT);
					expect(claims).toEqual(entry.payload);
					expect(issueAgentCert(root.org, branch, agent, IAT)).toBe(
						entry.jws,
					);
				});
			}

			it("assertions", () => {
				const main = root.branches.main!;
				const mainGen0 = mainAgentOf(certRoot.index);
				const signers: Record<string, { privateKey: Uint8Array }> = {
					org: root.org.ed25519,
					branch: main.ed25519,
					agent: mainGen0.ed25519,
					reader: root.org.reader,
					"reader-branch": main.reader,
				};
				for (const entry of certRoot.assertions) {
					const claims = assertionClaims(
						BASE_URL,
						entry.payload.iss,
						entry.payload.jti,
						entry.payload.iat,
					);
					expect(claims, entry.principal_kind).toEqual(entry.payload);
					const signer = signers[entry.principal_kind]!;
					expect(
						signJws(JwsTyp.Assertion, claims, signer.privateKey),
						entry.principal_kind,
					).toBe(entry.jws);
				}
			});

			it("assertion aud ignores trailing slashes on the base url", () => {
				const entry = certRoot.assertions[0];
				const { iss, jti, iat } = entry.payload;
				expect(assertionClaims(`${BASE_URL}//`, iss, jti, iat).aud).toBe(
					entry.payload.aud,
				);
			});

			it("register PoP", () => {
				const entry = certRoot.register_pop;
				const claims = registerPopClaims(
					BASE_URL,
					root.org,
					entry.challenge_id,
				);
				expect(claims).toEqual(entry.payload);
				expect(
					signJws(JwsTyp.RegisterPop, claims, root.org.ed25519.privateKey),
				).toBe(entry.jws);
			});
		});
	}
});

describe("kat.certs.roots: verifiers accept every fixture cert", () => {
	for (const certRoot of kat.certs.roots) {
		const root = roots[certRoot.index]!;
		it(`root ${certRoot.index}`, () => {
			for (const [name, entry] of Object.entries<any>(
				certRoot.branch_certs,
			)) {
				const claims: BranchCertClaims = verifyBranchCert(
					entry.jws,
					root.org.ed25519.publicKey,
				);
				expect(claims, name).toEqual(entry.payload);
			}
			for (const entry of certRoot.agent_certs) {
				const branch = root.branches[entry.branch]!;
				const claims: AgentCertClaims = verifyAgentCert(
					entry.jws,
					branch.ed25519.publicKey,
				);
				expect(claims, entry.agent_id).toEqual(entry.payload);
			}
		});
	}
});

describe("kat.certs.negatives", () => {
	const check = (
		list: unknown[],
		verify: (jws: string, pk: Uint8Array) => unknown,
	) => {
		for (const entry of list as Array<{
			name: string;
			jws: string;
			verifier_pk: string;
			request: unknown;
		}>) {
			const pk = unhex(entry.verifier_pk);
			if (entry.name === "field_mismatch") {
				const claims = verify(entry.jws, pk);
				expect(claims, entry.name).not.toEqual(entry.request);
				continue;
			}
			expect(() => verify(entry.jws, pk), entry.name).toThrow();
		}
	};

	it("refuses every branch_cert negative", () => {
		check(kat.certs.negatives.branch_cert, verifyBranchCert);
	});

	it("refuses every agent_cert negative", () => {
		check(kat.certs.negatives.agent_cert, verifyAgentCert);
	});
});

describe("verifyBranchEscrowKey", () => {
	const root0 = roots[0]!;
	const root1 = roots[1]!;
	const main = root0.branches.main!;
	const fleet = root0.branches.fleet!;
	const mainGen0 = mainAgentOf(0);
	const certRoot = kat.certs.roots[0];

	const mainAgentCert = certRoot.agent_certs.find(
		(entry: { branch: string; gen: number }) =>
			entry.branch === "main" && entry.gen === 0,
	).jws;

	const own: OwnIdentity = {
		orgId: root0.org.orgId,
		agentId: mainGen0.id,
		agentSigningPk: mainGen0.ed25519.publicKey,
		agentCertificate: mainAgentCert,
	};

	const base: BranchEscrowKeyResponse = {
		org_id: root0.org.orgId,
		org_signing_public_key: toBase64Url(root0.org.ed25519.publicKey),
		org_pq_signing_public_key: toBase64Url(root0.org.mlDsa65.publicKey),
		branch: "main",
		branch_certificate: certRoot.branch_certs.main.jws,
		escrow_public_key: toBase64Url(main.escrowX25519.publicKey),
		escrow_pq_public_key: toBase64Url(main.escrowMlKem768.publicKey),
	};

	it("accepts the own branch and returns the escrow keys", () => {
		const verified = verifyBranchEscrowKey(base, own);
		expect(verified.orgId).toBe(root0.org.orgId);
		expect(verified.branch).toBe("main");
		expect(verified.x25519).toEqual(main.escrowX25519.publicKey);
		expect(verified.mlKem).toEqual(main.escrowMlKem768.publicKey);
	});

	const refusals: Array<[string, BranchEscrowKeyResponse, OwnIdentity]> = [
		[
			"sibling branch fleet",
			{
				...base,
				branch: "fleet",
				branch_certificate: certRoot.branch_certs.fleet.jws,
				escrow_public_key: toBase64Url(fleet.escrowX25519.publicKey),
				escrow_pq_public_key: toBase64Url(fleet.escrowMlKem768.publicKey),
			},
			own,
		],
		[
			"foreign org",
			{
				...base,
				org_id: root1.org.orgId,
				org_signing_public_key: toBase64Url(root1.org.ed25519.publicKey),
				org_pq_signing_public_key: toBase64Url(root1.org.mlDsa65.publicKey),
				branch_certificate: kat.certs.roots[1].branch_certs.main.jws,
			},
			own,
		],
		[
			"substituted escrow x25519",
			{ ...base, escrow_public_key: toBase64Url(fleet.escrowX25519.publicKey) },
			own,
		],
		[
			"substituted escrow ml-kem",
			{
				...base,
				escrow_pq_public_key: toBase64Url(fleet.escrowMlKem768.publicKey),
			},
			own,
		],
		[
			"branch cert org differs",
			{
				...base,
				branch_certificate: signJws(
					JwsTyp.BranchCert,
					branchCertClaims(root1.org.orgId, main, IAT),
					root0.org.ed25519.privateKey,
				),
			},
			own,
		],
		[
			"agent cert of another agent",
			base,
			{
				...own,
				agentCertificate: certRoot.agent_certs.find(
					(entry: { branch: string; gen: number }) =>
						entry.branch === "main" && entry.gen === 1,
				).jws,
			},
		],
		[
			"cert names another agent id",
			base,
			{ ...own, agentId: "00000000-0000-0000-0000-000000000000" },
		],
		[
			"org signing key swapped",
			{
				...base,
				org_signing_public_key: toBase64Url(root1.org.ed25519.publicKey),
			},
			own,
		],
	];

	for (const [name, resp, identity] of refusals) {
		it(`refuses ${name}`, () => {
			let thrown: unknown;
			try {
				verifyBranchEscrowKey(resp, identity);
			} catch (error) {
				thrown = error;
			}
			expect(thrown).toBeInstanceOf(BranchEscrowKeyError);
			expect((thrown as Error).message).toBe("branch escrow key invalid");
		});
	}
});
