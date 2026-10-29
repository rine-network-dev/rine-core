import { describe, expect, it } from "vitest";
import { agentCreateRequest, agentRotateRequest } from "../src/agent-body.js";
import {
	agentKeysFromDerived,
	deriveAgent,
	deriveBranch,
	deriveOrg,
	verifyAgentCert,
} from "../src/crypto/index.js";
import type { Custody } from "../src/custody.js";

const ROOT = new Uint8Array(32).fill(4);
const AGENT_ID = "11111111-1111-4111-8111-111111111111";
const BRANCH = "main";

const org = deriveOrg(ROOT);
const branch = deriveBranch(org, BRANCH);
const custody: Custody = { orgId: org.orgId, branch };

const KEY_MATERIAL_FIELDS = [
	"branch",
	"signing_public_key",
	"encryption_public_key",
	"pq_encryption_public_key",
	"pq_signing_public_key",
	"mls_signing_public_key",
	"agent_certificate",
];

describe("agentCreateRequest", () => {
	it("test_agentCreateRequest_when_called_then_generation_0_keys_match_deriveAgent", () => {
		const { keys } = agentCreateRequest(custody, AGENT_ID, { name: "Test Agent" });
		expect(keys).toEqual(agentKeysFromDerived(deriveAgent(branch, AGENT_ID, 0)));
	});

	it("test_agentCreateRequest_when_called_then_the_certificate_verifies_and_claims_match", () => {
		const { body } = agentCreateRequest(custody, AGENT_ID, { name: "Test Agent" });
		const claims = verifyAgentCert(body.agent_certificate, branch.ed25519.publicKey);
		expect(claims.agent).toBe(AGENT_ID);
		expect(claims.gen).toBe(0);
		expect(claims.branch).toBe(BRANCH);
		expect(claims.org).toBe(org.orgId);
	});

	it("test_agentCreateRequest_when_flags_are_set_then_they_are_included", () => {
		const { body } = agentCreateRequest(custody, AGENT_ID, {
			name: "Test Agent",
			humanOversight: true,
			unlisted: false,
		});
		expect(body.human_oversight).toBe(true);
		expect(body.unlisted).toBe(false);
	});

	it("test_agentCreateRequest_when_flags_are_absent_then_they_are_omitted", () => {
		const { body } = agentCreateRequest(custody, AGENT_ID, { name: "Test Agent" });
		expect(body).not.toHaveProperty("human_oversight");
		expect(body).not.toHaveProperty("unlisted");
	});
});

describe("agentRotateRequest", () => {
	it("test_agentRotateRequest_when_called_then_key_gen_is_set_and_id_name_flags_are_absent", () => {
		const { body } = agentRotateRequest(custody, AGENT_ID, 1);
		expect(body.key_gen).toBe(1);
		for (const field of ["id", "name", "human_oversight", "unlisted"]) {
			expect(body).not.toHaveProperty(field);
		}
	});

	it("test_agentRotateRequest_when_compared_to_create_then_key_material_shapes_are_identical", () => {
		const create = agentCreateRequest(custody, AGENT_ID, { name: "Test Agent" });
		const rotate = agentRotateRequest(custody, AGENT_ID, 1);

		const createKeys = Object.keys(create.body).filter(
			(key) => !["id", "name"].includes(key),
		);
		const rotateKeys = Object.keys(rotate.body).filter((key) => key !== "key_gen");
		expect(new Set(rotateKeys)).toEqual(new Set(createKeys));
		expect(rotateKeys.sort()).toEqual([...KEY_MATERIAL_FIELDS].sort());
	});

	it("test_agentRotateRequest_when_called_then_the_rotated_keys_differ_from_generation_0", () => {
		const create = agentCreateRequest(custody, AGENT_ID, { name: "Test Agent" });
		const rotate = agentRotateRequest(custody, AGENT_ID, 1);
		expect(rotate.keys.signing.publicKey).not.toEqual(create.keys.signing.publicKey);
		expect(rotate.keys.encryption.publicKey).not.toEqual(
			create.keys.encryption.publicKey,
		);
		expect(rotate.keys.pqEncryption.publicKey).not.toEqual(
			create.keys.pqEncryption.publicKey,
		);
		expect(rotate.keys.mls.publicKey).not.toEqual(create.keys.mls.publicKey);
	});
});
