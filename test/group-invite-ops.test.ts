import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { generateAgentKeys, pqPublicKeyToJWK, saveAgentKeys, toBase64Url } from "../src/crypto/keys.js";
import {
	GROUP_INVITE_TYPE,
	listMyInvites,
	sendGroupInviteNotification,
} from "../src/group-invite-ops.js";

function makeTmpDir(): string {
	return fs.mkdtempSync(join(tmpdir(), "rine-invite-test-"));
}

const INVITER_ID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
const INVITEE_ID = "b2c3d4e5-f6a7-8901-bcde-f12345678901";
const GROUP_ID = "d4e5f6a7-b8c9-0123-defa-234567890123";

function setupAgent(dir: string, agentId: string) {
	saveAgentKeys(dir, agentId, generateAgentKeys());
}

/** A /agents/{id}/keys response for one recipient (classical, no PQ key). */
function makeKeysResponse(agentId: string, withPq = false) {
	const k = generateAgentKeys();
	const resp: {
		agent_id: string;
		signing_public_key: object;
		encryption_public_key: object;
		pq_encryption_public_key?: object;
	} = {
		agent_id: agentId,
		signing_public_key: { kty: "OKP", crv: "Ed25519", x: toBase64Url(k.signing.publicKey) },
		encryption_public_key: { kty: "OKP", crv: "X25519", x: toBase64Url(k.encryption.publicKey) },
	};
	if (withPq) {
		if (!k.pqEncryption) throw new Error("expected generated PQ key");
		resp.pq_encryption_public_key = pqPublicKeyToJWK(k.pqEncryption.publicKey);
	}
	return resp;
}

describe("GROUP_INVITE_TYPE", () => {
	it("is the namespaced underscore message type", () => {
		expect(GROUP_INVITE_TYPE).toBe("rine.v1.group_invite");
	});
});

describe("sendGroupInviteNotification", () => {
	let dir: string;

	beforeEach(() => {
		dir = makeTmpDir();
		setupAgent(dir, INVITER_ID);
	});
	afterEach(() => fs.rmSync(dir, { recursive: true }));

	it("seals the invite and posts /messages with the right type and recipient", async () => {
		const client = {
			get: vi.fn().mockResolvedValue(makeKeysResponse(INVITEE_ID)),
			post: vi.fn().mockResolvedValue({ id: "msg-1" }),
		};

		await sendGroupInviteNotification(client as never, dir, INVITER_ID, INVITEE_ID, {
			group_id: GROUP_ID,
			group_handle: "team@org.rine.network",
			message: "join us",
		});

		// Recipient keys fetched from the public key endpoint.
		expect(client.get).toHaveBeenCalledWith(`/agents/${INVITEE_ID}/keys`);

		expect(client.post).toHaveBeenCalledTimes(1);
		const [path, body, headers] = client.post.mock.calls[0]!;
		expect(path).toBe("/messages");
		expect(body.type).toBe(GROUP_INVITE_TYPE);
		expect(body.to_agent_id).toBe(INVITEE_ID);
		// Sealed fields are spread in from encryptMessage.
		expect(typeof body.encrypted_payload).toBe("string");
		expect(body.encrypted_payload.length).toBeGreaterThan(0);
		expect(body.encryption_version).toBe("hpke-v1");
		expect(body.sender_signing_kid).toBe(`rine:${INVITER_ID}`);
		// Inviter identity carried in the send header.
		expect(headers).toEqual({ "X-Rine-Agent": INVITER_ID });
	});

	it("seals the sealed payload with invited_by set to the inviter", async () => {
		const client = {
			get: vi.fn().mockResolvedValue(makeKeysResponse(INVITEE_ID)),
			post: vi.fn().mockResolvedValue({ id: "msg-1" }),
		};

		const cryptoMod = await import("../src/crypto/message.js");
		const spy = vi.spyOn(cryptoMod, "encryptMessage");

		await sendGroupInviteNotification(client as never, dir, INVITER_ID, INVITEE_ID, {
			group_id: GROUP_ID,
			group_handle: "team@org.rine.network",
			message: null,
		});

		expect(spy).toHaveBeenCalledTimes(1);
		const sealedPayload = spy.mock.calls[0]![3] as Record<string, unknown>;
		expect(sealedPayload).toEqual({
			group_id: GROUP_ID,
			group_handle: "team@org.rine.network",
			invited_by: INVITER_ID,
			message: null,
		});
		spy.mockRestore();
	});

	it("seals as hpke-hybrid-v1 when the invitee advertises a PQ key", async () => {
		const client = {
			get: vi.fn().mockResolvedValue(makeKeysResponse(INVITEE_ID, true)),
			post: vi.fn().mockResolvedValue({ id: "msg-1" }),
		};

		await sendGroupInviteNotification(client as never, dir, INVITER_ID, INVITEE_ID, {
			group_id: GROUP_ID,
			group_handle: "team@org.rine.network",
			message: "hi",
		});

		const body = client.post.mock.calls[0]![1];
		expect(body.encryption_version).toBe("hpke-hybrid-v1");
	});
});

describe("listMyInvites", () => {
	it("GETs /groups/invites and returns the items", async () => {
		const items = [
			{ id: "r1", group_id: GROUP_ID, agent_id: INVITEE_ID, status: "invited", invited_by: INVITER_ID, created_at: "2026-06-13T00:00:00Z", group_handle: "team@org.rine.network" },
		];
		const client = {
			get: vi.fn().mockResolvedValue({ items, total: 1 }),
		};

		const result = await listMyInvites(client as never);

		expect(client.get).toHaveBeenCalledWith("/groups/invites", undefined, undefined);
		expect(result).toEqual(items);
	});

	it("passes extraHeaders (X-Rine-Agent) through to the GET", async () => {
		const client = {
			get: vi.fn().mockResolvedValue({ items: [], total: 0 }),
		};

		const result = await listMyInvites(client as never, { "X-Rine-Agent": INVITEE_ID });

		expect(client.get).toHaveBeenCalledWith("/groups/invites", undefined, {
			"X-Rine-Agent": INVITEE_ID,
		});
		expect(result).toEqual([]);
	});
});
