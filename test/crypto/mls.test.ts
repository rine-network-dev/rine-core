import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { VERSION_MLS } from "../../src/crypto/mls.js";
import {
	generateMlsKeyPackage,
	createMlsGroup,
	addMemberToMlsGroup,
	removeMemberFromMlsGroup,
	processMlsWelcome,
	processMlsCommit,
	encryptMlsAppMessage,
	decryptMlsAppMessage,
} from "../../src/crypto/mls.js";
import {
	uploadKeyPackages,
	claimKeyPackages,
	mlsInit,
	mlsCommit,
	fetchHandshakes,
	fetchWelcomes,
	fetchGroupInfo,
	submitProposal,
} from "../../src/crypto/mls-api.js";
import {
	externalJoinMlsGroup,
} from "../../src/crypto/mls.js";
import {
	saveMlsState,
	loadMlsState,
	deleteMlsState,
	savePrivateKeyPackages,
	loadPrivateKeyPackage,
	deletePrivateKeyPackage,
	listPrivateKeyPackages,
} from "../../src/crypto/mls-state.js";
import {
	decryptGroupMessage,
	encryptMlsGroupMessage,
} from "../../src/crypto/message.js";
import {
	generateAgentKeys,
	generateSigningKeyPair,
	saveAgentKeys,
	signingPublicKeyToJWK,
	toBase64Url,
	fromBase64Url,
} from "../../src/crypto/keys.js";

// ── VERSION_MLS ──────────────────────────────────────────────────────────────

describe("VERSION_MLS", () => {
	it("equals 0x04", () => {
		expect(VERSION_MLS).toBe(0x04);
	});
});

// ── MLS crypto real implementations ─────────────────────────────────────────

describe("MLS crypto — generateMlsKeyPackage", () => {
	it("produces publicBlob, privateBlob, and keyPackageRef", async () => {
		const { privateKey } = generateSigningKeyPair();
		const result = await generateMlsKeyPackage(privateKey);
		expect(result.publicBlob).toBeInstanceOf(Uint8Array);
		expect(result.publicBlob.length).toBeGreaterThan(0);
		expect(result.privateBlob).toBeInstanceOf(Uint8Array);
		expect(result.privateBlob.length).toBeGreaterThan(0);
		expect(result.keyPackageRef).toBeInstanceOf(Uint8Array);
		expect(result.keyPackageRef.length).toBeGreaterThan(0);
	});
});

describe("MLS crypto — createMlsGroup", () => {
	it("creates a group with stateBlob, groupInfo, commitBlob", async () => {
		const { privateKey } = generateSigningKeyPair();
		const result = await createMlsGroup(privateKey);
		expect(result.stateBlob).toBeInstanceOf(Uint8Array);
		expect(result.stateBlob.length).toBeGreaterThan(0);
		expect(result.groupInfo).toBeInstanceOf(Uint8Array);
		expect(result.commitBlob).toBeInstanceOf(Uint8Array);
		// createGroup(0) + self-commit advances the creator to epoch 1.
		expect(result.epoch).toBe(1);
	});
});

describe("MLS crypto — add + welcome round-trip", () => {
	it("adds a member and processes the welcome", async () => {
		const creator = generateSigningKeyPair();
		const joiner = generateSigningKeyPair();

		const group = await createMlsGroup(creator.privateKey);
		const joinerKp = await generateMlsKeyPackage(joiner.privateKey);

		const addResult = await addMemberToMlsGroup(group.stateBlob, joinerKp.publicBlob);
		expect(addResult.welcomeBlob.length).toBeGreaterThan(0);
		expect(addResult.commitBlob.length).toBeGreaterThan(0);
		// A fresh, current-epoch GroupInfo is returned so callers can publish it
		// for the next external joiner.
		expect(addResult.groupInfo.length).toBeGreaterThan(0);
		// The add commit advances the group from epoch 1 to epoch 2.
		expect(addResult.epoch).toBe(2);

		const welcomeResult = await processMlsWelcome(
			addResult.welcomeBlob,
			joinerKp.publicBlob,
			joinerKp.privateBlob,
		);
		expect(welcomeResult.groupId.length).toBeGreaterThan(0);
		expect(welcomeResult.epoch).toBeGreaterThanOrEqual(0);
		expect(welcomeResult.cipherSuite).toBe(1);
		expect(welcomeResult.stateBlob.length).toBeGreaterThan(0);
	});
});

describe("MLS crypto — removeMemberFromMlsGroup", () => {
	it("returns a commit + fresh GroupInfo and advances the epoch by one", async () => {
		const creator = generateSigningKeyPair();
		const joiner = generateSigningKeyPair();

		const group = await createMlsGroup(creator.privateKey); // epoch 1
		const joinerKp = await generateMlsKeyPackage(joiner.privateKey);
		const add = await addMemberToMlsGroup(group.stateBlob, joinerKp.publicBlob); // epoch 2

		// Remove the joiner (leaf index 1) — advances to epoch 3.
		const removed = await removeMemberFromMlsGroup(add.updatedState, 1);
		expect(removed.commitBlob.length).toBeGreaterThan(0);
		expect(removed.groupInfo.length).toBeGreaterThan(0);
		expect(removed.epoch).toBe(3);
	});
});

describe("MLS crypto — encrypt/decrypt round-trip", () => {
	it("encrypts and decrypts an application message", async () => {
		const creator = generateSigningKeyPair();
		const joiner = generateSigningKeyPair();

		const group = await createMlsGroup(creator.privateKey);
		const joinerKp = await generateMlsKeyPackage(joiner.privateKey);
		const addResult = await addMemberToMlsGroup(group.stateBlob, joinerKp.publicBlob);

		// Creator encrypts
		const plaintext = new TextEncoder().encode("hello MLS");
		const enc = await encryptMlsAppMessage(addResult.updatedState, plaintext);
		expect(enc.ciphertext.length).toBeGreaterThan(0);

		// Joiner decrypts
		const welcomeResult = await processMlsWelcome(
			addResult.welcomeBlob,
			joinerKp.publicBlob,
			joinerKp.privateBlob,
		);
		const dec = await decryptMlsAppMessage(welcomeResult.stateBlob, enc.ciphertext);
		expect(new TextDecoder().decode(dec.plaintext)).toBe("hello MLS");
	});
});

describe("MLS crypto — external-commit self-join round-trip", () => {
	it("joiner self-joins via GroupInfo (no Welcome); both can exchange app messages", async () => {
		const creator = generateSigningKeyPair();
		const joiner = generateSigningKeyPair();

		// Creator makes the group; its GroupInfo (with external_pub + ratchet_tree)
		// is the only thing the joiner needs — no member mints a Welcome.
		const group = await createMlsGroup(creator.privateKey);

		const joined = await externalJoinMlsGroup(joiner.privateKey, group.groupInfo);
		expect(joined.commitBlob.length).toBeGreaterThan(0);
		expect(joined.stateBlob.length).toBeGreaterThan(0);
		expect(joined.groupInfo.length).toBeGreaterThan(0); // fresh GroupInfo for the NEXT joiner
		// External join advances the epoch (group was at epoch 1 after init commit).
		expect(joined.epoch).toBeGreaterThan(1);

		// Existing member processes the public external commit -> advances epoch.
		const advanced = await processMlsCommit(group.stateBlob, joined.commitBlob);
		expect(advanced.epoch).toBe(joined.epoch);

		// Joiner sends an app message; the member decrypts it.
		const msg = new TextEncoder().encode("hello from external joiner");
		const enc = await encryptMlsAppMessage(joined.stateBlob, msg);
		const dec = await decryptMlsAppMessage(advanced.updatedState, enc.ciphertext);
		expect(new TextDecoder().decode(dec.plaintext)).toBe("hello from external joiner");
	});

	it("rejects a non-GroupInfo blob", async () => {
		const joiner = generateSigningKeyPair();
		const creator = generateSigningKeyPair();
		const group = await createMlsGroup(creator.privateKey);
		// commitBlob is an mls_public_message, not an mls_group_info.
		await expect(
			externalJoinMlsGroup(joiner.privateKey, group.commitBlob),
		).rejects.toThrow("Failed to decode MLS GroupInfo");
	});
});

// ── MLS API client ───────────────────────────────────────────────────────────

describe("MLS API client", () => {
	function makeMockClient() {
		return {
			get: vi.fn().mockResolvedValue({}),
			post: vi.fn().mockResolvedValue({}),
		};
	}

	it("uploadKeyPackages POSTs to correct path with packages", async () => {
		const client = makeMockClient();
		client.post.mockResolvedValue({ stored: 5 });
		const result = await uploadKeyPackages(
			client as never,
			"agent-123",
			["pkg1", "pkg2"],
		);
		expect(result).toEqual({ stored: 5 });
		expect(client.post).toHaveBeenCalledWith(
			"/agents/agent-123/mls/key-packages",
			{ packages: ["pkg1", "pkg2"] },
		);
	});

	it("claimKeyPackages GETs correct path with count param", async () => {
		const resp = { packages: ["p1"], agent_id: "agent-123" };
		const client = makeMockClient();
		client.get.mockResolvedValue(resp);
		const result = await claimKeyPackages(client as never, "agent-123", 3);
		expect(result).toEqual(resp);
		expect(client.get).toHaveBeenCalledWith(
			"/agents/agent-123/mls/key-packages",
			{ count: "3" },
		);
	});

	it("mlsInit POSTs to correct path", async () => {
		const resp = { mls_pending: true, members: [] };
		const client = makeMockClient();
		client.post.mockResolvedValue(resp);
		const result = await mlsInit(client as never, "group-456");
		expect(result).toEqual(resp);
		expect(client.post).toHaveBeenCalledWith(
			"/groups/group-456/mls/init",
			{},
			undefined,
		);
	});

	it("mlsCommit POSTs to correct path with body", async () => {
		const body = { commit: "base64commit", welcomes: [], group_info: "gi" };
		const resp = { epoch: 1, delivered_to: 2 };
		const client = makeMockClient();
		client.post.mockResolvedValue(resp);
		const result = await mlsCommit(client as never, "group-456", body);
		expect(result).toEqual(resp);
		expect(client.post).toHaveBeenCalledWith(
			"/groups/group-456/mls/commit",
			body,
			undefined,
		);
	});

	it("fetchHandshakes GETs correct path with optional since_epoch", async () => {
		const resp = { handshakes: [] };
		const client = makeMockClient();
		client.get.mockResolvedValue(resp);
		const result = await fetchHandshakes(client as never, "group-456", 5);
		expect(result).toEqual(resp);
		expect(client.get).toHaveBeenCalledWith(
			"/groups/group-456/mls/handshakes",
			{ since_epoch: "5" },
			undefined,
		);
	});

	it("fetchHandshakes GETs with empty params when no since_epoch", async () => {
		const client = makeMockClient();
		client.get.mockResolvedValue({ handshakes: [] });
		await fetchHandshakes(client as never, "group-456");
		expect(client.get).toHaveBeenCalledWith(
			"/groups/group-456/mls/handshakes",
			{},
			undefined,
		);
	});

	it("fetchWelcomes GETs correct path", async () => {
		const resp = { welcomes: [] };
		const client = makeMockClient();
		client.get.mockResolvedValue(resp);
		const result = await fetchWelcomes(client as never, "agent-789");
		expect(result).toEqual(resp);
		expect(client.get).toHaveBeenCalledWith(
			"/agents/agent-789/mls/welcomes",
		);
	});

	it("fetchGroupInfo GETs the group-info path", async () => {
		const resp = { group_info: "base64gi", epoch: 3 };
		const client = makeMockClient();
		client.get.mockResolvedValue(resp);
		const result = await fetchGroupInfo(client as never, "group-456");
		expect(result).toEqual(resp);
		expect(client.get).toHaveBeenCalledWith(
			"/groups/group-456/mls/group-info",
			undefined,
			undefined,
		);
	});

	it("submitProposal POSTs to correct path with proposal", async () => {
		const resp = { id: "prop-1", delivered_to: 3 };
		const client = makeMockClient();
		client.post.mockResolvedValue(resp);
		const result = await submitProposal(
			client as never,
			"group-456",
			"base64proposal",
		);
		expect(result).toEqual(resp);
		expect(client.post).toHaveBeenCalledWith(
			"/groups/group-456/mls/proposals",
			{ proposal: "base64proposal" },
			undefined,
		);
	});
});

// ── MLS state persistence ────────────────────────────────────────────────────

describe("MLS state persistence", () => {
	let tmpDir: string;
	const agentId = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
	const groupId = "d4e5f6a7-b8c9-0123-defa-234567890123";

	beforeEach(() => {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "rine-mls-state-"));
	});

	afterEach(() => {
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	it("saveMlsState + loadMlsState round-trips state and metadata", () => {
		const stateBlob = new Uint8Array([10, 20, 30, 40, 50]);
		const metadata = { groupId, epoch: 3, cipherSuite: 1 };
		saveMlsState(tmpDir, agentId, groupId, stateBlob, metadata);

		const loaded = loadMlsState(tmpDir, agentId, groupId);
		expect(loaded).not.toBeNull();
		expect(Buffer.from(loaded!.stateBlob).equals(Buffer.from(stateBlob))).toBe(true);
		expect(loaded!.metadata.groupId).toBe(groupId);
		expect(loaded!.metadata.epoch).toBe(3);
		expect(loaded!.metadata.cipherSuite).toBe(1);
	});

	it("loadMlsState returns null for non-existent path", () => {
		const result = loadMlsState(tmpDir, agentId, "ffffffff-ffff-ffff-ffff-ffffffffffff");
		expect(result).toBeNull();
	});

	it("deleteMlsState removes state", () => {
		const stateBlob = new Uint8Array([1, 2, 3]);
		const metadata = { groupId, epoch: 0, cipherSuite: 1 };
		saveMlsState(tmpDir, agentId, groupId, stateBlob, metadata);

		expect(loadMlsState(tmpDir, agentId, groupId)).not.toBeNull();
		deleteMlsState(tmpDir, agentId, groupId);
		expect(loadMlsState(tmpDir, agentId, groupId)).toBeNull();
	});

	it("sets restrictive file permissions (0o600) on state.bin", () => {
		const stateBlob = new Uint8Array([99]);
		const metadata = { groupId, epoch: 0, cipherSuite: 1 };
		saveMlsState(tmpDir, agentId, groupId, stateBlob, metadata);

		const statePath = path.join(
			tmpDir, "keys", agentId, "mls", groupId, "state.bin",
		);
		const stat = fs.statSync(statePath);
		expect(stat.mode & 0o777).toBe(0o600);
	});
});

// ── Private Key Package storage ────────────────────────────────────────────

describe("Private Key Package storage", () => {
	let tmpDir: string;
	const agentId = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";

	beforeEach(() => {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "rine-mls-pkp-"));
	});

	afterEach(() => {
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	it("save + load round-trips private key packages", () => {
		const ref = new Uint8Array([0xab, 0xcd, 0xef]);
		const publicBlob = new Uint8Array([1, 2, 3]);
		const privateBlob = new Uint8Array([4, 5, 6]);
		savePrivateKeyPackages(tmpDir, agentId, [{ ref, publicBlob, privateBlob }]);

		const loaded = loadPrivateKeyPackage(tmpDir, agentId, ref);
		expect(loaded).not.toBeNull();
		expect(Buffer.from(loaded!.publicBlob)).toEqual(Buffer.from(publicBlob));
		expect(Buffer.from(loaded!.privateBlob)).toEqual(Buffer.from(privateBlob));
	});

	it("loadPrivateKeyPackage returns null for non-existent ref", () => {
		const result = loadPrivateKeyPackage(tmpDir, agentId, new Uint8Array([0xff]));
		expect(result).toBeNull();
	});

	it("deletePrivateKeyPackage removes a stored package", () => {
		const ref = new Uint8Array([0x01, 0x02]);
		savePrivateKeyPackages(tmpDir, agentId, [
			{ ref, publicBlob: new Uint8Array([1]), privateBlob: new Uint8Array([2]) },
		]);
		expect(loadPrivateKeyPackage(tmpDir, agentId, ref)).not.toBeNull();
		deletePrivateKeyPackage(tmpDir, agentId, ref);
		expect(loadPrivateKeyPackage(tmpDir, agentId, ref)).toBeNull();
	});

	it("listPrivateKeyPackages returns all stored packages", () => {
		const ref1 = new Uint8Array([0xaa]);
		const ref2 = new Uint8Array([0xbb]);
		savePrivateKeyPackages(tmpDir, agentId, [
			{ ref: ref1, publicBlob: new Uint8Array([1]), privateBlob: new Uint8Array([10]) },
			{ ref: ref2, publicBlob: new Uint8Array([2]), privateBlob: new Uint8Array([20]) },
		]);
		const list = listPrivateKeyPackages(tmpDir, agentId);
		expect(list).toHaveLength(2);
		const refs = list.map((p) => p.ref).sort();
		expect(refs).toEqual(["aa", "bb"]);
	});

	it("listPrivateKeyPackages returns empty for non-existent dir", () => {
		const list = listPrivateKeyPackages(tmpDir, agentId);
		expect(list).toEqual([]);
	});
});

// ── decryptGroupMessage MLS dispatch ─────────────────────────────────────────

describe("decryptGroupMessage MLS dispatch", () => {
	let tmpDir: string;
	const agentId = "b2c3d4e5-f6a7-8901-bcde-f12345678901";

	beforeEach(() => {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "rine-mls-dispatch-"));
	});

	afterEach(() => {
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	it("throws when MLS payload has no stored state and recovery fails", async () => {
		const keys = generateAgentKeys();
		saveAgentKeys(tmpDir, agentId, keys);

		const payload = new Uint8Array([0x04, 0xde, 0xad, 0xbe, 0xef, 0x01, 0x02]);
		const encoded = toBase64Url(payload);

		// Mock handles the recovery path: processMlsWelcomes (empty), then
		// externalJoinMlsGroup (no GroupInfo → fails), then syncMlsGroup.
		const mockClient = {
			get: vi.fn().mockResolvedValue({ welcomes: [], handshakes: [] }),
			post: vi.fn(),
		};

		await expect(
			decryptGroupMessage(
				tmpDir,
				agentId,
				"c3d4e5f6-a7b8-9012-cdef-123456789012",
				encoded,
				mockClient as never,
			),
		).rejects.toThrow("Cannot self-join MLS group");
	});
});

// ── encryptMlsGroupMessage → decryptGroupMessage (Phase 5 group send) ─────────

describe("encryptMlsGroupMessage end-to-end", () => {
	let tmpDir: string;
	const creatorId = "11111111-1111-4111-8111-111111111111";
	const joinerId = "22222222-2222-4222-8222-222222222222";
	const groupId = "33333333-3333-4333-8333-333333333333"; // rine group UUID

	beforeEach(() => {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "rine-mls-e2e-"));
	});

	afterEach(() => {
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	it("creator encrypts (mls-v1, 0x04 tag) and joiner decrypts + verifies", async () => {
		const creatorKeys = generateAgentKeys();
		const joinerKeys = generateAgentKeys();
		saveAgentKeys(tmpDir, creatorId, creatorKeys);
		saveAgentKeys(tmpDir, joinerId, joinerKeys);

		// Creator builds the MLS group around its own Ed25519 signing key and
		// adds the joiner; both persist state under the SAME rine group UUID.
		const group = await createMlsGroup(creatorKeys.signing.privateKey);
		const joinerKp = await generateMlsKeyPackage(joinerKeys.signing.privateKey);
		const add = await addMemberToMlsGroup(group.stateBlob, joinerKp.publicBlob);
		saveMlsState(tmpDir, creatorId, groupId, add.updatedState, {
			groupId,
			epoch: 1,
			cipherSuite: 1,
		});
		const welcome = await processMlsWelcome(
			add.welcomeBlob,
			joinerKp.publicBlob,
			joinerKp.privateBlob,
		);
		saveMlsState(tmpDir, joinerId, groupId, welcome.stateBlob, {
			groupId,
			epoch: welcome.epoch,
			cipherSuite: welcome.cipherSuite,
		});

		// Creator encrypts a group message via the high-level Phase 5 helper.
		const enc = await encryptMlsGroupMessage(tmpDir, creatorId, groupId, {
			hello: "world",
		});
		expect(enc.encryption_version).toBe("mls-v1");
		expect(enc.sender_signing_kid).toBe(`rine:${creatorId}`);
		// Wire format: version-byte 0x04 prefix on the MLS ciphertext.
		expect(fromBase64Url(enc.encrypted_payload)[0]).toBe(VERSION_MLS);

		// verifyEnvelopeSender fetches the sender's signing key.
		const client = {
			get: vi.fn().mockResolvedValue({
				signing_public_key: signingPublicKeyToJWK(creatorKeys.signing.publicKey),
			}),
			post: vi.fn(),
		};

		// Joiner decrypts via the version-byte dispatch in decryptGroupMessage.
		const dec = await decryptGroupMessage(
			tmpDir,
			joinerId,
			groupId,
			enc.encrypted_payload,
			client as never,
		);
		expect(JSON.parse(dec.plaintext)).toEqual({ hello: "world" });
		expect(dec.verified).toBe(true);
		expect(dec.verificationStatus).toBe("verified");
	});

	it("throws a clear error when no MLS state exists for the group", async () => {
		const keys = generateAgentKeys();
		saveAgentKeys(tmpDir, creatorId, keys);
		await expect(
			encryptMlsGroupMessage(tmpDir, creatorId, groupId, { x: 1 }),
		).rejects.toThrow("No MLS state for group");
	});
});
