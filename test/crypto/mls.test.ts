import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fromBase64Url } from "../../src/crypto/keys.js";
import { decryptGroupMessage } from "../../src/message-group.js";
import { encryptMlsGroupMessage } from "../../src/message-mls.js";
import {
	isMlsError,
	isUnprocessableCommit,
	mlsErrorCode,
} from "../../src/crypto/mls-errors.js";
import { deleteMlsState, loadMlsState } from "../../src/crypto/mls-state.js";
import {
	MLS_CIPHER_SUITE_XWING,
	VERSION_MLS,
	isNoMlsStateError,
	isRecoverableMlsRead,
	loadMlsGroup,
	mlsGroupIdBytes,
	mlsStoreRoot,
	openMlsClient,
	openMlsGroup,
} from "../../src/crypto/mls.js";
import { KEY_PACKAGE_MAX_BATCH } from "@rine-network/mls";
import { World, type WorldAgent } from "./world.js";

const CREATOR_ID = "11111111-1111-4111-8111-111111111111";
const JOINER_ID = "22222222-2222-4222-8222-222222222222";
const GROUP_ID = "33333333-3333-4333-8333-333333333333";

let tmpDir: string;
let world: World;

beforeEach(() => {
	tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "rine-mls-"));
	world = new World();
	delete process.env["RINE_MLS_EPOCH_RETENTION"];
});

afterEach(() => {
	fs.rmSync(tmpDir, { recursive: true, force: true });
	delete process.env["RINE_MLS_EPOCH_RETENTION"];
});

function agent(agentId: string): WorldAgent {
	const seated = world.addAgent({ id: agentId });
	world.save(tmpDir, seated);
	return seated;
}

/**
 * A client that answers the signing-key lookup `verifyEnvelopeSender` makes, and
 * the sync/welcome reads the MLS recovery path makes with an empty bundle — so a
 * decrypt that cannot be recovered surfaces its own MLS error rather than a
 * stub-shaped one.
 */
function keyServer() {
	const base = world.client();
	return {
		get: vi.fn(
			async (
				path: string,
				params?: Record<string, string | number | boolean>,
			) =>
				path.includes("/keys")
					? base.get(path, params)
					: { welcomes: [], handshakes: [] },
		),
		post: vi.fn(),
	};
}

// ── wire constants ───────────────────────────────────────────────────────────

describe("MLS wire constants", () => {
	it("tags an mls-v1 payload with 0x04", () => {
		expect(VERSION_MLS).toBe(0x04);
	});

	it("is the post-quantum X-Wing suite", () => {
		expect(MLS_CIPHER_SUITE_XWING).toBe(0xf057);
	});
});

// ── store layout ─────────────────────────────────────────────────────────────

describe("mlsStoreRoot", () => {
	it("keeps the native store out of the ts-mls-era directory", () => {
		const root = mlsStoreRoot("/cfg", CREATOR_ID);
		expect(root).toBe(path.join("/cfg", "keys", CREATOR_ID, "mls2"));
	});

	it("rejects an agent id that is not a UUID", () => {
		expect(() => mlsStoreRoot("/cfg", "../escape")).toThrow("must be a UUID");
	});
});

describe("mlsGroupIdBytes", () => {
	it("is the rine group UUID's raw 16 bytes", () => {
		const bytes = mlsGroupIdBytes(GROUP_ID);
		expect(bytes).toHaveLength(16);
		expect(Buffer.from(bytes).toString("hex")).toBe(GROUP_ID.replace(/-/g, ""));
	});

	it("rejects a group id that is not a UUID", () => {
		expect(() => mlsGroupIdBytes("not-a-uuid")).toThrow("must be a UUID");
	});
});

// ── client and epoch retention ───────────────────────────────────────────────

describe("openMlsClient", () => {
	it("mints with the post-quantum default suite", () => {
		agent(CREATOR_ID);
		expect(openMlsClient(tmpDir, CREATOR_ID).cipherSuite()).toBe(
			MLS_CIPHER_SUITE_XWING,
		);
	});

	it("opens under the agent's derived mls key and its id as the credential", () => {
		const seated = agent(CREATOR_ID);
		const client = openMlsClient(tmpDir, CREATOR_ID);
		expect(Buffer.from(client.leafPublicKey())).toEqual(
			Buffer.from(seated.derived.mlsEd25519.publicKey),
		);
		expect(Buffer.from(client.agentId()).toString("ascii")).toBe(CREATOR_ID);
	});

	it("keeps the full epoch backlog when the retention knob is unset", () => {
		agent(CREATOR_ID);
		expect(() => openMlsClient(tmpDir, CREATOR_ID)).not.toThrow();
	});

	it("accepts a positive epoch retention limit", () => {
		agent(CREATOR_ID);
		process.env["RINE_MLS_EPOCH_RETENTION"] = "2";
		expect(() => openMlsClient(tmpDir, CREATOR_ID)).not.toThrow();
	});

	it("refuses a retention limit that would break the group", () => {
		agent(CREATOR_ID);
		process.env["RINE_MLS_EPOCH_RETENTION"] = "0";
		expect(() => openMlsClient(tmpDir, CREATOR_ID)).toThrow(
			"positive integer of epochs",
		);
	});

	it("refuses a retention limit that is not a number", () => {
		agent(CREATOR_ID);
		process.env["RINE_MLS_EPOCH_RETENTION"] = "lots";
		expect(() => openMlsClient(tmpDir, CREATOR_ID)).toThrow(
			"positive integer of epochs",
		);
	});
});

// ── key package pool ─────────────────────────────────────────────────────────

describe("key package pool", () => {
	it("mints the batch it was asked for and holds every private half", () => {
		agent(CREATOR_ID);
		const client = openMlsClient(tmpDir, CREATOR_ID);
		expect(client.keyPackageCount()).toBe(0);
		expect(client.generateKeyPackages(4)).toHaveLength(4);
		expect(client.keyPackageCount()).toBe(4);
	});

	it("refuses a batch over the cap outright rather than truncating it", () => {
		agent(CREATOR_ID);
		const client = openMlsClient(tmpDir, CREATOR_ID);
		let raised: unknown;
		try {
			client.generateKeyPackages(KEY_PACKAGE_MAX_BATCH + 1);
		} catch (err) {
			raised = err;
		}
		expect(mlsErrorCode(raised)).toBe("RINE_MLS_KEY_PACKAGE_BATCH_TOO_LARGE");
		expect(client.keyPackageCount()).toBe(0);
	});
});

// ── error vocabulary ─────────────────────────────────────────────────────────

describe("MLS error classification", () => {
	const nativeErr = (code: string) =>
		Object.assign(new Error("boom"), { code });

	it("recognises a native failure by its code, not its message", () => {
		expect(mlsErrorCode(nativeErr("RINE_MLS_PROTOCOL"))).toBe(
			"RINE_MLS_PROTOCOL",
		);
		expect(isMlsError(nativeErr("RINE_MLS_PROTOCOL"))).toBe(true);
		expect(isMlsError(new Error("RINE_MLS_PROTOCOL"))).toBe(false);
		expect(mlsErrorCode(undefined)).toBeNull();
	});

	it("NACKs an unusable commit but never our own store failure", () => {
		expect(isUnprocessableCommit(nativeErr("RINE_MLS_PROTOCOL"))).toBe(true);
		expect(isUnprocessableCommit(nativeErr("RINE_MLS_EPOCH_CONFLICT"))).toBe(
			true,
		);
		expect(isUnprocessableCommit(nativeErr("RINE_MLS_STORE"))).toBe(false);
		expect(isUnprocessableCommit(nativeErr("RINE_MLS_PANIC"))).toBe(false);
		expect(isUnprocessableCommit(nativeErr("RINE_MLS_POISONED"))).toBe(false);
		expect(isUnprocessableCommit(new Error("transport"))).toBe(false);
	});

	it("treats a missing-state failure as recoverable and an aged-out self-read as not", () => {
		expect(isNoMlsStateError(new Error("No MLS state for group x"))).toBe(true);
		expect(isRecoverableMlsRead(new Error("No MLS state for group x"))).toBe(
			true,
		);
		expect(isRecoverableMlsRead(nativeErr("RINE_MLS_PROTOCOL"))).toBe(true);
		expect(
			isRecoverableMlsRead(nativeErr("RINE_MLS_SELF_MESSAGE_NOT_CACHED")),
		).toBe(false);
		expect(isRecoverableMlsRead(nativeErr("RINE_MLS_STORE"))).toBe(false);
		expect(isRecoverableMlsRead(new Error("transport"))).toBe(false);
	});
});

// ── local state lifecycle ────────────────────────────────────────────────────

describe("MLS local state", () => {
	it("reports no state before a group is founded", () => {
		agent(CREATOR_ID);
		expect(loadMlsState(tmpDir, CREATOR_ID, GROUP_ID)).toBeNull();
		expect(
			loadMlsGroup(openMlsClient(tmpDir, CREATOR_ID), GROUP_ID),
		).toBeNull();
	});

	it("reports the group's epoch and membership once founded", () => {
		agent(CREATOR_ID);
		const client = openMlsClient(tmpDir, CREATOR_ID);
		client.createGroup(mlsGroupIdBytes(GROUP_ID)).save();

		expect(loadMlsState(tmpDir, CREATOR_ID, GROUP_ID)).toEqual({
			groupId: GROUP_ID,
			epoch: 1,
		});
	});

	it("retires a group's state, and retiring one that was never there is not an error", () => {
		agent(CREATOR_ID);
		openMlsClient(tmpDir, CREATOR_ID)
			.createGroup(mlsGroupIdBytes(GROUP_ID))
			.save();
		expect(loadMlsState(tmpDir, CREATOR_ID, GROUP_ID)).not.toBeNull();

		deleteMlsState(tmpDir, CREATOR_ID, GROUP_ID);
		expect(loadMlsState(tmpDir, CREATOR_ID, GROUP_ID)).toBeNull();
		expect(() => deleteMlsState(tmpDir, CREATOR_ID, GROUP_ID)).not.toThrow();
	});

	it("fails a required group with the message every surface's recovery path matches", () => {
		agent(CREATOR_ID);
		expect(() => openMlsGroup(tmpDir, CREATOR_ID, GROUP_ID)).toThrow(
			`No MLS state for group ${GROUP_ID}`,
		);
	});
});

// ── group message round trip ─────────────────────────────────────────────────

describe("MLS group messages", () => {
	function foundGroupWithJoiner() {
		agent(CREATOR_ID);
		agent(JOINER_ID);

		const joinerClient = openMlsClient(tmpDir, JOINER_ID);
		const keyPackage = joinerClient.generateKeyPackage();

		const creatorClient = openMlsClient(tmpDir, CREATOR_ID);
		const group = creatorClient.createGroupWithMembers(
			mlsGroupIdBytes(GROUP_ID),
			[keyPackage],
		);
		const bundle = group.lastCommit();
		if (!bundle) throw new Error("founding commit missing");
		group.save();

		joinerClient.joinFromWelcome(bundle.welcomes[0]!).save();
	}

	it("round-trips a signed envelope from the founder to a welcomed member", async () => {
		foundGroupWithJoiner();

		const enc = await encryptMlsGroupMessage(tmpDir, CREATOR_ID, GROUP_ID, {
			hello: "world",
		});
		expect(enc.encryption_version).toBe("mls-v1");
		expect(enc.sender_signing_kid).toBe(`rine:${CREATOR_ID}#0`);
		expect(fromBase64Url(enc.encrypted_payload)[0]).toBe(VERSION_MLS);

		const dec = await decryptGroupMessage(
			tmpDir,
			JOINER_ID,
			GROUP_ID,
			enc.encrypted_payload,
			keyServer() as never,
			CREATOR_ID,
		);
		expect(JSON.parse(dec.plaintext)).toEqual({ hello: "world" });
		expect(dec.verified).toBe(true);
		expect(dec.verificationStatus).toBe("verified");
	});

	it("lets the sender read its own message back, which MLS forward secrecy alone would not", async () => {
		foundGroupWithJoiner();

		const enc = await encryptMlsGroupMessage(tmpDir, CREATOR_ID, GROUP_ID, {
			mine: true,
		});
		const dec = await decryptGroupMessage(
			tmpDir,
			CREATOR_ID,
			GROUP_ID,
			enc.encrypted_payload,
			keyServer() as never,
			CREATOR_ID,
		);
		expect(JSON.parse(dec.plaintext)).toEqual({ mine: true });
		expect(dec.senderKid).toBe(`rine:${CREATOR_ID}#0`);
	});

	it("refuses a message whose envelope names an agent other than the row's sender", async () => {
		foundGroupWithJoiner();

		const enc = await encryptMlsGroupMessage(tmpDir, CREATOR_ID, GROUP_ID, {
			hello: "world",
		});

		// The envelope is genuinely the creator's, but the server authenticated the
		// joiner as the sender of this row.
		await expect(
			decryptGroupMessage(
				tmpDir,
				JOINER_ID,
				GROUP_ID,
				enc.encrypted_payload,
				keyServer() as never,
				JOINER_ID,
			),
		).rejects.toThrow("Envelope sender does not match the message sender");

		// The refusal lands after the ratchet is saved, so the message has already
		// spent its key: replaying it — even attributed correctly this time — finds
		// that generation gone. A refused message costs its sender exactly what an
		// accepted one does, so retrying it tells an attacker nothing.
		await expect(
			decryptGroupMessage(
				tmpDir,
				JOINER_ID,
				GROUP_ID,
				enc.encrypted_payload,
				keyServer() as never,
				CREATOR_ID,
			),
		).rejects.toThrow(/key not available/);
	});

	it("accepts the same message when the row's sender is the envelope's signer", async () => {
		foundGroupWithJoiner();

		const enc = await encryptMlsGroupMessage(tmpDir, CREATOR_ID, GROUP_ID, {
			hello: "world",
		});

		const dec = await decryptGroupMessage(
			tmpDir,
			JOINER_ID,
			GROUP_ID,
			enc.encrypted_payload,
			keyServer() as never,
			CREATOR_ID.toUpperCase(),
		);

		expect(JSON.parse(dec.plaintext)).toEqual({ hello: "world" });
		expect(dec.verified).toBe(true);
	});

	it("refuses to encrypt for a group this agent has no state for", async () => {
		agent(CREATOR_ID);
		await expect(
			encryptMlsGroupMessage(tmpDir, CREATOR_ID, GROUP_ID, { x: 1 }),
		).rejects.toThrow("No MLS state for group");
	});

	it("attempts recovery, then surfaces the failure, for an MLS payload it cannot place", async () => {
		agent(CREATOR_ID);
		const payload = Buffer.from(
			new Uint8Array([VERSION_MLS, 0xde, 0xad, 0xbe, 0xef]),
		).toString("base64url");

		// Recovery: no welcomes, no published GroupInfo to self-join against.
		const client = {
			get: vi.fn().mockResolvedValue({ welcomes: [], handshakes: [] }),
			post: vi.fn(),
		};

		await expect(
			decryptGroupMessage(
				tmpDir,
				CREATOR_ID,
				GROUP_ID,
				payload,
				client as never,
				CREATOR_ID,
			),
		).rejects.toThrow("Cannot self-join MLS group");
	});
});
