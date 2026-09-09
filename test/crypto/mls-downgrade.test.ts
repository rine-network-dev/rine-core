/**
 * The downgrade guard.
 *
 * The four-cell truth table is local MLS state × what the server claims. Only
 * one cell refuses; the other three are ordinary, and one of them (no local
 * state, server says not-MLS) is the open billboard group, which is sender-key
 * for good, so the converse test matters as much as the refusal.
 */
import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

/**
 * The one seam this is about: opening the native store. It is counted, not
 * faked — the spy delegates to the real `openMlsClient`, so every other test in
 * this file still drives the genuine core, and "the guard does not open the
 * store per row" can be asserted as the number it actually is.
 */
const { openMlsClientSpy } = vi.hoisted(() => ({ openMlsClientSpy: vi.fn() }));

vi.mock("../../src/crypto/mls.js", async (importOriginal) => {
	const actual =
		await importOriginal<typeof import("../../src/crypto/mls.js")>();
	openMlsClientSpy.mockImplementation(actual.openMlsClient);
	return { ...actual, openMlsClient: openMlsClientSpy };
});

import {
	DOWNGRADE_REFUSED_CODE,
	MlsDowngradeError,
	isMlsDowngradeError,
} from "../../src/crypto/downgrade-error.js";
import type { AgentKeys } from "../../src/crypto/keys.js";
import {
	generateAgentKeys,
	saveAgentKeys,
	signingPublicKeyToJWK,
} from "../../src/crypto/keys.js";
import {
	decryptGroupMessage,
	encryptGroupMessage,
} from "../../src/crypto/message.js";
import { assertNoMlsDowngrade } from "../../src/crypto/mls-downgrade.js";
import { noteMlsStateChanged } from "../../src/crypto/mls-state.js";
import {
	isUnprocessableCommit,
	mlsErrorCode,
} from "../../src/crypto/mls-errors.js";
import {
	isRecoverableMlsRead,
	mlsGroupIdBytes,
	openMlsClient,
} from "../../src/crypto/mls.js";
import {
	loadSenderKeyStates,
	saveSenderKeyState,
} from "../../src/crypto/sender-keys-helpers.js";
import { generateSenderKey } from "../../src/crypto/sender-keys.js";

const SENDER_ID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
const READER_ID = "b2c3d4e5-f6a7-8901-bcde-f12345678901";
const GROUP_ID = "c3d4e5f6-a7b8-9012-cdef-123456789012";

let dir: string;

// Each test gets its own config dir, and the memo is keyed by config dir, so no
// test can inherit another's remembered answer.
beforeEach(() => {
	dir = fs.mkdtempSync(join(tmpdir(), "rine-downgrade-"));
});

afterEach(() => {
	fs.rmSync(dir, { recursive: true, force: true });
});

function setupAgent(agentId: string): AgentKeys {
	const keys = generateAgentKeys();
	saveAgentKeys(dir, agentId, keys);
	return keys;
}

/**
 * Give this agent real local MLS state for a group, as a Welcome would —
 * including the invalidation the production establisher does at its own
 * mutation site.
 */
function plantMlsState(agentId: string, groupId: string = GROUP_ID): void {
	openMlsClient(dir, agentId).createGroup(mlsGroupIdBytes(groupId)).save();
	noteMlsStateChanged(dir, agentId, groupId);
}

function keyServer(keys: AgentKeys) {
	return {
		get: vi.fn(async (path: string) =>
			path.includes("/keys")
				? { signing_public_key: signingPublicKeyToJWK(keys.signing.publicKey) }
				: { welcomes: [], handshakes: [] },
		),
		post: vi.fn(),
	} as never;
}

/** One sender-key row, plus the reader's copy of the key state to open it. */
async function senderKeyRow(senderKeys: AgentKeys, payload: object) {
	const state = generateSenderKey(GROUP_ID, SENDER_ID);
	// The sender's own copy, which `encryptGroupMessage` advances in place. A
	// stand-in sender needs it as much as a real one does: the tail refuses a
	// state that is on no disk at all rather than discarding the advance.
	saveSenderKeyState(dir, SENDER_ID, GROUP_ID, [state]);
	const { result } = await encryptGroupMessage(
		dir,
		SENDER_ID,
		GROUP_ID,
		state,
		payload,
	);
	saveSenderKeyState(dir, READER_ID, GROUP_ID, [state]);
	return { payload: result.encrypted_payload, client: keyServer(senderKeys) };
}

function senderKeyStateOnDisk(): string {
	return fs.readFileSync(
		join(dir, "keys", READER_ID, "sender_keys", `${GROUP_ID}.json`),
		"utf-8",
	);
}

// ── the four-cell truth table ────────────────────────────────────────────────

describe("assertNoMlsDowngrade", () => {
	beforeEach(() => setupAgent(READER_ID));

	it("test_assert_no_mls_downgrade_when_no_state_and_server_says_sender_key_passes", () => {
		expect(() =>
			assertNoMlsDowngrade(dir, READER_ID, GROUP_ID, false),
		).not.toThrow();
	});

	it("test_assert_no_mls_downgrade_when_no_state_and_server_says_mls_passes", () => {
		expect(() =>
			assertNoMlsDowngrade(dir, READER_ID, GROUP_ID, true),
		).not.toThrow();
	});

	it("test_assert_no_mls_downgrade_when_state_and_server_says_mls_passes", () => {
		plantMlsState(READER_ID);
		expect(() =>
			assertNoMlsDowngrade(dir, READER_ID, GROUP_ID, true),
		).not.toThrow();
	});

	it("test_assert_no_mls_downgrade_when_state_and_server_says_sender_key_refuses", () => {
		plantMlsState(READER_ID);
		let raised: unknown;
		try {
			assertNoMlsDowngrade(dir, READER_ID, GROUP_ID, false);
		} catch (err) {
			raised = err;
		}
		expect(raised).toBeInstanceOf(MlsDowngradeError);
		expect((raised as MlsDowngradeError).code).toBe(DOWNGRADE_REFUSED_CODE);
		expect((raised as MlsDowngradeError).groupId).toBe(GROUP_ID);
	});

	it("test_assert_no_mls_downgrade_when_state_is_another_groups_passes", () => {
		plantMlsState(READER_ID);
		const other = "d4e5f6a7-b8c9-4012-8def-1234567890ab";
		expect(() =>
			assertNoMlsDowngrade(dir, READER_ID, other, false),
		).not.toThrow();
	});

	it("test_assert_no_mls_downgrade_when_asked_repeatedly_opens_the_store_once", () => {
		// The memo is what keeps a group read off the MLS store per row:
		// the guard runs once per row, so the store open has to be amortised over
		// the whole page. What keeps the memo honest is invalidation at the
		// mutation plus the on-disk stamp, both covered in
		// `mls-state-invalidation.test.ts`.
		plantMlsState(READER_ID);
		openMlsClientSpy.mockClear();

		for (let row = 0; row < 20; row++) {
			expect(() =>
				assertNoMlsDowngrade(dir, READER_ID, GROUP_ID, false),
			).toThrow(MlsDowngradeError);
		}

		expect(openMlsClientSpy).toHaveBeenCalledTimes(1);
	});

	it("test_assert_no_mls_downgrade_when_a_billboard_row_repeats_opens_the_store_once", () => {
		// The hot path: an open-enrolment group holds no state, and every row asks.
		openMlsClientSpy.mockClear();

		for (let row = 0; row < 20; row++) {
			expect(() =>
				assertNoMlsDowngrade(dir, READER_ID, GROUP_ID, false),
			).not.toThrow();
		}

		expect(openMlsClientSpy).toHaveBeenCalledTimes(1);
	});
});

// ── outside the MLS recoverable taxonomy ─────────────────────────────────────

describe("MlsDowngradeError classification", () => {
	const err = new MlsDowngradeError(GROUP_ID);

	it("test_downgrade_error_when_classified_is_not_a_recoverable_mls_read", () => {
		expect(isRecoverableMlsRead(err)).toBe(false);
	});

	it("test_downgrade_error_when_classified_is_not_an_unprocessable_commit", () => {
		// An unprocessable commit earns a NACK. A downgrade refusal must never
		// reach that path: NACKing would roll back a commit and then swallow the
		// refusal in the one-shot recovery.
		expect(isUnprocessableCommit(err)).toBe(false);
	});

	it("test_downgrade_error_when_read_for_a_code_is_outside_the_mls_namespace", () => {
		expect(DOWNGRADE_REFUSED_CODE).toBe("RINE_DOWNGRADE_REFUSED");
		expect(DOWNGRADE_REFUSED_CODE.startsWith("RINE_MLS_")).toBe(false);
		expect(mlsErrorCode(err)).toBeNull();
	});

	it("test_is_mls_downgrade_error_when_given_a_code_only_object_matches_on_the_code", () => {
		// Surfaces branch on the code, never on the message: a refusal recognised
		// by its text stops being recognised the moment the text is reworded.
		expect(isMlsDowngradeError({ code: DOWNGRADE_REFUSED_CODE })).toBe(true);
		expect(isMlsDowngradeError(new Error(err.message))).toBe(false);
		expect(isMlsDowngradeError(err)).toBe(true);
	});
});

// ── the read path ────────────────────────────────────────────────────────────

describe("decryptGroupMessage downgrade guard", () => {
	let senderKeys: AgentKeys;

	beforeEach(() => {
		senderKeys = setupAgent(SENDER_ID);
		setupAgent(READER_ID);
	});

	it("test_decrypt_group_message_when_open_billboard_group_has_no_mls_state_decrypts", async () => {
		// The converse: an open billboard group is sender-key encrypted by
		// design and holds no local MLS state. It must keep reading.
		const body = { announcement: "open enrolment, all welcome" };
		const { payload, client } = await senderKeyRow(senderKeys, body);

		const decrypted = await decryptGroupMessage(
			dir,
			READER_ID,
			GROUP_ID,
			payload,
			client,
			SENDER_ID,
		);

		expect(JSON.parse(decrypted.plaintext)).toEqual(body);
		expect(decrypted.verificationStatus).toBe("verified");
	});

	it("test_decrypt_group_message_when_sender_key_row_and_local_mls_state_refuses", async () => {
		const { payload, client } = await senderKeyRow(senderKeys, { x: 1 });
		plantMlsState(READER_ID);
		const before = senderKeyStateOnDisk();

		let raised: unknown;
		try {
			await decryptGroupMessage(
				dir,
				READER_ID,
				GROUP_ID,
				payload,
				client,
				SENDER_ID,
			);
		} catch (err) {
			raised = err;
		}

		expect(raised).toBeInstanceOf(MlsDowngradeError);
		expect((raised as MlsDowngradeError).code).toBe(DOWNGRADE_REFUSED_CODE);
		// The refusal lands before the ratchet is touched: nothing was consumed, so
		// the row stays openable once the contradiction is resolved.
		expect(senderKeyStateOnDisk()).toBe(before);
		expect(loadSenderKeyStates(dir, READER_ID, GROUP_ID)[0]?.messageIndex).toBe(
			0,
		);
	});

	it("test_decrypt_group_message_when_mls_state_is_another_groups_still_decrypts", async () => {
		const body = { still: "fine" };
		const { payload, client } = await senderKeyRow(senderKeys, body);
		// State for a DIFFERENT group is not evidence about this one.
		plantMlsState(READER_ID, "d4e5f6a7-b8c9-4012-8def-1234567890ab");

		const decrypted = await decryptGroupMessage(
			dir,
			READER_ID,
			GROUP_ID,
			payload,
			client,
			SENDER_ID,
		);
		expect(JSON.parse(decrypted.plaintext)).toEqual(body);
	});
});
