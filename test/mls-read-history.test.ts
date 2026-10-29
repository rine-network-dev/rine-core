/**
 * Reading a group message from a sender that has rotated since, against the REAL
 * native core.
 *
 * A prior-epoch message from a member whose leaf key has since changed opens only
 * if the reader's allowed set holds the sender's old generation. A process that
 * never synced holds none, so the read admits the sender's chain-verified history
 * itself, before the first decrypt: the prior-epoch open spends its ratchet key
 * before the identity check, so a retry after a refusal would find nothing to open.
 *
 * Only the network is faked, by the rotation scene's stand-in server. Device `d1`
 * holds the sender A, device `dr` the reader R.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { isMlsError } from "../src/crypto/mls-errors.js";

vi.mock("../src/mls-escrow-key.js", async () =>
	(await import("./mls-escrow-harness.js")).escrowKeyModule(),
);

vi.mock("../src/crypto/mls-api.js", async () => {
	const actual = await vi.importActual<
		typeof import("../src/crypto/mls-api.js")
	>("../src/crypto/mls-api.js");
	return {
		...actual,
		uploadKeyPackages: vi.fn(async (_c: unknown, _a: unknown, p: string[]) => ({
			stored: p.length,
		})),
		claimKeyPackages: vi.fn(),
		claimKeyPackagesBatch: vi.fn(),
		mlsInit: vi.fn(),
		mlsCommit: vi.fn(),
		mlsAck: vi.fn(),
		mlsNack: vi.fn(),
		fetchHandshakes: vi.fn(),
		fetchWelcomes: vi.fn(),
		fetchGroupInfo: vi.fn(),
	};
});

import type { AgentKeysResponse } from "../src/api-types.js";
import { decryptGroupMessage } from "../src/message-group.js";
import { encryptMlsGroupMessage } from "../src/message-mls.js";
import { syncMlsGroup } from "../src/mls-ops.js";
import { selfUpdateGroup } from "../src/mls-self-update.js";
import { clientFor } from "./mls-hold-scene.js";
import { rotatedActor, setUpHeldGroup } from "./mls-pending-commit-scene.js";
import {
	A,
	G1,
	R,
	proc,
	scene,
	tearDownRotationScene,
} from "./mls-rotation-scene.js";

/** Before the world's `superseded_at`, so the old generation's signature still counts. */
const SENT_AT = "2025-12-01T00:00:00Z";

beforeEach(setUpHeldGroup);
afterEach(tearDownRotationScene);

/** A sends at the current epoch; the sealed payload is what the server would store. */
async function sendFromA(n: string): Promise<string> {
	const sent = await encryptMlsGroupMessage(scene.d1, A, G1, { n });
	return sent.encrypted_payload;
}

/** A rotates its leaf and R applies the commit, in a process of its own. */
async function rotateAndSync(n: number): Promise<void> {
	await selfUpdateGroup(rotatedActor(n), G1);
	await syncMlsGroup(scene.dr, R, G1, clientFor(R), undefined);
}

/** R reads from a process that has admitted nobody. */
function readAsR(process: number, payload: string, client = clientFor(R)) {
	return decryptGroupMessage(
		proc(scene.dr, process),
		R,
		G1,
		payload,
		client,
		A,
		SENT_AT,
	);
}

describe("a read past the sender's rotation", () => {
	it("test_decryptGroupMessage_when_the_sender_rotated_since_then_a_fresh_process_opens_it", async () => {
		const payload = await sendFromA("before the rotation");
		await rotateAndSync(1);

		const opened = await readAsR(1, payload);

		expect(JSON.parse(opened.plaintext)).toEqual({ n: "before the rotation" });
	});

	it("test_decryptGroupMessage_when_the_history_read_fails_then_the_ratchet_is_untouched_and_a_retry_opens", async () => {
		const payload = await sendFromA("kept for the retry");
		await rotateAndSync(2);
		const down = clientFor(R) as unknown as {
			get: (...a: unknown[]) => Promise<unknown>;
		};
		const real = down.get;
		down.get = async (path: unknown, ...rest: unknown[]) => {
			if (/^\/agents\//.test(String(path)))
				throw new Error("server unreachable");
			return real(path, ...rest);
		};

		await expect(readAsR(2, payload, down as never)).rejects.toThrow(
			"server unreachable",
		);
		const opened = await readAsR(2, payload);

		expect(JSON.parse(opened.plaintext)).toEqual({ n: "kept for the retry" });
	});

	it("test_decryptGroupMessage_when_the_message_is_from_the_current_epoch_then_no_history_is_read", async () => {
		await rotateAndSync(3);
		const payload = await sendFromA("after the rotation");
		const client = clientFor(R);
		const get = vi.spyOn(
			client as unknown as { get: (...a: unknown[]) => unknown },
			"get",
		);

		const opened = await readAsR(3, payload, client);

		expect(JSON.parse(opened.plaintext)).toEqual({ n: "after the rotation" });
		expect(get.mock.calls.filter(([, params]) => params !== undefined)).toEqual(
			[],
		);
	});
});

describe("a read whose sender history has a generation that fails the chain", () => {
	/** R's client, served a first generation of A whose encryption key does not match its certificate. */
	function clientBreakingFirstGeneration() {
		const real = clientFor(R) as unknown as {
			get: (...a: unknown[]) => Promise<AgentKeysResponse>;
		};
		return {
			...real,
			get: async (path: unknown, params?: Record<string, unknown>, ...rest: unknown[]) => {
				const reply = await real.get(path, params, ...rest);
				const isFirstGenerationOfA = path === `/agents/${A}/keys` && params?.["gen"] === 0;
				return isFirstGenerationOfA
					? {
							...reply,
							encryption_public_key: scene.world.published(R).encryption_public_key,
						}
					: reply;
			},
		} as never;
	}

	async function sentBeforeEachRotation(): Promise<[string, string]> {
		const first = await sendFromA("under the first generation");
		await rotateAndSync(4);
		const second = await sendFromA("under the second generation");
		await rotateAndSync(5);
		return [first, second];
	}

	it("test_decryptGroupMessage_when_a_history_generation_fails_the_chain_then_its_message_is_refused_and_a_valid_one_opens", async () => {
		const [first, second] = await sentBeforeEachRotation();
		const broken = clientBreakingFirstGeneration();

		const opened = await readAsR(4, second, broken);
		const refusal = await readAsR(5, first, broken).then(
			() => null,
			(err: unknown) => err,
		);
		expect(isMlsError(refusal)).toBe(true);

		expect(JSON.parse(opened.plaintext)).toEqual({ n: "under the second generation" });
	});

	it("test_decryptGroupMessage_when_every_history_generation_verifies_then_the_first_generation_opens", async () => {
		const [first] = await sentBeforeEachRotation();

		const opened = await readAsR(6, first);

		expect(JSON.parse(opened.plaintext)).toEqual({ n: "under the first generation" });
	});
});
