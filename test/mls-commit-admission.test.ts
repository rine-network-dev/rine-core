/**
 * The catch-up admission loop in isolation: when it admits, what it retries,
 * and where it stops. The native core is replaced by a handle that refuses on
 * script; the one external, the chain-verified peer read, is a spy.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../src/mls-allowed.js", () => ({ admitPeers: vi.fn(async () => []) }));

import { MLS_ERR_PEER_NOT_ADMITTED } from "../src/crypto/mls-errors.js";
import { admitRefusedPeers, removedAgents } from "../src/mls-commit-admission.js";
import { type PeerActor, admitPeers } from "../src/mls-allowed.js";

const PEER_X = "d4e5f6a7-b8c9-0123-def1-234567890123";
const PEER_Y = "e5f6a7b8-c9d0-1234-ef12-345678901234";
const actor = { configDir: "unused", agentId: "unused" } as unknown as PeerActor;

function refusal(code = MLS_ERR_PEER_NOT_ADMITTED): Error {
	return Object.assign(new Error("the input carries a leaf this member has not admitted"), { code });
}

/** A handle whose successive calls refuse the named peers, then succeed. */
function scripted(refused: (string | Uint8Array | null)[]) {
	const queue = [...refused];
	let named: Uint8Array | null = null;
	let calls = 0;
	return {
		source: { refusedPeer: () => named },
		attempt: () => {
			calls += 1;
			const next = queue.shift();
			if (next === undefined) return "applied";
			named = typeof next === "string" ? new TextEncoder().encode(next) : next;
			throw refusal();
		},
		calls: () => calls,
	};
}

beforeEach(() => {
	vi.clearAllMocks();
	vi.mocked(admitPeers).mockResolvedValue([]);
});

describe("admitRefusedPeers", () => {
	it("test_admit_when_the_attempt_succeeds_then_nothing_is_read", async () => {
		const handle = scripted([]);

		await expect(admitRefusedPeers(actor, handle.source, handle.attempt)).resolves.toBe("applied");

		expect(admitPeers).not.toHaveBeenCalled();
		expect(handle.calls()).toBe(1);
	});

	it("test_admit_when_the_failure_is_not_a_refusal_then_it_is_rethrown_unread", async () => {
		const failure = refusal("RINE_MLS_PROTOCOL");

		await expect(
			admitRefusedPeers(actor, { refusedPeer: () => new TextEncoder().encode(PEER_X) }, () => {
				throw failure;
			}),
		).rejects.toBe(failure);

		expect(admitPeers).not.toHaveBeenCalled();
	});

	it("test_admit_when_a_peer_is_refused_then_it_is_verified_once_and_the_retry_applies", async () => {
		const handle = scripted([PEER_X]);

		await expect(admitRefusedPeers(actor, handle.source, handle.attempt)).resolves.toBe("applied");

		expect(admitPeers).toHaveBeenCalledTimes(1);
		expect(admitPeers).toHaveBeenCalledWith(actor, [PEER_X]);
		expect(handle.calls()).toBe(2);
	});

	it("test_admit_when_the_same_peer_is_refused_again_then_the_second_refusal_is_final", async () => {
		const handle = scripted([PEER_X, PEER_X, PEER_X, PEER_X]);

		await expect(
			admitRefusedPeers(actor, handle.source, handle.attempt),
		).rejects.toMatchObject({ code: MLS_ERR_PEER_NOT_ADMITTED });

		expect(admitPeers).toHaveBeenCalledTimes(1);
		expect(handle.calls()).toBe(2);
	});

	it("test_admit_when_two_peers_are_refused_in_turn_then_each_is_verified_once", async () => {
		const handle = scripted([PEER_X, PEER_Y]);

		await expect(admitRefusedPeers(actor, handle.source, handle.attempt)).resolves.toBe("applied");

		expect(vi.mocked(admitPeers).mock.calls.map(([, ids]) => ids)).toEqual([[PEER_X], [PEER_Y]]);
		expect(handle.calls()).toBe(3);
	});

	it("test_admit_when_a_limit_is_reached_then_the_next_refusal_is_final_and_unread", async () => {
		const handle = scripted([PEER_X, PEER_Y]);

		await expect(
			admitRefusedPeers(actor, handle.source, handle.attempt, 1),
		).rejects.toMatchObject({ code: MLS_ERR_PEER_NOT_ADMITTED });

		expect(vi.mocked(admitPeers).mock.calls.map(([, ids]) => ids)).toEqual([[PEER_X]]);
		expect(handle.calls()).toBe(2);
	});

	it("test_admit_when_the_limit_covers_every_refusal_then_the_retry_applies", async () => {
		const handle = scripted([PEER_X, PEER_Y]);

		await expect(
			admitRefusedPeers(actor, handle.source, handle.attempt, 2),
		).resolves.toBe("applied");

		expect(admitPeers).toHaveBeenCalledTimes(2);
	});

	it.each<[string, Uint8Array | null]>([
		["the_core_names_nobody", null],
		["the_name_is_not_text", Uint8Array.from([0xff, 0xfe])],
		["the_name_is_not_an_agent_id", new TextEncoder().encode("not-a-uuid")],
	])("test_admit_when_%s_then_the_refusal_is_thrown_unread", async (_name, named) => {
		const handle = scripted([named]);

		await expect(
			admitRefusedPeers(actor, handle.source, handle.attempt),
		).rejects.toMatchObject({ code: MLS_ERR_PEER_NOT_ADMITTED });

		expect(admitPeers).not.toHaveBeenCalled();
		expect(handle.calls()).toBe(1);
	});

	it("test_admit_when_the_verification_fails_then_that_failure_surfaces_and_nothing_retries", async () => {
		const outage = new Error("unavailable");
		vi.mocked(admitPeers).mockRejectedValue(outage);
		const handle = scripted([PEER_X]);

		await expect(admitRefusedPeers(actor, handle.source, handle.attempt)).rejects.toBe(outage);

		expect(handle.calls()).toBe(1);
	});
});

describe("removedAgents", () => {
	it("test_removed_agents_when_the_identity_is_an_agent_id_then_it_is_declared", () => {
		expect(removedAgents(new TextEncoder().encode(PEER_X))).toEqual([PEER_X]);
	});

	it("test_removed_agents_when_the_identity_is_not_an_agent_id_then_nothing_is_declared", () => {
		expect(removedAgents(new TextEncoder().encode("not-an-agent"))).toEqual([]);
		expect(removedAgents(new Uint8Array([0xff, 0xfe]))).toEqual([]);
		expect(removedAgents(new Uint8Array())).toEqual([]);
	});
});
