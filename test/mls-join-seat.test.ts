/**
 * The join verb's answer to a 409 `already_a_member`, shared by every surface.
 *
 * The establishment it runs is `establishAfterAlreadyAMember`, tested against
 * the real native core in mls-join-already-member.test.ts; this file fakes that
 * one call and owns what the helper adds: the cheap check before the actor
 * lookup, the sink for a failed setup, and the member row it hands back.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";

const mockAfterAlreadyAMember = vi.fn();

vi.mock("../src/mls-join-establish.js", async (importOriginal) => ({
	...(await importOriginal<typeof import("../src/mls-join-establish.js")>()),
	establishAfterAlreadyAMember: (...args: unknown[]) =>
		mockAfterAlreadyAMember(...args),
}));

const { MlsEstablishStep, MlsMembershipOutcome } = await import(
	"../src/mls-join-establish.js"
);
const { seatedMemberAfterConflict } = await import("../src/mls-join-seat.js");

const GROUP_ID = "11111111-1111-4111-8111-111111111111";
const AGENT_ID = "22222222-2222-4222-8222-222222222222";
const ROW = { agent_id: AGENT_ID, role: "member" };
const HEADERS = { "X-Rine-Agent": AGENT_ID };

function alreadyAMember() {
	return Object.assign(new Error("already a member"), {
		status: 409,
		code: "already_a_member",
	});
}

function setUp(members: unknown = { items: [{ agent_id: "other" }, ROW] }) {
	const get = vi.fn().mockResolvedValue(members);
	const actingAgent = vi.fn().mockResolvedValue(AGENT_ID);
	const onFailed = vi.fn();
	const join = {
		configDir: "/tmp/seat",
		groupId: GROUP_ID,
		client: { get } as never,
		actingAgent,
	};
	return { get, actingAgent, onFailed, join };
}

beforeEach(() => {
	vi.resetAllMocks();
	mockAfterAlreadyAMember.mockResolvedValue({
		outcome: MlsMembershipOutcome.Installed,
	});
});

describe("a join answered with already_a_member", () => {
	it.each([
		MlsMembershipOutcome.Installed,
		MlsMembershipOutcome.Reseated,
		MlsMembershipOutcome.ExternalJoined,
	])("test_seatedMember_when_the_setup_ends_%s_then_the_agents_row_comes_back", async (outcome) => {
		const { get, onFailed, join } = setUp();
		mockAfterAlreadyAMember.mockResolvedValue({ outcome });
		const conflict = alreadyAMember();

		await expect(
			seatedMemberAfterConflict(conflict, join, onFailed),
		).resolves.toEqual(ROW);
		expect(mockAfterAlreadyAMember).toHaveBeenCalledWith(
			conflict,
			"/tmp/seat",
			AGENT_ID,
			GROUP_ID,
			join.client,
			HEADERS,
		);
		expect(get).toHaveBeenCalledWith(
			`/groups/${GROUP_ID}/members`,
			undefined,
			HEADERS,
		);
		expect(onFailed).not.toHaveBeenCalled();
	});

	it("test_seatedMember_when_the_error_is_another_failure_then_the_actor_is_never_asked", async () => {
		const { actingAgent, onFailed, join } = setUp();
		const other = Object.assign(new Error("x"), {
			status: 409,
			code: "other_conflict",
		});

		await expect(
			seatedMemberAfterConflict(other, join, onFailed),
		).resolves.toBeNull();
		expect(actingAgent).not.toHaveBeenCalled();
		expect(mockAfterAlreadyAMember).not.toHaveBeenCalled();
	});

	it("test_seatedMember_when_the_actor_cannot_be_resolved_then_the_409_stands", async () => {
		const { actingAgent, onFailed, join } = setUp();
		actingAgent.mockRejectedValue(new Error("no agent"));

		await expect(
			seatedMemberAfterConflict(alreadyAMember(), join, onFailed),
		).resolves.toBeNull();
		expect(mockAfterAlreadyAMember).not.toHaveBeenCalled();
	});

	it("test_seatedMember_when_state_is_already_held_then_the_409_stands", async () => {
		const { get, onFailed, join } = setUp();
		mockAfterAlreadyAMember.mockResolvedValue(null);

		await expect(
			seatedMemberAfterConflict(alreadyAMember(), join, onFailed),
		).resolves.toBeNull();
		expect(get).not.toHaveBeenCalled();
	});

	it("test_seatedMember_when_the_setup_fails_then_the_sink_hears_it_once_and_the_409_stands", async () => {
		const { get, onFailed, join } = setUp();
		const failed = {
			outcome: MlsMembershipOutcome.Failed,
			reason: "socket hang up",
			failure: {
				step: MlsEstablishStep.ExternalJoin,
				error: new Error("socket hang up"),
			},
		};
		mockAfterAlreadyAMember.mockResolvedValue(failed);

		await expect(
			seatedMemberAfterConflict(alreadyAMember(), join, onFailed),
		).resolves.toBeNull();
		expect(onFailed).toHaveBeenCalledTimes(1);
		expect(onFailed).toHaveBeenCalledWith(failed);
		expect(get).not.toHaveBeenCalled();
	});

	it.each([MlsMembershipOutcome.NotMls, MlsMembershipOutcome.Held])("test_seatedMember_when_the_setup_ends_%s_then_the_409_stands_silently", async (outcome) => {
		const { get, onFailed, join } = setUp();
		mockAfterAlreadyAMember.mockResolvedValue({ outcome });

		await expect(
			seatedMemberAfterConflict(alreadyAMember(), join, onFailed),
		).resolves.toBeNull();
		expect(onFailed).not.toHaveBeenCalled();
		expect(get).not.toHaveBeenCalled();
	});

	it("test_seatedMember_when_the_members_read_lacks_the_agent_then_the_409_stands", async () => {
		const { onFailed, join } = setUp({ items: [] });

		await expect(
			seatedMemberAfterConflict(alreadyAMember(), join, onFailed),
		).resolves.toBeNull();
	});

	it("test_seatedMember_when_the_members_read_fails_then_the_409_stands", async () => {
		const { get, onFailed, join } = setUp();
		get.mockRejectedValue(new Error("503"));

		await expect(
			seatedMemberAfterConflict(alreadyAMember(), join, onFailed),
		).resolves.toBeNull();
	});

	it("test_seatedMember_when_the_surface_reads_the_roster_then_its_row_comes_back", async () => {
		const { get, onFailed, join } = setUp();
		const own = { agent_id: AGENT_ID, parsed: true };
		const readMembers = vi.fn().mockResolvedValue([{ agent_id: "other" }, own]);

		await expect(
			seatedMemberAfterConflict(alreadyAMember(), join, onFailed, readMembers),
		).resolves.toBe(own);
		expect(readMembers).toHaveBeenCalledWith(HEADERS);
		expect(get).not.toHaveBeenCalled();
	});

	it("test_seatedMember_when_a_refusal_is_raised_then_it_propagates", async () => {
		const { onFailed, join } = setUp();
		const refusal = new Error("Refusing the MLS welcome");
		mockAfterAlreadyAMember.mockRejectedValue(refusal);

		await expect(
			seatedMemberAfterConflict(alreadyAMember(), join, onFailed),
		).rejects.toBe(refusal);
	});
});
