import { describe, expect, it, vi } from "vitest";
import { KeyChainError } from "../src/crypto/key-chain.js";
import { RineApiError } from "../src/errors.js";
import type { ReadContext } from "../src/org-reader/context.js";
import { openDirect } from "../src/org-reader/direct.js";
import { ReaderNetworkError } from "../src/org-reader/fetch-budget.js";
import {
	ReadGapReason,
	escrowForged,
	keysUnavailable,
	memberRejected,
	unreadable,
} from "../src/org-reader/gaps.js";
import {
	EPOCH,
	closedGroupSuite,
	escrowRowOf,
} from "./org-reader-mls-fixture.js";
import { native, nativeError } from "./org-reader-native-seam.js";
import { contextFor, party, rowOf } from "./org-reader-world.js";

vi.mock("@rine-network/mls", async (importActual) => {
	const { wrapNative } = await import("./org-reader-native-seam.js");
	return wrapNative(await importActual<typeof import("@rine-network/mls")>());
});

const { world, key, group, goodRow, setup, read } = closedGroupSuite();

/** Fail the key reads of `failing` agents with `error`; every other agent's keys are served as usual. */
function failKeysOf(ctx: ReadContext, error: Error, ...failing: string[]) {
	const served = ctx.client.agentKeys.bind(ctx.client);
	vi.spyOn(ctx.client, "agentKeys").mockImplementation((id, gen) =>
		failing.includes(id) ? Promise.reject(error) : served(id, gen),
	);
}

const TRANSIENT: [string, () => Error][] = [
	["a_429", () => new RineApiError(429, "slow down")],
	["a_503", () => new RineApiError(503, "unavailable")],
	["a_network_failure", () => new ReaderNetworkError("the request failed")],
];

describe("a hostile or broken escrow", () => {
	it("forges_a_copy_filed_under_a_hostile_branch_name", async () => {
		const hostile = { ...goodRow(), branch: "../main" };
		const s = setup([hostile]);
		const message = await read(s, group.rowFor(group.send("x")));
		expect(message.gap).toEqual(escrowForged(EPOCH));
		expect(s.reader.findings).toEqual([{ groupId: group.groupId, gap: escrowForged(EPOCH) }]);
	});

	it("is_unreadable_when_the_uploaders_key_chain_is_refused", async () => {
		const s = setup();
		failKeysOf(s.ctx, new KeyChainError("agent_cert"), group.founder.id);
		const message = await read(s, group.rowFor(group.send("x")));
		expect(message.gap).toEqual(unreadable(EPOCH));
	});
});

describe.each(TRANSIENT)("%s while reading keys", (_, failure) => {
	it("leaves_a_direct_row_with_keys_unavailable", async () => {
		const recipient = world.addAgent();
		const ctx = contextFor(key, [world]);
		failKeysOf(ctx, failure(), recipient.id);
		const row = rowOf({
			sender: party(group.sender),
			recipient: party(recipient),
			ciphertext: new Uint8Array(8),
		});
		expect((await openDirect(ctx, row)).gap).toEqual(keysUnavailable());
	});

	it("leaves_a_closed_group_row_with_keys_unavailable_when_the_uploaders_failed", async () => {
		const s = setup();
		failKeysOf(s.ctx, failure(), group.founder.id);
		const message = await read(s, group.rowFor(group.send("x")));
		expect(message.gap).toEqual(keysUnavailable(EPOCH));
		expect(s.reader.findings).toEqual([]);
	});

	it("leaves_a_closed_group_row_with_keys_unavailable_when_the_signers_failed", async () => {
		const s = setup();
		failKeysOf(s.ctx, failure(), group.sender.id);
		const message = await read(s, group.rowFor(group.send("x")));
		expect(message.gap).toEqual(keysUnavailable(EPOCH));
		expect(message.gap?.reason).not.toBe(ReadGapReason.MemberRejected);
		expect(s.reader.findings).toEqual([]);
	});
});

describe("a signer whose keys the server does not have", () => {
	it("is_a_rejected_member_when_the_latest_keys_are_404", async () => {
		const s = setup();
		failKeysOf(s.ctx, new RineApiError(404, "not found"), group.sender.id);
		const message = await read(s, group.rowFor(group.send("x")));
		expect(message.gap).toEqual(memberRejected(EPOCH));
	});
});

describe("a panic in the native core", () => {
	const panic = () => nativeError("RINE_MLS_PANIC");

	it("makes_the_epoch_unreadable_and_names_nobody", async () => {
		const s = setup();
		native.opens.push(panic());
		const message = await read(s, group.rowFor(group.send("x")));
		expect(message.gap).toEqual(unreadable(EPOCH));
		expect(s.reader.findings).toEqual([]);
	});

	it("is_the_same_when_the_reader_cannot_be_built", async () => {
		const s = setup();
		native.builds.push(panic());
		const message = await read(s, group.rowFor(group.send("x")));
		expect(message.gap).toEqual(unreadable(EPOCH));
		expect(s.reader.findings).toEqual([]);
	});

	it("does_not_name_the_uploader_of_a_copy_that_panicked_beside_one_that_opened", async () => {
		const second = world.addAgent();
		const s = setup([
			goodRow(),
			escrowRowOf(world, second, group.groupId, group.exported),
		]);
		native.opens.push(undefined, panic());
		const message = await read(s, group.rowFor(group.send("beside")));
		expect(message.text).toBe("beside");
		expect(s.reader.findings).toEqual([]);
	});
});

describe("a defect in the addon binding", () => {
	it("rethrows_a_type_error_from_a_missing_binding_when_building", async () => {
		const s = setup();
		native.builds.push(new TypeError("EpochReader.fromEscrow is not a function"));
		await expect(read(s, group.rowFor(group.send("x")))).rejects.toBeInstanceOf(
			TypeError,
		);
	});

	it("rethrows_a_type_error_raised_while_opening", async () => {
		const s = setup();
		native.opens.push(new TypeError("not a Uint8Array"));
		await expect(read(s, group.rowFor(group.send("x")))).rejects.toBeInstanceOf(
			TypeError,
		);
	});
});
