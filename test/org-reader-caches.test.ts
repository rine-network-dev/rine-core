import { randomUUID } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import { SENDER_KEY_DISTRIBUTION_TYPE } from "../src/control-frames.js";
import { signingKid, toBase64Url } from "../src/crypto/keys.js";
import { generateSenderKey, sealGroup } from "../src/crypto/sender-keys.js";
import { keysUnavailable, noEscrow } from "../src/org-reader/gaps.js";
import { TokenBucket } from "../src/org-reader/fetch-budget.js";
import { OrgReader, type OrgReaderOptions } from "../src/org-reader/reader.js";
import type { Row } from "../src/org-reader/rows.js";
import { World } from "./crypto/world.js";
import { jsonResponse } from "./org-reader-client-fixture.js";
import {
	EPOCH,
	closedGroupSuite,
	escrowRowOf,
	foreignPlaintext,
} from "./org-reader-mls-fixture.js";
import { native, nativeError } from "./org-reader-native-seam.js";
import {
	API,
	envelopeFrom,
	orgWorld,
	party,
	rowOf,
	sealTo,
	worldTransport,
} from "./org-reader-world.js";

vi.mock("@rine-network/mls", async (importActual) => {
	const { wrapNative } = await import("./org-reader-native-seam.js");
	return wrapNative(await importActual<typeof import("@rine-network/mls")>());
});

const { world, key, group, goodRow } = closedGroupSuite();

/** The activity row as the org feed carries it. */
function itemOf(row: Row): Record<string, unknown> {
	const partyOf = (p: Row["sender"]) => ({
		agent_id: p.agentId,
		handle: p.handle,
		org_id: p.orgId,
		own: p.own,
	});
	return {
		id: row.id,
		created_at: row.createdAt,
		type: row.type,
		direction: row.direction,
		from: partyOf(row.sender),
		to: row.recipient === null ? null : partyOf(row.recipient),
		group:
			row.groupId === null ? null : { id: row.groupId, handle: row.groupHandle },
		conversation_id: row.conversationId,
		encryption_version: row.encryptionVersion,
		payload: { encrypted_payload: toBase64Url(row.ciphertext) },
	};
}

/** What the scripted server holds, and what was asked of it. */
interface Feed {
	items: Row[];
	distributions: Row[];
	escrow: unknown[];
	failing: Set<string>;
	activityCalls: URL[];
	active: number;
	maxActive: number;
	activityDelayMs: number;
}

function newFeed(): Feed {
	return {
		items: [],
		distributions: [],
		escrow: [],
		failing: new Set(),
		activityCalls: [],
		active: 0,
		maxActive: 0,
		activityDelayMs: 0,
	};
}

/** Answers the feed and escrow routes from `feed`; keys and the token come from the worlds. */
function serve(feed: Feed, worlds: readonly World[]): typeof fetch {
	const base = worldTransport(worlds, (id) =>
		feed.failing.has(id) ? jsonResponse({ error: "unavailable" }, 503) : undefined,
	);
	return (async (input: Parameters<typeof fetch>[0], init?: RequestInit) => {
		const url = new URL(String(input));
		if (url.pathname === "/orgs/me/mls-escrow")
			return jsonResponse({ rows: feed.escrow, next_cursor: null });
		if (url.pathname !== "/org/activity") return base(input, init);
		feed.activityCalls.push(url);
		feed.active++;
		feed.maxActive = Math.max(feed.maxActive, feed.active);
		await new Promise((done) => setTimeout(done, feed.activityDelayMs));
		feed.active--;
		const rows = url.searchParams.has("type") ? feed.distributions : feed.items;
		return jsonResponse({ items: rows.map(itemOf), next_cursor: null });
	}) as typeof fetch;
}

function readerFor(
	feed: Feed,
	worlds: readonly World[] = [world],
	extra: Partial<OrgReaderOptions> = {},
) {
	return new OrgReader({
		apiUrl: API,
		key,
		fetch: serve(feed, worlds),
		bucket: new TokenBucket({ perMinute: 60_000 }),
		...extra,
	});
}

describe("the epoch readers kept across reads", () => {
	it("looks_again_at_an_epoch_that_gapped_on_the_next_read", async () => {
		const feed = newFeed();
		feed.items = [group.rowFor(group.send("hello"))];
		const reader = readerFor(feed);
		const first = await reader.read();
		expect(first.items[0]?.gap).toEqual(noEscrow(EPOCH));
		expect(native.built).toBe(0);
		feed.escrow = [goodRow()];
		const second = await reader.read();
		expect(second.items[0]?.text).toBe("hello");
		expect(second.items[0]?.gap).toBeNull();
	});

	it("opens_an_epoch_that_lacked_keys_once_the_key_fetch_succeeds", async () => {
		const feed = newFeed();
		feed.items = [group.rowFor(group.send("hello"))];
		feed.escrow = [goodRow()];
		feed.failing.add(group.sender.id);
		const reader = readerFor(feed);
		const first = await reader.read();
		expect(first.items[0]?.gap).toEqual(keysUnavailable(EPOCH));
		expect(first.findings).toEqual([]);
		feed.failing.clear();
		const second = await reader.read();
		expect(second.items[0]?.text).toBe("hello");
		expect(second.items[0]?.gap).toBeNull();
		expect(second.findings).toEqual([]);
	});

	it("judges_a_re_uploaded_copy_with_a_different_plaintext_afresh", async () => {
		const feed = newFeed();
		feed.items = [group.rowFor(group.send("hello"))];
		feed.escrow = [goodRow()];
		const reader = readerFor(feed);
		expect((await reader.read()).items[0]?.text).toBe("hello");
		feed.escrow = [
			escrowRowOf(world, group.founder, group.groupId, {
				...group.exported,
				plaintext: foreignPlaintext,
			}),
		];
		const again = await reader.read();
		expect(again.items[0]?.text).toBeNull();
		expect(again.items[0]?.gap).not.toBeNull();
	});

	it("rebuilds_from_the_kept_plaintext_when_a_later_read_opens_an_earlier_message", async () => {
		const feed = newFeed();
		feed.escrow = [goodRow()];
		const earlier = group.rowFor(group.send("first"));
		const later = group.rowFor(group.send("second"));
		const reader = readerFor(feed);
		feed.items = [later];
		expect((await reader.read()).items[0]?.text).toBe("second");
		expect(native.built).toBe(1);
		feed.items = [earlier];
		// The kept reader has moved past the earlier message's generation.
		native.opens.push(nativeError("RINE_MLS_GENERATION_TOO_FAR"));
		const again = await reader.read();
		expect(again.items[0]?.text).toBe("first");
		expect(native.built).toBe(2);
		expect(native.opened).toBe(3);
	});
});

describe("reads", () => {
	it("are_serialised_so_two_concurrent_reads_never_overlap_on_the_wire", async () => {
		const feed = newFeed();
		feed.activityDelayMs = 15;
		const reader = readerFor(feed);
		await Promise.all([reader.read(), reader.read(), reader.read()]);
		expect(feed.activityCalls).toHaveLength(3);
		expect(feed.maxActive).toBe(1);
	});

	it("go_on_after_a_read_that_failed", async () => {
		const feed = newFeed();
		let failNext = true;
		const served = serve(feed, [world]);
		const reader = readerFor(feed, [world], {
			fetch: (async (input: Parameters<typeof fetch>[0], init?: RequestInit) => {
				if (failNext && new URL(String(input)).pathname === "/org/activity") {
					failNext = false;
					return jsonResponse({ error: "down" }, 500);
				}
				return served(input, init);
			}) as typeof fetch,
		});
		const [failed, next] = await Promise.allSettled([
			reader.read(),
			reader.read(),
		]);
		expect(failed.status).toBe("rejected");
		expect(next.status).toBe("fulfilled");
	});

	it("wait_for_the_read_in_flight_before_close_zeroes_the_key", async () => {
		const own = orgWorld();
		const feed = newFeed();
		feed.activityDelayMs = 15;
		const reader = readerFor(feed, [own.world], { key: own.key });
		const pending = reader.read();
		const closing = reader.close();
		await expect(pending).resolves.toMatchObject({ items: [] });
		await closing;
		expect(() => own.key.branchRead("main")).toThrow("disposed");
	});
});

describe("the sender-key distributions kept across reads", () => {
	const other = new World();
	const poster = other.addAgent();
	const member = world.addAgent();
	const groupId = randomUUID();
	const early = (minute: number) => {
		const at = `2026-02-01T10:${String(minute).padStart(2, "0")}:00.000000Z`;
		return { createdAt: at, createdAtMicros: Date.parse(at) * 1000 };
	};

	async function post(state: ReturnType<typeof generateSenderKey>, text: string, minute: number) {
		const { encryptedPayload, updatedState } = await sealGroup(
			poster.derived.ed25519.privateKey,
			signingKid(poster.id, poster.gen),
			state,
			new TextEncoder().encode(text),
		);
		const row = rowOf({
			...early(minute),
			sender: party(poster, false),
			recipient: null,
			groupId,
			type: "rine.v1.group_message",
			direction: "received",
			encryptionVersion: "sender-key-v1",
			ciphertext: encryptedPayload,
		});
		return { row, updatedState };
	}

	function distributionRow(state: ReturnType<typeof generateSenderKey>): Row {
		const payload = new TextEncoder().encode(
			JSON.stringify({
				group_id: state.groupId,
				sender_key_id: state.senderKeyId,
				chain_key: toBase64Url(state.chainKey),
				message_index: state.messageIndex,
			}),
		);
		return rowOf({
			...early(0),
			sender: party(poster, false),
			recipient: party(member),
			type: SENDER_KEY_DISTRIBUTION_TYPE,
			direction: "received",
			ciphertext: sealTo(member, envelopeFrom(poster, member.id, payload)),
		});
	}

	const walks = (feed: Feed) =>
		feed.activityCalls.filter((url) => url.searchParams.has("type"));

	it("are_not_walked_again_once_they_cover_the_rows_of_a_later_read", async () => {
		const state = generateSenderKey(groupId, poster.id);
		const feed = newFeed();
		feed.distributions = [distributionRow(state)];
		const first = await post(state, "one", 1);
		const second = await post(first.updatedState, "two", 2);
		const reader = readerFor(feed, [world, other]);
		feed.items = [first.row];
		expect((await reader.read()).items[0]?.text).toBe("one");
		expect(walks(feed)).toHaveLength(1);
		feed.items = [second.row];
		const again = await reader.read();
		expect(again.items[0]?.text).toBe("two");
		expect(walks(feed)).toHaveLength(1);
	});
});
