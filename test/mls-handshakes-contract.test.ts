/**
 * The handshakes read's pending standing, pinned against the golden fixtures the server contract
 * suite records from the real router (`rine-sdk/tests/contract/fixtures/`).
 *
 * A key update held by an open-enrollment group is applied, held or dropped on the standing the
 * server names. The five standings are plain strings the settle switches on, so one the server
 * renames would fall to the settle's unknown-standing branch while a hand-typed stub still
 * parsed. No module is mocked: each golden body goes through the real feed reader.
 */
import { describe, expect, it } from "vitest";

import type { MlsHandshakeEntry } from "../src/crypto/mls-api.js";
import { OwnCommitStanding, fetchHandshakeFeed } from "../src/crypto/mls-handshake-feed.js";
import { golden } from "./helpers/golden.js";

const GROUP_ID = "c3d4e5f6-a7b8-9012-cdef-123456789012";
const STANDINGS = ["tentative", "confirmed", "rolled_back", "superseded", "absent"];

interface HandshakesBody {
	handshakes: MlsHandshakeEntry[];
	pending_commit: string;
}

const clientServing = (body: HandshakesBody, asked: Record<string, string>[]) =>
	({
		get: async (_path: string, params: Record<string, string>) => {
			asked.push(params);
			return body;
		},
	}) as never;

describe("the handshakes read's pending standing", () => {
	it.each(STANDINGS)(
		"test_handshake_feed_when_the_server_answers_pending_%s_then_the_feed_keeps_the_standing_and_the_commits",
		async (standing) => {
			const { body } = golden<HandshakesBody>(`mls_handshakes_200_pending_${standing}.json`);
			const asked: Record<string, string>[] = [];

			const feed = await fetchHandshakeFeed(clientServing(body, asked), GROUP_ID, 1, undefined, 2);

			expect(asked).toEqual([{ since_epoch: "1", pending_epoch: "2" }]);
			expect(feed).toEqual({ handshakes: body.handshakes, pendingCommit: standing });
		},
	);

	it("test_own_commit_standing_when_the_goldens_are_replayed_then_it_holds_exactly_their_five_strings", () => {
		expect([...Object.values(OwnCommitStanding)].sort()).toEqual([...STANDINGS].sort());
	});
});
