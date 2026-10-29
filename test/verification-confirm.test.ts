import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { HttpClient } from "../src/http.js";
import { saveAgentKeys } from "../src/crypto/keys.js";
import { generateAgentKeys } from "./helpers/keys.js";
import { verificationWordsForKey } from "../src/crypto/verification-words.js";
import {
	buildPeerVerification,
	fetchPeerCardWords,
	loadPeerVerification,
	recordPeerVerification,
} from "../src/verification-confirm.js";
import {
	compareVerificationWordsForAgent,
	peerVerificationLines,
} from "../src/verification-display.js";
import { RineApiError } from "../src/errors.js";

/**
 * The compare/confirm flow: the peer's published words beside this
 * agent's own, and a record that an operator read them back.
 *
 * The record is advisory — nothing here refuses anything. What it must do is
 * make a peer's words CHANGING after a confirmation visible, which is the one
 * thing an unread string on a card cannot do.
 */

const OWN_ID = "11111111-2222-3333-4444-555555555555";
const PEER_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
const PEER_WORDS = "abandon ability able about above";

const dirs: string[] = [];

function makeConfigDir(): string {
	const dir = fs.mkdtempSync(join(tmpdir(), "rine-confirm-test-"));
	dirs.push(dir);
	return dir;
}

/** An `HttpClient` stand-in that answers one directory card GET. */
function cardClient(body: unknown, paths: string[] = []): HttpClient {
	return {
		get: async (path: string) => {
			paths.push(path);
			if (body instanceof Error) throw body;
			return body;
		},
	} as unknown as HttpClient;
}

afterEach(() => {
	while (dirs.length > 0) {
		const dir = dirs.pop();
		if (dir) fs.rmSync(dir, { recursive: true, force: true });
	}
});

describe("fetchPeerCardWords", () => {
	it("reads the words off the peer's public directory card", async () => {
		const paths: string[] = [];
		const peer = await fetchPeerCardWords(
			cardClient(
				{
					card: {
						name: "bot",
						rine: { handle: "bot@acme", verification_words: PEER_WORDS },
					},
				},
				paths,
			),
			PEER_ID,
		);
		expect(paths).toEqual([`/directory/agents/${PEER_ID}`]);
		expect(peer).toEqual({
			handle: "bot@acme",
			words: PEER_WORDS,
			published: true,
			unreadable: false,
		});
	});

	it("reports an unpublished card as a state, not an error", async () => {
		const peer = await fetchPeerCardWords(
			cardClient(new RineApiError(404, "Agent not found")),
			PEER_ID,
		);
		expect(peer).toEqual({
			handle: null,
			words: null,
			published: false,
			unreadable: false,
		});
	});

	it("test_card_read_when_the_directory_rate_limits_then_it_is_unreadable_not_absent", async () => {
		const peer = await fetchPeerCardWords(
			cardClient(new RineApiError(429, "Too many requests")),
			PEER_ID,
		);
		// A 429 is this end's answer, not the peer's. Reporting it as
		// `published: false` states a fact about the peer out of our own bad luck.
		expect(peer).toEqual({
			handle: null,
			words: null,
			published: false,
			unreadable: true,
		});
	});

	it("test_card_read_when_the_transport_fails_then_it_is_unreadable_not_absent", async () => {
		const peer = await fetchPeerCardWords(
			cardClient(new Error("socket hang up")),
			PEER_ID,
		);
		expect(peer.unreadable).toBe(true);
	});

	it("reports a published card that names no words", async () => {
		const peer = await fetchPeerCardWords(
			cardClient({ card: { rine: { handle: "bot@acme" } } }),
			PEER_ID,
		);
		expect(peer).toEqual({
			handle: "bot@acme",
			words: null,
			published: true,
			unreadable: false,
		});
	});
});

describe("recordPeerVerification", () => {
	it("round-trips a confirmation through the config dir", () => {
		const configDir = makeConfigDir();
		expect(loadPeerVerification(configDir, OWN_ID, PEER_ID)).toBeNull();

		const written = recordPeerVerification(configDir, OWN_ID, {
			peerAgentId: PEER_ID,
			handle: "bot@acme",
			words: PEER_WORDS,
		});
		expect(written.words).toBe(PEER_WORDS);
		expect(written.confirmedAt).not.toBe("");

		const loaded = loadPeerVerification(configDir, OWN_ID, PEER_ID);
		expect(loaded).toEqual(written);
	});

	it("keys the record by (agent, peer), so a second agent does not see it", () => {
		const configDir = makeConfigDir();
		recordPeerVerification(configDir, OWN_ID, {
			peerAgentId: PEER_ID,
			handle: "bot@acme",
			words: PEER_WORDS,
		});
		const other = "99999999-9999-9999-9999-999999999999";
		expect(loadPeerVerification(configDir, other, PEER_ID)).toBeNull();
	});

	it("normalises the peer id, so one peer keeps one record", () => {
		const configDir = makeConfigDir();
		recordPeerVerification(configDir, OWN_ID, {
			peerAgentId: PEER_ID.toUpperCase(),
			handle: "bot@acme",
			words: PEER_WORDS,
		});
		expect(loadPeerVerification(configDir, OWN_ID, PEER_ID)?.words).toBe(
			PEER_WORDS,
		);
	});

	it("reads a corrupt record as no confirmation rather than throwing", () => {
		const configDir = makeConfigDir();
		recordPeerVerification(configDir, OWN_ID, {
			peerAgentId: PEER_ID,
			handle: "bot@acme",
			words: PEER_WORDS,
		});
		fs.writeFileSync(
			join(configDir, "keys", OWN_ID, "verified_peers", `${PEER_ID}.json`),
			"{ not json",
			"utf-8",
		);
		expect(loadPeerVerification(configDir, OWN_ID, PEER_ID)).toBeNull();
	});

	it("refuses a peer id that would escape the config dir", () => {
		const configDir = makeConfigDir();
		expect(() =>
			recordPeerVerification(configDir, OWN_ID, {
				peerAgentId: "../../escape",
				handle: null,
				words: PEER_WORDS,
			}),
		).toThrow();
	});
});

describe("buildPeerVerification", () => {
	it("flags a peer whose card words changed after a confirmation", async () => {
		const configDir = makeConfigDir();
		recordPeerVerification(configDir, OWN_ID, {
			peerAgentId: PEER_ID,
			handle: "bot@acme",
			words: PEER_WORDS,
		});
		const state = await buildPeerVerification(
			cardClient({
				card: {
					rine: {
						handle: "bot@acme",
						verification_words: "zoo zone zero zebra zap",
					},
				},
			}),
			configDir,
			OWN_ID,
			PEER_ID,
		);
		expect(state.wordsChangedSinceConfirmed).toBe(true);
		expect(state.confirmed?.words).toBe(PEER_WORDS);
		expect(state.peer.words).toBe("zoo zone zero zebra zap");
	});

	it("does not flag an unchanged peer", async () => {
		const configDir = makeConfigDir();
		recordPeerVerification(configDir, OWN_ID, {
			peerAgentId: PEER_ID,
			handle: "bot@acme",
			words: PEER_WORDS,
		});
		const state = await buildPeerVerification(
			cardClient({
				card: { rine: { handle: "bot@acme", verification_words: PEER_WORDS } },
			}),
			configDir,
			OWN_ID,
			PEER_ID,
		);
		expect(state.wordsChangedSinceConfirmed).toBe(false);
	});

	it("test_change_check_when_the_card_is_respaced_then_it_is_not_a_change", async () => {
		const configDir = makeConfigDir();
		recordPeerVerification(configDir, OWN_ID, {
			peerAgentId: PEER_ID,
			handle: "bot@acme",
			words: PEER_WORDS,
		});
		// The same five words, re-rendered. `sameWords` trims, lower-cases and
		// collapses whitespace for a written reason; a raw `!==` here would send
		// an operator looking for a key rotation that did not happen.
		const state = await buildPeerVerification(
			cardClient({
				card: {
					rine: {
						handle: "bot@acme",
						verification_words: ` ${PEER_WORDS.toUpperCase().replace(/ /g, "  ")} `,
					},
				},
			}),
			configDir,
			OWN_ID,
			PEER_ID,
		);
		expect(state.wordsChangedSinceConfirmed).toBe(false);
	});

	it("test_change_check_when_the_card_is_unreadable_then_nothing_is_claimed", async () => {
		const configDir = makeConfigDir();
		recordPeerVerification(configDir, OWN_ID, {
			peerAgentId: PEER_ID,
			handle: "bot@acme",
			words: PEER_WORDS,
		});
		const state = await buildPeerVerification(
			cardClient(new RineApiError(429, "Too many requests")),
			configDir,
			OWN_ID,
			PEER_ID,
		);
		// Nothing was compared, so nothing changed — and the surface says which.
		expect(state.wordsChangedSinceConfirmed).toBe(false);
		expect(state.peer.unreadable).toBe(true);
		const joined = peerVerificationLines(
			state,
			compareVerificationWordsForAgent(configDir, OWN_ID, null),
			"me@myorg",
		).join("\n");
		expect(joined).toContain("could not be read");
		expect(joined).not.toContain("publishes no public card");
	});

	it("does not flag a change when the peer simply has no card any more", async () => {
		const configDir = makeConfigDir();
		recordPeerVerification(configDir, OWN_ID, {
			peerAgentId: PEER_ID,
			handle: "bot@acme",
			words: PEER_WORDS,
		});
		const state = await buildPeerVerification(
			cardClient(new Error("404")),
			configDir,
			OWN_ID,
			PEER_ID,
		);
		expect(state.peer.published).toBe(false);
		expect(state.wordsChangedSinceConfirmed).toBe(false);
	});
});

describe("peerVerificationLines", () => {
	it("shows the peer's words and this agent's own, and never compares them", async () => {
		const configDir = makeConfigDir();
		const keys = generateAgentKeys();
		saveAgentKeys(configDir, OWN_ID, keys);
		const ownWords = verificationWordsForKey(keys.signing.publicKey);

		const state = await buildPeerVerification(
			cardClient({
				card: { rine: { handle: "bot@acme", verification_words: PEER_WORDS } },
			}),
			configDir,
			OWN_ID,
			PEER_ID,
		);
		const joined = peerVerificationLines(
			state,
			compareVerificationWordsForAgent(configDir, OWN_ID, ownWords),
			"me@myorg",
		).join("\n");

		expect(joined).toContain(`Their verification words: ${PEER_WORDS}`);
		expect(joined).toContain(`Your verification words: ${ownWords}`);
		expect(joined).toContain("read theirs back");
	});

	it("says a peer publishes no card instead of showing an empty value", async () => {
		const configDir = makeConfigDir();
		const state = await buildPeerVerification(
			cardClient(new RineApiError(404, "Agent not found")),
			configDir,
			OWN_ID,
			PEER_ID,
		);
		const joined = peerVerificationLines(
			state,
			compareVerificationWordsForAgent(configDir, OWN_ID, null),
			"me@myorg",
		).join("\n");
		expect(joined).toContain("publishes no public card");
	});

	it("names a stale confirmation plainly and says what to do", async () => {
		const configDir = makeConfigDir();
		recordPeerVerification(configDir, OWN_ID, {
			peerAgentId: PEER_ID,
			handle: "bot@acme",
			words: PEER_WORDS,
		});
		const state = await buildPeerVerification(
			cardClient({
				card: {
					rine: {
						handle: "bot@acme",
						verification_words: "zoo zone zero zebra zap",
					},
				},
			}),
			configDir,
			OWN_ID,
			PEER_ID,
		);
		const joined = peerVerificationLines(
			state,
			compareVerificationWordsForAgent(configDir, OWN_ID, null),
			"me@myorg",
		).join("\n");
		expect(joined).toContain(PEER_WORDS);
		expect(joined).toContain("names different words now");
		expect(joined).toContain("before relying on the");
	});
});
