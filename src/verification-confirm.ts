/**
 * The out-of-band compare/confirm flow, and the record it leaves behind.
 *
 * Recomputing an agent's own words proves the config dir and the server agree
 * about that agent's signing key. It says nothing about a **peer**: a peer's
 * words and any key you could fetch for it both come from the same server, so
 * deriving one from the other compares the server against itself.
 *
 * What closes that gap is two people. This flow puts the peer's published words
 * beside the words this client derives for its own agent, so each operator can
 * read their five words to the other over a channel the server does not carry —
 * a call, a meeting, a signed document — and then records that it happened.
 *
 * The record is local and advisory. It gates nothing: a peer that has never
 * been confirmed is still reachable, and a confirmation that has gone stale
 * still sends. What it buys is that a peer's words changing after a
 * confirmation is **visible**, instead of being a string nobody re-read.
 */

import * as fs from "node:fs";
import { join } from "node:path";
import { validatePathId } from "./crypto/keys.js";
import { sameWords } from "./crypto/verification-words.js";
import { RineApiError } from "./errors.js";
import type { HttpClient } from "./http.js";

/** One peer's words, as this operator confirmed them out of band. */
export interface PeerVerificationRecord {
	/** The peer agent the confirmation is about. */
	peerAgentId: string;
	/** The peer's handle when it was confirmed — for a human reading the file. */
	handle: string | null;
	/** The words that were read back. A later change to them makes this stale. */
	words: string;
	/** When the operator confirmed, ISO-8601. */
	confirmedAt: string;
}

/** A peer's published identity, as its public card states it. */
export interface PeerCardWords {
	handle: string | null;
	/** The words on the peer's card, or `null` when it publishes none. */
	words: string | null;
	/** `false` when the peer publishes no public card at all. */
	published: boolean;
	/**
	 * `true` when the card could not be READ — a rate limit, a 5xx, a network
	 * failure. Distinct from `published: false`, which is the peer's own answer
	 * (a 404). Collapsing the two renders a positive claim about the peer out of
	 * this client's own bad luck, and silently suppresses
	 * {@link PeerVerificationState.wordsChangedSinceConfirmed}, which is the one
	 * warning the confirmation record exists to produce.
	 */
	unreadable: boolean;
}

/** Everything the compare/confirm verb renders for one peer. */
export interface PeerVerificationState {
	peerAgentId: string;
	peer: PeerCardWords;
	/** A previous confirmation for this peer, or `null`. */
	confirmed: PeerVerificationRecord | null;
	/**
	 * `true` when this peer was confirmed before and its card's words have
	 * changed since — the one condition the record exists to make visible.
	 *
	 * Only ever true against words actually read. When the card could not be read
	 * ({@link PeerCardWords.unreadable}) this is `false` because nothing was
	 * compared, NOT because nothing changed, and a surface must say so rather
	 * than let a held confirmation read as still good.
	 */
	wordsChangedSinceConfirmed: boolean;
}

/** Where one agent's peer confirmations live. */
function peersDir(configDir: string, agentId: string): string {
	validatePathId(agentId, "agent ID");
	return join(configDir, "keys", agentId, "verified_peers");
}

function peerFile(
	configDir: string,
	agentId: string,
	peerAgentId: string,
): string {
	validatePathId(peerAgentId, "peer agent ID");
	// The server spells agent ids lower-case; `validatePathId` accepts either,
	// so the file name is normalised to keep one record per peer.
	return join(
		peersDir(configDir, agentId),
		`${peerAgentId.toLowerCase()}.json`,
	);
}

/**
 * The confirmation this agent holds for a peer, or `null` if there is none.
 *
 * An unreadable or malformed record reads as no confirmation: it is advisory
 * state, and refusing to run the verb over a corrupt file would be worse than
 * asking the operator to confirm again.
 */
export function loadPeerVerification(
	configDir: string,
	agentId: string,
	peerAgentId: string,
): PeerVerificationRecord | null {
	const path = peerFile(configDir, agentId, peerAgentId);
	try {
		const parsed = JSON.parse(fs.readFileSync(path, "utf-8")) as
			Partial<PeerVerificationRecord> | undefined;
		if (!parsed || typeof parsed.words !== "string") return null;
		return {
			peerAgentId: peerAgentId.toLowerCase(),
			handle: typeof parsed.handle === "string" ? parsed.handle : null,
			words: parsed.words,
			confirmedAt:
				typeof parsed.confirmedAt === "string" ? parsed.confirmedAt : "",
		};
	} catch {
		return null;
	}
}

/**
 * Record that an operator read a peer's words back and they agreed.
 *
 * @returns The record as written, so a caller can render it verbatim.
 */
export function recordPeerVerification(
	configDir: string,
	agentId: string,
	peer: { peerAgentId: string; handle: string | null; words: string },
): PeerVerificationRecord {
	const record: PeerVerificationRecord = {
		peerAgentId: peer.peerAgentId.toLowerCase(),
		handle: peer.handle,
		words: peer.words,
		confirmedAt: new Date().toISOString(),
	};
	const dir = peersDir(configDir, agentId);
	fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
	const path = peerFile(configDir, agentId, peer.peerAgentId);
	fs.writeFileSync(path, JSON.stringify(record), "utf-8");
	fs.chmodSync(path, 0o600);
	return record;
}

/**
 * Read a peer's published words off its public agent card.
 *
 * Public by design — the card is what the peer's operator can point anyone at,
 * which is why this flow needs no server change. An agent with no public card
 * publishes no words, and that is a state to render, not an error.
 *
 * 🔴 A 404 and a failure are two different answers and are kept apart. Only a
 * 404 is the peer saying it publishes nothing; the public directory is rate
 * limited, so a 429 — or a 5xx, or a dropped connection — folded into the same
 * value would print "this peer publishes no public card" as a fact about the
 * peer, and would suppress the stale-confirmation warning at the same time.
 */
export async function fetchPeerCardWords(
	client: HttpClient,
	peerAgentId: string,
): Promise<PeerCardWords> {
	let body: unknown;
	try {
		body = await client.get(`/directory/agents/${peerAgentId}`);
	} catch (err) {
		const absent = err instanceof RineApiError && err.status === 404;
		return {
			handle: null,
			words: null,
			published: false,
			unreadable: !absent,
		};
	}
	const envelope = body as { card?: Record<string, unknown> } | undefined;
	const card = (envelope?.card ?? body) as Record<string, unknown> | undefined;
	const rine = (card?.rine ?? {}) as Record<string, unknown>;
	return {
		handle: typeof rine.handle === "string" ? rine.handle : null,
		words:
			typeof rine.verification_words === "string"
				? rine.verification_words
				: null,
		published: true,
		unreadable: false,
	};
}

/** Fetch a peer's published words and fold in any confirmation already held. */
export async function buildPeerVerification(
	client: HttpClient,
	configDir: string,
	agentId: string,
	peerAgentId: string,
): Promise<PeerVerificationState> {
	const peer = await fetchPeerCardWords(client, peerAgentId);
	const confirmed = loadPeerVerification(configDir, agentId, peerAgentId);
	return {
		peerAgentId: peerAgentId.toLowerCase(),
		peer,
		confirmed,
		// `sameWords`, never `!==`: it trims, lower-cases and collapses whitespace
		// runs for a written reason, and this is the comparison that raises the
		// alarm. A card re-rendered with different spacing must not send an
		// operator looking for a key rotation that did not happen.
		wordsChangedSinceConfirmed:
			confirmed !== null &&
			peer.words !== null &&
			!sameWords(confirmed.words, peer.words),
	};
}
