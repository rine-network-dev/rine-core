/**
 * Rendering an agent's verification words on a surface that holds its keys.
 *
 * `crypto/verification-words.ts` derives the words and compares them; this is
 * the half every display surface shares — where the held key comes from, and
 * what the four outcomes read like in a terminal. It lives here rather than on
 * each surface because there are ten of them, and ten copies of a mismatch
 * explanation is ten explanations that drift.
 *
 * 🔴 The held key is loaded from the config dir, never fetched. A key read back
 * from `GET /agents/{id}/keys` is the server's own assertion, so words derived
 * from it agree with the server's by construction and the comparison says
 * nothing at all.
 */

import { loadAgentKeys } from "./crypto/keys.js";
import {
	type VerificationWordsComparison,
	compareVerificationWords,
} from "./crypto/verification-words.js";
import type { PeerVerificationState } from "./verification-confirm.js";

/**
 * Compare an agent's asserted words against the ones its local keys derive.
 *
 * @param configDir Config dir holding this agent's keys.
 * @param agentId The agent the words belong to.
 * @param assertedWords The words the server named, e.g. from an agent record.
 * @returns Both values and why either is absent. A config dir with no usable
 *   signing key for the agent yields `"not-computed"` rather than throwing:
 *   whether this client can recompute is a state to render, not a failure.
 */
export function compareVerificationWordsForAgent(
	configDir: string,
	agentId: string,
	assertedWords: string | null | undefined,
): VerificationWordsComparison {
	let heldKey: Uint8Array | null = null;
	try {
		heldKey = loadAgentKeys(configDir, agentId).signing.publicKey;
	} catch {
		// Missing, corrupt, or a config dir belonging to a different agent —
		// all one state to a reader: this client cannot recompute.
		heldKey = null;
	}
	return compareVerificationWords(heldKey, assertedWords);
}

/**
 * The lines a text surface prints for a comparison, in order.
 *
 * A mismatch is a designed state: both values render, the explanation is plain
 * and names what usually causes it, and nothing here gates sending. An empty
 * array means there is nothing to say — no local key and no asserted words.
 *
 * @param comparison The result of {@link compareVerificationWordsForAgent}.
 * @param label Prefix for the words line; surfaces that align a column of
 *   labels pass their own.
 */
export function verificationWordsLines(
	comparison: VerificationWordsComparison,
	label = "Verification words",
): string[] {
	switch (comparison.status) {
		case "match":
			return [`${label}: ${comparison.computed}`];
		case "mismatch":
			return [
				`${label} (this client): ${comparison.computed}`,
				`${label} (server):       ${comparison.asserted}`,
				"These differ. The words are derived from an agent's signing key, so the",
				"server holds a different signing key than this config dir does. A config",
				"dir copied from another machine, or a signing key republished elsewhere,",
				"both look like this. Messages still send and arrive.",
				"Publish this agent's public key again, or point RINE_CONFIG_DIR at the",
				"keys it was created with.",
			];
		case "not-computed":
			if (comparison.asserted === null) return [];
			return [
				`${label} (server): ${comparison.asserted}`,
				"Not recomputed here: this config dir holds no usable signing key for this",
				"agent, so these words are the server's statement rather than this client's.",
			];
		case "not-asserted":
			return [
				`${label}: ${comparison.computed}`,
				"The server names no words for this agent, so there is nothing to compare",
				"against.",
			];
	}
}

/**
 * The lines the compare/confirm verb prints: a peer's published words beside
 * this agent's own, and whatever confirmation is already on record.
 *
 * The two values are deliberately not compared with each other — they belong to
 * two different agents and will never be equal. What compares them is two
 * operators reading them aloud, which is the whole point of the flow.
 *
 * @param state The peer's card words plus any confirmation already held.
 * @param own This agent's own words, recomputed from the key it holds.
 * @param ownHandle This agent's handle, for the operator reading the output.
 */
export function peerVerificationLines(
	state: PeerVerificationState,
	own: VerificationWordsComparison,
	ownHandle: string,
): string[] {
	const peerName = state.peer.handle ?? state.peerAgentId;
	const lines: string[] = [`Peer: ${peerName}`];

	if (state.peer.unreadable) {
		lines.push(
			"  This peer's public card could not be read just now, so there are no",
			"  words to compare against. That is this end's answer, not the peer's —",
			"  the public directory is rate limited. Try again shortly.",
		);
	} else if (!state.peer.published) {
		lines.push(
			"  This peer publishes no public card, so it names no words to compare.",
		);
	} else if (state.peer.words === null) {
		lines.push("  Their card names no verification words.");
	} else {
		lines.push(`  Their verification words: ${state.peer.words}`);
	}

	lines.push(`You: ${ownHandle}`);
	for (const line of verificationWordsLines(own, "  Your verification words")) {
		lines.push(line);
	}

	lines.push(
		"",
		"Read your words to the peer's operator over a channel rine does not carry,",
		"and have them read theirs back. What you hear should be the peer's words",
		"above; what they hear should be the words on your card. Both matching means",
		"each of you holds the key the other's card publishes.",
	);

	if (state.confirmed !== null) {
		lines.push(
			"",
			`Confirmed on ${state.confirmed.confirmedAt} against: ${state.confirmed.words}`,
		);
		if (state.peer.unreadable) {
			lines.push(
				"Whether their card still names those words could not be checked, because",
				"the card could not be read. This confirmation is neither confirmed nor",
				"stale right now.",
			);
		} else if (state.wordsChangedSinceConfirmed) {
			lines.push(
				"Their card names different words now. A peer that republished its signing",
				"key looks like this. Read the current words back before relying on the",
				"earlier confirmation.",
			);
		}
	}

	return lines;
}
