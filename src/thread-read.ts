/**
 * Fetching a transcript, by whichever of the two things it was named by.
 *
 * `crypto/thread.ts` owns what a row RENDERS as; this owns where the rows come
 * from. The two shapes are one call for a caller because they are one question:
 * a group and a conversation are different entities, but "show me this
 * transcript" is the same request either way, and every surface that had to
 * branch on it grew its own branch.
 *
 * 🔴 The group-keyed read and the conversation-keyed read do NOT return the
 * same rows for a group that predates the group⇄conversation cutover (alembic
 * 0015 is schema-only and forward-only, so both message shapes are permanent).
 * The group-keyed one is the group's own history and is the complete
 * answer; the conversation-keyed one cannot reach a pre-cutover post at all.
 * Anything comparing the two pins a tolerance, never an equality.
 */

import type { ThreadRow } from "./crypto/thread.js";
import type { HttpClient } from "./http.js";
import { resolveGroupUuid } from "./resolve-group.js";
import type { ThreadRef } from "./thread-ref.js";

/** One bounded window of a transcript, as the server returns it. */
export interface ThreadPage {
	messages: ThreadRow[];
	truncated?: boolean;
}

export interface ReadThreadOptions {
	/** Max most-recent turns to return. The server applies its own default. */
	readonly limit?: number | string;
	/** `X-Rine-Agent` and anything else the caller carries. */
	readonly extraHeaders?: Record<string, string>;
}

/**
 * The route that reads one conversation's rows.
 *
 * 🔴 Exported as a builder, and both stacks' readers go through it, because
 * this route is written down in more than one package: `readThreadPage` below
 * and `rine-ts-sdk`'s `transcriptPath` each used to hold their own copy of the
 * string. Two copies of a route is how one of them survives a server-side
 * rename. The Python SDK made the same split this round
 * (`rine-sdk/src/rine/thread_words.py`), and the contract gate reads both
 * (`tests/helpers_client_paths.py::CORE_ROUTE_BUILDERS`).
 */
export function conversationTranscriptPath(conversationId: string): string {
	return `/conversations/${conversationId}/messages`;
}

/**
 * The route that reads one group's OWN rows, keyed by the group.
 *
 * Not the group's conversation: see this module's header for why the two
 * legitimately disagree on a pre-cutover group.
 */
export function groupTranscriptPath(groupId: string): string {
	return `/groups/${groupId}/messages`;
}

/**
 * Read the most-recent window of a transcript.
 *
 * A group reference is resolved first ({@link resolveGroupUuid}) and then read
 * by the group's own id. What that resolve costs is per SPELLING:
 * a UUID is one indexed `GET /groups/{id}`, a handle is one
 * `GET /groups?handle=`, and a bare name is the org's `GET /groups` roster. The
 * roster is what tells an unknown reference from a real one, so the other two
 * spellings buy it only when their own read answered nothing — and what it buys
 * differs between them. A UUID names the group by identity, so a roster read
 * after it can only ever say which groups there were instead: refusal, never
 * resolution. A handle can still RESOLVE on it — the fallback puts the local
 * part of an unmatched `#name@org` through the same tiers a bare name gets
 * (`resolveGroupByHandle`, `./resolve-group.ts`), which is one roster read and
 * two possible endings. The server re-gates the transcript read on live group
 * membership, so nothing here decides who may see what.
 *
 * The caller's headers ride BOTH legs. `GET /groups` selects on the org today,
 * so the acting agent changes nothing about which group a name resolves to —
 * but a resolve attributed to the client's default agent sitting next to a read
 * attributed to the named one is two different actors answering one call, and
 * the day that route becomes agent-scoped it would resolve the wrong group
 * silently.
 */
export async function readThreadPage(
	client: HttpClient,
	ref: ThreadRef,
	opts: ReadThreadOptions = {},
): Promise<ThreadPage> {
	const params: Record<string, string | number | boolean> = {};
	if (opts.limit !== undefined) params.limit = opts.limit;

	const path =
		ref.kind === "group"
			? groupTranscriptPath(await resolveGroupUuid(client, ref.ref, opts.extraHeaders))
			: conversationTranscriptPath(ref.conversationId);
	return (await client.get(path, params, opts.extraHeaders)) as ThreadPage;
}
