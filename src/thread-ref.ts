/**
 * How a caller names the transcript it wants to read, in the one place every
 * TypeScript surface reads it.
 *
 * Every other group verb on this stack takes the group — a handle or a UUID.
 * The one that reads what the group SAID took a conversation UUID instead: the
 * id of a different entity, whose only source is a column in another verb's
 * output. A caller holding a group and reaching for the transcript had nothing
 * to name it with, so it named the group anyway, in a parameter typed
 * `uuid.UUID` on the server, and got a framework 422 back with no sentence in
 * it. The group reference is the missing spelling; this module is the contract
 * that admits it.
 *
 * It lives in `rine-core` for the reason `vote-words.ts` and `actor.ts` do: the
 * CLI and the MCP server depend on core and not on the SDK, so a contract that
 * lived only in the SDK is one they could only re-declare — and a refusal
 * re-declared is a refusal that drifts.
 *
 * 🔴 Nothing here reaches the network. Naming both references, naming neither,
 * or naming a conversation that cannot be a UUID are all decided locally,
 * before a request is spent: the whole point is that the worst error surface in
 * the product (a pydantic 422 rendered through an error formatter's
 * `status: detail` fallback) stops being reachable by the likeliest mistake.
 * The group resolution that follows a valid reference lives in
 * `resolve-group.ts`, and the read itself in `thread-read.ts`.
 */

import { parsesAsUuid } from "./resolve-handle.js";

/**
 * How one surface spells the two references, for the sentences it has to print.
 *
 * The same shape, and the same reason, as {@link ActorSurface} in `actor.ts`: a
 * refusal that names a parameter has to name it as the caller types it, or it
 * sends them to a spelling their surface does not accept. A CLI caller passes
 * `--group`; a tool call carries a JSON key.
 */
export interface ThreadRefSurface {
	/** How this surface spells the group reference: `--group`, `group`. */
	readonly group: string;
	/** How it spells the conversation: `<conversation-id>`, `conversation_id`. */
	readonly conversation: string;
}

/**
 * The spellings of the TypeScript surfaces that read a transcript.
 *
 * `sdk` is camelCase because that is what a TypeScript method takes; `tool` is
 * the JSON-schema spelling every model-facing surface shares.
 */
export const THREAD_REF_SURFACES = {
	cli: { group: "--group", conversation: "<conversation-id>" },
	sdk: { group: "group", conversation: "conversationId" },
	tool: { group: "group", conversation: "conversation_id" },
} as const satisfies Record<string, ThreadRefSurface>;

/** Which transcript a caller asked for, once exactly one reference was named. */
export type ThreadRef =
	| { readonly kind: "group"; readonly ref: string }
	| { readonly kind: "conversation"; readonly conversationId: string };

/**
 * The refusal when a caller names both references, or neither.
 *
 * One sentence for both arms, on the shipped precedent of
 * `INVITE_TARGET_REQUIRED` (`rine-hermes`) and its four twins: the mistake is
 * the same one — the caller has not said which of two shapes this call is — and
 * the answer is the same, so a second wording would only be a second thing to
 * keep in step.
 */
export function threadRefRequiredRefusal(
	surface: ThreadRefSurface = THREAD_REF_SURFACES.sdk,
): string {
	return (
		`Name exactly one of ${surface.group} (a group handle, name or UUID) or ` +
		`${surface.conversation} (a conversation UUID).`
	);
}

/**
 * The refusal when the conversation reference cannot be a conversation.
 *
 * 🔴 It names the parameter that DOES take a group, which is the whole of its
 * value: a caller that reached for the transcript holding a group made this
 * mistake because the verb offered nowhere to put one. Saying only "that is not
 * a UUID" would leave them exactly where they were. The three spellings that
 * parameter accepts are listed, because what the caller is missing is where to
 * put the reference they already hold — it cannot know their group.
 *
 * 🔴 **The placeholder ban, second rung — this site shipped the argument that
 * was overturned.** It used to print `group=#logistics@acme.rine.network`,
 * defended in the Python twin's docstring as *"a worked example teaches the
 * spelling; a template invites a placeholder"* — an argument drawn from the
 * same measurement and landing on the opposite side. That measurement found
 * the local part moved with the world's subject matter while the domain did not
 * move at all, so a printed domain is pasted verbatim. Rung 1 is unreachable
 * here for the reason the old docstring itself gave — this path holds no roster
 * and cannot derive the caller's org — so it takes rung 2 and describes the
 * three spellings instead of showing one. Not a slot either
 * (`check-model-facing-examples.mjs`'s `template-org` rule).
 *
 * Twin of `rine.thread_words.not_a_conversation_uuid`, to the word.
 */
export function notAConversationUuidRefusal(
	value: string,
	surface: ThreadRefSurface = THREAD_REF_SURFACES.sdk,
): string {
	return (
		`${surface.conversation} must be a conversation UUID; "${value}" is not ` +
		`one. To read a group, name the group instead — ${surface.group} takes a ` +
		`group's whole handle, a bare group name, or its UUID.`
	);
}

/**
 * Trimmed, with empty-after-trim treated as *absent*.
 *
 * Same rule and same reason as `normalizeActor`: an optional argument a
 * scaffolder or a shell left as the empty string is the shipped shape of "not
 * given", and reading it as given turns a missing reference into a malformed
 * one — the caller then gets a sentence about the value they did not pass.
 *
 * This is the one place the twin stacks differ by design: Python's
 * `refuse_if_two_transcript_references` asks `is not None`, so `group=""` is
 * "named" there. A TypeScript caller reaches this through a shell (`--group ""`
 * survives) or an untyped tool payload far more often than a Python one does,
 * and both stacks refuse the same call — only the sentence differs, and the one
 * this side prints is the one that fits what happened.
 */
function referenceGiven(value: string | null | undefined): string | undefined {
	if (value === undefined || value === null) return undefined;
	const trimmed = value.trim();
	return trimmed === "" ? undefined : trimmed;
}

/**
 * Decide which transcript was asked for, or refuse locally saying why.
 *
 * Exactly one of the two references, and a conversation reference has to be a
 * UUID. Both checks happen before any resolution and before any request, so a
 * caller that named the wrong thing spends nothing finding out.
 *
 * @throws {Error} Both or neither reference named
 *   ({@link threadRefRequiredRefusal}), or a conversation reference that cannot
 *   be a UUID ({@link notAConversationUuidRefusal}).
 */
export function resolveThreadRef(
	named: {
		readonly group?: string | null;
		readonly conversationId?: string | null;
	},
	surface: ThreadRefSurface = THREAD_REF_SURFACES.sdk,
): ThreadRef {
	const group = referenceGiven(named.group);
	const conversationId = referenceGiven(named.conversationId);

	if ((group === undefined) === (conversationId === undefined)) {
		throw new Error(threadRefRequiredRefusal(surface));
	}
	if (group !== undefined) return { kind: "group", ref: group };
	// Narrowing only: the equality above already established that exactly one of
	// the two is present, so this branch has a conversation reference.
	const id = conversationId as string;
	// `parsesAsUuid`, never the strict `UUID_RE`: the server types that path
	// parameter `uuid.UUID`, which has always accepted the dashless, `urn:uuid:`
	// and braced spellings too. Refusing those here would be a capability
	// removal wearing a validation fix.
	if (!parsesAsUuid(id)) {
		throw new Error(notAConversationUuidRefusal(id, surface));
	}
	return { kind: "conversation", conversationId: id };
}
