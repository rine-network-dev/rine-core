/**
 * What rine says when a group message is sealed under a sender key this agent
 * does not hold — and the one predicate every surface recognises it by.
 *
 * There are two audiences and they are not the same one, which is why this
 * module exists at all:
 *
 * - **The library talks to itself** through {@link UNKNOWN_SENDER_KEY_CLAUSE}.
 *   `openGroup` throws it, and three recovery paths catch it to decide whether
 *   a one-shot key fetch is worth attempting. That string is a control signal
 *   with a UUID stapled to it, and it was open-coded as a regular expression in
 *   every one of those three places — so rewording the throw broke the recovery
 *   silently, which is exactly what a refusal must never be able to do.
 * - **rine talks to an operator** through {@link senderKeyUnavailableMessage}.
 *   That happens at the surface, once the recovery has run and failed, when the
 *   answer is final and there is something true to say about what to do next.
 *
 * So the translation is at the boundary, never at the throw: the internal
 * string stays byte-stable and is now written once, and the sentence an agent
 * reads is composed here on the model `group-words.ts` and `vote-words.ts` set.
 *
 * It lives in `rine-core` rather than the TypeScript SDK for that module's
 * stated reason: the CLI and the MCP server depend on core and not on the SDK,
 * so a constant that lived only in the SDK is one they could only re-declare.
 */

/**
 * The clause the sender-key open throws when it holds no state for an id.
 *
 * 🔴 Internal vocabulary, not an operator sentence — never print it. It is the
 * *only* thing that tells "the key material has not arrived yet, go and fetch
 * it" apart from every other decrypt failure, and the id after it is what the
 * fetch targets, so it is matched by {@link unknownSenderKeyId} and by nothing
 * hand-rolled.
 *
 * Composed into the throw rather than repeated at it, so the matcher and the
 * thrower cannot drift apart.
 */
export const UNKNOWN_SENDER_KEY_CLAUSE = "unknown sender key id: ";

/**
 * The sender key id an "unknown sender key" failure names, or null for any
 * other error.
 *
 * The shared replacement for three identical open-coded regexes. Returning the
 * id rather than a boolean is what lets a caller stay a single expression: the
 * id is the recovery's target, and every call site needed both answers.
 */
export function unknownSenderKeyId(err: unknown): string | null {
	if (!(err instanceof Error)) return null;
	if (!err.message.startsWith(UNKNOWN_SENDER_KEY_CLAUSE)) return null;
	const id = err.message.slice(UNKNOWN_SENDER_KEY_CLAUSE.length);
	return id.length > 0 ? id : null;
}

/**
 * Discriminator carried on every {@link SenderKeyUnavailableError}.
 *
 * A stable field rather than a name, so a consumer that catches this across a
 * bundle boundary — where two copies of `rine-core` make `instanceof` answer
 * false — still has something to branch on that is not the sentence's words.
 *
 * Exported because it is also the value of the SDKs' `decrypt_error_code`: a
 * row that could not be opened carries this code beside the sentence, and a
 * renderer decides which tier to print by comparing against this constant.
 * Comparing against the sentence's words instead is the stringly-typed API the
 * whole module exists to remove — and the words are meant to be rewritten.
 *
 * 🔴 It means the verdict, not the symptom: it is set only where the one-shot
 * recovery has already run and come back with nothing (see
 * {@link SenderKeyUnavailableError}). A failure that never got that far is not
 * this code.
 */
export const SENDER_KEY_UNAVAILABLE_CODE = "sender_key_unavailable";

/**
 * The final answer to a group read whose sender key never arrived.
 *
 * Thrown only after the one-shot recovery has been given its turn, so it is a
 * verdict and not a retry hint. 🔴 Never mint it before that turn: the sentence
 * says the key is not coming through the path the caller would otherwise be
 * told to try, and ahead of the recovery that is not yet known. It IS honest on
 * the retirement short-circuit, where the scan takes nothing because a
 * retirement refuses everything it would have taken — which is why the sentence
 * below speaks of what this agent could take, never of a fetch it performed.
 *
 * Its `message` is the composed sentence, which is what a surface prints — the
 * class name is for a caller that wants to branch, and a surface that renders
 * `String(err)` instead of `err.message` would put "SenderKeyUnavailableError:"
 * in front of an explanation and turn it back into the noise it replaced.
 */
export class SenderKeyUnavailableError extends Error {
	readonly code = SENDER_KEY_UNAVAILABLE_CODE;

	constructor(
		readonly senderKeyId: string,
		readonly groupId: string | undefined,
		options?: { cause?: unknown },
	) {
		super(senderKeyUnavailableMessage(senderKeyId), options);
		this.name = "SenderKeyUnavailableError";
	}
}

/**
 * What an agent is told when the key this message needs is not here.
 *
 * Four clauses, in the order the seat-403 refusal set: what was refused, the
 * fact behind it, what to do instead, and what did and did not happen to the
 * world.
 *
 * Every clause is measured, not reassuring. The second names both ways the
 * state can be absent — never distributed, or retired by a leave —
 * and says the retirement lifts itself, because it does: the read path's scan
 * spends the marker as soon as the server names this agent a member again. The
 * third asks for a fresh post rather than a re-send of the old one, because a
 * distribution carries the key's *current* position: the sender's next post is
 * readable and this one is not, and the fourth clause says so rather than
 * letting an operator wait for a message that is never coming back. The old
 * Python twin promised a fetch instead — a remedy the SDK had already
 * performed before raising.
 */
export function senderKeyUnavailableMessage(senderKeyId: string): string {
	return (
		"rine cannot open this group message: it is sealed under sender key " +
		`${senderKeyId}, and this agent holds no key by that id. ` +
		"A sender key arrives in a distribution the sender addresses to each " +
		"member, and there is no distribution here this agent can take for that " +
		"key — either it was never sent to this agent, or this agent left the " +
		"group and its keys were retired with it, which refuses the ones it did " +
		"receive (a retirement lifts itself on the next read once the group " +
		"names this agent a member again). " +
		"Ask the sender to post to the group again: its next post distributes " +
		"the current key to every member without one, and everything it sends " +
		"from then on is readable. " +
		"This message stays sealed — a distribution carries the key's current " +
		"position and nothing earlier, so no later one reopens it. Nothing was " +
		"deleted, no other message was affected, and no key was consumed."
	);
}

/**
 * The same refusal, cut to one row of a render that carries many.
 *
 * A thread, an inbox or a stream renders N rows and cannot spend a paragraph on
 * each: eight unopenable rows is ~4.8 KB of identical prose, and on a surface
 * that feeds a model that is 4.8 KB of context bought for one fact. But
 * `[decrypt failed]` is a sentence-shaped nothing — it names no
 * cause and offers no move. This names both in the width available, and
 * {@link senderKeyExplainer} decides which of the two a row gets: the full
 * sentence on the render's first row carrying this cause, this on every row
 * after it. So the full sentence is never more than one step away, and
 * usually zero: it is on the first row of this same render, and failing that,
 * one single-message read of the row this marker sits on.
 *
 * 🔴 It carries no sender key id, no group id and no agent, and is printed
 * byte-identically on every row, so a reader cannot count distinct keys off a
 * render. The id rides on the once-per-render sentence,
 * which is parsed out of the caller's own ciphertext.
 *
 * 🔴 Byte-identical to the Python twin in `rine-sdk/src/rine/sender_key_words.py`,
 * which no gate binds to this one — `rine-sdk/tests/test_sender_key_refusal.py`
 * reads this source and pins it.
 */
export const SENDER_KEY_UNAVAILABLE_PREVIEW =
	"[no sender key: ask the sender to post to the group again]";

/**
 * The marker for a render that never let the recovery run.
 *
 * The repeat arm of {@link senderKeyNotRecoveredMessage}, and it exists because
 * one marker cannot serve both sentences: a render whose first row says "no
 * fetch went looking, so this is not a final answer" may not mark its remaining
 * rows with a remedy only a *final* answer has earned. Marked with
 * {@link SENDER_KEY_UNAVAILABLE_PREVIEW} they did exactly that. This names the
 * move that IS available to a render that skipped the recovery, and it is the
 * same move on every such surface: ask for that one message by id, where the
 * recovery is affordable and does run.
 */
export const SENDER_KEY_NOT_RECOVERED_PREVIEW =
	"[no sender key: read this message on its own to find out whether one is coming]";

/**
 * The move back to the recovery for a caller that switched it off — true only
 * where the reader holds the switch, i.e. a TypeScript SDK `decrypt` given
 * `retrySenderKey: false`. The default remedy of
 * {@link senderKeyNotRecoveredMessage}.
 */
export const RECOVERY_LEFT_ON_REMEDY =
	"read the message again with the sender-key recovery left on.";

/**
 * The same move phrased for a surface with no such switch to offer.
 *
 * A tool surface does not expose `retrySenderKey`, so naming the switch there
 * sent a reader looking for a control that surface does not have, while the
 * move that does work was one call away and unnamed. This names the shape
 * rather than any one verb, because it is the same shape wherever it is true:
 * `rine_read`, `rine message read`, `read()`.
 *
 * ⚠️ It is the INBOX PAGE that declines the recovery, and not many-row reads as
 * a class — this docstring used to say the latter and it was false of four
 * shipped surfaces. The one read that carries this remedy is the MCP inbox page
 * (`rine-mcp/src/tools/messaging-decrypt.ts`, re-exported verbatim by
 * OpenClaw), which opens each row with the plain `decryptGroupMessage` because
 * a round trip per row does not pay on a page. Every OTHER many-row group read
 * on both TypeScript stacks performs the recovery: the transcript read
 * (`crypto/thread-row.ts` → `decryptGroupMessageWithRecovery`, so the CLI, the
 * MCP server and OpenClaw), the SDK transcript read
 * (`rine-ts-sdk/src/resources/thread-row.ts`, `retrySenderKey: isGroup`, so
 * mastra and eve), and the SDK inbox (`resources/messages.ts`,
 * `retrySenderKey: true`). The Python SDK's transcript read performs it too —
 * `thread()` spends one distribution scan for the whole render — so the reader
 * that genuinely declines on that stack is `get_conversation_messages()`, which
 * hands rows to a caller's own renderer. It has no `retrySenderKey` to name
 * either: on Python the choice is which reader you call, not a flag you pass.
 */
export const SINGLE_MESSAGE_READ_REMEDY =
	"read this one message on its own, which does go looking before it answers.";

/**
 * What a caller is told when it declined the recovery.
 *
 * The one thing {@link senderKeyUnavailableMessage} may not say here: that no
 * distribution is coming. A decrypt that opted out of the one-shot fetch never
 * looked, so the verdict has not been earned and the remedy has not been ruled
 * out. This names the cause, says plainly that nothing went looking, and stops —
 * the alternative was printing {@link UNKNOWN_SENDER_KEY_CLAUSE}, the control
 * string, straight at a reader.
 *
 * `remedy` is the last clause, because the move back is the one part of this
 * sentence that is not the same everywhere. Both spellings are constants here —
 * {@link RECOVERY_LEFT_ON_REMEDY} and {@link SINGLE_MESSAGE_READ_REMEDY} — so a
 * surface picks one rather than writing a fifth sentence about sender keys.
 */
export function senderKeyNotRecoveredMessage(
	senderKeyId: string,
	remedy: string = RECOVERY_LEFT_ON_REMEDY,
): string {
	return (
		"rine cannot open this group message: it is sealed under sender key " +
		`${senderKeyId}, and this agent holds no key by that id. This read did ` +
		"not go looking for the distribution that carries it, so whether one is " +
		`waiting for this agent is unknown and this is not a final answer — ${remedy}`
	);
}

/**
 * The operator-facing refusal for an "unknown sender key" failure, or null
 * when the error is something else.
 *
 * The boundary translator itself: a surface calls this where it is about to
 * report a failure to a human or an agent, and passes anything it does not
 * recognise through untouched. `cause` keeps the original throw reachable for
 * a debugger without putting it in front of the reader.
 *
 * Two shapes arrive here and both are this failure: the raw clause thrown by
 * the sender-key open, and a {@link SenderKeyUnavailableError} the recovery
 * already translated — {@link decryptGroupMessageWithRecovery} throws the
 * second, so a surface downstream of it saw nothing to recognise until this
 * function knew both. The already-translated one is returned as it is, matched
 * on {@link SENDER_KEY_UNAVAILABLE_CODE} rather than `instanceof`, because two
 * copies of this module in one bundle make `instanceof` answer false.
 */
export function asSenderKeyUnavailable(
	err: unknown,
	groupId?: string,
): SenderKeyUnavailableError | null {
	if (
		typeof err === "object" &&
		err !== null &&
		(err as { code?: unknown }).code === SENDER_KEY_UNAVAILABLE_CODE
	) {
		return err as SenderKeyUnavailableError;
	}
	const senderKeyId = unknownSenderKeyId(err);
	if (senderKeyId === null) return null;
	return new SenderKeyUnavailableError(senderKeyId, groupId, { cause: err });
}
