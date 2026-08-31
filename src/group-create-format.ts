/**
 * What a client says about the group it has just created.
 *
 * Its own module rather than part of `group-format.ts`, because it answers a
 * different question from a different input. `groupEncryption` describes a group
 * ROW — the durable object every surface can re-read at any time — while this
 * reads a CREATE RESULT, which exists for one call and carries two fields the
 * row does not have and never will. Keeping the two apart is also what keeps
 * both files inside the ~200-line budget.
 *
 * It lives in `rine-core` because two published agent surfaces render this
 * answer — `rine-mastra` and `rine-eve` — and they depend on this package and
 * on the TS SDK, not on each other. It arrived here as two hand-synchronised
 * byte-identical copies, which is the drift class the twin tests exist to catch.
 */

import type { GroupRegimeFields } from "./crypto/group-predicates.js";
import {
	groupIsMls,
	groupMlsInitInFlight,
	groupMlsNeverFounded,
} from "./crypto/group-predicates.js";
import { MLS_PENDING_SELF_CLEAR_SECONDS } from "./crypto/mls-init-in-flight.js";
import type { MlsAdmissionResult } from "./mls-admission.js";
import {
	type UnfoundedGroupRepair,
	unfoundedGroupNote,
} from "./mls-recovery-format.js";

/**
 * The fields {@link createdGroupMls} reads off a create result, and nothing
 * else.
 *
 * Structural rather than the TS SDK's concrete `GroupCreateResult`, for the
 * reason {@link GroupRegimeFields} gives about the predicates it extends: this
 * package sits UNDER the SDK, so it cannot name that type, and a shape stated
 * as the fields it reads is satisfied by the SDK's zod-inferred row, by a
 * projection of it, and by a hand-built fixture alike.
 *
 * Both extra fields are sensed for PRESENCE only — neither is read — because
 * presence is the whole of what they say. `mlsInit` is declared as its failed
 * shape rather than as `unknown` so a caller cannot hand this a landed init and
 * have it graded as a failure.
 */
export interface CreatedGroupMlsFields extends GroupRegimeFields {
	/** Present exactly when an MLS init ran and its founding commit landed. */
	mlsAdmission?: MlsAdmissionResult;
	/** Present exactly when an attempted MLS init did NOT land. */
	mlsInit?: { ok: false };
}

/**
 * The two halves of a create head's encryption answer.
 *
 * `mode` is the one field the head interpolates — `${mode} E2EE` — and `note` is
 * the rest of the sentence when one field cannot carry it. An empty `note` is
 * the normal case, not a silence: three of the four states below say everything
 * they have to say in the mode field.
 */
export interface CreatedGroupMls {
	mode: string;
	note: string;
}

/** How the create head names a founding this client watched fail. */
export const MLS_FOUNDING_FAILED_MODE = "MLS (founding failed)";

/**
 * The rest of that answer, and deliberately NOT `unfoundedGroupNote()`.
 *
 * 🔴 That note states the group's messages ARE sealed with sender keys, which
 * is exactly the half this state cannot promise: an init POST that reached the
 * server before the failure leaves `mls_pending` set, and the server then
 * refuses every non-`mls-v1` send into the group until its own self-clear runs.
 * The create response is minted BEFORE the init, so its `mls_pending` is false
 * on both sides of that fork and cannot tell them apart — this names the fork
 * instead of guessing which side of it the caller is on, the same way its
 * Python twin `rine.format._ENCRYPTION_WORDS["mls-failed"]` does. The window is
 * this package's own constant rather than a retyped number.
 *
 * It names no verb at all, and no `repair` word reaches it: the two ways out of
 * a failed init are different operations on the two sides of that same fork, so
 * naming either one here would be the guess the sentence exists to avoid.
 * {@link UnfoundedGroupRepair} reaches the never-founded arm only — the one
 * state with a single remedy — exactly as it reaches one arm of
 * `groupEncryption`. Both surfaces that render this note today, `rine-mastra`
 * and `rine-eve`, have no verb that founds a group either way.
 */
export const MLS_FOUNDING_FAILED_NOTE =
	"The group has not got the MLS it was created for and is NOT post-quantum." +
	" If the founding attempt reached the server before it failed, the server" +
	" refuses every non-MLS send here until it clears the half-started init," +
	` within ${Math.round(MLS_PENDING_SELF_CLEAR_SECONDS / 60)} minutes; after` +
	" that the group runs sender keys, like any group with no ratchet tree.";

/**
 * What the create head says a brand-new group runs, plus the rest of the answer
 * when one field is not enough for it.
 *
 * 🔴 Read off the CREATE RESULT, never off the group row alone. Both MLS steps
 * `groups.create` runs are best-effort and the group is created either way, so
 * the row this head renders is the PRE-init one on two different paths —
 * {@link groupMlsNeverFounded} answers `true` to that row while being FALSE of
 * both:
 *
 *   - the founding LANDED and only the re-read that follows it was refused.
 *     The tree exists, the group carries `mls-v1`, and the server refuses a
 *     sender-key send into it. `mlsAdmission` is present exactly here, because
 *     it is what the founding returned — and the leaves it lists are printed a
 *     few lines below by its caller, so a head that also said "never founded"
 *     contradicted itself inside one message.
 *   - the founding did NOT land. `mlsInit` is present exactly here, and
 *     {@link MLS_FOUNDING_FAILED_NOTE} says why that is not the same state.
 *
 * The mode field never restates what the note says: the abbreviated
 * parenthetical a list row uses (`groupModeLabel`, declared per rendering
 * package) exists because a row has no space for the sentence, and saying it
 * twice in two phrasings inside one answer is what a model parrots back instead
 * of acting on.
 *
 * `repair` is how the CALLER spells the verb that founds a group's MLS state,
 * and it reaches exactly one arm — the never-founded one — for the same reason
 * `groupEncryption` takes it and passes it to the same place. It defaults to
 * `"none"`, which is an answer and not a silence: a surface with no founding
 * verb gets a sentence that says so rather than one naming somebody else's.
 */
export function createdGroupMls(
	g: CreatedGroupMlsFields,
	repair: UnfoundedGroupRepair = "none",
): CreatedGroupMls {
	if (g.mlsAdmission !== undefined) return { mode: "MLS", note: "" };
	if (g.mlsInit !== undefined)
		return { mode: MLS_FOUNDING_FAILED_MODE, note: MLS_FOUNDING_FAILED_NOTE };
	// The plain regime word, because the note below carries the qualification a
	// list row compresses into a parenthetical.
	if (groupMlsNeverFounded(g))
		return { mode: "sender-key", note: unfoundedGroupNote(repair) };
	// Everything left: the create reported no MLS outcome either way, and the
	// group is not one created for an MLS it has not got. The never-founded
	// answer a list row's label would give is unreachable here — the arm above
	// took it — so what is left is the same two-answer question that label asks
	// first, and the head asks it of the row because nothing else is left to ask.
	return {
		mode: groupIsMls(g) || groupMlsInitInFlight(g) ? "MLS" : "sender-key",
		note: "",
	};
}
