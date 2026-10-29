import type { GroupRead } from "./api-types.js";
import {
	groupIsMls,
	groupMlsInitInFlight,
	groupMlsNeverFounded,
} from "./crypto/group-predicates.js";
import {
	MLS_CIPHER_SUITE_XWING,
} from "./crypto/mls.js";
import {
	ENCRYPTION_VERSIONS,
	type GroupEncryptionVersion,
} from "./encryption-versions.js";
import type { CreatedGroupMlsFields } from "./group-create-format.js";
import {
	type UnfoundedGroupRepair,
	unfoundedGroupNote,
} from "./mls-recovery-format.js";

/**
 * Which cryptography a group actually runs, and whether it is post-quantum.
 *
 * An operator creating `--enrollment open` gets Sender Keys, not MLS, and
 * nothing said so — not the printed table and not `--json`. The server
 * keeps open enrollment off the MLS path, because MLS would hand an unattested
 * joiner a cryptographic seat. So the choice of enrollment is also a choice of
 * crypto, and it is made at create time by someone who has no way to see that.
 *
 * 🔴 The enrollment policy is not the whole of the answer, and reading it as if
 * it were is how this told a closed group it was running post-quantum MLS while
 * its messages carried `sender-key-v1`. What a group RUNS is the MLS latch and
 * the init window; what it was created FOR is `mls_enabled`. A group can have
 * the second and not the first, permanently, and that group is the one every
 * field here used to describe wrongly — so it gets both halves of the answer:
 * the sender keys it runs, and the MLS it has not got.
 *
 * This lives in `rine-core` because more than one surface answers the question:
 * the CLI prints it, and the MCP removal verbs branch their sentence on it.
 */
export interface GroupEncryption {
	regime: "mls" | "sender-key";
	/** The `encryption_version` every message in this group carries. */
	version: GroupEncryptionVersion;
	post_quantum: boolean;
	/** True while the group is an MLS group whose ratchet tree is not founded yet. */
	pending: boolean;
	/**
	 * True when the group was created to run MLS and its ratchet tree was never
	 * founded — so the four fields above describe **sender keys**, which is what
	 * this group's messages really carry, and this is the rest of the answer.
	 *
	 * Its own field rather than a third `regime` value: `regime` answers which
	 * cryptography the traffic runs and has exactly two, and a third value would
	 * be read by every consumer that switches on it — including two matrix
	 * graders and `retirementMessage` — as a regime rine does not have.
	 */
	mls_never_founded: boolean;
	summary: string;
}

const XWING = "rine's post-quantum X-Wing ciphersuite";
const UNFOUNDED = " The group's ratchet tree is not founded yet.";

/** The suite a group runs: X-Wing by name, any value this client does not know by its number. */
function suiteLabel(suite: number): string {
	return suite === MLS_CIPHER_SUITE_XWING
		? XWING
		: `ciphersuite 0x${suite.toString(16).padStart(4, "0")}`;
}

/**
 * The head BOTH sender-key answers open on — the ordinary one below, and the
 * never-founded one composed at {@link groupEncryption}.
 *
 * 🔴 Its Python twin is `rine.format._SENDER_KEYS_HEAD` and the two are byte
 * for byte identical, because both stacks build the never-founded summary as
 * this head plus {@link unfoundedGroupNote}: a rewording on one stack alone is
 * two products describing one group in two different first sentences.
 * It had already drifted once — `Sender Keys — NOT
 * post-quantum.` here against `Sender Keys, which are NOT post-quantum.` there,
 * on the one string the two stacks share — and nothing looked, because the twin
 * suite bound the note and not the head it is appended to. It is bound now, by
 * `rine-core/test/mls-recovery-twin.test.ts`.
 */
const SENDER_KEY_HEAD = "Sender Keys — NOT post-quantum.";

/**
 * 🔴 It names BOTH ways to be here, and its Python twin
 * `rine.format._ENCRYPTION_WORDS["sender-key"]` names the same two. Naming only
 * open enrollment tells the operator of a closed `--no-mls` group that their
 * private group's encryption is explained by who can join it — a misstatement
 * about the policy, on the one row that has no open enrollment to blame.
 */
const SENDER_KEY_SUMMARY =
	`${SENDER_KEY_HEAD} A group runs them whenever it has no` +
	" ratchet tree: open-enrollment groups by design, because the server keeps" +
	" open enrollment off the MLS path rather than hand an unattested joiner a" +
	" cryptographic seat, and a closed group created without MLS too. Removal" +
	" here is enforced by rine's delivery filter, not by cryptography.";

/**
 * A group as a client holds it: the row, plus the founding this client has just
 * run and the row it is holding cannot show.
 *
 * `mlsAdmission` is what `initMlsGroup` returned, and it is present on exactly
 * one path — a create whose MLS founding LANDED. Every re-read of the group
 * carries the latch instead and needs none of this, which is why the field is
 * optional and why a plain `GroupRead` satisfies this type unchanged.
 *
 * 🔴 It is the ONE create-result field the answer below reads. The other,
 * `mlsInit` — a founding this client watched FAIL — is deliberately not here:
 * that state's honest answer is that the server may refuse every non-MLS send
 * into the group for the next 15 minutes, and {@link GroupEncryption}'s
 * two-valued `regime` cannot say so. It is `createdGroupMls`'s second arm, and a
 * surface that can observe a failed init renders that instead.
 */
export type RenderableGroup = GroupRead &
	Pick<CreatedGroupMlsFields, "mlsAdmission">;

/**
 * 🔴 The arms are the shared predicates, in the order Python's
 * `group_encryption` asks them, and never a second reading of the MLS columns.
 * Branching on `enrollment_policy === "open"` alone answered for FOUR different
 * groups at once — an init in flight, a tree never founded, a closed group
 * created without MLS, and a founded one — and told three of them they were
 * running post-quantum MLS while their messages carried `sender-key-v1`.
 *
 * `repair` is how THIS surface spells the verb that founds a group's MLS state,
 * and it reaches exactly one arm — the never-founded one, the only state that
 * has a remedy. It defaults to `"none"`, which is an answer and not a silence:
 * six surfaces have no verb that founds a group, and the sentence they get says
 * so rather than naming somebody else's. The clause never mentions a sync,
 * because the caller here is describing a group and not reporting one.
 */
export function groupEncryption(
	g: RenderableGroup,
	repair: UnfoundedGroupRepair = "none",
): GroupEncryption {
	// The founding LANDED and only the confirming re-read after it was refused:
	// the row is then the PRE-init one, and every predicate below reads it as a
	// group whose ratchet tree was never founded — so the operator is sent to
	// found what this client founded seconds ago. The admission is what the
	// founding returned and the only thing that says otherwise. Its Python twin
	// asks the same question in the same place (`rine.format.group_encryption`,
	// the `mls_admission` arm), and `createdGroupMls` asks it of the same field.
	const founded = groupIsMls(g) || g.mlsAdmission !== undefined;
	// A latched group, and one whose init is in flight: both really do carry
	// `mls-v1`, because the server refuses a sender-key send into either. The
	// suite is the server's own `mls_cipher_suite`. A group still founding
	// carries none, and neither does one whose founding just landed (the row
	// predates the init): both will run the one suite rine speaks.
	if (founded || groupMlsInitInFlight(g)) {
		const suite = g.mls_cipher_suite ?? MLS_CIPHER_SUITE_XWING;
		const postQuantum = suite === MLS_CIPHER_SUITE_XWING;
		const pending = !founded;
		return {
			regime: "mls",
			version: ENCRYPTION_VERSIONS.MLS_V1,
			post_quantum: postQuantum,
			pending,
			mls_never_founded: false,
			summary: `MLS (RFC 9420) on ${suiteLabel(suite)}.${pending ? UNFOUNDED : ""}`,
		};
	}
	// Created to run MLS, never founded. Every field below is the traffic, and
	// the traffic is sender keys: the server does not freeze this group, so a
	// send into it takes the sender-key branch and is accepted. `mls_never_founded`
	// is the half `regime` cannot carry.
	if (groupMlsNeverFounded(g)) {
		return {
			regime: "sender-key",
			version: ENCRYPTION_VERSIONS.SENDER_KEY_V1,
			post_quantum: false,
			pending: false,
			mls_never_founded: true,
			summary: `${SENDER_KEY_HEAD} ${unfoundedGroupNote(repair)}`,
		};
	}
	// Everything left runs sender keys and was never going to run anything else:
	// an open group, or a closed one whose `mls_enabled` says it was created
	// without MLS. The summary names neither policy as the reason, because both
	// land here.
	return {
		regime: "sender-key",
		version: ENCRYPTION_VERSIONS.SENDER_KEY_V1,
		post_quantum: false,
		pending: false,
		mls_never_founded: false,
		summary: SENDER_KEY_SUMMARY,
	};
}

/** One line an operator can read the crypto regime off, table or not. */
export function encryptionLine(
	g: RenderableGroup,
	repair: UnfoundedGroupRepair = "none",
): string {
	return `Encryption: ${groupEncryption(g, repair).summary}`;
}
