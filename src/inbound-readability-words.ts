/**
 * The verdict vocabulary of {@link openInbound}: what a runtime is told about an
 * inbound envelope it may not be able to open.
 *
 * Split out of `inbound-readability.ts` for the file-size budget, on the same
 * terms as every other `*-words.ts` here — no I/O, no crypto, no client, and
 * nothing that can fail. The ladder that PRODUCES these verdicts is next door;
 * this file is only what the answers are called.
 */
import type {
	DecryptResult,
	RefusedDecrypt,
	VerificationStatus,
} from "./crypto/index.js";
import type { HttpClient } from "./http.js";

/** What this agent needs in hand to decide one envelope's readability. */
export interface OpenInboundArgs {
	readonly client: HttpClient;
	readonly configDir: string;
	readonly agentId: string;
	/**
	 * The sender the SERVER authenticated, or null when the row carries none.
	 * The envelope's own claim of authorship is checked against it; without one
	 * there is nothing to check it against, so nothing is opened on trust.
	 */
	readonly fromAgentId: string | null;
	readonly groupId: string | null;
	readonly messageType: string;
	readonly encryptedPayload: string;
	readonly encryptionVersion: string;
	/**
	 * The row's server `created_at`. A signature under a sender key that has
	 * since been superseded is accepted only when the row predates the
	 * supersession, so omitting it fails closed for older generations.
	 */
	readonly createdAt?: string;
}

/**
 * Why an envelope stayed closed.
 *
 * 🔴 The split that matters is PERMANENT vs MAY-HEAL, because a runtime's two
 * actions differ: a permanent verdict is drained with one loud line, a may-heal
 * verdict is set aside and retried under a bound. Retrying a permanent one is
 * waste, and re-presenting attacker-controlled bytes on a schedule is a log
 * amplifier whose cadence the attacker chooses.
 *
 * - `refused` — PERMANENT. The read completed and withheld its content: the
 *   author is one of the `isAuthenticityFailure` verdicts, or the decrypt
 *   returned no text for any other reason. Neither changes on a retry.
 * - `sealed` — MAY HEAL. A group message under a sender key this agent does not
 *   hold, after the one-shot recovery has had its turn. The key arrives as an
 *   ordinary inbound DM, which is what makes a later sweep worth running.
 * - `mls-recoverable` — MAY HEAL. No local MLS key opens this yet; installing
 *   Welcomes or syncing commits might change that.
 * - `mls-evicted` — carried as its own arm rather than folded into the one
 *   above, whose remedy would be a move the reader cannot complete: no sync
 *   undoes a Remove.
 * - `failed` — MAY HEAL, unknown cause. Everything unclassified, including the
 *   transport failures of the recovery's own fetch.
 * - `not-ciphertext` — nothing was attempted: no authenticated sender, an empty
 *   payload, or an encryption this build does not open. Nothing is withheld,
 *   and this is the arm that keeps an A2A artifact behaving as it does today.
 * - `no-keys` — this agent holds no key material at all in this config dir.
 */
export type Unreadable =
	| {
			readonly kind: "refused";
			readonly verificationStatus: VerificationStatus;
			/**
			 * The withheld result, when one exists — the 1:1 decrypt REPORTS an
			 * authenticity refusal, the group decrypts THROW it. Carried so a
			 * surface can render the verdict, the kid the envelope named and the
			 * signature mark exactly as it does today. 🔴 `RefusedDecrypt` types
			 * `plaintext` as `undefined`, so this field cannot carry content.
			 */
			readonly result: RefusedDecrypt | null;
	  }
	| {
			readonly kind: "sealed";
			readonly groupId: string;
			readonly senderKeyId: string;
	  }
	| {
			readonly kind: "mls-evicted";
			readonly groupId: string;
			readonly err: unknown;
	  }
	| {
			readonly kind: "mls-recoverable";
			readonly groupId: string;
			readonly err: unknown;
	  }
	| {
			readonly kind: "failed";
			readonly groupId: string | null;
			readonly err: unknown;
	  }
	| { readonly kind: "not-ciphertext" }
	| { readonly kind: "no-keys" };

/** An envelope that opened, and what reading it did to local key state. */
export interface Opened {
	readonly kind: "opened";
	/** Plaintext present: every no-content outcome is an {@link Unreadable}. */
	readonly result: DecryptResult;
	/** True when this read took delivery of a peer's sender key. */
	readonly senderKeyIngested: boolean;
}

/** What `openInbound` answers. */
export type Readability = Opened | Unreadable;

/**
 * What `probeReadability` answers: the same verdicts with no content on any arm.
 *
 * 🔴 The `opened` arm has no `result` field, which is what makes "a probe's
 * plaintext is never logged, never passed to a harness and never near a
 * transcript" a property of the TYPE rather than a comment a later edit can
 * undo.
 */
export type Probe = { readonly kind: "opened" } | Unreadable;

/**
 * Is this verdict PERMANENT — will another read of the same bytes, however much
 * later, return it again?
 *
 * 🔴 The split {@link Unreadable}'s own header calls "the split that matters"
 * was declared in prose and then expressed nowhere, so every runtime re-derived
 * it from `kind` and they disagreed — one recording `mls-evicted` as retryable
 * while this package's own classifier documents that no sync undoes a Remove.
 * Asked here, once, so a new arm has to answer the question instead of
 * defaulting to "retry it five times" by being unlisted.
 *
 * - `refused` — permanent. An authenticity verdict is a property of the bytes,
 *   and re-presenting attacker-controlled bytes on a schedule is a log amplifier
 *   whose cadence the attacker picks.
 * - `mls-evicted` — permanent. The remedy for the arm it is deliberately not
 *   folded into is a move the reader cannot complete, and a message encrypted
 *   for epochs this member has no keys for does not become readable by rejoining.
 * - everything else — may heal, so a bounded retry is worth running: the sender
 *   key arrives as an ordinary DM, a Welcome or a commit lands, an operator
 *   restores the config dir, an unclassified failure was transport.
 *
 * 🔴 Permanent means "stop RETRYING", never "consume the row". Whether a
 * permanent verdict is also acked is the caller's policy and differs by
 * surface — `rine-openclaw` drains `refused` and acks nothing else. A caller
 * must not read this as permission to mark a message delivered.
 *
 * The Python twin of this split is `hermes_rine._setaside.SetAsideReason`, whose
 * `AUTHENTICITY` member is recorded already-exhausted for the same reason; it
 * has no MLS arm to decide, because the Python SDK reports a decrypt refusal as
 * a sentence rather than as a classified verdict.
 */
export function isPermanent(verdict: Probe): boolean {
	return verdict.kind === "refused" || verdict.kind === "mls-evicted";
}
