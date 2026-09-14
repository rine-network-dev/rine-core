/**
 * The readability ladder: what a runtime is told about an envelope BEFORE it
 * wakes a model, and which of those answers may heal on a retry.
 *
 * 🔴 Two properties here are the ones the whole set-aside design rests on, and
 * both are invisible to a suite that only checks the happy path:
 *
 * 1. `openInbound` performs the sender-key ingest ITSELF. A runtime that probes
 *    a `rine.v1.sender_key_distribution` DM and discards it without ingesting
 *    leaves every sealed entry sealed forever — the ingest is the mechanism by
 *    which a set-aside entry heals, so it cannot be the caller's job.
 * 2. `probeReadability`'s answer carries no content on ANY arm. That is what
 *    makes "a probe's plaintext never reaches a transcript" a property of the
 *    code rather than a comment.
 *
 * Real crypto wherever a real envelope can be built, because the classification
 * has to hold on the path that actually decrypts. The one exception is the
 * thrown-group-failure block at the end, which injects the errors it is
 * classifying: `RINE_MLS_GROUP_INACTIVE` cannot be produced without a real
 * eviction, and the ORDER those arms are asked in is the thing under test.
 */
import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
	encryptGroupMessage,
	loadSenderKeyStates,
	saveSenderKeyState,
} from "../src/crypto/index.js";
import type { AgentKeys } from "../src/crypto/keys.js";
import {
	generateAgentKeys,
	saveAgentKeys,
	toBase64Url,
} from "../src/crypto/keys.js";
import type { VerificationStatus } from "../src/crypto/message.js";
import { encryptMessage, getAgentPublicKeys } from "../src/crypto/message.js";
import { MLS_ERR_GROUP_INACTIVE } from "../src/crypto/mls-errors.js";
import { noMlsStateError } from "../src/crypto/mls.js";
import { generateSenderKey } from "../src/crypto/sender-keys.js";
import type { OpenInboundArgs, Probe } from "../src/inbound-readability.js";
import {
	isPermanent,
	openInbound,
	probeReadability,
} from "../src/inbound-readability.js";

const READER_ID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
const PEER_ID = "b2c3d4e5-f6a7-8901-bcde-f12345678901";
const THIRD_ID = "e5f6a7b8-c9d0-1234-efab-345678901234";
const GROUP_ID = "c3d4e5f6-a7b8-9012-cdef-123456789012";

/**
 * A client answering the three reads this ladder can make: the peer's published
 * keys (the verify), and — on the group path's one-shot recovery — the roster
 * and the inbox listing. `inbox` empty is the recovery finding nothing, which is
 * what turns a missing key into a verdict.
 */
function makeClient(peerKeys: AgentKeys, inbox: unknown[] = []) {
	return {
		get: vi.fn().mockImplementation((path: string) => {
			if (path === `/groups/${GROUP_ID}/members`) {
				return Promise.resolve({ items: [{ agent_id: PEER_ID }] });
			}
			if (path === `/agents/${READER_ID}/messages`) {
				return Promise.resolve({ items: inbox });
			}
			if (path.endsWith("/keys")) {
				return Promise.resolve({
					agent_id: PEER_ID,
					...getAgentPublicKeys("", PEER_ID, peerKeys),
				});
			}
			return Promise.reject(new Error(`Unexpected GET: ${path}`));
		}),
		post: vi.fn(),
	};
}

describe("openInbound / probeReadability", () => {
	let dir: string;
	let readerKeys: AgentKeys;
	let peerKeys: AgentKeys;
	let client: ReturnType<typeof makeClient>;

	/** One opened envelope's arguments, with the field under test overridden. */
	function args(over: Partial<OpenInboundArgs> = {}): OpenInboundArgs {
		return {
			client: client as never,
			configDir: dir,
			agentId: READER_ID,
			fromAgentId: PEER_ID,
			groupId: null,
			messageType: "rine.v1.message",
			encryptedPayload: "",
			encryptionVersion: "hpke-hybrid-v1",
			...over,
		};
	}

	/** A real 1:1 envelope from the peer to the reader. */
	async function sealedDm(payload: unknown): Promise<string> {
		const sealed = await encryptMessage(
			dir,
			PEER_ID,
			readerKeys.encryption.publicKey,
			payload,
		);
		return sealed.encrypted_payload;
	}

	beforeEach(() => {
		dir = fs.mkdtempSync(join(tmpdir(), "rine-readability-test-"));
		readerKeys = generateAgentKeys();
		saveAgentKeys(dir, READER_ID, readerKeys);
		peerKeys = generateAgentKeys();
		saveAgentKeys(dir, PEER_ID, peerKeys);
		client = makeClient(peerKeys);
	});
	afterEach(() => fs.rmSync(dir, { recursive: true }));

	it("test_openInbound_when_the_row_names_no_authenticated_sender_then_not_ciphertext", async () => {
		// No server-authenticated sender means nothing to check the envelope's own
		// claim of authorship against, so nothing is opened on trust.
		const verdict = await openInbound(
			args({ fromAgentId: null, encryptedPayload: await sealedDm({ a: 1 }) }),
		);

		expect(verdict.kind).toBe("not-ciphertext");
	});

	it("test_openInbound_when_the_envelope_is_a_cleartext_a2a_artifact_then_not_ciphertext", async () => {
		// 🔴 The arm that keeps an A2A frame dispatching exactly as it does today.
		// `normalizeA2A` emits `encryptionVersion: "cleartext"`, and a gate that
		// asked "is the payload non-empty" instead would try to decrypt it.
		const verdict = await openInbound(
			args({ encryptionVersion: "cleartext", encryptedPayload: "not-base64" }),
		);

		expect(verdict.kind).toBe("not-ciphertext");
	});

	it("test_openInbound_when_the_payload_is_empty_then_not_ciphertext", async () => {
		expect((await openInbound(args())).kind).toBe("not-ciphertext");
	});

	it("test_openInbound_when_the_pre_gate_refuses_then_it_costs_no_request", async () => {
		// The gate is in front of the crypto AND in front of the network: a
		// quarantined or undecryptable-by-version row must not cost a round trip
		// per poll tick.
		await openInbound(args({ fromAgentId: null }));

		expect(client.get).not.toHaveBeenCalled();
	});

	it("test_openInbound_when_the_agent_holds_no_key_material_then_no_keys", async () => {
		const payload = await sealedDm({ a: 1 });
		const empty = fs.mkdtempSync(join(tmpdir(), "rine-readability-bare-"));
		try {
			const verdict = await openInbound(
				args({ configDir: empty, encryptedPayload: payload }),
			);

			expect(verdict.kind).toBe("no-keys");
		} finally {
			fs.rmSync(empty, { recursive: true });
		}
	});

	it("test_openInbound_when_a_direct_envelope_opens_then_the_plaintext_comes_back", async () => {
		const verdict = await openInbound(
			args({ encryptedPayload: await sealedDm({ hello: "world" }) }),
		);

		expect(verdict.kind).toBe("opened");
		if (verdict.kind !== "opened") return;
		expect(JSON.parse(verdict.result.plaintext)).toEqual({ hello: "world" });
		expect(verdict.result.verified).toBe(true);
		// Nothing was ingested: this is an ordinary message, not a distribution.
		expect(verdict.senderKeyIngested).toBe(false);
	});

	it("test_openInbound_when_a_distribution_dm_opens_then_the_key_is_ingested_here", async () => {
		// 🔴 The healing mechanism, pinned. Three callers used to do this
		// themselves after a successful open; a runtime that probes and discards
		// would not, and every sealed set-aside entry would stay sealed forever.
		const peerState = generateSenderKey(GROUP_ID, PEER_ID);
		const verdict = await openInbound(
			args({
				messageType: "rine.v1.sender_key_distribution",
				encryptedPayload: await sealedDm({
					group_id: GROUP_ID,
					sender_key_id: peerState.senderKeyId,
					chain_key: toBase64Url(peerState.chainKey),
					message_index: peerState.messageIndex,
					sender_agent_id: PEER_ID,
				}),
			}),
		);

		expect(verdict.kind).toBe("opened");
		if (verdict.kind !== "opened") return;
		expect(verdict.senderKeyIngested).toBe(true);
		expect(loadSenderKeyStates(dir, READER_ID, GROUP_ID)).toHaveLength(1);
	});

	it("test_openInbound_when_the_envelope_names_a_different_author_then_refused_without_content", async () => {
		// PERMANENT: the bytes are signed by the peer while the server attributes
		// the row to a third agent. No retry changes that, so this verdict must
		// never reach the set-aside list.
		const verdict = await openInbound(
			args({
				fromAgentId: THIRD_ID,
				encryptedPayload: await sealedDm({ hello: "world" }),
			}),
		);

		expect(verdict.kind).toBe("refused");
		if (verdict.kind !== "refused") return;
		expect(verdict.verificationStatus).toBe("sender-mismatch");
		// The verdict and the kid come back; the content does not.
		expect(verdict.result?.plaintext).toBeUndefined();
		expect(verdict.result?.senderKid).toBe(`rine:${PEER_ID}`);
	});

	it("test_openInbound_when_a_group_sender_key_never_arrives_then_sealed_names_the_key", async () => {
		// MAY HEAL: the key arrives as an ordinary inbound DM, which is exactly
		// why a later sweep is worth running. The empty inbox above is the
		// one-shot recovery having had its turn and found nothing.
		const peerState = generateSenderKey(GROUP_ID, PEER_ID);
		// The send refuses to encrypt under a state nothing persisted (it would
		// discard the ratchet advance), and the peer's own state file is keyed by
		// the PEER's id — the reader still holds nothing for this group.
		saveSenderKeyState(dir, PEER_ID, GROUP_ID, [peerState]);
		const { result } = await encryptGroupMessage(
			dir,
			PEER_ID,
			GROUP_ID,
			peerState,
			{ hello: "group" },
		);

		const verdict = await openInbound(
			args({
				groupId: GROUP_ID,
				encryptionVersion: "sender-key-v1",
				encryptedPayload: result.encrypted_payload,
			}),
		);

		expect(verdict.kind).toBe("sealed");
		if (verdict.kind !== "sealed") return;
		expect(verdict.senderKeyId).toBe(peerState.senderKeyId);
		expect(verdict.groupId).toBe(GROUP_ID);
	});

	it("test_openInbound_when_the_acting_agent_id_is_not_a_path_id_then_failed_rather_than_a_throw", async () => {
		// "Never throws" is the contract every runtime gate is written against:
		// a throw here would propagate into a transport loop that has no answer
		// for it. `../evil` is refused by `validatePathId` inside the pre-gate.
		const verdict = await openInbound(
			args({ agentId: "../evil", encryptedPayload: "AAAA" }),
		);

		expect(verdict.kind).toBe("failed");
	});

	it("test_probeReadability_when_an_envelope_opens_then_the_answer_carries_no_content", async () => {
		// 🔴 Structural, not documentary: the `opened` arm of a probe has no
		// `result` field at all, so there is nothing for a runtime to log, hand to
		// a harness, or leave in a transcript.
		const probe = await probeReadability(
			args({ encryptedPayload: await sealedDm({ hello: "world" }) }),
		);

		expect(probe).toEqual({ kind: "opened" });
		expect(Object.keys(probe)).toEqual(["kind"]);
		expect("result" in probe).toBe(false);
	});

	it("test_probeReadability_when_it_probes_a_distribution_dm_then_the_key_is_still_ingested", async () => {
		// The probe drops the content and keeps the side effect on LOCAL key
		// state — the two are not the same thing, and dropping the second is how
		// a sealed entry would never heal.
		const peerState = generateSenderKey(GROUP_ID, PEER_ID);
		const probe = await probeReadability(
			args({
				messageType: "rine.v1.sender_key_distribution",
				encryptedPayload: await sealedDm({
					group_id: GROUP_ID,
					sender_key_id: peerState.senderKeyId,
					chain_key: toBase64Url(peerState.chainKey),
					message_index: peerState.messageIndex,
					sender_agent_id: PEER_ID,
				}),
			}),
		);

		expect(probe.kind).toBe("opened");
		expect(loadSenderKeyStates(dir, READER_ID, GROUP_ID)).toHaveLength(1);
	});
});

/**
 * The thrown-group-failure arms, and the ORDER they are asked in.
 *
 * The errors are injected rather than provoked: `RINE_MLS_GROUP_INACTIVE` needs
 * a real Remove commit against a real ratchet tree, and what is under test is
 * the mapping and its order — not the native core's ability to raise it. The
 * decrypt is replaced through a non-hoisted `vi.doMock` so every other test in
 * this file keeps real crypto; `agentKeysExist` and the pre-gate are untouched
 * and still run for real against the temp dir.
 */
describe("openInbound's classification of a thrown group failure", () => {
	let dir: string;

	beforeEach(() => {
		dir = fs.mkdtempSync(join(tmpdir(), "rine-readability-classify-"));
		saveAgentKeys(dir, READER_ID, generateAgentKeys());
	});
	afterEach(() => {
		fs.rmSync(dir, { recursive: true });
		vi.doUnmock("../src/sender-key-recovery.js");
		vi.resetModules();
	});

	async function verdictFor(err: unknown) {
		vi.resetModules();
		vi.doMock("../src/sender-key-recovery.js", () => ({
			decryptGroupMessageWithRecovery: vi.fn().mockRejectedValue(err),
		}));
		const mod = await import("../src/inbound-readability.js");
		return await mod.openInbound({
			client: { get: vi.fn(), post: vi.fn() } as never,
			configDir: dir,
			agentId: READER_ID,
			fromAgentId: PEER_ID,
			groupId: GROUP_ID,
			messageType: "rine.v1.message",
			encryptedPayload: "AAAA",
			encryptionVersion: "mls-v1",
		});
	}

	it("test_classification_when_a_remove_commit_evicted_this_member_then_mls_evicted", async () => {
		// 🔴 Asked BEFORE the recoverable arm, which answers **true** for an
		// eviction — it is an unprocessable commit, and it is one. No sync undoes
		// a Remove, so the two must not collapse: a caller told "sync and retry"
		// is handed a move it cannot complete.
		const verdict = await verdictFor(
			Object.assign(new Error("group is inactive"), {
				code: MLS_ERR_GROUP_INACTIVE,
			}),
		);

		expect(verdict.kind).toBe("mls-evicted");
	});

	it("test_classification_when_this_agent_holds_no_mls_state_yet_then_mls_recoverable", async () => {
		const verdict = await verdictFor(noMlsStateError(GROUP_ID));

		expect(verdict.kind).toBe("mls-recoverable");
	});

	it("test_classification_when_the_cause_is_unrecognised_then_failed_carries_the_error", async () => {
		const err = new Error("socket hang up");
		const verdict = await verdictFor(err);

		expect(verdict.kind).toBe("failed");
		if (verdict.kind !== "failed") return;
		expect(verdict.err).toBe(err);
		expect(verdict.groupId).toBe(GROUP_ID);
	});

	it("test_classification_when_the_group_decrypt_throws_an_authenticity_verdict_then_refused", async () => {
		// Matched on the FIELD the error carries, never with `instanceof`: two
		// copies of this package in one bundle make `instanceof` answer false, and
		// this is the branch that decides whether forged bytes get retried on a
		// schedule. A plain object carrying the field is therefore classified —
		// which is the point, not a leniency.
		// Annotated, not inlined: the status has to be a real member of the union
		// the predicate screens against, so a rename over there fails the
		// TYPECHECK here instead of quietly turning this test into the one below.
		const forged: VerificationStatus = "invalid";
		const verdict = await verdictFor(
			Object.assign(new Error("Sender signature verification failed"), {
				verificationStatus: forged,
			}),
		);

		expect(verdict.kind).toBe("refused");
		if (verdict.kind !== "refused") return;
		expect(verdict.verificationStatus).toBe("invalid");
		// Nothing opened, so there is no withheld result to carry.
		expect(verdict.result).toBeNull();
	});

	it("test_classification_when_refused_then_the_arm_carries_the_status_and_nothing_else", async () => {
		// 🔴 The ABSENCE of `err` on this arm is a decision, not an omission, and
		// this is the only thing that says so. Every may-heal arm carries `err`;
		// this one deliberately does not, because `refused` is the arm a probe
		// hands to a runtime that will log it, and a thrown decrypt error is the
		// one place a crypto library's own message could carry fragments of what
		// it was decrypting. `result` is a `RefusedDecrypt`, which types
		// `plaintext` as `undefined`, so the field that IS here cannot carry
		// content by type.
		//
		// It is also the measured blocker for routing the CLI's own read through
		// this module: without `err` the CLI cannot reproduce its current
		// rendered output for a group authenticity failure byte for byte.
		// So adding `err` here is a live proposal — if a later pass takes it, this
		// assertion is what makes the no-content property get re-argued on purpose
		// instead of being lost in a diff.
		const verdict = await verdictFor(
			Object.assign(new Error("Sender signature verification failed"), {
				verificationStatus: "sender-mismatch" satisfies VerificationStatus,
			}),
		);

		expect(Object.keys(verdict).sort()).toEqual([
			"kind",
			"result",
			"verificationStatus",
		]);
	});

	it("test_classification_when_an_unrelated_error_carries_a_verified_status_then_it_is_not_refused", async () => {
		// The authenticity probe passes the status through `isAuthenticityFailure`,
		// so a field that happens to be named the same thing cannot smuggle an
		// error into the one permanent arm — which would make it undrainable and
		// unretryable at once.
		const benign: VerificationStatus = "verified";
		const verdict = await verdictFor(
			Object.assign(new Error("nothing to do with authorship"), {
				verificationStatus: benign,
			}),
		);

		expect(verdict.kind).toBe("failed");
	});
});

/**
 * Permanence, asked of the verdict vocabulary rather than re-derived by each
 * runtime. The table is the point: an arm added to `Unreadable` without an
 * answer here silently becomes "retry it until the bound gives up", which is
 * how `mls-evicted` came to burn five peek reads per message on a member no
 * epoch will ever open one for.
 */
describe("isPermanent", () => {
	it("test_isPermanent_over_every_arm_of_the_verdict_union", () => {
		const err = new Error("x");
		const table: Array<[Probe, boolean]> = [
			[{ kind: "opened" }, false],
			[{ kind: "refused", verificationStatus: "invalid", result: null }, true],
			[{ kind: "mls-evicted", groupId: GROUP_ID, err }, true],
			[{ kind: "sealed", groupId: GROUP_ID, senderKeyId: "k" }, false],
			[{ kind: "mls-recoverable", groupId: GROUP_ID, err }, false],
			[{ kind: "failed", groupId: null, err }, false],
			[{ kind: "not-ciphertext" }, false],
			[{ kind: "no-keys" }, false],
		];

		// 🔴 Every arm, counted: `Probe`'s two unions have eight members between
		// them, and an unlisted arm would otherwise just be absent from the table.
		expect(table).toHaveLength(8);
		for (const [verdict, permanent] of table) {
			expect(isPermanent(verdict), `${verdict.kind}`).toBe(permanent);
		}
	});

	it("test_isPermanent_says_nothing_about_acking", () => {
		// The one misreading with a consequence: `refused` is permanent AND the
		// only verdict `rine-openclaw` drains, so a reader can conclude permanence
		// is what licenses the ack. It is not — `mls-evicted` is permanent and
		// must never be acked, because not marking an unreadable row is the only
		// thing that keeps it in the rine inbox. This assertion exists to be read,
		// not to catch a bug.
		expect(isPermanent({ kind: "mls-evicted", groupId: GROUP_ID, err: null })).toBe(
			true,
		);
	});
});
