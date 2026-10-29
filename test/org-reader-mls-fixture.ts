// A real closed group for the MLS reader tests: two org agents in a group at epoch 1, the escrow
// rows the server would hold for it, and group messages signed and sealed the way members send them.
import { randomUUID } from "node:crypto";
import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeEach, vi } from "vitest";
import { encodeEnvelope } from "../src/crypto/envelope.js";
import { sealEscrow } from "../src/crypto/escrow.js";
import { signingKid, toBase64Url } from "../src/crypto/keys.js";
import { mlsGroupIdBytes, openMlsClient } from "../src/crypto/mls.js";
import { signMessage } from "../src/crypto/sign.js";
import type { ReadContext } from "../src/org-reader/context.js";
import type { EpochCopies, GoodCopy } from "../src/org-reader/escrow-book.js";
import type { Opened } from "../src/org-reader/mls-attempt.js";
import { EpochReaderCache } from "../src/org-reader/mls-open.js";
import { MlsReader } from "../src/org-reader/mls.js";
import type { Row } from "../src/org-reader/rows.js";
import { kat, unhex } from "./crypto/kat-fixture.js";
import type { World, WorldAgent } from "./crypto/world.js";
import { native } from "./org-reader-native-seam.js";
import { contextFor, orgWorld, party, rowOf } from "./org-reader-world.js";

/** Before the world's `supersededAt` (2026-01-01), so a past generation's signatures are still valid. */
export const EARLY = "2025-12-01T00:00:00.000000Z";

export const EPOCH = 1;

export interface EscrowExport {
	readonly epoch: number;
	readonly fp: Uint8Array;
	readonly plaintext: Uint8Array;
}

/** The server's escrow row for a copy `uploader` sealed and signed for `groupId`. */
export function escrowRowOf(
	world: World,
	uploader: WorldAgent,
	groupId: string,
	exported: EscrowExport,
) {
	const escrowKey = world.branch("main");
	const { sealed, uploaderSig } = sealEscrow(
		{
			orgId: world.org.orgId,
			branch: "main",
			x25519: escrowKey.escrowX25519.publicKey,
			mlKem: escrowKey.escrowMlKem768.publicKey,
		},
		{ groupId, epoch: exported.epoch, fp: exported.fp },
		{
			agentId: uploader.id,
			keyGen: uploader.gen,
			signingPrivateKey: uploader.derived.ed25519.privateKey,
		},
		exported.plaintext,
	);
	return {
		epoch: exported.epoch,
		fp: toBase64Url(exported.fp),
		branch: "main",
		uploader_agent_id: uploader.id,
		uploader_key_gen: uploader.gen,
		uploader_sig: toBase64Url(uploaderSig),
		sealed: toBase64Url(sealed),
		created_at: EARLY,
	};
}

/** `ctx`'s escrow route serves `rows`. */
export function serveEscrow(ctx: ReadContext, rows: readonly unknown[]) {
	return vi
		.spyOn(ctx.client, "escrowRows")
		.mockResolvedValue({ rows: [...rows], complete: true });
}

export interface ClosedGroup {
	readonly groupId: string;
	/** The member whose messages the tests read, and the founder who uploads the escrow. */
	readonly sender: WorldAgent;
	readonly founder: WorldAgent;
	readonly exported: EscrowExport;
	/** An `mls-v1` payload `sender` posts to the group, signed as a group message. */
	send(text: string): Uint8Array;
	/** The activity row of a payload as the org feed carries it. */
	rowFor(ciphertext: Uint8Array, as?: WorldAgent): Row;
	remove(): void;
}

/** A group founded by one org agent with another as its member, at epoch 1. */
export function foundGroup(world: World): ClosedGroup {
	const dir = fs.mkdtempSync(join(tmpdir(), "org-reader-mls-"));
	const founder = world.addAgent();
	const sender = world.addAgent();
	world.save(dir, founder);
	world.save(dir, sender);
	const groupId = randomUUID();
	const senderClient = openMlsClient(dir, sender.id);
	const founded = openMlsClient(dir, founder.id).createGroupWithMembers(
		mlsGroupIdBytes(groupId),
		[senderClient.generateKeyPackage()],
	);
	const welcome = founded.lastCommit()?.welcomes[0];
	if (welcome === undefined) throw new Error("the founding commit had no welcome");
	const member = senderClient.joinFromWelcome(welcome);
	const exported = founded
		.takeEscrowExports()
		.exports.find((candidate) => candidate.epoch === EPOCH);
	if (exported === undefined) throw new Error("no escrow export at epoch 1");
	return {
		groupId,
		sender,
		founder,
		exported,
		send(text) {
			const payload = new TextEncoder().encode(text);
			const signature = signMessage(
				sender.derived.ed25519.privateKey,
				{ kind: "GroupSig", groupId },
				payload,
			);
			return member.encryptApplicationMessage(
				encodeEnvelope(signingKid(sender.id, sender.gen), signature, payload),
			);
		},
		rowFor(ciphertext, as = sender) {
			return rowOf({
				sender: party(as),
				recipient: null,
				groupId,
				ciphertext,
				encryptionVersion: "mls-v1",
				direction: "received",
			});
		},
		remove() {
			fs.rmSync(dir, { recursive: true, force: true });
		},
	};
}

/** The epoch the reader-attempt tests build copies for. */
export const COPY_EPOCH = 4;
export const fpOf = (byte: number) => new Uint8Array(16).fill(byte);

/** A good copy uploaded by `uploader`; two calls with equal `fp` bytes give distinct arrays. */
export function copyOf(uploader: string, fp: Uint8Array): GoodCopy {
	return {
		copy: {
			epoch: COPY_EPOCH,
			fp,
			branch: "main",
			uploader,
			uploaderKeyGen: 0,
			uploaderSig: new Uint8Array(64),
			sealed: new Uint8Array(8),
			storedAt: "2026-02-01T00:00:00.000000Z",
		},
		plaintext: new Uint8Array(8),
	};
}

export function copies(over: Partial<EpochCopies> = {}): EpochCopies {
	return { good: [], bad: [], empty: false, unavailable: false, ...over };
}

export function openedBy(copy: GoodCopy): Opened {
	return {
		envelope: new Uint8Array(4),
		senderIndex: 0,
		generation: 0,
		signerPublicKey: new Uint8Array(32),
		copy,
	};
}

/** A valid plaintext that names another group: no reader can be built from it. */
export const foreignPlaintext = unhex(kat.mls_escrow.plaintext.bytes);

/**
 * One closed group shared by a test file: the world and group are founded once, removed after the
 * file, and the native seam is reset before each test. Call at module level.
 */
export function closedGroupSuite() {
	const { world, key } = orgWorld();
	const group = foundGroup(world);
	afterAll(() => group.remove());
	beforeEach(() => native.reset());

	const goodRow = () =>
		escrowRowOf(world, group.founder, group.groupId, group.exported);

	function setup(rows: readonly unknown[] = [goodRow()]) {
		const ctx = contextFor(key, [world]);
		serveEscrow(ctx, rows);
		const cache = new EpochReaderCache();
		return { ctx, cache, reader: new MlsReader(ctx, cache) };
	}

	/** What a read does for one row: prepare, then open. */
	async function read(
		s: ReturnType<typeof setup>,
		row: Row,
		reader: MlsReader = s.reader,
	) {
		s.ctx.pinRow(row);
		await reader.prepare([row]);
		return reader.open(row);
	}

	return { world, key, group, goodRow, setup, read };
}
