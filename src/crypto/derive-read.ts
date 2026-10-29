// Read-side half of the derivation tree: every label string lives here once, and derive.ts
// builds the full trees from these helpers. This module is the leaf of the pair, so it must
// not import derive.ts. deriveOrgRead derives the org signing material only to compute the
// org id and zeroes it before returning, so a reader never keeps rSign.
import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { CANONICAL_UUID_RE } from "../uuid.js";
import { ascii, bytesToUuid, concat } from "./bytes.js";
import type { KeyPair } from "./keys.js";

/** The spec's D(): HKDF-SHA256, empty salt, info = ASCII(label). */
export function hkdfDerive(
	parent: Uint8Array,
	label: string,
	length: number,
): Uint8Array {
	return hkdf(sha256, parent, new Uint8Array(0), ascii(label), length);
}

/** `id` when it is a canonical lowercase UUID (so NUL-free ASCII), else a throw naming `what`. */
export function canonicalUuid(id: string, what: string): string {
	if (!CANONICAL_UUID_RE.test(id)) throw new Error(`non-canonical ${what}`);
	return id;
}

export function canonicalAgentLabelId(id: string): string {
	return canonicalUuid(id, "agent id");
}

export function orgIdFromKeys(
	orgEd25519Pk: Uint8Array,
	orgMlDsaPk: Uint8Array,
): string {
	const digest = sha256(
		concat(ascii("rine.v1.org-id"), new Uint8Array(1), orgEd25519Pk, orgMlDsaPk),
	);
	const bytes = digest.slice(0, 16);
	bytes[6] = ((bytes[6] ?? 0) & 0x0f) | 0x80;
	bytes[8] = ((bytes[8] ?? 0) & 0x3f) | 0x80;
	return bytesToUuid(bytes);
}

export function ed25519Pair(seed: Uint8Array): KeyPair {
	return { privateKey: seed, publicKey: ed25519.getPublicKey(seed) };
}

export function x25519Pair(sk: Uint8Array): KeyPair {
	return { privateKey: sk, publicKey: x25519.getPublicKey(sk) };
}

export function mlKem768Pair(seed: Uint8Array): KeyPair {
	const { publicKey, secretKey } = ml_kem768.keygen(seed);
	secretKey.fill(0);
	return { privateKey: seed, publicKey };
}

export function mlDsa65Pair(xi: Uint8Array): KeyPair {
	const { publicKey, secretKey } = ml_dsa65.keygen(xi);
	secretKey.fill(0);
	return { privateKey: xi, publicKey };
}

export const rootReadSecret = (root: Uint8Array) =>
	hkdfDerive(root, "rine.v1.root/read", 32);
export const rootSignSecret = (root: Uint8Array) =>
	hkdfDerive(root, "rine.v1.root/sign", 32);
export const orgReaderPair = (rRead: Uint8Array) =>
	ed25519Pair(hkdfDerive(rRead, "rine.v1.reader/ed25519", 32));
export const orgEd25519Pair = (rSign: Uint8Array) =>
	ed25519Pair(hkdfDerive(rSign, "rine.v1.org/ed25519", 32));
export const orgMlDsa65Pair = (rSign: Uint8Array) =>
	mlDsa65Pair(hkdfDerive(rSign, "rine.v1.org/ml-dsa-65", 32));
export const branchReadSecret = (rRead: Uint8Array, name: string) =>
	hkdfDerive(rRead, `rine.v1.branch/${name}/read`, 32);
export const branchSignSecret = (rSign: Uint8Array, name: string) =>
	hkdfDerive(rSign, `rine.v1.branch/${name}/sign`, 32);

export interface EscrowReadKeys {
	escrowX25519: KeyPair;
	escrowMlKem768: KeyPair;
	reader: KeyPair;
}

export function escrowReadKeys(bRead: Uint8Array): EscrowReadKeys {
	return {
		escrowX25519: x25519Pair(
			hkdfDerive(bRead, "rine.v1.branch/escrow/x25519", 32),
		),
		escrowMlKem768: mlKem768Pair(
			hkdfDerive(bRead, "rine.v1.branch/escrow/ml-kem-768", 64),
		),
		reader: ed25519Pair(
			hkdfDerive(bRead, "rine.v1.branch/reader/ed25519", 32),
		),
	};
}

/** The label prefix every key of one agent generation hangs under. */
export function agentLabelBase(agentId: string, gen: number): string {
	if (!Number.isSafeInteger(gen) || gen < 0) throw new Error("invalid key_gen");
	return `rine.v1.agent/${canonicalAgentLabelId(agentId)}/${gen}`;
}

export interface AgentReadKeys {
	x25519: KeyPair;
	mlKem768: KeyPair;
}

export function agentReadKeys(
	bRead: Uint8Array,
	agentId: string,
	gen: number,
): AgentReadKeys {
	const base = agentLabelBase(agentId, gen);
	return {
		x25519: x25519Pair(hkdfDerive(bRead, `${base}/x25519`, 32)),
		mlKem768: mlKem768Pair(hkdfDerive(bRead, `${base}/ml-kem-768`, 64)),
	};
}

export interface OrgReadKeys {
	orgId: string;
	rRead: Uint8Array;
	reader: KeyPair;
}

export function deriveOrgRead(root: Uint8Array): OrgReadKeys {
	const rRead = rootReadSecret(root);
	const rSign = rootSignSecret(root);
	const signing: KeyPair[] = [];
	try {
		const ed = orgEd25519Pair(rSign);
		signing.push(ed);
		const mlDsa = orgMlDsa65Pair(rSign);
		signing.push(mlDsa);
		const orgId = orgIdFromKeys(ed.publicKey, mlDsa.publicKey);
		return { orgId, rRead, reader: orgReaderPair(rRead) };
	} catch (err) {
		rRead.fill(0);
		throw err;
	} finally {
		rSign.fill(0);
		for (const pair of signing) pair.privateKey.fill(0);
	}
}
