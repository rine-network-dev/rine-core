// Derivation tree: every key is HKDF-SHA256 over a labelled parent node.
// Port of scripts/vectors/lib/tree.mjs. keys.ts imports this module, so it must not
// import keys.ts at runtime (KeyPair is a type-only import).
import {
	agentLabelBase,
	branchReadSecret,
	branchSignSecret,
	ed25519Pair,
	escrowReadKeys,
	agentReadKeys,
	mlDsa65Pair,
	hkdfDerive,
	orgIdFromKeys,
	orgEd25519Pair,
	orgMlDsa65Pair,
	orgReaderPair,
	rootReadSecret,
	rootSignSecret,
} from "./derive-read.js";
import type { KeyPair } from "./keys.js";

export {
	canonicalAgentLabelId,
	canonicalUuid,
	hkdfDerive,
	orgIdFromKeys,
} from "./derive-read.js";

export const BRANCH_NAME_RE = /^[a-z0-9][a-z0-9-]{0,31}$/;

export function assertBranchName(name: string): string {
	if (!BRANCH_NAME_RE.test(name)) throw new Error("invalid branch name");
	return name;
}

export interface OrgKeys {
	rRead: Uint8Array;
	rSign: Uint8Array;
	orgId: string;
	reader: KeyPair;
	ed25519: KeyPair;
	mlDsa65: KeyPair;
}

export function deriveOrg(root: Uint8Array): OrgKeys {
	const rRead = rootReadSecret(root);
	const rSign = rootSignSecret(root);
	const ed25519Keys = orgEd25519Pair(rSign);
	const mlDsa65 = orgMlDsa65Pair(rSign);
	return {
		rRead,
		rSign,
		reader: orgReaderPair(rRead),
		ed25519: ed25519Keys,
		mlDsa65,
		orgId: orgIdFromKeys(ed25519Keys.publicKey, mlDsa65.publicKey),
	};
}

export interface BranchKeys {
	name: string;
	bRead: Uint8Array;
	bSign: Uint8Array;
	escrowX25519: KeyPair;
	escrowMlKem768: KeyPair;
	reader: KeyPair;
	ed25519: KeyPair;
	mlDsa65: KeyPair;
}

export function deriveBranch(
	org: Pick<OrgKeys, "rRead" | "rSign">,
	name: string,
): BranchKeys {
	assertBranchName(name);
	return branchFromSecrets(
		name,
		branchReadSecret(org.rRead, name),
		branchSignSecret(org.rSign, name),
	);
}

/** A branch delegate holds only B_read and B_sign; every branch key hangs below them. */
export function branchFromSecrets(
	name: string,
	bRead: Uint8Array,
	bSign: Uint8Array,
): BranchKeys {
	assertBranchName(name);
	return {
		name,
		bRead,
		bSign,
		...escrowReadKeys(bRead),
		ed25519: ed25519Pair(hkdfDerive(bSign, "rine.v1.branch/ed25519", 32)),
		mlDsa65: mlDsa65Pair(hkdfDerive(bSign, "rine.v1.branch/ml-dsa-65", 32)),
	};
}

export interface AgentDerivedKeys {
	id: string;
	gen: number;
	branch: string;
	x25519: KeyPair;
	mlKem768: KeyPair;
	ed25519: KeyPair;
	mlDsa65: KeyPair;
	mlsEd25519: KeyPair;
}

export function deriveAgent(
	branch: Pick<BranchKeys, "name" | "bRead" | "bSign">,
	agentId: string,
	gen: number,
): AgentDerivedKeys {
	const base = agentLabelBase(agentId, gen);
	return {
		id: agentId,
		gen,
		branch: branch.name,
		...agentReadKeys(branch.bRead, agentId, gen),
		ed25519: ed25519Pair(hkdfDerive(branch.bSign, `${base}/ed25519`, 32)),
		mlDsa65: mlDsa65Pair(hkdfDerive(branch.bSign, `${base}/ml-dsa-65`, 32)),
		mlsEd25519: ed25519Pair(
			hkdfDerive(branch.bSign, `${base}/mls-ed25519`, 32),
		),
	};
}
