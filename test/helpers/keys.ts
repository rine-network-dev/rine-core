import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import {
	type AgentKeys,
	type KeyPair,
	type PqKeyPair,
	pqKeyPairFromSeed,
} from "../../src/crypto/keys.js";
import { derivedAgentKeys } from "../../src/testing.js";

const MLKEM_SEED_BYTES = 64;

export function generateSigningKeyPair(): KeyPair {
	const privateKey = ed25519.utils.randomSecretKey();
	return { privateKey, publicKey: ed25519.getPublicKey(privateKey) };
}

export function generateEncryptionKeyPair(): KeyPair {
	const privateKey = x25519.utils.randomSecretKey();
	return { privateKey, publicKey: x25519.getPublicKey(privateKey) };
}

export function generatePqKeyPair(): PqKeyPair {
	return pqKeyPairFromSeed(
		crypto.getRandomValues(new Uint8Array(MLKEM_SEED_BYTES)),
	);
}

/** Leaf keys for a fresh agent, derived the way the product derives them: org root, branch, agent. */
export function generateAgentKeys(keyGen = 0): AgentKeys {
	return derivedAgentKeys(crypto.randomUUID(), keyGen);
}
