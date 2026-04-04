import { ed25519 } from "@noble/curves/ed25519.js";

export function signPayload(
	signingPrivateKey: Uint8Array,
	plaintext: Uint8Array,
): Uint8Array {
	return ed25519.sign(plaintext, signingPrivateKey);
}

export function verifySignature(
	signingPublicKey: Uint8Array,
	plaintext: Uint8Array,
	signature: Uint8Array,
): boolean {
	try {
		return ed25519.verify(signature, plaintext, signingPublicKey);
	} catch {
		return false;
	}
}
