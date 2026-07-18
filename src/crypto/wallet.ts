import * as fs from "node:fs";
import { join } from "node:path";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { bytesToHex, hexToBytes } from "@noble/curves/utils.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { writeAtomic } from "../config.js";
import { fromBase64Url, toBase64Url, validatePathId } from "./keys.js";

const SECP256K1_PRIVATE_KEY_SIZE = 32;
const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);

/** Generate a fresh secp256k1 wallet private key (32 bytes). */
export function generateWalletKey(): Uint8Array {
	return secp256k1.utils.randomSecretKey();
}

/**
 * EIP-55 checksummed hex address (case-encoded per keccak of the lowercase hex).
 * Accepts a bare or 0x-prefixed 40-char hex string.
 */
export function toChecksumAddress(hexAddr: string): string {
	const addr = hexAddr.replace(/^0x/i, "").toLowerCase();
	if (!/^[0-9a-f]{40}$/.test(addr)) {
		throw new Error(`Invalid EVM address: ${hexAddr}`);
	}
	const hash = bytesToHex(keccak_256(utf8(addr)));
	let out = "0x";
	for (let i = 0; i < addr.length; i++) {
		out +=
			Number.parseInt(hash[i] as string, 16) >= 8
				? (addr[i] as string).toUpperCase()
				: addr[i];
	}
	return out;
}

/** Derive the EIP-55 checksummed EVM address for a secp256k1 wallet key. */
export function deriveEvmAddress(privateKey: Uint8Array): string {
	const pub = secp256k1.getPublicKey(privateKey, false); // 65B uncompressed
	const hashed = keccak_256(pub.subarray(1)); // hash x||y (drop 0x04 prefix)
	return toChecksumAddress(bytesToHex(hashed.subarray(-20)));
}

/**
 * Sign a 32-byte digest, returning a 65-byte Ethereum signature (r‖s‖v) as
 * 0x-hex. `v = 27 + recovery`; noble produces a canonical low-s signature.
 */
export function signDigest(privateKey: Uint8Array, digest: Uint8Array): string {
	const rec = secp256k1.sign(digest, privateKey, {
		prehash: false,
		format: "recovered",
	}); // [recovery(1)][r(32)][s(32)]
	const sig = new Uint8Array(65);
	sig.set(rec.subarray(1, 65), 0); // r‖s
	sig[64] = 27 + (rec[0] as number);
	return `0x${bytesToHex(sig)}`;
}

/** Recover the signer's checksummed EVM address from a 65-byte sig + digest. */
export function recoverAddress(signature: string, digest: Uint8Array): string {
	const raw = hexToBytes(signature.replace(/^0x/i, ""));
	if (raw.length !== 65) {
		throw new Error(
			`Invalid signature length: expected 65 bytes, got ${raw.length}`,
		);
	}
	const recSig = new Uint8Array(65);
	recSig[0] = (raw[64] as number) - 27;
	recSig.set(raw.subarray(0, 64), 1);
	const compressed = secp256k1.recoverPublicKey(recSig, digest, {
		prehash: false,
	});
	const pub = secp256k1.Point.fromBytes(compressed).toBytes(false);
	return toChecksumAddress(
		bytesToHex(keccak_256(pub.subarray(1)).subarray(-20)),
	);
}

function walletDir(configDir: string, agentId: string): string {
	validatePathId(agentId, "agent ID");
	return join(configDir, "keys", agentId);
}

function walletKeyPath(configDir: string, agentId: string): string {
	return join(walletDir(configDir, agentId), "wallet.key");
}

/** Persist the wallet key beside the agent's signing/encryption keys (0700/0600). */
export function saveWalletKey(
	configDir: string,
	agentId: string,
	privateKey: Uint8Array,
): void {
	if (privateKey.length !== SECP256K1_PRIVATE_KEY_SIZE) {
		throw new Error(
			`Invalid wallet key: expected 32 bytes, got ${privateKey.length}`,
		);
	}
	const dir = walletDir(configDir, agentId);
	fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
	writeAtomic(walletKeyPath(configDir, agentId), toBase64Url(privateKey));
}

export function loadWalletKey(configDir: string, agentId: string): Uint8Array {
	const raw = fs
		.readFileSync(walletKeyPath(configDir, agentId), "utf-8")
		.trim();
	const priv = fromBase64Url(raw);
	if (priv.length !== SECP256K1_PRIVATE_KEY_SIZE) {
		throw new Error(
			`Corrupt wallet key: expected 32 bytes, got ${priv.length}`,
		);
	}
	return priv;
}

export function walletKeyExists(configDir: string, agentId: string): boolean {
	return fs.existsSync(walletKeyPath(configDir, agentId));
}

export function getWalletAddress(configDir: string, agentId: string): string {
	return deriveEvmAddress(loadWalletKey(configDir, agentId));
}

/**
 * Create a wallet for an agent, refusing to clobber an existing key.
 * Returns the derived EVM address.
 */
export function createWallet(
	configDir: string,
	agentId: string,
): { address: string } {
	if (walletKeyExists(configDir, agentId)) {
		throw new Error(`Wallet already exists for agent ${agentId}`);
	}
	const priv = generateWalletKey();
	saveWalletKey(configDir, agentId, priv);
	return { address: deriveEvmAddress(priv) };
}
