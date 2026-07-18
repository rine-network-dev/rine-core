import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { hexToBytes } from "@noble/curves/utils.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
	createWallet,
	deriveEvmAddress,
	generateWalletKey,
	getWalletAddress,
	loadWalletKey,
	recoverAddress,
	saveWalletKey,
	signDigest,
	toChecksumAddress,
	walletKeyExists,
} from "../../src/crypto/wallet.js";

const AGENT_ID = "11111111-2222-3333-4444-555555555555";
// Well-known secp256k1 vector: privkey 0x…01 → this address.
const PRIV_ONE = hexToBytes(
	"0000000000000000000000000000000000000000000000000000000000000001",
);
const ADDR_ONE = "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf";

function makeTmpDir(): string {
	return fs.mkdtempSync(join(tmpdir(), "rine-wallet-test-"));
}

describe("deriveEvmAddress", () => {
	it("derives_known_vector_when_privkey_one_returns_canonical_address", () => {
		expect(deriveEvmAddress(PRIV_ONE)).toBe(ADDR_ONE);
	});

	it("produces_eip55_checksum_when_derived_has_mixed_case", () => {
		const addr = deriveEvmAddress(PRIV_ONE);
		expect(addr).toBe(toChecksumAddress(addr.toLowerCase()));
	});
});

describe("signDigest / recoverAddress", () => {
	it("round_trips_when_signed_then_recovered_returns_signer_address", () => {
		const digest = keccak_256(new TextEncoder().encode("pay me"));
		const sig = signDigest(PRIV_ONE, digest);
		expect(sig).toMatch(/^0x[0-9a-f]{130}$/);
		expect(recoverAddress(sig, digest)).toBe(ADDR_ONE);
	});

	it("emits_ethereum_v_when_signed_last_byte_is_27_or_28", () => {
		const digest = keccak_256(new TextEncoder().encode("x"));
		const sig = signDigest(generateWalletKey(), digest);
		const v = Number.parseInt(sig.slice(-2), 16);
		expect([27, 28]).toContain(v);
	});
});

describe("wallet key storage", () => {
	let dir: string;
	beforeEach(() => {
		dir = makeTmpDir();
	});
	afterEach(() => {
		fs.rmSync(dir, { recursive: true });
	});

	it("round_trips_when_saved_then_loaded_returns_same_key", () => {
		const key = generateWalletKey();
		saveWalletKey(dir, AGENT_ID, key);
		expect(loadWalletKey(dir, AGENT_ID)).toEqual(key);
	});

	it("sets_0600_when_saved_wallet_key_file", () => {
		saveWalletKey(dir, AGENT_ID, generateWalletKey());
		const stat = fs.statSync(join(dir, "keys", AGENT_ID, "wallet.key"));
		expect(stat.mode & 0o777).toBe(0o600);
	});

	it("returns_false_when_no_wallet_exists", () => {
		expect(walletKeyExists(dir, AGENT_ID)).toBe(false);
	});

	it("creates_wallet_when_absent_and_exposes_address", () => {
		const { address } = createWallet(dir, AGENT_ID);
		expect(walletKeyExists(dir, AGENT_ID)).toBe(true);
		expect(getWalletAddress(dir, AGENT_ID)).toBe(address);
	});

	it("refuses_when_creating_over_existing_wallet", () => {
		createWallet(dir, AGENT_ID);
		expect(() => createWallet(dir, AGENT_ID)).toThrow(/already exists/);
	});

	it("throws_when_agent_id_is_not_a_uuid", () => {
		expect(() => saveWalletKey(dir, "../evil", generateWalletKey())).toThrow(
			/Invalid agent ID/,
		);
	});
});
