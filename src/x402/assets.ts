import { X402Error, X402_ERROR } from "./errors.js";
import type { PaymentRequirements, X402TokenExtra } from "./types.js";

/**
 * Canonical accounting precision. All v1.0 `exact`-scheme assets are 6-decimal
 * stablecoins (EURC/USDC on Base). Caps and daily-spend are tracked in these
 * canonical micro-units; per-asset amounts are scaled into them for comparison.
 */
export const CANONICAL_DECIMALS = 6;

export interface KnownAsset {
	symbol: string;
	network: string; // CAIP-2
	address: string; // lowercased 0x contract
	decimals: number;
	/**
	 * EIP-712 domain (`name`/`version`) for the `exact`/EIP-3009 scheme. Used to
	 * author an out-of-band expected-terms override WITHOUT trusting any
	 * payer-supplied `extra`. Kept identical to how every rine surface
	 * authors its own quotes (symbol name, version "2"); verify against the real
	 * on-chain domain at the live-testnet proof gate before publish.
	 */
	domain: X402TokenExtra;
}

/**
 * Constant table of the featured v1.0 assets. Addresses are the canonical
 * Circle deployments; verify at the live-testnet proof gate before publish.
 * Matching is by (network, address) — a wrong entry only prevents a symbol from
 * resolving (fail-closed), it can never redirect a payment.
 */
export const KNOWN_ASSETS: readonly KnownAsset[] = [
	// Base mainnet (eip155:8453)
	{
		symbol: "USDC",
		network: "eip155:8453",
		address: "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
		decimals: 6,
		domain: { name: "USDC", version: "2" },
	},
	{
		symbol: "EURC",
		network: "eip155:8453",
		address: "0x60a3e35cc302bfa44cb288bc5a4f316fdb1adb42",
		decimals: 6,
		domain: { name: "EURC", version: "2" },
	},
	// Base Sepolia testnet (eip155:84532)
	{
		symbol: "USDC",
		network: "eip155:84532",
		address: "0x036cbd53842c5426634e7929541ec2318f3dcf7e",
		decimals: 6,
		domain: { name: "USDC", version: "2" },
	},
	{
		symbol: "EURC",
		network: "eip155:84532",
		address: "0x808456652fdb597867f38412077a9182bf77359f",
		decimals: 6,
		domain: { name: "EURC", version: "2" },
	},
];

const ADDRESS_RE = /^0x[0-9a-f]{40}$/i;
const DECIMAL_RE = /^\d+(\.\d+)?$/;

/** Extract the numeric EVM chain id from a CAIP-2 `eip155:<n>` network. */
export function chainIdFromCaip2(network: string): number {
	const m = /^eip155:(\d+)$/.exec(network);
	if (!m) {
		throw new X402Error(
			X402_ERROR.INVALID_NETWORK,
			`Unsupported network (v1.0 signs eip155 chains only): ${network}`,
			{ network },
		);
	}
	return Number(m[1]);
}

export function lookupAsset(
	network: string,
	address: string,
): KnownAsset | undefined {
	const addr = address.toLowerCase();
	return KNOWN_ASSETS.find((a) => a.network === network && a.address === addr);
}

/**
 * Decimals for an asset — FAIL CLOSED. A registry hit returns the known token
 * precision; an asset absent from {@link KNOWN_ASSETS} is REJECTED with a typed
 * {@link X402Error}, never priced with an assumed default.
 *
 * Assuming a 6-decimal default would misprice a sub-6-decimal token: its signed
 * EIP-3009 `value` is atomic, so reading it at the wrong precision values it far
 * below its true worth. Rather than price it wrong, unknown decimals deny at
 * pricing time; a non-registry token must be added to the registry before it can
 * transact under the `exact` scheme.
 */
export function resolveDecimals(network: string, address: string): number {
	const known = lookupAsset(network, address);
	if (!known) {
		throw new X402Error(
			X402_ERROR.UNKNOWN_ASSET_DECIMALS,
			`Cannot resolve decimals for asset ${address} on ${network}: not in the known-asset registry (refusing to assume a default — fail closed)`,
			{ network, asset: address },
		);
	}
	return known.decimals;
}

/**
 * The EIP-712 domain (`extra`) for a known asset — operator-trusted, registry-
 * derived. Lets a payee author an out-of-band expected-terms override without
 * inheriting the payer-controlled `extra`. Unknown assets FAIL CLOSED,
 * exactly like {@link resolveDecimals} (an override can only target a registry
 * asset — `parseUnits`/`resolveDecimals` already reject a non-registry one).
 */
export function resolveTokenExtra(
	network: string,
	address: string,
): X402TokenExtra {
	const known = lookupAsset(network, address);
	if (!known) {
		throw new X402Error(
			X402_ERROR.UNKNOWN_ASSET_DECIMALS,
			`Cannot resolve the EIP-712 domain for asset ${address} on ${network}: not in the known-asset registry (fail closed)`,
			{ network, asset: address },
		);
	}
	return { ...known.domain };
}

/** Parse a decimal major-unit string into atomic units at `decimals` precision. */
export function parseUnits(value: string, decimals: number): bigint {
	if (!DECIMAL_RE.test(value)) {
		throw new X402Error(X402_ERROR.INVALID_AMOUNT, `Invalid amount: ${value}`, {
			value,
		});
	}
	const [intPart, fracPart = ""] = value.split(".");
	if (fracPart.length > decimals) {
		throw new X402Error(
			X402_ERROR.INVALID_AMOUNT,
			`Amount ${value} exceeds ${decimals}-decimal precision`,
			{ value, decimals },
		);
	}
	const frac = fracPart.padEnd(decimals, "0");
	return BigInt(intPart || "0") * 10n ** BigInt(decimals) + BigInt(frac || "0");
}

/** Rescale an atomic value between two decimal precisions (floor on downscale). */
export function scaleToDecimals(
	atomic: bigint,
	from: number,
	to: number,
): bigint {
	if (to >= from) return atomic * 10n ** BigInt(to - from);
	return atomic / 10n ** BigInt(from - to);
}

/**
 * The requirement's atomic amount string, tolerant of x402 version drift: x402
 * V2 spells the field `amount`, V1 spelled it `maxAmountRequired`. Reading either
 * (V2 preferred) keeps the payer able to consume a real inbound quote whichever
 * name the payee's facilitator emits; the value is identical, only the key moved.
 */
export function requirementAmount(req: PaymentRequirements): string {
	const raw = req.amount ?? req.maxAmountRequired;
	if (raw === undefined) {
		throw new X402Error(
			X402_ERROR.INVALID_REQUIREMENT,
			"Requirement is missing an amount (neither `amount` nor `maxAmountRequired`)",
		);
	}
	return raw;
}

/**
 * Parse a raw atomic-units decimal string into a bigint (typed guard). Shared by
 * {@link parseAtomicAmount} (a requirement's `amount`) and the payee-side signed-
 * value defense (an EIP-3009 `authorization.value`), so both reject a non-integer
 * value with the same typed {@link X402Error} instead of a silent `BigInt` throw.
 */
export function parseAtomicUnits(value: string, label = "Amount"): bigint {
	if (!/^\d+$/.test(value)) {
		throw new X402Error(
			X402_ERROR.INVALID_REQUIREMENT,
			`${label} must be atomic integer units, got: ${value}`,
			{ value },
		);
	}
	return BigInt(value);
}

/** Parse a requirement's atomic amount string into a bigint (typed guard). */
export function parseAtomicAmount(req: PaymentRequirements): bigint {
	return parseAtomicUnits(requirementAmount(req), "Requirement amount");
}

/** A requirement's value expressed in canonical (6-decimal) micro-units. */
export function requirementCanonicalAmount(req: PaymentRequirements): bigint {
	const decimals = resolveDecimals(req.network, req.asset);
	return scaleToDecimals(parseAtomicAmount(req), decimals, CANONICAL_DECIMALS);
}

/**
 * Is a requirement's asset allowed? An `allowedAssets` entry matches either
 * directly by contract address (case-insensitive) or by symbol resolved through
 * the known-asset registry for the requirement's network. Unknown symbols
 * fail-closed.
 */
export function isAssetAllowed(
	req: PaymentRequirements,
	allowedAssets: string[],
): boolean {
	const asset = req.asset.toLowerCase();
	for (const raw of allowedAssets) {
		const entry = raw.trim();
		if (ADDRESS_RE.test(entry)) {
			if (entry.toLowerCase() === asset) return true;
			continue;
		}
		const known = KNOWN_ASSETS.find(
			(a) =>
				a.network === req.network &&
				a.symbol.toUpperCase() === entry.toUpperCase(),
		);
		if (known && known.address === asset) return true;
	}
	return false;
}
