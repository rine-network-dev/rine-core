import { X402Error, X402_ERROR } from "./errors.js";
import type { PaymentRequirements } from "./types.js";

/**
 * Canonical accounting precision. All v1.0 `exact`-scheme assets are 6-decimal
 * stablecoins (EURC/USDC on Base). Caps and daily-spend are tracked in these
 * canonical micro-units; per-asset amounts are scaled into them for comparison.
 */
export const CANONICAL_DECIMALS = 6;

/** Fallback decimals for an unrecognised `exact`-scheme stablecoin. Chosen as
 * the low end so an unknown asset is never treated as *more* valuable than it is
 * (an over-estimate of decimals would silently relax the caps). */
export const DEFAULT_STABLECOIN_DECIMALS = 6;

export interface KnownAsset {
	symbol: string;
	network: string; // CAIP-2
	address: string; // lowercased 0x contract
	decimals: number;
}

/**
 * Lane-C constant table of the featured v1.0 assets. Addresses are the canonical
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
	},
	{
		symbol: "EURC",
		network: "eip155:8453",
		address: "0x60a3e35cc302bfa44cb288bc5a4f316fdb1adb42",
		decimals: 6,
	},
	// Base Sepolia testnet (eip155:84532)
	{
		symbol: "USDC",
		network: "eip155:84532",
		address: "0x036cbd53842c5426634e7929541ec2318f3dcf7e",
		decimals: 6,
	},
	{
		symbol: "EURC",
		network: "eip155:84532",
		address: "0x808456652fdb597867f38412077a9182bf77359f",
		decimals: 6,
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

/** Decimals for an asset: registry hit, else the safe stablecoin default. */
export function resolveDecimals(network: string, address: string): number {
	return lookupAsset(network, address)?.decimals ?? DEFAULT_STABLECOIN_DECIMALS;
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

/** Parse a requirement's atomic amount string into a bigint (typed guard). */
export function parseAtomicAmount(req: PaymentRequirements): bigint {
	const amount = requirementAmount(req);
	if (!/^\d+$/.test(amount)) {
		throw new X402Error(
			X402_ERROR.INVALID_REQUIREMENT,
			`Requirement amount must be atomic integer units, got: ${amount}`,
			{ amount },
		);
	}
	return BigInt(amount);
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
