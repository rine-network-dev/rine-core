import * as fs from "node:fs";
import { join } from "node:path";
import { writeAtomic } from "../config.js";
import { validatePathId } from "../crypto/keys.js";
import {
	CANONICAL_DECIMALS,
	isAssetAllowed,
	parseUnits,
	requirementCanonicalAmount,
} from "./assets.js";
// Journal read/write + the reserve-under-lock commit live in ./spend-journal.js so
// this file stays focused on policy shape/enforcement (S2 decomposition).
import { X402Error, X402_ERROR } from "./errors.js";
import {
	type PaymentPolicy,
	type PaymentRequirements,
	X402_SUPPORTED_SCHEMES,
} from "./types.js";

/**
 * Enforce the spend policy for a single requirement. Deny-by-default: a null
 * policy always throws. Throws a typed {@link X402Error} on any violation;
 * returns silently when the requirement is payable within caps.
 *
 * @param dailySpentCanonical already-spent amount today, in canonical micro-units.
 */
export function enforcePolicy(
	policy: PaymentPolicy | null,
	req: PaymentRequirements,
	dailySpentCanonical: bigint,
): void {
	if (!policy) {
		throw new X402Error(
			X402_ERROR.NO_POLICY,
			"No spend policy configured — payments are denied by default",
		);
	}
	if (!(X402_SUPPORTED_SCHEMES as readonly string[]).includes(req.scheme)) {
		throw new X402Error(
			X402_ERROR.SCHEME_UNSUPPORTED,
			`Unsupported scheme: ${req.scheme} (v1.0 supports 'exact')`,
			{ scheme: req.scheme },
		);
	}
	if (!policy.allowedNetworks.includes(req.network)) {
		throw new X402Error(
			X402_ERROR.NETWORK_NOT_ALLOWED,
			`Network not allowed by policy: ${req.network}`,
			{ network: req.network },
		);
	}
	if (!isAssetAllowed(req, policy.allowedAssets)) {
		throw new X402Error(
			X402_ERROR.ASSET_NOT_ALLOWED,
			`Asset not allowed by policy: ${req.asset} on ${req.network}`,
			{ asset: req.asset, network: req.network },
		);
	}
	const value = requirementCanonicalAmount(req);
	const perTx = parseUnits(policy.perTxCap, CANONICAL_DECIMALS);
	if (value > perTx) {
		throw new X402Error(
			X402_ERROR.PER_TX_CAP_EXCEEDED,
			`Payment exceeds per-transaction cap (${policy.perTxCap})`,
			{ value: value.toString(), cap: perTx.toString() },
		);
	}
	const daily = parseUnits(policy.dailyCap, CANONICAL_DECIMALS);
	if (dailySpentCanonical + value > daily) {
		throw new X402Error(
			X402_ERROR.DAILY_CAP_EXCEEDED,
			`Payment would exceed daily cap (${policy.dailyCap})`,
			{
				value: value.toString(),
				spent: dailySpentCanonical.toString(),
				cap: daily.toString(),
			},
		);
	}
}

/** Whether a requirement is at/below the auto-pay threshold (policy required). */
export function isAutoPayable(
	policy: PaymentPolicy,
	req: PaymentRequirements,
): boolean {
	const threshold = parseUnits(policy.autoPayThreshold, CANONICAL_DECIMALS);
	return requirementCanonicalAmount(req) <= threshold;
}

function assertStringArray(value: unknown, field: string): void {
	if (!Array.isArray(value) || value.some((v) => typeof v !== "string")) {
		throw new X402Error(
			X402_ERROR.INVALID_POLICY,
			`Policy field '${field}' must be a string array`,
		);
	}
}

/** Structurally validate a policy object before persisting it. */
export function validatePolicy(policy: PaymentPolicy): void {
	for (const field of ["perTxCap", "dailyCap", "autoPayThreshold"] as const) {
		if (typeof policy[field] !== "string") {
			throw new X402Error(
				X402_ERROR.INVALID_POLICY,
				`Policy field '${field}' must be a decimal string`,
			);
		}
		// Reuse the amount parser purely for its validation side-effect.
		parseUnits(policy[field], CANONICAL_DECIMALS);
	}
	assertStringArray(policy.allowedAssets, "allowedAssets");
	assertStringArray(policy.allowedNetworks, "allowedNetworks");
}

function policyPath(configDir: string, agentId: string): string {
	validatePathId(agentId, "agent ID");
	return join(configDir, "keys", agentId, "payments.json");
}

export function loadPolicy(
	configDir: string,
	agentId: string,
): PaymentPolicy | null {
	try {
		return JSON.parse(
			fs.readFileSync(policyPath(configDir, agentId), "utf-8"),
		) as PaymentPolicy;
	} catch {
		return null;
	}
}

export function savePolicy(
	configDir: string,
	agentId: string,
	policy: PaymentPolicy,
): void {
	validatePolicy(policy);
	const dir = join(configDir, "keys", agentId);
	fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
	writeAtomic(policyPath(configDir, agentId), JSON.stringify(policy, null, 2));
}
