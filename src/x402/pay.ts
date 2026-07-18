import { randomBytes } from "@noble/curves/utils.js";
import { deriveEvmAddress, signDigest } from "../crypto/wallet.js";
import { chainIdFromCaip2, requirementAmount } from "./assets.js";
import { type Eip712Domain, eip3009Digest } from "./eip3009.js";
import { X402Error, X402_ERROR } from "./errors.js";
import { enforcePolicy } from "./policy.js";
import {
	type Eip3009Authorization,
	type PaymentPayload,
	type PaymentPolicy,
	type PaymentRequired,
	type PaymentRequirements,
	X402_VERSION,
} from "./types.js";

/**
 * Deterministic requirement selection (REQ-W03). Iterates `accepts[]` in the
 * payee's advertised order (their preference wins) and returns the FIRST entry
 * that satisfies the spend policy. Deny-by-default: a null policy makes every
 * candidate fail. Throws {@link X402Error} `no-acceptable-requirement` if none
 * pass, carrying the last per-candidate rejection reason.
 */
export function selectRequirement(
	pr: PaymentRequired,
	policy: PaymentPolicy | null,
	dailySpentCanonical: bigint,
): PaymentRequirements {
	if (!Array.isArray(pr.accepts) || pr.accepts.length === 0) {
		throw new X402Error(
			X402_ERROR.INVALID_REQUIREMENT,
			"PaymentRequired.accepts[] is empty",
		);
	}
	let lastError: X402Error | undefined;
	for (const req of pr.accepts) {
		try {
			enforcePolicy(policy, req, dailySpentCanonical);
			return req;
		} catch (err) {
			if (err instanceof X402Error) {
				lastError = err;
				continue;
			}
			throw err;
		}
	}
	throw new X402Error(
		X402_ERROR.NO_ACCEPTABLE_REQUIREMENT,
		`No requirement in accepts[] satisfies the spend policy: ${lastError?.message ?? "unknown"}`,
		{ reason: lastError?.code },
	);
}

/**
 * Ceiling (seconds) applied to a payee-quoted `maxTimeoutSeconds` before it
 * becomes the EIP-3009 `validBefore`. The payee controls that field verbatim; an
 * absurd value (e.g. 10 years) would keep the signed pull-authorization live far
 * longer than intended. 24h comfortably covers `settle-after-delivery` task
 * windows while killing multi-year authorizations. Clamping is fail-closed — it
 * only ever shortens validity, never extends it.
 */
export const MAX_AUTHORIZATION_TTL_SECONDS = 86_400;

export interface BuildPaymentOptions {
	/** Unix seconds override (default `Date.now()/1000`) — inject for tests. */
	now?: number;
	/** 32-byte nonce override — inject for deterministic tests. */
	nonce?: Uint8Array;
	/** Seconds of backdating applied to `validAfter` for clock skew (default 60). */
	validAfterSkewSeconds?: number;
}

/**
 * Build and sign a `PaymentPayload` (REQ-W03) for a chosen requirement. The
 * signer pins `to`/`value`/`asset`/`network` inside the EIP-712 signature, so a
 * relayer or facilitator cannot redirect funds. Echoes `resource`/`extensions`
 * and the chosen requirement (`accepted`) verbatim per the x402 contract.
 */
export function buildPaymentPayload(
	pr: PaymentRequired,
	requirement: PaymentRequirements,
	walletPrivateKey: Uint8Array,
	opts: BuildPaymentOptions = {},
): PaymentPayload {
	const now = opts.now ?? Math.floor(Date.now() / 1000);
	const skew = opts.validAfterSkewSeconds ?? 60;
	const nonce = opts.nonce ?? randomBytes(32);
	if (nonce.length !== 32) {
		throw new X402Error(
			X402_ERROR.INVALID_REQUIREMENT,
			`Nonce must be 32 bytes, got ${nonce.length}`,
		);
	}
	const ttl = Math.min(
		requirement.maxTimeoutSeconds,
		MAX_AUTHORIZATION_TTL_SECONDS,
	);
	const authorization: Eip3009Authorization = {
		from: deriveEvmAddress(walletPrivateKey),
		to: requirement.payTo,
		value: requirementAmount(requirement),
		validAfter: String(now - skew),
		validBefore: String(now + ttl),
		nonce: `0x${Buffer.from(nonce).toString("hex")}`,
	};
	const domain: Eip712Domain = {
		name: requirement.extra.name,
		version: requirement.extra.version,
		chainId: chainIdFromCaip2(requirement.network),
		verifyingContract: requirement.asset,
	};
	const digest = eip3009Digest(domain, authorization);
	const signature = signDigest(walletPrivateKey, digest);
	return {
		x402Version: pr.x402Version ?? X402_VERSION,
		resource: pr.resource,
		accepted: requirement,
		payload: { signature, authorization },
		extensions: pr.extensions ?? {},
	};
}
