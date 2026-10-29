import { KEY_PACKAGE_TARGET } from "@rine-network/mls";
import { mlsToBase64, uploadKeyPackages } from "./crypto/mls-api.js";
import { openMlsClient } from "./crypto/mls.js";
import { RineApiError } from "./errors.js";
import type { HttpClient } from "./http.js";
import { cutoverMlsKeyPackages } from "./mls-cutover.js";

/**
 * The KeyPackage pool policy is owned by the native core and read from it here,
 * never restated — the TypeScript and Python stacks must top up to the same
 * inventory or one of them silently becomes un-addable first.
 */
/** Inventory an agent is topped back up to when replenishment fires. */
export const MLS_KEY_PACKAGE_TARGET = KEY_PACKAGE_TARGET;

/**
 * Mint and upload MLS key packages for an agent, enabling other agents to add
 * them to MLS groups.
 *
 * The private halves are persisted by the native core before the blobs are
 * returned: a key package the server hands out whose private half we never
 * stored yields a Welcome we can never process, while a stored private half the
 * server never received only wastes a file.
 */
export async function publishMlsKeyPackages(
	configDir: string,
	agentId: string,
	client: Pick<HttpClient, "post">,
	count = MLS_KEY_PACKAGE_TARGET,
): Promise<{ stored: number }> {
	const mls = openMlsClient(configDir, agentId);
	const packages = mls.generateKeyPackages(count).map(mlsToBase64);
	return uploadKeyPackages(client, agentId, packages);
}

export interface MlsKeyPackageStatus {
	/** Unconsumed key packages held before this call. */
	available: number;
	/** Key packages minted and uploaded by this call; 0 means no-op. */
	published: number;
	/** Server inventory is at its cap — a no-op success, not a failure. */
	capReached: boolean;
}

/**
 * Low-water replenishment of an agent's own MLS key package inventory.
 *
 * Onboarding mints a fixed batch and every add by a peer consumes one globally,
 * so without replenishment an agent eventually becomes un-addable: the adder
 * either fails with "No key packages available" or silently drops the agent
 * from the group it is initializing.
 *
 * Inventory is read from the locally stored private halves, because the
 * server's `GET /agents/{id}/mls/key-packages` is a destructive CLAIM and there
 * is no read-only count endpoint. The local mirror follows the server as claims
 * turn into processed Welcomes; it can over-count (never under-count) when an
 * upload fails after the private halves were minted, or when a peer claims a
 * package whose Welcome is never delivered, which delays a top-up rather than
 * pushing the inventory past the server's cap.
 *
 * An agent that has not yet had its KeyPackage cutover gets that instead of a
 * top-up: its pool is bare ts-mls-era key packages, and topping up a pool this
 * core cannot read would only mix framings. This is the only place the cutover
 * fires, which is why `mlsHeartbeat` (`mls-heartbeat.ts`) — the one call every
 * MLS operation routes through — awaits it: an upgraded agent that only reads, syncs,
 * self-joins or removes would otherwise never cut over, and its whole published
 * pool would stay unreadable to every peer.
 */
export async function ensureMlsKeyPackages(
	configDir: string,
	agentId: string,
	client: HttpClient,
): Promise<MlsKeyPackageStatus> {
	const cutover = await cutoverMlsKeyPackages(configDir, agentId, client);
	if (cutover) {
		return { available: 0, published: cutover.stored, capReached: false };
	}

	const mls = openMlsClient(configDir, agentId);
	const available = mls.keyPackageCount();
	const batch = mls.replenishKeyPackages();
	if (batch.length === 0) return { available, published: 0, capReached: false };

	try {
		const { stored } = await uploadKeyPackages(
			client,
			agentId,
			batch.map(mlsToBase64),
		);
		return { available, published: stored, capReached: false };
	} catch (err) {
		// The server refuses an upload that would exceed its inventory cap. Being
		// at the cap means the agent already has far more than enough packages, so
		// this is a no-op success rather than an error.
		if (isInventoryFull(err))
			return { available, published: 0, capReached: true };
		throw err;
	}
}

/**
 * Replenish as a side effect of an MLS operation. Replenishment is maintenance,
 * never the caller's purpose: a failed top-up must not fail a group add or undo
 * a Welcome that already succeeded, and every subsequent MLS operation retries
 * it, so the inventory self-heals with no user-facing surface.
 *
 * The heartbeat does not go through here — it awaits {@link
 * ensureMlsKeyPackages} itself, because it has to know whether the beat
 * actually did the maintenance its floor then claims was done. This is the
 * wrapper for the callers that genuinely do not care: onboarding, and any
 * surface topping an agent up outside an MLS verb.
 */
export async function replenishMlsKeyPackages(
	configDir: string,
	agentId: string,
	client: HttpClient,
): Promise<void> {
	try {
		await ensureMlsKeyPackages(configDir, agentId, client);
	} catch {
		// retried on the next MLS operation
	}
}

/** The server's error code for an upload refused at the inventory cap. */
const INVENTORY_FULL_CODE = "key_package_inventory_full";

/**
 * The server refusing an upload that would push this agent past its per-agent
 * inventory cap. A no-op success wherever it is caught: an agent at the cap has
 * far more key packages than any peer can claim.
 *
 * The error code decides; the detail's prose is the fallback for a server that
 * answers the refusal without one. The Python twin is
 * `rine._mls.is_inventory_full`.
 */
export function isInventoryFull(err: unknown): boolean {
	return (
		err instanceof RineApiError &&
		(err.code === INVENTORY_FULL_CODE || /inventory full/i.test(err.detail))
	);
}
