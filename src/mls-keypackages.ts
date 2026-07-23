import {
  KEY_PACKAGE_LOW_WATER,
  KEY_PACKAGE_MAX_BATCH,
  KEY_PACKAGE_TARGET,
} from "@rine-network/mls";
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
/** Inventory below which replenishment fires. Sitting *at* the mark is a no-op. */
export const MLS_KEY_PACKAGE_LOW_WATER = KEY_PACKAGE_LOW_WATER;
/**
 * Largest batch one publish call may mint. The cap is client-side on purpose:
 * a full post-quantum top-up is hundreds of kilobytes of request body and
 * neither the server nor the proxy in front of it declares a body limit, so
 * this is the only lever. Over the cap is a typed refusal, never a silently
 * truncated batch.
 */
export const MLS_KEY_PACKAGE_MAX_BATCH = KEY_PACKAGE_MAX_BATCH;

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
  client: HttpClient,
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
 * core cannot read would only mix framings. This is where the cutover fires
 * because every MLS operation already replenishes here, so an upgraded agent
 * cuts over on its next group operation with no command to run and no call site
 * to change.
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

function isInventoryFull(err: unknown): boolean {
  return err instanceof RineApiError && /inventory full/i.test(err.detail);
}
