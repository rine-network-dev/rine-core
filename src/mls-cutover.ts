/**
 * The one-way KeyPackage cutover from ts-mls to the native core.
 *
 * A pre-cutover pool is a *bare* RFC 9420 KeyPackage; this core mints and reads
 * only the MLSMessage-framed one. The two do not interoperate, so every package
 * already sitting in an upgraded agent's server-side pool is dead weight that a
 * peer can still claim — and claiming one costs that peer a failed add, because
 * the server consumes a claimed package whether or not it turned out to be
 * readable. Walking the pool one 409 at a time is therefore exactly the wrong
 * shape (and is rejected); the pool is replaced as a whole, once.
 *
 * What "drain" can mean against the server as it exists: there is no DELETE for
 * key packages, and the server is unchanged this release. But
 * `GET /agents/{id}/mls/key-packages` *is* a destructive claim, an org may claim
 * its own agent's packages, and a claim marks `consumed_at`. So the client
 * drains its own stale pool by claiming it out and discarding what comes back,
 * then publishes a fresh pool. The stale packages are gone server-side, not
 * merely outnumbered.
 */
import * as fs from "node:fs";
import { join } from "node:path";
import {
  claimKeyPackages,
  mlsToBase64,
  uploadKeyPackages,
} from "./crypto/mls-api.js";
import { validatePathId } from "./crypto/keys.js";
import { openMlsClient } from "./crypto/mls.js";
import { RineApiError } from "./errors.js";
import type { HttpClient } from "./http.js";

/** Largest `count` the claim endpoint accepts in one request. */
const DRAIN_PAGE = 100;
/**
 * Pages the drain will claim before giving up. The server caps an agent's
 * inventory at 200 packages, so two pages empty a full pool; the extra pages
 * absorb a peer uploading concurrently without ever letting a drain loop
 * forever against a server that keeps answering.
 */
const DRAIN_MAX_PAGES = 4;

/** Marker format version. `2` is the ts-mls → native-core cutover. */
const CUTOVER_VERSION = 2;

export interface MlsCutoverResult {
  /** Stale key packages claimed out of the server pool and discarded. */
  drained: number;
  /** Fresh key packages minted by this core and accepted by the server. */
  stored: number;
}

interface MlsCutoverRecord extends MlsCutoverResult {
  version: number;
  completedAt: string;
}

/** The ts-mls-era store: group blobs and the bare key packages' private halves. */
function legacyStoreDir(configDir: string, agentId: string): string {
  validatePathId(agentId, "agent ID");
  return join(configDir, "keys", agentId, "mls");
}

/** Written only after a cutover completed end to end, so a failure retries. */
function cutoverMarkerPath(configDir: string, agentId: string): string {
  validatePathId(agentId, "agent ID");
  return join(configDir, "keys", agentId, "mls-cutover.json");
}

/**
 * Whether this agent's server-side pool may still hold pre-cutover packages.
 *
 * The evidence is local and indirect on purpose: the server has no read-only
 * key-package endpoint (its only read is the destructive claim), so the pool
 * cannot be inspected without consuming it. What can be seen is whether this
 * config dir was ever driven by the ts-mls-era code, which is exactly the
 * condition under which it published bare key packages.
 *
 * Limit, stated rather than hidden: an agent whose keys were copied to a fresh
 * config dir has no local evidence, so the cutover does not fire for it. Its
 * stale pool is emptied the slow way, by peers claiming packages that fail with
 * `RINE_MLS_UNREADABLE_KEY_PACKAGE`, until an explicit
 * {@link drainAndRepublishMlsKeyPackages} is run for it.
 */
export function needsMlsKeyPackageCutover(
  configDir: string,
  agentId: string,
): boolean {
  if (fs.existsSync(cutoverMarkerPath(configDir, agentId))) return false;
  return fs.existsSync(legacyStoreDir(configDir, agentId));
}

/**
 * Run the KeyPackage cutover for an agent that has not had one, and record it.
 *
 * Returns `null` when the agent needs no cutover, which is every agent
 * onboarded by this core. The legacy store itself is left on disk untouched:
 * it holds private key material this release cannot read, and deleting a user's
 * key material to save a marker file is not a trade worth making.
 */
export async function cutoverMlsKeyPackages(
  configDir: string,
  agentId: string,
  client: HttpClient,
): Promise<MlsCutoverResult | null> {
  if (!needsMlsKeyPackageCutover(configDir, agentId)) return null;
  const result = await drainAndRepublishMlsKeyPackages(
    configDir,
    agentId,
    client,
  );
  writeCutoverMarker(configDir, agentId, result);
  return result;
}

/**
 * Discard this agent's whole KeyPackage pool — server side and local — and
 * publish a fresh one minted by this core.
 *
 * Ordering is the whole design. The new pool is minted locally first (the core
 * persists each private half before returning the blob, so a crash costs a file
 * and never a published package we cannot answer for). Then the stale pool is
 * claimed out, because the server hands out the *oldest* unconsumed package
 * first: publishing before draining would leave every peer claiming stale
 * packages until the last one was consumed. Then the fresh pool is uploaded.
 *
 * The window that remains: between the last claim and the upload landing, this
 * agent has no claimable key package, so a peer adding it in that instant gets
 * the server's "No key packages available" — a clean, retriable refusal rather
 * than a broken join. If the upload itself fails the window stays open, and the
 * next MLS operation this agent performs closes it by retrying the cutover.
 */
export async function drainAndRepublishMlsKeyPackages(
  configDir: string,
  agentId: string,
  client: HttpClient,
): Promise<MlsCutoverResult> {
  const mls = openMlsClient(configDir, agentId);
  const packages = mls.drainAndRepublishKeyPackages().map(mlsToBase64);
  const drained = await claimOutPool(client, agentId);
  const { stored } = await uploadKeyPackages(client, agentId, packages);
  return { drained, stored };
}

/** Claim the agent's own unconsumed packages until the server reports none left. */
async function claimOutPool(
  client: HttpClient,
  agentId: string,
): Promise<number> {
  let drained = 0;
  for (let page = 0; page < DRAIN_MAX_PAGES; page++) {
    let claimed: { packages: string[] };
    try {
      claimed = await claimKeyPackages(client, agentId, DRAIN_PAGE);
    } catch (err) {
      if (isPoolEmpty(err)) return drained;
      throw err;
    }
    drained += claimed.packages.length;
    if (claimed.packages.length < DRAIN_PAGE) return drained;
  }
  return drained;
}

/**
 * The server answers an exhausted pool with a conflict. Matched on the detail
 * text and not the status, so it still holds if the status ever changes — an
 * empty pool is the drain's success condition, never an error to propagate.
 */
function isPoolEmpty(err: unknown): boolean {
  return (
    err instanceof RineApiError && /no key packages available/i.test(err.detail)
  );
}

function writeCutoverMarker(
  configDir: string,
  agentId: string,
  result: MlsCutoverResult,
): void {
  const record: MlsCutoverRecord = {
    version: CUTOVER_VERSION,
    completedAt: new Date().toISOString(),
    ...result,
  };
  const path = cutoverMarkerPath(configDir, agentId);
  fs.mkdirSync(join(path, ".."), { recursive: true, mode: 0o700 });
  fs.writeFileSync(path, JSON.stringify(record), "utf-8");
  fs.chmodSync(path, 0o600);
}
