/**
 * The one pace the MLS maintenance work keeps: the key-package heartbeat, the
 * cross-group escrow sweep and the base of the escrow retry backoff all count
 * in this interval. Its own module so the sweep can read it without importing
 * the heartbeat that calls the sweep.
 */

/**
 * Shortest gap between two gated heartbeats for one (config dir, agent) in one
 * process. Keyed on the agent and not on the group because the inventory is
 * per-agent: ten groups draw down one pool.
 */
export const MLS_HEARTBEAT_MIN_INTERVAL_MS = 60_000;
