/**
 * The state of the rotation scene: its agents, groups and the record of what the
 * stand-in server holds. `mls-rotation-server.ts` serves it and
 * `mls-rotation-scene.ts` sets it up.
 */
import type { World } from "./crypto/world.js";

export const A = "a1a1a1a1-0000-4000-8000-000000000001";
export const B = "b2b2b2b2-0000-4000-8000-000000000002";
export const R = "c3c3c3c3-0000-4000-8000-000000000003";
export const C = "d4d4d4d4-0000-4000-8000-000000000004";
export const G1 = "11111111-0000-4000-8000-0000000000a1";
export const G2 = "22222222-0000-4000-8000-0000000000a2";

export interface PostedCommit {
	epoch: number;
	commit: string;
	group_info?: string;
}

export interface QueuedWelcome {
	id: string;
	group_id: string;
	blob: string;
	created_at: string;
}

export interface RotationScene {
	root: string;
	/** The siblings A and B. */
	d1: string;
	/** The remote founder R. */
	dr: string;
	/** The remote joiner C. */
	dc: string;
	world: World;
	rosters: Map<string, string[]>;
	posted: Map<string, PostedCommit[]>;
	welcomes: Map<string, QueuedWelcome[]>;
	/** KeyPackages served ahead of freshly minted ones, per agent. */
	keyPackages: Map<string, string[]>;
	/** Agents whose rows the batch key read leaves out, as it does for a revoked agent. */
	omitted: Set<string>;
	client: never;
}

/** Set by {@link setUpRotationScene}; the tests read and steer the scene through it. */
export const scene = {} as RotationScene;

/** The device directory each agent's keys live on. */
export const deviceOf = new Map<string, string>();
