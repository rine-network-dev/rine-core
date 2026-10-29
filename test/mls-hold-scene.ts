/**
 * A stand-in commit server that can hold a commit tentatively, on top of the
 * rotation scene.
 *
 * It wraps the scene's mocked `mlsCommit` and `fetchHandshakes` (call
 * {@link installHoldServer} after `setUpRotationScene`). Every call must go
 * through {@link clientFor}, which names the agent making it. It then models the
 * handshakes read the way the server decides it:
 *
 *   - a commit is never fanned back to its own sender;
 *   - a read that finds nothing to serve while the group has confirmed an epoch
 *     past `since_epoch` is refused 409 `mls_resync_required`;
 *   - a read that names `pending_epoch` also answers where the caller's own
 *     commit at that epoch stands, and measures reachability from that epoch
 *     only when the standing is `confirmed`.
 */
import { vi } from "vitest";
import { fetchHandshakes, mlsCommit } from "../src/crypto/mls-api.js";
import { OwnCommitStanding } from "../src/crypto/mls-handshake-feed.js";
import { RineApiError } from "../src/errors.js";
import { scene } from "./mls-rotation-scene.js";

export const hold = {
	/** What a commit post answers as `confirmed`. */
	confirmed: true,
	/** Errors the next commit posts throw, in order. */
	postErrors: [] as Error[],
	/** Called as each post arrives, before it is recorded: the write-ahead witness. */
	onPost: undefined as undefined | ((as: string, groupId: string) => void),
	/** The commit posts that reached the server: who, which group, which epoch. */
	posts: [] as { as: string; groupId: string; epoch: number }[],
	/**
	 * Where the caller's own commit stands, per group. Absent means the server's
	 * reading of the posts: `tentative` when the caller posted at the pending
	 * epoch, `superseded` when a peer's commit holds it, else `absent`.
	 */
	standings: new Map<string, OwnCommitStanding>(),
	/** Handshakes the server serves on top of the posted ones: a peer's later commit. */
	extraHandshakes: [] as { epoch: number; blob: string }[],
	/** Answer a handshakes read without `pending_commit`, as a server that predates it does. */
	omitStanding: false,
	/** Pending epochs the handshakes reads carried, in order. */
	pendingReads: [] as { groupId: string; pendingEpoch: number | undefined }[],
};

/** The scene client, tagged with the agent that is calling through it. */
export function clientFor(agentId: string): never {
	const base = scene.client as unknown as { get: (...args: unknown[]) => Promise<unknown> };
	const tagged = {
		...base,
		as: agentId,
		get: async (path: string, params?: Record<string, string>, headers?: unknown) => {
			const route = /^\/groups\/([^/]+)\/mls\/handshakes$/.exec(path);
			if (!route) return base.get(path, params, headers);
			const pending = params?.["pending_epoch"];
			return serve(agentId, route[1]!, Number(params?.["since_epoch"]), pending === undefined ? undefined : Number(pending));
		},
	};
	return tagged as never;
}

const asOf = (client: unknown): string => (client as { as?: string }).as ?? "";

/** Drop the newest commit the server holds for `groupId`, as a rollback does. */
export function dropNewestCommit(groupId: string): void {
	scene.posted.get(groupId)?.pop();
	hold.posts = hold.posts.filter((p, i, all) => !(p.groupId === groupId && i === all.map((q) => q.groupId).lastIndexOf(groupId)));
}

export function resetHoldServer(): void {
	hold.confirmed = true;
	hold.postErrors = [];
	hold.onPost = undefined;
	hold.posts = [];
	hold.standings = new Map();
	hold.pendingReads = [];
	hold.omitStanding = false;
	hold.extraHandshakes = [];
}

let feed: (client: unknown, groupId: string, since?: number) => Promise<Awaited<ReturnType<typeof fetchHandshakes>>>;

const wrote = (as: string, groupId: string, epoch: number): boolean =>
	hold.posts.some((p) => p.groupId === groupId && p.as === as && p.epoch === epoch);

function standingAt(as: string, groupId: string, epoch: number): OwnCommitStanding {
	const set = hold.standings.get(groupId);
	if (set) return set;
	if (wrote(as, groupId, epoch)) return OwnCommitStanding.Tentative;
	const held = (scene.posted.get(groupId) ?? []).some((h) => h.epoch === epoch);
	return held ? OwnCommitStanding.Superseded : OwnCommitStanding.Absent;
}

/** The handshakes read as the server answers it, for the agent `as`. */
async function serve(as: string, groupId: string, since: number, pending?: number) {
	hold.pendingReads.push({ groupId, pendingEpoch: pending });
	const served = await feed({ as }, groupId, since);
	const handshakes = [
		...served.handshakes,
		...hold.extraHandshakes.map((h, i) => ({ id: `extra-${i}`, created_at: "2026-01-01T00:00:00Z", ...h })),
	];
	const standing = standingAt(as, groupId, since + 1);
	const peers = (scene.posted.get(groupId) ?? []).map((h) => h.epoch).filter((e) => !wrote(as, groupId, e));
	const confirmed = Math.max(0, ...peers, standing === OwnCommitStanding.Confirmed ? since + 1 : 0);
	const from = pending !== undefined && standing === OwnCommitStanding.Confirmed ? pending : since;
	if (handshakes.length === 0 && from < confirmed) {
		throw new RineApiError(409, "resync required", undefined, "mls_resync_required");
	}
	return pending === undefined || hold.omitStanding ? { handshakes } : { handshakes, pending_commit: standing };
}

export function installHoldServer(): void {
	resetHoldServer();
	const post = vi.mocked(mlsCommit).getMockImplementation()!;
	const handshakes = vi.mocked(fetchHandshakes).getMockImplementation()!;
	vi.mocked(mlsCommit).mockImplementation(async (client, groupId, body, headers) => {
		const error = hold.postErrors.shift();
		if (error) throw error;
		hold.onPost?.(asOf(client), groupId);
		const resp = await post(client, groupId, body, headers);
		hold.posts.push({ as: asOf(client), groupId, epoch: body.epoch ?? 0 });
		return { ...resp, confirmed: hold.confirmed };
	});
	feed = async (client, groupId, since) => {
		const all = await handshakes(client as never, groupId, since);
		const mine = new Set(
			hold.posts.filter((p) => p.groupId === groupId && p.as === asOf(client)).map((p) => p.epoch),
		);
		return { handshakes: all.handshakes.filter((h) => !mine.has(h.epoch ?? -1)) };
	};
	vi.mocked(fetchHandshakes).mockImplementation(async (client, groupId, since) => {
		const { handshakes: served } = await serve(asOf(client), groupId, since ?? 0);
		return { handshakes: served };
	});
}
