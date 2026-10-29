import type { HttpClient } from "../http.js";
import type { MlsHandshakeEntry } from "./mls-api.js";

/** Where the server holds the caller's own pending commit, as the handshakes read answers it. */
export const OwnCommitStanding = {
	/** Accepted, and no member has acknowledged it yet. */
	Tentative: "tentative",
	/** A member acknowledged it: it is the group's commit at its epoch. */
	Confirmed: "confirmed",
	/** The server quarantined it, or the latch fell back below its epoch. */
	RolledBack: "rolled_back",
	/** Another agent's commit holds its epoch. */
	Superseded: "superseded",
	/** The server holds no commit of the caller's at that epoch. */
	Absent: "absent",
} as const;
export type OwnCommitStanding = (typeof OwnCommitStanding)[keyof typeof OwnCommitStanding];

export interface MlsHandshakeFeed {
	handshakes: MlsHandshakeEntry[];
	/** Present only when the request named a `pending_epoch`. */
	pendingCommit?: OwnCommitStanding;
}

/**
 * The commits served since `sinceEpoch`. With `pendingEpoch` (which must be
 * `sinceEpoch + 1`) the server also says where the caller's own commit at that
 * epoch stands, and measures replay reachability from it only when it is
 * confirmed, so a holder of a confirmed commit is not sent to a resync.
 */
export async function fetchHandshakeFeed(
	client: HttpClient,
	groupId: string,
	sinceEpoch?: number,
	extraHeaders?: Record<string, string>,
	pendingEpoch?: number,
): Promise<MlsHandshakeFeed> {
	const params: Record<string, string> = {};
	if (sinceEpoch !== undefined) params["since_epoch"] = String(sinceEpoch);
	if (pendingEpoch !== undefined) params["pending_epoch"] = String(pendingEpoch);
	const body = (await client.get(
		`/groups/${groupId}/mls/handshakes`,
		params,
		extraHeaders,
	)) as { handshakes: MlsHandshakeEntry[]; pending_commit?: OwnCommitStanding | null };
	const feed: MlsHandshakeFeed = { handshakes: body.handshakes };
	if (body.pending_commit != null) feed.pendingCommit = body.pending_commit;
	return feed;
}
