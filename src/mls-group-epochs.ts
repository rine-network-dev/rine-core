/**
 * The epoch a group has confirmed, read in one place.
 *
 * `GET /groups/{id}/mls/group-info` answers three epoch-shaped numbers, and they
 * are not interchangeable:
 *
 *   - `epoch` is the newest commit the server has accepted, confirmed or still
 *     tentative. It is what a commit must be built against.
 *   - `confirmed_epoch` is the newest **peer-confirmed** epoch: the one a
 *     joiner's token points at, and the only epoch a member can be said to be
 *     behind. This is the one read here.
 *   - `latch_epoch` is the epoch the server accepted a commit at. Nothing reads
 *     it: a pending commit learns where it stands from the handshakes read
 *     (`fetchHandshakeFeed`), which decides under the group lock.
 *
 * `null` means the group has no confirmed GroupInfo yet (a brand-new group whose
 * first commit is still awaiting a peer ACK is the ordinary case), so a distance
 * measured against it is unknown rather than zero.
 */
import { fetchGroupInfo } from "./crypto/mls-api.js";
import { RineApiError } from "./errors.js";
import type { HttpClient } from "./http.js";

interface GroupEpochs {
	/** The newest peer-confirmed epoch: where a joiner's token points. Null when the group has none. */
	confirmed: number | null;
}

/**
 * The group's confirmed epoch, or `null` when the group has published
 * no confirmed GroupInfo yet.
 *
 * The server says "no confirmed GroupInfo yet" with a 409 carrying
 * `pending_confirmation`; that is an answer, not a failure, so it becomes
 * `null`. Every other failure is rethrown unchanged — a caller that cannot tell
 * a missing GroupInfo from an outage would report a wedged group where there is
 * only a network problem.
 */
export async function fetchGroupEpochs(
	client: HttpClient,
	groupId: string,
	extraHeaders?: Record<string, string>,
): Promise<GroupEpochs | null> {
	try {
		const info = await fetchGroupInfo(client, groupId, extraHeaders);
		return { confirmed: info.confirmed_epoch ?? null };
	} catch (err) {
		if (
			err instanceof RineApiError &&
			err.status === 409 &&
			err.code === "pending_confirmation"
		) {
			return null;
		}
		throw err;
	}
}
