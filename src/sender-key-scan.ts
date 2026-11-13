/**
 * One pass over the distribution inbox: what it installed, and what it never
 * looked at.
 *
 * The second number is the whole reason this shape exists. The scan reads ONE
 * page of `limit: 100` and follows no cursor, so on an agent whose distribution
 * inbox is longer than that page the pass is a partial one — and the count of
 * what it installed cannot say so. Carrying the two together is what lets the
 * sync answer state the shortfall instead of reporting a partial pass as a
 * whole one.
 */
export interface SenderKeyScan {
	/**
	 * Sender keys newly installed by this pass. What every read path reads, and
	 * the number `fetchAndIngestPendingSKDistributions` hands back.
	 */
	ingested: number;
	/**
	 * How many distribution DMs this pass did not open: the rows the server
	 * counts BEYOND the page it read, plus any of that page a targeted scan
	 * stopped short of. `0` when the pass opened everything, and `0` again when
	 * the server sent no total to compare against.
	 *
	 * 🔴 The two halves are one number because they are one fact. A scan given a
	 * `targetSenderKeyId` breaks the moment it installs that key, so the rest of
	 * its own page is as unopened as the rows past the end of it — counting only
	 * the second half would report a partial pass as a whole one on exactly the
	 * path that stops early.
	 *
	 * 🔴 It is a count of what this pass did not LOOK at, and says nothing about
	 * what those DMs hold: the inbox listing is every distribution this agent has
	 * ever been sent, so most of the ones behind that page are keys it installed
	 * long ago. A renderer may state the number and may not conclude a missing
	 * key from it.
	 */
	unscanned: number;
	/**
	 * Opened rows that threw (a GET or a decrypt), so the key may be behind them.
	 * A row that has thrown on `ROW_FAILURE_LIMIT` scans in a row is no
	 * longer counted: it is a permanent failure, and counting it would keep the
	 * negative cache off for good.
	 */
	failed: number;
}
