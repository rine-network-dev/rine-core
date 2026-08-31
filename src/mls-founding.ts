import { claimKeyPackagesBatch } from "./crypto/mls-api.js";
import type { HttpClient } from "./http.js";

/**
 * Base64 bytes one founding `POST /groups/{id}/mls/commit` may weigh.
 *
 * A founding POST carries the commit, the republished GroupInfo and one Welcome
 * per admitted member — and every Welcome carries the whole ratchet tree, so the
 * body grows with the size of the group being founded times the size of the
 * batch. A fixed batch size cannot bound that. The old fixed 13 was calibrated
 * at a 14-member group and held nowhere else: MEASURED, the largest POST of a
 * 1000-member founding was 27,435,696 B, 45.7x the ~600 kB its own docstring
 * promised.
 *
 * Checking this budget against the server's caps, without re-deriving anything:
 *
 * - a single blob is capped at `MLS_BLOB_MAX_B64` = 2 MiB
 *   (`src/rine/api/mls_schemas.py`); at the 500-member ceiling a Welcome is
 *   ~0.95 MB, 45 % of it;
 * - `MlsCommitRequest.welcomes` accepts at most `MLS_COMMIT_WELCOMES_MAX`
 *   entries, so that — not this budget — is what bounds a batch in a small
 *   group;
 * - the schema-permitted maximum body is therefore 34 x 2 MiB = 68 MiB, inside
 *   the 69 MiB `body_size_middleware` backstop — which is DERIVED from that
 *   maximum plus a MiB of JSON envelope, so the margin is deliberate and thin
 *   rather than accidental. This budget is 8 MiB, an eighth of what the server
 *   would accept, because founding should be responsive and not merely legal.
 *
 * Why 8 MiB is a floor as well as a ceiling: at the 500-member group limit
 * (`rine.core.group_limits.MAX_GROUP_MEMBERS`) even a ONE-member commit weighs
 * ~2.7 MB, so any budget below that would make a full-size group unfoundable at
 * every batch size. 8 MiB carries 3x that, and still admits the server's full
 * 32-entry batch for groups up to ~90 members.
 *
 * What the budget costs, stated rather than buried: founding a 500-member group
 * moves ~292 MB in 39 commits under this rule, against ~268 MB in 16 commits at
 * a flat batch of 32 — 9 % more traffic to hold the largest single body at
 * 7.8 MB instead of 30.6 MB. The old constant failed on body size, not on total
 * traffic, which is why the fix is a declared budget rather than a smaller
 * number.
 */
export const MLS_FOUNDING_POST_BUDGET_B64 = 8 * 1024 * 1024;

/**
 * Welcome entries the server accepts in one commit — `MlsCommitRequest.welcomes`
 * `max_length` (`src/rine/api/mls_schemas.py`). A batch is never larger than
 * this, whatever the budget allows.
 */
const MLS_COMMIT_WELCOMES_MAX = 32;

/**
 * Base64 bytes of Welcome per seated member, and the size-independent remainder.
 *
 * MEASURED on the default post-quantum suite `0xF057`, against real Welcome
 * bytes at the sizes quoted below. What re-checks them is the live-schedule walk
 * in `rine-mls/crates/rine-mls-core/tests/scale_founding.rs`: it drives the very
 * schedule this file computes, commit by commit against the real MLS core, and
 * fails if any POST outweighs the budget these coefficients were used to keep it
 * under. That test restates the coefficients from here rather than deriving
 * them, so it is a check on this estimate, never its source.
 * The per-member rate mirrors `MLS_WELCOME_B64_PER_MEMBER` in
 * `src/rine/core/group_limits.py` — the same measured number, in a language that
 * cannot import it. The intercept is what makes this estimate an UPPER bound at
 * every measured size rather than a floor (estimate vs measured Welcome:
 * 42,988 / 38,208 at N=16, 199,900 / 198,452 at N=100, 480,100 / 477,320 at
 * N=250, 1,881,100 / 1,866,664 at N=1000). Under-estimating is what produces an
 * oversized POST, so the model error is spent in the safe direction. Classical
 * `0x0001` blobs are ~6.9x smaller, so sizing every suite on the post-quantum
 * rate is conservative there too.
 */
const WELCOME_B64_PER_MEMBER = 1_868;
const WELCOME_B64_BASE = 13_100;

/**
 * The commit's UpdatePath plus the republished GroupInfo, priced in Welcomes.
 * MEASURED at 1.85 Welcomes on `0xF057` and 1.41 on `0x0001`, at every size;
 * rounded up, which is the same rounding as the `floor(BUDGET / Welcome) - 2`
 * approximation the measured curve was fitted with: the commit and the
 * republished GroupInfo together cost under two Welcomes at every size, so
 * charging exactly two never under-prices the POST.
 */
const COMMIT_AND_GROUP_INFO_IN_WELCOMES = 2;

/**
 * Estimated base64 weight of a founding POST admitting `batch` members into a
 * tree of `seated` members. `seated` counts the joiners: a Welcome describes the
 * tree the joiner lands in, not the one that existed before the commit.
 */
function foundingPostB64(seated: number, batch: number): number {
	const welcome = WELCOME_B64_PER_MEMBER * seated + WELCOME_B64_BASE;
	return welcome * (batch + COMMIT_AND_GROUP_INFO_IN_WELCOMES);
}

/** The largest batch a group of `seated` members can admit within the budget. */
function batchSizeAt(seated: number): number {
	let batch = MLS_COMMIT_WELCOMES_MAX;
	while (
		batch > 1 &&
		foundingPostB64(seated + batch, batch) > MLS_FOUNDING_POST_BUDGET_B64
	) {
		batch--;
	}
	return batch;
}

/**
 * How many members each successive commit admits, for `joinerCount` members
 * joining a tree that already holds `seated`. The batch shrinks as the tree
 * grows, because the cost of a batch is the batch times the size of the group
 * it is joining — the last batch of a large founding joins a nearly-complete
 * tree, so it is the heaviest POST the founding ever sends.
 *
 * Seating 499 joiners into a group of 1 takes 39 commits: 32 members in the
 * first, 2 in the last, none of them weighing more than ~7.8 MB. The batch
 * never falls below 1, so a group at the ceiling always founds.
 *
 * `seated` defaults to 1 — the founder alone — which is founding. Any other
 * value is a later admission into a group that already exists: founding is the
 * case `seated = 1`, and batched adds are the same arithmetic started further
 * along, which is why there is one function and not two.
 */
export function mlsFoundingBatchSizes(
	joinerCount: number,
	seated = 1,
): number[] {
	const sizes: number[] = [];
	let tree = seated;
	while (tree - seated < joinerCount) {
		const batch = Math.min(joinerCount - (tree - seated), batchSizeAt(tree));
		sizes.push(batch);
		tree += batch;
	}
	return sizes;
}

/**
 * Agent ids one `POST /agents/mls/key-packages/claim` accepts, matching the cap
 * on `GET /agents/keys` (`src/rine/api/agents.py`). The client chunks to it rather
 * than trusting the server to take whatever it sends: an unchunked client
 * against a server-side id cap is the live defect this chunking closes on the
 * sender-key side, where a 201-recipient group send throws the 400 out of the
 * send with nothing distributed at all.
 */
export const MLS_CLAIM_AGENTS_MAX = 200;

/**
 * Claim one KeyPackage each for `agentIds`, chunked at `MLS_CLAIM_AGENTS_MAX`.
 *
 * Founding used to claim one agent at a time: 999 sequential round trips,
 * 3.56 MB and ~20 s of wall clock before the first commit at N=1000.
 *
 * An agent the server holds no KeyPackage for comes back with an empty
 * `packages` array — not an error, and not a missing entry — and is simply
 * absent from the returned map, so founding skips that member instead of
 * failing. Keys are lower-cased, so a caller may look them up by whatever
 * casing it holds the agent id in.
 */
export async function claimFoundingKeyPackages(
	client: HttpClient,
	agentIds: string[],
): Promise<Map<string, string>> {
	const claimed = new Map<string, string>();
	for (let i = 0; i < agentIds.length; i += MLS_CLAIM_AGENTS_MAX) {
		const { claims } = await claimKeyPackagesBatch(
			client,
			agentIds.slice(i, i + MLS_CLAIM_AGENTS_MAX),
		);
		for (const claim of claims) {
			const first = claim.packages[0];
			if (first) claimed.set(claim.agent_id.toLowerCase(), first);
		}
	}
	return claimed;
}
