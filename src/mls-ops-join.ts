import type { MlsClient } from "@rine-network/mls";
import { ACTING_AGENT_HEADER } from "./actor.js";
import { fetchWelcomes } from "./crypto/mls-api.js";
import type { HttpClient } from "./http.js";
import { openPeerMlsClient } from "./mls-allowed.js";
import {
	type EscrowReport,
	emptyReport,
	mergeReports,
} from "./mls-escrow-report.js";
import { mlsHeartbeat } from "./mls-heartbeat.js";
import { topUpFromServerCount } from "./mls-keypackage-topup.js";
import { installWelcome } from "./mls-welcome-install.js";
import { type PassRefusal, pickRefusal } from "./mls-welcome-pick.js";
import { WelcomeSpool, isSpoolableId } from "./mls-welcome-spool.js";
import { welcomeReleaser } from "./mls-welcome-release.js";

/** What installing this agent's pending Welcomes achieved. */
export interface WelcomeOutcome {
	processed: number;
	groupIds: string[];
	/** Welcomes this pass dropped rather than installed. */
	discarded: number;
	escrow: EscrowReport;
}

/** How a caller narrows a pass to the one group it is establishing. */
export interface ProcessMlsWelcomesOptions {
	/**
	 * The group this call is establishing state for, when there is exactly one.
	 *
	 * It decides which refusal is raised — see {@link pickRefusal} — and it is
	 * what keeps a refusal for an unrelated group from failing this caller's
	 * work. A caller processing the whole queue (a pre-send sync, a join verb
	 * that does not know which Welcome it is waiting for) leaves it unset.
	 */
	forGroup?: string;
}

/**
 * Fetch all pending MLS welcomes for an agent and process them, establishing
 * local group state for each group the agent has been added to.
 *
 * The native core matches the Welcome to the private half of the KeyPackage it
 * was sealed to and consumes that half on `save()`, so nothing here has to
 * bookkeep key packages.
 *
 * Ordering is the whole design. `GET /agents/{id}/mls/welcomes` marks every
 * Welcome it returns consumed in the same transaction that returns it, so the
 * response is the only copy: it is spooled to disk (`mls-welcome-spool.ts`)
 * before anything is done with it, and an entry leaves the spool only once its
 * join has a final outcome.
 *
 * Every Welcome passes {@link welcomeRefusal} before it is adopted — the group
 * substitution guard, which is what stands between a server-minted group and
 * this agent's real state for the id it claims. A refusal a later attempt could
 * clear keeps its bytes on the spool ({@link refusalIsRetryable}); a
 * deterministic one discards them. Either way the rest of the batch still
 * installs, because abandoning the loop on the first refusal would strand every
 * legitimate Welcome behind it. The same holds for a Welcome no MLS core here
 * can open and for one the server named something that is not a file name: both
 * are dropped and the pass carries on, as the Python twin does.
 *
 * Before any of that, the group's roster read is classified
 * ({@link admitWelcomePeers}). A 403 — an invitation this agent has not
 * accepted yet — keeps the Welcome unopened under the refused-entry bound; a
 * 404 discards it; a transient answer keeps it spooled and unopened for the next
 * pass. A pass that set a Welcome aside asks the server for its key-package
 * count and publishes the shortfall, because the local mirror still counts the
 * halves those Welcomes hold.
 *
 * READ — the Python twin logs the dropped-Welcome cases with a `logger.warning`
 * and this stack does not: rine-core has no logging facility, and its
 * convention for a partial failure is silent degradation with a throw reserved
 * for a total one (`sender-key-ops.ts` `fetchPublishedKeys`). Both stacks count
 * every drop (an unusable Welcome, a poisoned name, a vanished group, a
 * retained entry aged out) into `discarded`, so a caller can say it out loud.
 *
 * 🔴 **Which refusal is raised is {@link pickRefusal}'s decision, and a caller
 * that knows the group it is establishing must say so via `forGroup`.** Without
 * it the pass falls back to "the first refusal whose bytes arrived in this
 * pass" — loud once, then quiet, so a single unusable Welcome cannot fail every
 * future join, send and read on this agent.
 */
export async function processMlsWelcomes(
	configDir: string,
	agentId: string,
	client: HttpClient,
	opts: ProcessMlsWelcomesOptions = {},
): Promise<WelcomeOutcome> {
	const spool = new WelcomeSpool(configDir, agentId);
	// The acting-agent header is what makes the roster read answer for a
	// multi-agent org: without it the group routes cannot tell which agent is
	// asking, and the guard would degrade to its unreadable-roster answer.
	const actor = {
		configDir,
		agentId,
		client,
		extraHeaders: { [ACTING_AGENT_HEADER]: agentId },
	};
	// Opened on first use and shared with the releaser, so a pass that drops
	// nothing and has nothing pending opens no client.
	let opened: MlsClient | undefined;
	const mlsClient = () => (opened ??= openPeerMlsClient(actor));
	const release = welcomeReleaser(mlsClient);
	// Bound the carried-over set BEFORE this pass's arrivals land. The count
	// bound reaches refused entries only, so neither this pass's batch nor one
	// an aborted pass carried over is evicted by its own size — spooling is not
	// the same event as having had a chance.
	let discarded = spool.prune(release);
	// The fetch is one-shot, so an id it returns has never been spooled before:
	// this set is exactly "arrived in this pass".
	const arrived = new Set<string>();
	const { welcomes } = await fetchWelcomes(client, agentId);
	for (const welcome of welcomes) {
		// State is keyed by the rine group UUID (carried on the welcome delivery),
		// which is also what the founder put in the MLS group id. Skip welcomes the
		// server could not associate with a group.
		if (!welcome.group_id) continue;
		if (!isSpoolableId(welcome.id)) {
			// The id becomes the file name, so a server free to answer with a path
			// fragment is free to place the file (MEASURED: `../../../profiles`
			// overwrote the profile store). Asked here rather than caught out of
			// `store`, so a genuine write failure still fails the pass instead of
			// being mistaken for a poisoned name — and so one poisoned name costs
			// its own Welcome and not the rest of the batch.
			discarded += 1;
			continue;
		}
		spool.store({ ...welcome, group_id: welcome.group_id });
		arrived.add(welcome.id);
	}

	const pending = spool.pending();
	if (pending.length === 0) {
		return { processed: 0, groupIds: [], discarded, escrow: emptyReport() };
	}

	const mls = mlsClient();
	const groupIds: string[] = [];
	const refusals: PassRefusal[] = [];
	let escrow = emptyReport();

	// Welcomes this pass set aside without opening because the roster answered
	// definitively. Each still holds the private half it was sealed to, so the
	// local mirror cannot see that the server pool spent it.
	let setAside = 0;

	const ctx = { spool, release, actor, client, mls, configDir, agentId };
	for (const entry of pending) {
		const step = await installWelcome(ctx, entry);
		switch (step.kind) {
			case "waiting":
				break;
			case "set-aside":
				discarded += step.discarded;
				setAside += 1;
				break;
			case "dropped":
				discarded += 1;
				break;
			case "installed":
				groupIds.push(step.groupId);
				escrow = mergeReports(escrow, step.escrow);
				break;
			case "refused":
				discarded += step.discarded;
				refusals.push({
					refusal: step.refusal,
					isNew: arrived.has(entry.delivery.id),
				});
				break;
			default: {
				const unhandled: never = step;
				throw new Error(`unhandled welcome step: ${String(unhandled)}`);
			}
		}
	}

	// Each processed welcome consumed one key package, and this is the only path
	// on which an agent's OWN inventory shrinks — so the beat here is forced,
	// never gated: waiting out a floor would leave the agent short in exactly
	// the window a peer is most likely to add it.
	//
	// Unconditional WITHIN THE PASS, which is the whole claim and the wording the
	// Python twin carries. A pass that found nothing returns early and never
	// arrives here — and 🔴 the fix is NOT to hoist this call above that return.
	// Those agents get their beat from the `postMlsCommit`/`syncMlsGroup` seams;
	// hoisting it would change behaviour nobody has ruled on.
	//
	// A pass whose Welcomes were all dropped still needs it: a dropped Welcome
	// releases its half, so the local mirror is short until a beat republishes.
	await mlsHeartbeat({ configDir, agentId, client }, "forced");
	// A Welcome set aside unopened still holds its private half, so the beat
	// above — which counts the local mirror — reads a full pool while the server
	// may hold none. Only the server's own count can see that, and only a pass
	// that set something aside pays for asking: a healthy pass, and the ordinary
	// beat, make no extra request.
	if (setAside > 0) await topUpFromServerCount({ configDir, agentId, client });
	const refused = pickRefusal(refusals, opts.forGroup);
	if (refused) throw refused;

	return { processed: groupIds.length, groupIds, discarded, escrow };
}
