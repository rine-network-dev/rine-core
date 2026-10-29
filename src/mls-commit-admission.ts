/**
 * Catch-up admission: a peer the native core refuses by name is chain-verified,
 * and the same input is tried again.
 *
 * A member that missed a commit meets leaves it never saw, so an input that adds
 * a peer is refused until that peer is in the allowed set. The core says which
 * agent it refused, and this loop is the one place that answers by verifying that
 * agent through {@link admitPeers} and retrying. Nothing enters the allowed set
 * except through that verification.
 *
 * Sync, resync and reseat read a tree or a commit another member built, so a leaf
 * in it can be refused for real. The removal and orphan commit builds are wrapped
 * the same way, but a core refuses a commit build only over the committer's own
 * leaf, so there the retry is a guard that no honest setup reaches.
 *
 * The id is authenticated on a commit (the core checks the sender's signature
 * before it looks at a leaf), but NOT on a Welcome: tree validation runs before
 * any signature, so anyone who can encrypt to one of this agent's key packages can
 * name any agent. The Welcome open therefore passes a limit, which caps the work a
 * single input can cost.
 */
import { canonicalUuid } from "./crypto/derive.js";
import { MLS_ERR_PEER_NOT_ADMITTED, mlsErrorCode } from "./crypto/mls-errors.js";
import { type PeerActor, admitPeers } from "./mls-allowed.js";

/** A native handle that records the agent its last call refused: an `MlsClient` or an `MlsGroup`. */
export interface RefusalSource {
	refusedPeer(): Uint8Array | null;
}

const asciiDecoder = new TextDecoder("utf-8", { fatal: true });

/**
 * The canonical agent id a credential identity names, or `null` when the bytes
 * are not one. An identity is the agent id as ASCII, so a leaf whose identity
 * does not parse belongs to no agent the server could be asked about.
 */
export function agentIdOfIdentity(identity: Uint8Array): string | null {
	try {
		return canonicalUuid(asciiDecoder.decode(identity), "credential identity");
	} catch {
		return null;
	}
}

/** The agent ids a leaf identity declares in a commit's `removes`: its own, or none. */
export function removedAgents(identity: Uint8Array): string[] {
	const id = agentIdOfIdentity(identity);
	return id === null ? [] : [id];
}

/** The canonical agent id the source's last call refused, or `null` when it names none. */
export function refusedAgentId(source: RefusalSource): string | null {
	const raw = source.refusedPeer();
	return raw === null ? null : agentIdOfIdentity(raw);
}

/**
 * Run `attempt`, and when the core refuses a leaf by name, chain-verify that
 * agent and run it again.
 *
 * Each retry follows a verification of an agent not yet verified in this call,
 * so the loop makes at most one attempt more than the input has distinct
 * refused agents. A second refusal of an agent already verified is final: its
 * leaf key is not the verified one, or the server no longer vouches for it.
 * That refusal is thrown as the core raised it, with its stable code. A failure
 * of the verification itself (a transport error) propagates as itself, so no
 * caller mistakes it for a verdict on the input.
 *
 * `limit` caps the verifications one call performs: the refusal after the
 * `limit`th is final too, so an input naming more agents than that is unusable
 * rather than a bill of unbounded reads.
 */
export async function admitRefusedPeers<T>(
	actor: PeerActor,
	source: RefusalSource,
	attempt: () => T,
	limit = Number.POSITIVE_INFINITY,
): Promise<T> {
	const verified = new Set<string>();
	for (;;) {
		try {
			return attempt();
		} catch (err) {
			if (mlsErrorCode(err) !== MLS_ERR_PEER_NOT_ADMITTED) throw err;
			const id = refusedAgentId(source);
			if (id === null || verified.has(id) || verified.size >= limit) throw err;
			verified.add(id);
			await admitPeers(actor, [id]);
		}
	}
}
