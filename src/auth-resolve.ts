// Which principal a set of dirs signs as.
import { type AssertionSigner, agentSigner } from "./assertion.js";
import { signerFor } from "./auth-signer.js";
import type { OrgKeys } from "./crypto/derive.js";
import { loadAgentKeys } from "./crypto/keys.js";
import { type CustodyDirs, loadOrgFromOwner } from "./custody.js";
import { type Principal, PrincipalKind, parsePrincipal } from "./principal.js";
import { DEFAULT_PROFILE, getProfile } from "./profiles.js";
import type { ProfileEntry } from "./types.js";

/**
 * The dirs of an agent runtime: it signs as the agent whose leaf keys the config
 * dir holds and never reads an owner dir, so a `root.key` on the host cannot make
 * it act as the org.
 */
export interface AgentOnlyDirs {
	configDir: string;
	ownerDir?: undefined;
	agentOnly: true;
}

/** What {@link resolveAuth} reads an identity from. */
export type AuthDirs = CustodyDirs | AgentOnlyDirs;

export const AGENT_ONLY_OWNER_DIR =
	"An agent-only runtime takes no owner directory: it never reads one.";

/** Dirs asked for an agent-only runtime and for an owner dir at once. */
export class AgentOnlyOwnerDirError extends Error {
	constructor() {
		super(AGENT_ONLY_OWNER_DIR);
		this.name = "AgentOnlyOwnerDirError";
	}
}

export const ORG_CLAIM_MISMATCH =
	"The profile names an org that does not match its principal or root.";

export interface ResolvedAuth {
	signer: AssertionSigner;
	orgId: string | undefined;
	/** Where this principal's access token is cached: the owner dir for anything derived from `root.key`. */
	cacheDir: string;
	/**
	 * The one agent this principal can act as, set only for an agent principal:
	 * the server lets it act as nobody else, so an agent-scoped job (the escrow
	 * sweep) over a shared config dir must not touch a sibling's files with it.
	 */
	agentId?: string;
}

/**
 * The profile a dir acts as. A named profile is looked up in the runtime dir
 * first; the default profile prefers the org when the owner dir holds a
 * `root.key`. The owner dir's profile applies to a runtime dir only when both
 * name the same org, so a second org's runtime dir (an agent kit) is never
 * signed as the org whose root the host holds. The Python twin is
 * `_choose_profile`.
 */
function chooseProfile(
	dirs: CustodyDirs,
	profile: string | undefined,
	hasOwner: boolean,
): ProfileEntry | undefined {
	const name = profile ?? DEFAULT_PROFILE;
	const runtime = getProfile(dirs.configDir, name);
	let owner = hasOwner ? getProfile(dirs.ownerDir, name) : undefined;
	if (
		owner !== undefined &&
		runtime !== undefined &&
		runtime.org_id !== owner.org_id
	)
		owner = undefined;
	return profile === undefined ? (owner ?? runtime) : (runtime ?? owner);
}

/**
 * Refuse a profile whose org id disagrees with what the key material proves.
 *
 * The profile's `org_id` becomes the org every own agent is pinned to, so it
 * must be the org the principal names and, when the key came from `root.key`,
 * the org that root derives. The Python twin is `_check_org_claim`.
 */
function checkOrgClaim(
	entry: ProfileEntry,
	principal: Principal,
	org: OrgKeys | undefined,
	fromRoot: boolean,
): void {
	if (
		principal.kind === PrincipalKind.Agent ||
		principal.kind === PrincipalKind.Delegate
	)
		return;
	if (
		principal.orgId !== entry.org_id ||
		(fromRoot && org !== undefined && org.orgId !== entry.org_id)
	) {
		throw new Error(ORG_CLAIM_MISMATCH);
	}
}

function resolveAgentOnly(
	dirs: AgentOnlyDirs,
	profile: string | undefined,
): ResolvedAuth | undefined {
	if (dirs.ownerDir !== undefined) throw new AgentOnlyOwnerDirError();
	const entry = getProfile(dirs.configDir, profile ?? DEFAULT_PROFILE);
	if (entry === undefined) return undefined;
	const principal = parsePrincipal(entry.principal);
	if (principal.kind !== PrincipalKind.Agent) return undefined;
	return {
		signer: agentSigner(
			principal.agentId,
			loadAgentKeys(dirs.configDir, principal.agentId),
		),
		orgId: entry.org_id,
		cacheDir: dirs.configDir,
		agentId: principal.agentId,
	};
}

/**
 * The signer for `profile`, or undefined when this dir holds no identity to act as.
 * An agent-only runtime resolves only an agent profile from the config dir and never
 * reads `root.key` or a branch key file, so any other principal resolves to nothing.
 */
export function resolveAuth(
	dirs: AuthDirs,
	profile?: string,
): ResolvedAuth | undefined {
	if (dirs.agentOnly === true) return resolveAgentOnly(dirs, profile);
	const org = loadOrgFromOwner(dirs.ownerDir);
	const entry = chooseProfile(dirs, profile, org !== undefined);
	if (entry === undefined) return undefined;
	const principal = parsePrincipal(entry.principal);
	const resolved = signerFor(principal, dirs, org);
	if (resolved === undefined) return undefined;
	checkOrgClaim(entry, principal, org, resolved.fromRoot);
	return {
		signer: resolved.signer,
		orgId: entry.org_id,
		cacheDir: resolved.fromRoot ? dirs.ownerDir : dirs.configDir,
		...(principal.kind === PrincipalKind.Agent && {
			agentId: principal.agentId,
		}),
	};
}
