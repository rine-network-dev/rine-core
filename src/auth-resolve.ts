// Which principal a set of dirs signs as.
import {
	type AssertionSigner,
	agentSigner,
	branchReaderSigner,
	branchSigner,
	orgReaderSigner,
	orgSigner,
} from "./assertion.js";
import { loadBranchSecrets } from "./branch-files.js";
import { type OrgKeys, deriveBranch } from "./crypto/derive.js";
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
	"An agent-only runtime takes no owner dir: it never reads one.";

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

function signerFor(
	principal: Principal,
	dirs: Pick<CustodyDirs, "configDir">,
	org: OrgKeys | undefined,
): { signer: AssertionSigner; fromRoot: boolean } | undefined {
	switch (principal.kind) {
		case PrincipalKind.Org:
			return org && { signer: orgSigner(org), fromRoot: true };
		case PrincipalKind.Agent:
			return {
				signer: agentSigner(
					principal.agentId,
					loadAgentKeys(dirs.configDir, principal.agentId),
				),
				fromRoot: false,
			};
		case PrincipalKind.Branch: {
			const held = loadBranchSecrets(dirs.configDir, principal.name);
			if (held) {
				return { signer: branchSigner(principal.orgId, held), fromRoot: false };
			}
			return (
				org && {
					signer: branchSigner(principal.orgId, deriveBranch(org, principal.name)),
					fromRoot: true,
				}
			);
		}
		case PrincipalKind.Reader: {
			if (principal.name === undefined) {
				return org && { signer: orgReaderSigner(org), fromRoot: true };
			}
			const held = loadBranchSecrets(dirs.configDir, principal.name);
			if (held) {
				return {
					signer: branchReaderSigner(principal.orgId, held),
					fromRoot: false,
				};
			}
			return (
				org && {
					signer: branchReaderSigner(
						principal.orgId,
						deriveBranch(org, principal.name),
					),
					fromRoot: true,
				}
			);
		}
	}
}

/**
 * The profile a dir acts as. A named profile is looked up in the runtime dir
 * first; the default profile prefers the org when the owner dir holds a
 * `root.key`.
 */
function chooseProfile(
	dirs: CustodyDirs,
	profile: string | undefined,
	hasOwner: boolean,
): ProfileEntry | undefined {
	const name = profile ?? DEFAULT_PROFILE;
	const runtime = getProfile(dirs.configDir, name);
	const owner = hasOwner ? getProfile(dirs.ownerDir, name) : undefined;
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
	if (principal.kind === PrincipalKind.Agent) return;
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
