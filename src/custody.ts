// Where key material lives and which principal a dir acts as.
import * as fs from "node:fs";
import { join } from "node:path";
import { loadBranchSecrets } from "./branch-files.js";
import {
	type BranchKeys,
	type OrgKeys,
	deriveBranch,
	deriveOrg,
} from "./crypto/derive.js";
import { loadRoot } from "./owner.js";
import { loadProfiles } from "./profiles.js";
import { CANONICAL_UUID_RE } from "./uuid.js";

export interface CustodyDirs {
	/** The runtime config dir: agent/branch profiles, leaf keys, branch key files. */
	configDir: string;
	/** The owner dir: `root.key`, the phrase, the org profile. */
	ownerDir: string;
	/** Always absent: tells these dirs apart from the agent-only form in `AuthDirs`. */
	agentOnly?: false;
}

/** An org's identity and the branch it signs under, enough to mint or rotate agents. */
export interface Custody {
	orgId: string;
	branch: BranchKeys;
}

/** The org derived from `root.key`, or undefined for a dir without one. */
export function loadOrgFromOwner(ownerDir: string): OrgKeys | undefined {
	const root = loadRoot(ownerDir);
	return root === undefined ? undefined : deriveOrg(root);
}

/**
 * Custody of `branch`: derived from `root.key` when the owner dir has one, else
 * from the delegate's `branch/<name>/*.key` files plus the org id its profile names.
 */
export function loadCustody(dirs: CustodyDirs, branch: string): Custody {
	const org = loadOrgFromOwner(dirs.ownerDir);
	if (org !== undefined) {
		return { orgId: org.orgId, branch: deriveBranch(org, branch) };
	}
	const held = loadBranchSecrets(dirs.configDir, branch);
	const orgId = Object.values(loadProfiles(dirs.configDir)).find(
		(entry) => entry.branch === branch,
	)?.org_id;
	if (held === undefined || orgId === undefined) {
		throw new Error(
			`No key material for branch '${branch}': need root.key in the owner dir or branch key files in the config dir`,
		);
	}
	return { orgId, branch: held };
}

/** Agent ids whose leaf keys this config dir holds. */
export function localAgentIds(configDir: string): string[] {
	try {
		return fs
			.readdirSync(join(configDir, "keys"))
			.filter((id) => CANONICAL_UUID_RE.test(id));
	} catch {
		return [];
	}
}
