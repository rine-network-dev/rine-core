// The signer a principal signs assertions with, from the keys this machine holds.
import {
	type AssertionSigner,
	agentSigner,
	branchReaderSigner,
	branchSigner,
	delegateSigner,
	orgReaderSigner,
	orgSigner,
} from "./assertion.js";
import { loadBranchSecrets } from "./branch-files.js";
import { type OrgKeys, deriveBranch } from "./crypto/derive.js";
import { loadAgentKeys } from "./crypto/keys.js";
import type { CustodyDirs } from "./custody.js";
import { loadDelegateSeed } from "./delegate-files.js";
import { type Principal, PrincipalKind } from "./principal.js";

/** The signer for `principal`, and whether it came from the org root; undefined when no key is held. */
export function signerFor(
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
		case PrincipalKind.Delegate: {
			const seed = loadDelegateSeed(dirs.configDir, principal.delegateId);
			return (
				seed && {
					signer: delegateSigner(principal.delegateId, seed),
					fromRoot: false,
				}
			);
		}
		case PrincipalKind.Branch: {
			const held = loadBranchSecrets(dirs.configDir, principal.name);
			if (held) {
				return { signer: branchSigner(principal.orgId, held), fromRoot: false };
			}
			return (
				org && {
					signer: branchSigner(
						principal.orgId,
						deriveBranch(org, principal.name),
					),
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
