// The owner side of a recovery: the org root and the org profile in the owner dir.
// `rine org recover --owner-only` is this and nothing else, for a caller that needs
// the org to sign in but must not rewrite leaf keys or reseat groups.
import { deriveOrg, entropyFromPhrase, orgWords } from "./crypto/index.js";
import type { CustodyDirs } from "./custody.js";
import { assertFreshOwnerDir, saveRoot } from "./owner.js";
import { PrincipalKind, principalString } from "./principal.js";
import { addProfileIfAbsent } from "./profiles.js";

/** Write the root and the org's `profile` entry into a fresh owner dir. */
export function saveOwnerIdentity(
	ownerDir: string,
	profile: string,
	root: Uint8Array,
	orgId: string,
): void {
	saveRoot(ownerDir, root);
	addProfileIfAbsent(ownerDir, profile, {
		org_id: orgId,
		principal: principalString({ kind: PrincipalKind.Org, orgId }),
	});
}

/**
 * Derive the org from the recovery phrase and write its root and profile into the
 * owner dir. No request is made and no leaf key, token or group state is touched:
 * the org id is a function of the phrase, so there is nothing to ask a server. The
 * phrase is never echoed. Returns the org id and its verification words.
 */
export function restoreOwnerFromPhrase(
	dirs: CustodyDirs,
	profile: string,
	phrase: string,
): { orgId: string; orgWords: string } {
	assertFreshOwnerDir(dirs.ownerDir, dirs.configDir);
	const root = entropyFromPhrase(phrase);
	const { orgId } = deriveOrg(root);
	saveOwnerIdentity(dirs.ownerDir, profile, root, orgId);
	return { orgId, orgWords: orgWords(orgId) };
}
