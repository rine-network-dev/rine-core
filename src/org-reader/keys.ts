// The org reader's key: one read secret and the reader signer, held in #private fields so no
// enumerable property, JSON output or inspect output shows key bytes. The root is read
// once, turned into the read secret by deriveOrgRead and zeroed; the reader never keeps rSign.
import { type AssertionSigner, orgReaderSigner } from "../assertion.js";
import { assertBranchName } from "../crypto/derive.js";
import { branchReadSecret, deriveOrgRead } from "../crypto/derive-read.js";
import type { KeyPair } from "../crypto/keys.js";
import { loadRoot, ROOT_KEY_FILE } from "../owner.js";
import { type Principal, PrincipalKind } from "../principal.js";

export class ReadKey {
	/** The org id, taken from the root itself: a local anchor, never a server answer. */
	readonly orgId: string;
	readonly #rRead: Uint8Array;
	readonly #reader: KeyPair;
	readonly #branches = new Map<string, Uint8Array>();
	#disposed = false;

	private constructor(orgId: string, rRead: Uint8Array, reader: KeyPair) {
		this.orgId = orgId;
		this.#rRead = rRead;
		this.#reader = reader;
	}

	/** The org-wide reader of the org whose `root.key` sits in `ownerDir`. */
	static fromOwnerDir(ownerDir: string): ReadKey {
		const root = loadRoot(ownerDir);
		if (root === undefined) {
			throw new Error(`No ${ROOT_KEY_FILE} in ${ownerDir}`);
		}
		try {
			return ReadKey.fromRoot(root);
		} finally {
			root.fill(0);
		}
	}

	/** The org-wide reader of `root`. The caller keeps ownership of `root` and zeroes it. */
	static fromRoot(root: Uint8Array): ReadKey {
		const { orgId, rRead, reader } = deriveOrgRead(root);
		return new ReadKey(orgId, rRead, reader);
	}

	/** The `reader:<org>` principal. */
	get principal(): Principal {
		return { kind: PrincipalKind.Reader, orgId: this.orgId };
	}

	/** The reader principal and its assertion seed; the seed is zeroed by `dispose()`. */
	get signer(): AssertionSigner {
		this.#assertLive();
		return orgReaderSigner({ orgId: this.orgId, reader: this.#reader });
	}

	/** `B_read` of `name`, derived once and zeroed by `dispose()`. */
	branchRead(name: string): Uint8Array {
		this.#assertLive();
		let bRead = this.#branches.get(name);
		if (bRead === undefined) {
			bRead = branchReadSecret(this.#rRead, assertBranchName(name));
			this.#branches.set(name, bRead);
		}
		return bRead;
	}

	/** Zero the read secret, the signer seed and every cached `B_read`. Idempotent. */
	dispose(): void {
		this.#disposed = true;
		this.#rRead.fill(0);
		this.#reader.privateKey.fill(0);
		for (const bRead of this.#branches.values()) bRead.fill(0);
		this.#branches.clear();
	}

	#assertLive(): void {
		if (this.#disposed) throw new Error("ReadKey is disposed");
	}
}
