import { describe, expect, it, vi } from "vitest";
import { deriveOrg, fromBase64Url } from "../src/crypto/index.js";
import { deriveBranch } from "../src/crypto/derive.js";
import type { HttpClient } from "../src/http.js";
import { branchPublication, createBranch, revokeBranch } from "../src/org-branch.js";

const org = deriveOrg(new Uint8Array(32).fill(3));

function fakeClient() {
	return { post: vi.fn(async () => ({})), delete: vi.fn(async () => ({})) } as unknown as HttpClient & {
		post: ReturnType<typeof vi.fn>;
		delete: ReturnType<typeof vi.fn>;
	};
}

describe("createBranch", () => {
	it("posts the branch name, its public keys and an org-signed certificate", async () => {
		const client = fakeClient();
		const branch = deriveBranch(org, "partner-a");

		await createBranch(client, org, branch);

		expect(client.post).toHaveBeenCalledTimes(1);
		const [path, body] = client.post.mock.calls[0] as [string, Record<string, string>];
		const signingKey = body.signing_public_key as string;
		expect(path).toBe("/orgs/me/branches");
		expect(body.name).toBe("partner-a");
		expect(Object.keys(body).sort()).toEqual(
			[
				"certificate",
				"escrow_pq_public_key",
				"escrow_public_key",
				"name",
				"pq_signing_public_key",
				"reader_public_key",
				"signing_public_key",
			].sort(),
		);
		expect(fromBase64Url(signingKey)).toEqual(branch.ed25519.publicKey);
	});
});

describe("branchPublication", () => {
	it("carries no secret of the branch", () => {
		const branch = deriveBranch(org, "partner-a");
		const text = JSON.stringify(branchPublication(org, branch, 1_700_000_000));

		expect(text).not.toContain(Buffer.from(branch.bRead).toString("base64url"));
		expect(text).not.toContain(Buffer.from(branch.bSign).toString("base64url"));
	});
});

describe("revokeBranch", () => {
	it("deletes the branch by its encoded name", async () => {
		const client = fakeClient();

		await revokeBranch(client, "partner-a");

		expect(client.delete).toHaveBeenCalledWith("/orgs/me/branches/partner-a", undefined, {
			confirm: false,
		});
	});

	it("sends the confirm field when asked to revoke a protected branch", async () => {
		const client = fakeClient();

		await revokeBranch(client, "main", true);

		expect(client.delete).toHaveBeenCalledWith("/orgs/me/branches/main", undefined, {
			confirm: true,
		});
	});

	it("refuses a name that would leave the branches path", async () => {
		const client = fakeClient();

		await expect(revokeBranch(client, "../../agents/x")).rejects.toThrow("invalid branch name");
		expect(client.delete).not.toHaveBeenCalled();
	});
});
