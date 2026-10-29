/**
 * The shared MLS group send: the order of drain, encrypt and post, the scoped
 * no-state recovery and the single `escrow_missing` retry. The native group and
 * the network are the externals, so they are replaced; the control flow under
 * test is real.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";

const calls = vi.hoisted(() => [] as string[]);
const hoisted = vi.hoisted(() => ({
	encrypt: vi.fn(),
	prepare: vi.fn(),
	welcomes: vi.fn(),
	sync: vi.fn(),
	upload: vi.fn(),
}));

vi.mock("../src/message-mls.js", () => ({ encryptMlsGroupMessage: hoisted.encrypt }));
vi.mock("../src/mls-ops-join.js", () => ({ processMlsWelcomes: hoisted.welcomes }));
vi.mock("../src/mls-ops-sync.js", () => ({ syncMlsGroup: hoisted.sync }));
vi.mock("../src/mls-escrow-upload.js", async (importOriginal) => ({
	...(await importOriginal<typeof import("../src/mls-escrow-upload.js")>()),
	uploadPendingEscrow: hoisted.upload,
}));
vi.mock("../src/mls-escrow-send.js", async (importOriginal) => ({
	...(await importOriginal<typeof import("../src/mls-escrow-send.js")>()),
	prepareEscrowForSend: hoisted.prepare,
}));

import { noMlsStateError } from "../src/crypto/mls.js";
import { RineApiError } from "../src/errors.js";
import type { HttpClient } from "../src/http.js";
import { sealAndPostMlsGroupMessage } from "../src/mls-group-send.js";

const actor = {
	configDir: "/cfg",
	agentId: "agent-1",
	client: {} as HttpClient,
};
const escrowMissing = () => new RineApiError(409, "escrow missing", undefined, "escrow_missing");

beforeEach(() => {
	calls.length = 0;
	for (const fn of Object.values(hoisted)) fn.mockReset();
	hoisted.welcomes.mockImplementation(async () => {
		calls.push("welcomes");
	});
	hoisted.sync.mockImplementation(async () => {
		calls.push("sync");
	});
	hoisted.prepare.mockImplementation(async () => {
		calls.push("prepare");
		return "fp-one";
	});
	hoisted.encrypt.mockImplementation(async () => {
		calls.push("encrypt");
		return { encrypted_payload: "ct", encryption_version: "mls-v1" };
	});
	hoisted.upload.mockImplementation(async () => {
		calls.push("upload");
	});
});

describe("sealAndPostMlsGroupMessage", () => {
	it("drains the escrow before it encrypts and posts the fingerprint it drained", async () => {
		const post = vi.fn(async () => "posted");

		const result = await sealAndPostMlsGroupMessage(actor, "g1", { hi: 1 }, post);

		expect(result).toBe("posted");
		expect(calls).toEqual(["welcomes", "sync", "prepare", "encrypt"]);
		expect(post).toHaveBeenCalledWith({
			encrypted_payload: "ct",
			encryption_version: "mls-v1",
			escrow_fp: "fp-one",
		});
	});

	it("does not encrypt when the drain cannot run", async () => {
		hoisted.prepare.mockRejectedValueOnce(new Error("escrow gap"));

		await expect(sealAndPostMlsGroupMessage(actor, "g1", {}, vi.fn())).rejects.toThrow("escrow gap");

		expect(hoisted.encrypt).not.toHaveBeenCalled();
	});

	it("installs the welcomes scoped to this group once when no state is held, then seals", async () => {
		hoisted.prepare
			.mockRejectedValueOnce(noMlsStateError("g1"))
			.mockResolvedValueOnce("fp-two");
		const post = vi.fn(async () => "posted");

		await sealAndPostMlsGroupMessage(actor, "g1", {}, post);

		expect(hoisted.welcomes).toHaveBeenLastCalledWith("/cfg", "agent-1", actor.client, {
			forGroup: "g1",
		});
		expect(post).toHaveBeenCalledWith(expect.objectContaining({ escrow_fp: "fp-two" }));
	});

	it("posts once more with the same fingerprint after an escrow_missing refusal", async () => {
		const post = vi
			.fn<(fields: { escrow_fp: string }) => Promise<string>>()
			.mockRejectedValueOnce(escrowMissing())
			.mockResolvedValueOnce("posted");

		await sealAndPostMlsGroupMessage(actor, "g1", {}, post);

		expect(hoisted.upload).toHaveBeenCalledTimes(1);
		expect(post.mock.calls.map(([fields]) => fields.escrow_fp)).toEqual(["fp-one", "fp-one"]);
		expect(hoisted.encrypt).toHaveBeenCalledTimes(1);
	});

	it("gives up after a second escrow_missing", async () => {
		const post = vi.fn().mockRejectedValue(escrowMissing());

		await expect(sealAndPostMlsGroupMessage(actor, "g1", {}, post)).rejects.toThrow(RineApiError);

		expect(post).toHaveBeenCalledTimes(2);
	});
});
