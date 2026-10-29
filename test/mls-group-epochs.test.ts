/**
 * The confirmed epoch a group publishes, read through the one fetcher.
 *
 * Only the network is mocked: `fetchGroupInfo` is a `vi.fn()` and everything
 * else in `crypto/mls-api.js` is the real module. A test here fails when the
 * fetcher invents an epoch the server did not send, swallows a failure that is
 * not the "no confirmed GroupInfo yet" refusal, or drops the acting-agent
 * headers a multi-agent client needs.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../src/crypto/mls-api.js", async () => {
	const actual = await vi.importActual<typeof import("../src/crypto/mls-api.js")>(
		"../src/crypto/mls-api.js",
	);
	return {
		...actual,
		fetchGroupInfo: vi.fn(),
	};
});

import { fetchGroupInfo } from "../src/crypto/mls-api.js";
import { RineApiError } from "../src/errors.js";
import { fetchGroupEpochs } from "../src/mls-group-epochs.js";

const GROUP_ID = "c3d4e5f6-a7b8-9012-cdef-123456789012";
const client = {} as never;

beforeEach(() => {
	vi.clearAllMocks();
});

describe("fetchGroupEpochs", () => {
	it("test_fetch_group_epochs_when_the_response_carries_both_then_it_returns_the_confirmed_one", async () => {
		vi.mocked(fetchGroupInfo).mockResolvedValue({
			group_info: "blob",
			epoch: 7,
			confirmed_epoch: 5,
			latch_epoch: 7,
		});

		await expect(fetchGroupEpochs(client, GROUP_ID)).resolves.toEqual({
			confirmed: 5,
		});
	});

	it("test_fetch_group_epochs_when_the_response_lacks_both_then_it_is_null", async () => {
		vi.mocked(fetchGroupInfo).mockResolvedValue({
			group_info: null,
			epoch: null,
		});

		await expect(fetchGroupEpochs(client, GROUP_ID)).resolves.toEqual({
			confirmed: null,
		});
	});

	it("test_fetch_group_epochs_when_the_group_has_no_confirmed_group_info_then_it_returns_null", async () => {
		vi.mocked(fetchGroupInfo).mockRejectedValue(
			new RineApiError(409, "pending", undefined, "pending_confirmation"),
		);

		await expect(fetchGroupEpochs(client, GROUP_ID)).resolves.toBeNull();
	});

	it("test_fetch_group_epochs_when_a_409_names_another_code_then_it_rethrows", async () => {
		const err = new RineApiError(409, "conflict", undefined, "epoch_conflict");
		vi.mocked(fetchGroupInfo).mockRejectedValue(err);

		await expect(fetchGroupEpochs(client, GROUP_ID)).rejects.toBe(err);
	});

	it("test_fetch_group_epochs_when_the_failure_is_not_an_api_error_then_it_rethrows", async () => {
		const err = new Error("boom");
		vi.mocked(fetchGroupInfo).mockRejectedValue(err);

		await expect(fetchGroupEpochs(client, GROUP_ID)).rejects.toBe(err);
	});

	it("test_fetch_group_epochs_when_headers_are_given_then_they_reach_the_fetcher", async () => {
		vi.mocked(fetchGroupInfo).mockResolvedValue({
			group_info: null,
			epoch: null,
		});
		const headers = { "X-Rine-Agent": "b2c3d4e5-f6a7-8901-bcde-f12345678901" };

		await fetchGroupEpochs(client, GROUP_ID, headers);

		expect(fetchGroupInfo).toHaveBeenCalledWith(client, GROUP_ID, headers);
	});
});
