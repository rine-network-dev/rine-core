/**
 * The group-info response shape, pinned against the golden fixtures the server
 * contract suite records (`rine-sdk/tests/contract/fixtures/`), so a field the
 * server renames or reorders is read here as the break it is and not as a
 * hand-typed mock that still parses.
 *
 * No module is mocked: the fixture body goes through the real fetcher.
 */
import { describe, expect, it } from "vitest";

import { type MlsGroupInfoResponse, fetchGroupInfo } from "../src/crypto/mls-api.js";
import { fetchGroupEpochs } from "../src/mls-group-epochs.js";
import { golden } from "./helpers/golden.js";

const GROUP_ID = "c3d4e5f6-a7b8-9012-cdef-123456789012";

const served = (name: string): MlsGroupInfoResponse => golden<MlsGroupInfoResponse>(name).body;

const clientServing = (body: MlsGroupInfoResponse) => ({ get: async () => body }) as never;

describe("the group-info response", () => {
	it.each([
		["mls_group_info_200_settled.json"],
		["mls_group_info_200_tentative.json"],
	])("test_group_info_when_the_server_answers_%s_then_the_fetcher_keeps_every_field", async (name) => {
		const body = served(name);

		await expect(fetchGroupInfo(clientServing(body), GROUP_ID)).resolves.toEqual(body);
	});

	it.each([
		["mls_group_info_200_settled.json"],
		["mls_group_info_200_tentative.json"],
	])("test_group_epochs_when_the_server_answers_%s_then_confirmed_is_confirmed_epoch_and_not_the_latch", async (name) => {
		const body = served(name);

		const epochs = await fetchGroupEpochs(clientServing(body), GROUP_ID);

		expect(epochs).toEqual({ confirmed: body.confirmed_epoch });
	});

	it("test_group_info_when_the_latch_is_ahead_of_the_confirmed_epoch_then_the_two_differ_in_the_fixture", () => {
		const body = served("mls_group_info_200_tentative.json");

		expect(body.latch_epoch).toBeGreaterThan(body.confirmed_epoch as number);
	});
});
