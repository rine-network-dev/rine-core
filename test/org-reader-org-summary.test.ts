import { describe, expect, it } from "vitest";
import { ReaderClient } from "../src/org-reader/client.js";
import { fetchOrgSummary } from "../src/org-reader/org-summary.js";
import { MalformedPageError } from "../src/org-reader/page-envelope.js";
import {
	READER_SIGNER,
	jsonResponse,
	router,
} from "./org-reader-client-fixture.js";

function clientAnswering(whoami: () => Response) {
	const transport = router({
		"POST /oauth/token": () =>
			jsonResponse({ access_token: "tok", expires_in: 900 }),
		"GET /whoami": whoami,
	});
	return new ReaderClient({
		apiUrl: "https://api.test",
		signer: READER_SIGNER,
		fetch: transport,
		now: () => 0,
		refreshMarginMs: 60_000,
	}).client;
}

describe("fetchOrgSummary", () => {
	it("test_fetchOrgSummary_whoamiAnswers_returnsNameAndSlugOnly", async () => {
		const client = clientAnswering(() =>
			jsonResponse({
				org: { id: "o-1", name: "Acme GmbH", slug: "acme", trust_tier: 2 },
				principal: { kind: "org_reader" },
				agents: [],
			}),
		);
		await expect(fetchOrgSummary(client)).resolves.toEqual({
			name: "Acme GmbH",
			slug: "acme",
		});
	});

	it.each([
		["no org", {}],
		["a numeric name", { org: { name: 7, slug: "acme" } }],
		["a missing slug", { org: { name: "Acme" } }],
	])("test_fetchOrgSummary_%s_isMalformed", async (_label, body) => {
		const client = clientAnswering(() => jsonResponse(body));
		await expect(fetchOrgSummary(client)).rejects.toBeInstanceOf(
			MalformedPageError,
		);
	});
});
