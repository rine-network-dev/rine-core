import { describe, expect, it, vi } from "vitest";
import { PRESETS, Preset, Surface, invalidSurfaces, isNamedPreset } from "../src/agent-exposure.js";
import type { HttpClient } from "../src/http.js";
import * as allow from "../src/org-allow.js";
import * as rules from "../src/org-rules.js";
import {
	Decision,
	MessageDefault,
	PolicyRule,
	RULE_MODES,
	RuleDirection,
	RuleMode,
	RuleRefusal,
	ScopeKind,
	TypeClass,
} from "../src/org-rules-types.js";
import codes from "./fixtures/governance-codes.json" with { type: "json" };
import exposure from "./fixtures/exposure.json" with { type: "json" };
import shapes from "./fixtures/governance-shapes.json" with { type: "json" };

const ENTRY = "44444444-4444-4444-8444-444444444444";
const ORG = "55555555-5555-4555-8555-555555555555";

function fake(body: unknown = {}) {
	const fn = () => vi.fn(async () => body);
	return { get: fn(), post: fn(), put: fn(), patch: fn(), delete: fn() } as unknown as HttpClient &
		Record<"get" | "post" | "put" | "patch" | "delete", ReturnType<typeof vi.fn>>;
}

describe("the closed sets match the server's fixture", () => {
	it("test_codes_when_compared_to_the_fixture_then_every_enum_is_equal", () => {
		expect(Object.values(PolicyRule)).toEqual(codes.policy_rules);
		expect(Object.values(RuleMode)).toEqual(codes.rule_modes);
		expect(Object.values(RuleRefusal)).toEqual(codes.rule_refusals);
		expect(Object.values(RuleDirection)).toEqual(codes.directions);
		expect(Object.values(ScopeKind)).toEqual(codes.scope_kinds);
		expect(Object.values(Decision)).toEqual(codes.decisions);
		expect(Object.values(TypeClass)).toEqual(codes.type_classes);
		expect(Object.values(Surface)).toEqual(codes.exposure_surfaces);
		expect(Object.values(Preset)).toEqual(codes.exposure_presets);
		expect(Object.values(MessageDefault)).toEqual(["deny", "allow"]);
	});

	it("test_modes_when_a_rule_is_listed_then_it_is_one_of_the_fixture_modes", () => {
		expect(Object.keys(RULE_MODES)).toEqual(codes.policy_rules);
		for (const modes of Object.values(RULE_MODES))
			for (const m of modes) expect(codes.rule_modes).toContain(m);
	});

	it("test_presets_when_compared_to_the_exposure_fixture_then_equal", () => {
		expect(PRESETS).toEqual(exposure.presets);
		expect(invalidSurfaces({ ...PRESETS.listed, card: false })).toEqual(["directory", "a2a"]);
		expect(invalidSurfaces(PRESETS.findable)).toEqual([]);
		expect(isNamedPreset("custom")).toBe(false);
		expect(isNamedPreset("listed")).toBe(true);
	});
});

describe("rule routes", () => {
	it("test_rules_when_patched_then_version_and_nested_rules_are_sent", async () => {
		const c = fake(shapes.policy);
		await rules.getPolicy(c);
		await rules.patchRules(c, 4, { funnel: { mode: "enforce" } });
		expect(c.get).toHaveBeenCalledWith("/org/policy");
		expect(c.patch).toHaveBeenCalledWith("/org/policy", {
			version: 4,
			rules: { funnel: { mode: "enforce" } },
		});
	});

	it("test_preview_when_asked_then_rule_and_mode_are_query_params", async () => {
		const c = fake();
		await rules.previewRule(c, PolicyRule.ExternalOutbound);
		expect(c.get).toHaveBeenCalledWith("/org/policy/preview", {
			rule: "external_outbound",
			mode: "enforce",
		});
	});

	it("test_stop_existing_when_called_then_posts_the_rule", async () => {
		const c = fake();
		await rules.stopExisting(c, PolicyRule.Funnel);
		expect(c.post).toHaveBeenCalledWith("/org/policy/stop-existing", { rule: "funnel" });
	});
});

describe("allow, lookup and domain routes", () => {
	it("test_allow_when_written_and_removed_then_put_and_delete_with_reason", async () => {
		const c = fake();
		const entry = {
			direction: RuleDirection.Outbound,
			counterparty_org_id: ORG,
			decision: Decision.Allow,
			reason: "partner",
		};
		await allow.putAllow(c, entry);
		await allow.deleteAllow(c, ENTRY, "ended");
		expect(c.put).toHaveBeenCalledWith("/org/allow", entry);
		expect(c.delete).toHaveBeenCalledWith(`/org/allow/${ENTRY}`, undefined, undefined, {
			reason: "ended",
		});
		await expect(allow.deleteAllow(c, "nope", "x")).rejects.toThrow(/Invalid entry ID/);
	});

	it("test_allow_when_paged_then_every_page_is_followed", async () => {
		const c = fake();
		c.get
			.mockResolvedValueOnce({ entries: [{ id: "a" }], next_cursor: ENTRY })
			.mockResolvedValueOnce({ entries: [{ id: "b" }], next_cursor: null });
		const all = await allow.fetchAllAllow(c);
		expect(all.map((e) => e.id)).toEqual(["a", "b"]);
		expect(c.get.mock.calls[1]?.[1]).toMatchObject({ after: ENTRY });
	});

	it("test_lookup_and_domains_when_called_then_use_their_routes", async () => {
		const c = fake();
		await allow.lookupCounterparty(c, "acme");
		await allow.addDomain(c, "a.test");
		await allow.listDomains(c);
		await allow.verifyDomain(c, "a.test");
		await allow.removeDomain(c, "a.test");
		expect(c.get.mock.calls.map((x) => x[0])).toEqual([
			"/org/counterparties/lookup",
			"/org/domains",
		]);
		expect(c.post.mock.calls.map((x) => x[0])).toEqual([
			"/org/domains",
			"/org/domains/a.test/verify",
		]);
		expect(c.delete).toHaveBeenCalledWith("/org/domains/a.test");
	});
});
