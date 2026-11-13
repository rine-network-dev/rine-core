import { describe, expect, it, vi } from "vitest";
import {
	type ExposureSet,
	aboveCeiling,
	capTo,
	exposureDiff,
	hidesDid,
	presetOf,
} from "../src/agent-exposure.js";
import * as api from "../src/agent-exposure-api.js";
import { EXPOSURE_COPY, cappedLine, orgSummaryLine, previewLines, summaryLine, switchLines } from "../src/agent-exposure-words.js";
import type { HttpClient } from "../src/http.js";
import fixture from "./fixtures/exposure.json" with { type: "json" };

const ID = "11111111-1111-4111-8111-111111111111";

describe("the exposure table the server also runs", () => {
	for (const c of fixture.cases) {
		it(`test_exposure_when_${c.name.replace(/\W+/g, "_")}_then_matches_the_fixture`, () => {
			expect(aboveCeiling(c.target, c.ceiling)).toEqual(c.above);
			expect(capTo(c.current, c.ceiling)).toEqual(c.cap);
			const d = exposureDiff(c.current, c.target);
			expect({ turned_on: d.turnedOn, turned_off: d.turnedOff }).toEqual(c.diff);
			expect(presetOf(c.target, c.a2a_available)).toBe(c.preset);
			expect(hidesDid(c.current, c.target)).toBe(c.hides_did);
		});
	}
});

describe("the words", () => {
	it("test_copy_when_compared_to_the_fixture_then_every_template_is_equal", () => {
		const c = fixture.copy;
		expect(EXPOSURE_COPY.presetLabels).toEqual(c.preset_labels);
		expect(EXPOSURE_COPY.surfaceNames).toEqual(c.surface_names);
		expect(EXPOSURE_COPY.summary).toEqual(c.summary);
		expect(EXPOSURE_COPY.switches).toEqual(c.switches);
		expect(EXPOSURE_COPY.alwaysOn).toEqual(c.always_on);
		expect(EXPOSURE_COPY.footer).toBe(c.footer);
		expect(EXPOSURE_COPY.didWarning).toBe(c.did_warning);
		expect(EXPOSURE_COPY.preview).toEqual({
			turnsOn: c.preview.turns_on,
			turnsOff: c.preview.turns_off,
			noChange: c.preview.no_change,
		});
		expect(EXPOSURE_COPY.ceiling).toBe(c.ceiling);
		expect(EXPOSURE_COPY.aboveCeiling).toBe(c.above_ceiling);
		expect(EXPOSURE_COPY.orgSummary).toBe(c.org_summary);
		expect(EXPOSURE_COPY.refused).toBe(c.refused);
		expect(EXPOSURE_COPY.invalid).toBe(c.invalid);
		expect(EXPOSURE_COPY.createdPrivate).toBe(c.created_private);
		expect(EXPOSURE_COPY.capped).toBe(c.capped);
		expect(EXPOSURE_COPY.help).toBe(c.help);
	});

	it("test_capped_line_when_the_preset_is_lower_then_names_both_else_null", () => {
		expect(cappedLine("listed", "findable")).toBe(
			"Capped to findable by your organisation's directory_listing ceiling (you asked for listed).",
		);
		expect(cappedLine("listed", "listed")).toBeNull();
		expect(cappedLine(undefined, "private")).toBeNull();
		expect(cappedLine("listed", null)).toBeNull();
	});

	it("test_summary_when_custom_then_names_what_is_on_and_off", () => {
		const e: ExposureSet = { directory: false, card: true, a2a: true, did: false };
		expect(summaryLine("bot", e, true)).toBe(
			"bot uses custom settings: profile card, A2A discovery on; directory listing, DID document off.",
		);
		expect(summaryLine("bot", fixture.presets.private, true)).toContain("bot is private.");
	});

	it("test_switch_lines_when_a2a_unavailable_then_say_so_and_end_with_the_footer", () => {
		const lines = switchLines("bot", {
			exposure: fixture.presets.findable,
			preset: "findable",
			a2a_available: false,
			always_on: ["keys", "webfinger"],
			ceiling: null,
			above_ceiling: [],
		});
		expect(lines).toHaveLength(7);
		expect(lines[2]).toBe("A2A discovery [off]: Not available: A2A is not enabled for bot.");
		expect(lines[4]).toContain("Handle lookup (always on)");
		expect(lines[6]).toContain("not by these settings.");
	});

	it("test_preview_when_nothing_changes_then_no_change_and_when_did_hidden_then_warns", () => {
		const base = { current: fixture.presets.listed, target: fixture.presets.listed, invalid: [], refused: [] };
		expect(previewLines("bot", { ...base, turned_on: [], turned_off: [], hides_did: false })).toEqual(["No change."]);
		expect(
			previewLines("bot", { ...base, turned_on: [], turned_off: ["did"], hides_did: true }),
		).toEqual(["Turns off: DID document.", "Others can no longer check bot's did:web signatures."]);
	});

	it("test_org_summary_when_rendered_then_counts_fill_the_template", () => {
		const line = orgSummaryLine({
			presets: { private: 1, findable: 2, listed: 3, custom: 4 },
			switches: { directory: 0, card: 0, a2a: 0, did: 0 },
			ceiling: null,
			above_ceiling: { count: 5, ids: [] },
		});
		expect(line).toBe("1 private, 2 findable by handle, 3 listed, 4 custom. 5 show more than the organisation's limit.");
	});
});

describe("routes and the create body", () => {
	function fake() {
		const fn = () => vi.fn(async () => ({}));
		return { get: fn(), post: fn(), put: fn() } as unknown as HttpClient &
			Record<"get" | "post" | "put", ReturnType<typeof vi.fn>>;
	}

	it("test_routes_when_called_then_paths_and_bodies_match_the_server", async () => {
		const c = fake();
		await api.getExposure(c, ID);
		await api.previewExposure(c, ID, "private");
		await api.putExposure(c, ID, fixture.presets.listed);
		await api.getOrgExposure(c);
		expect(c.get).toHaveBeenCalledWith(`/agents/${ID}/exposure`);
		expect(c.post).toHaveBeenCalledWith(`/agents/${ID}/exposure/preview`, { exposure: "private" });
		expect(c.put).toHaveBeenCalledWith(`/agents/${ID}/exposure`, { exposure: fixture.presets.listed });
		expect(c.get).toHaveBeenCalledWith("/org/exposure");
	});
});
