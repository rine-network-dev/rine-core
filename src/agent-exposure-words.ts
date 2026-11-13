/**
 * What the clients say about exposure. The templates are held equal to `copy` in
 * `test/fixtures/exposure.json`; the dashboard twin pins the same table.
 */
import {
	type ExposurePlanView,
	type ExposureSet,
	type ExposureView,
	type NamedPreset,
	type OrgExposureView,
	Preset,
	Surface,
	presetOf,
} from "./agent-exposure.js";

export const EXPOSURE_COPY = {
	presetLabels: {
		private: "Private",
		findable: "Findable by handle",
		listed: "Listed",
		custom: "Custom",
	},
	surfaceNames: {
		directory: "directory listing",
		card: "profile card",
		a2a: "A2A discovery",
		did: "DID document",
	},
	none: "none",
	summary: {
		private:
			"{name} is private. It is not in the directory, and others cannot read its profile, A2A card or DID document. Anyone who knows its handle can still look up its address.",
		findable:
			"Anyone who knows {name}'s handle can look it up and read its profile. It is not in the directory.",
		listed: "{name} is listed in the rine directory. Anyone can find it and read its profile.",
		custom: "{name} uses custom settings: {on} on; {off} off.",
	},
	switches: {
		directory: { label: "Directory listing", on: "Shown in the rine directory and its search." },
		card: { label: "Profile card", on: "Anyone can read {name}'s profile." },
		a2a: {
			label: "A2A discovery",
			on: "Other A2A agents can discover {name} at its agent.json address.",
			unavailable: "Not available: A2A is not enabled for {name}.",
		},
		did: { label: "DID document", on: "Anyone can check {name}'s did:web identity and signatures." },
	},
	alwaysOn: {
		webfinger: {
			label: "Handle lookup (always on)",
			on: "Anyone who knows {name}'s handle can look up its agent id and links.",
		},
		keys: {
			label: "Public keys (always on)",
			on: "Senders need these to encrypt messages to {name}.",
		},
	},
	footer:
		"Whether a message reaches {name} is decided by your organisation's inbound rules and allow lists, not by these settings.",
	didWarning: "Others can no longer check {name}'s did:web signatures.",
	preview: {
		turnsOn: "Turns on: {surfaces}.",
		turnsOff: "Turns off: {surfaces}.",
		noChange: "No change.",
	},
	ceiling:
		"Your organisation allows at most: {ceiling}. To change it: rine org rules set directory_listing enforce --max {preset}",
	aboveCeiling:
		"{name} shows more than your organisation now allows ({surfaces}). It keeps doing so until an administrator runs: rine org rules stop-existing directory_listing",
	orgSummary:
		"{private} private, {findable} findable by handle, {listed} listed, {custom} custom. {above} show more than the organisation's limit.",
	refused:
		"This organisation's directory_listing rule does not allow its agents to turn on: {surfaces}.",
	invalid: "Directory listing and A2A discovery need the profile card on.",
	createdPrivate:
		"{name} was created private, as your organisation's directory_listing rule asks. To let others read its profile: rine agent exposure set {name} findable",
	capped:
		"Capped to {preset} by your organisation's directory_listing ceiling (you asked for {asked}).",
	help: "A handle lookup always works and returns the agent's id and links. These settings control the directory listing, the profile card, A2A discovery and the DID document. Whether a message is delivered is decided by your organisation's inbound rules and allow lists, not by these settings.",
} as const;

function fill(template: string, values: Record<string, string | number>): string {
	return template.replace(/\{(\w+)\}/g, (_m, key: string) => String(values[key] ?? `{${key}}`));
}

const names = (surfaces: readonly Surface[]): string =>
	surfaces.length === 0
		? EXPOSURE_COPY.none
		: surfaces.map((s) => EXPOSURE_COPY.surfaceNames[s]).join(", ");

const SURFACES = Object.values(Surface);

/** One line for the preset the agent's switches equal. */
export function summaryLine(name: string, exposure: ExposureSet, a2aAvailable: boolean): string {
	return presetLine(name, exposure, presetOf(exposure, a2aAvailable));
}

/** The line for a preset the server has already named, for switches that may not carry a2a. */
export function presetLine(name: string, exposure: ExposureSet, preset: Preset): string {
	return fill(EXPOSURE_COPY.summary[preset], {
		name,
		on: names(SURFACES.filter((s) => exposure[s])),
		off: names(SURFACES.filter((s) => !exposure[s])),
	});
}

/** A label and its line for each switch, the two always-on lines, then the footer. */
export function switchLines(name: string, view: ExposureView): string[] {
	const lines = SURFACES.map((s) => {
		const copy = EXPOSURE_COPY.switches[s];
		const state = view.exposure[s] ? "on" : "off";
		const text =
			s === Surface.A2a && !view.a2a_available
				? EXPOSURE_COPY.switches.a2a.unavailable
				: view.exposure[s]
					? copy.on
					: "Off.";
		return `${copy.label} [${state}]: ${fill(text, { name })}`;
	});
	for (const key of ["webfinger", "keys"] as const) {
		const copy = EXPOSURE_COPY.alwaysOn[key];
		lines.push(`${copy.label}: ${fill(copy.on, { name })}`);
	}
	return [...lines, fill(EXPOSURE_COPY.footer, { name })];
}

/** The ceiling as a preset name, or the switches it leaves on. */
export function ceilingLine(ceiling: ExposureSet): string {
	const preset = presetOf(ceiling, true);
	const label =
		preset === Preset.Custom
			? names(SURFACES.filter((s) => ceiling[s]))
			: EXPOSURE_COPY.presetLabels[preset].toLowerCase();
	return fill(EXPOSURE_COPY.ceiling, { ceiling: label, preset: preset === Preset.Custom ? "private|findable|listed" : preset });
}

/** A notice when the agent shows more than the ceiling, else null. */
export function aboveCeilingLine(name: string, view: ExposureView): string | null {
	if (view.above_ceiling.length === 0) return null;
	return fill(EXPOSURE_COPY.aboveCeiling, { name, surfaces: names(view.above_ceiling) });
}

/** What a write would change, and the DID warning. */
export function previewLines(name: string, plan: ExposurePlanView): string[] {
	const lines: string[] = [];
	if (plan.turned_on.length > 0)
		lines.push(fill(EXPOSURE_COPY.preview.turnsOn, { surfaces: names(plan.turned_on) }));
	if (plan.turned_off.length > 0)
		lines.push(fill(EXPOSURE_COPY.preview.turnsOff, { surfaces: names(plan.turned_off) }));
	if (lines.length === 0) lines.push(EXPOSURE_COPY.preview.noChange);
	if (plan.hides_did) lines.push(fill(EXPOSURE_COPY.didWarning, { name }));
	return lines;
}

/** The switches a change asked for that the ceiling refuses. */
export function refusedLine(plan: ExposurePlanView): string {
	return fill(EXPOSURE_COPY.refused, { surfaces: names(plan.refused) });
}

/** The organisation's exposure summary line. */
export function orgSummaryLine(view: OrgExposureView): string {
	return fill(EXPOSURE_COPY.orgSummary, {
		private: view.presets.private,
		findable: view.presets.findable,
		listed: view.presets.listed,
		custom: view.presets.custom,
		above: view.above_ceiling.count,
	});
}

/** The line for an agent that came back Private after a create. */
export function createdPrivateLine(name: string): string {
	return fill(EXPOSURE_COPY.createdPrivate, { name });
}

/** The notice for a create the ceiling lowered, or null when the agent got what was asked. */
export function cappedLine(asked: NamedPreset | undefined, got: Preset | null | undefined): string | null {
	if (asked === undefined || got == null || got === asked) return null;
	return fill(EXPOSURE_COPY.capped, { preset: got, asked });
}
