/**
 * What an agent shows the outside: four switches and three presets. Mirrors
 * `src/rine/core/agent_exposure.py` and is held equal to it by `test/fixtures/exposure.json`.
 * Keys and webfinger are always served and are not switches. `directory` and `a2a` need `card`.
 */

export const Surface = {
	Directory: "directory",
	Card: "card",
	A2a: "a2a",
	Did: "did",
} as const;
export type Surface = (typeof Surface)[keyof typeof Surface];

export const Preset = {
	Private: "private",
	Findable: "findable",
	Listed: "listed",
	Custom: "custom",
} as const;
export type Preset = (typeof Preset)[keyof typeof Preset];

export type ExposureSet = Record<Surface, boolean>;

/** The presets a caller may name; `custom` is only ever a reading. */
export type NamedPreset = Exclude<Preset, typeof Preset.Custom>;

export const PRESETS: Readonly<Record<NamedPreset, ExposureSet>> = {
	private: { directory: false, card: false, a2a: false, did: false },
	findable: { directory: false, card: true, a2a: false, did: true },
	listed: { directory: true, card: true, a2a: true, did: true },
};

/** The switches that are on without the card they need. */
export function invalidSurfaces(exposure: ExposureSet): Surface[] {
	if (exposure.card) return [];
	return [Surface.Directory, Surface.A2a].filter((s) => exposure[s]);
}

export function isNamedPreset(value: string): value is NamedPreset {
	return Object.hasOwn(PRESETS, value);
}

const SURFACES = Object.values(Surface);

function onSet(exposure: ExposureSet): Set<Surface> {
	return new Set(SURFACES.filter((s) => exposure[s]));
}

function ofSurfaces(on: Iterable<Surface>): ExposureSet {
	const held = new Set(on);
	return {
		directory: held.has(Surface.Directory),
		card: held.has(Surface.Card),
		a2a: held.has(Surface.A2a),
		did: held.has(Surface.Did),
	};
}

/** The preset `exposure` equals, or `custom`; `a2a` is ignored when A2A is not available. */
export function presetOf(exposure: ExposureSet, a2aAvailable: boolean): Preset {
	for (const name of Object.keys(PRESETS) as NamedPreset[]) {
		const members = PRESETS[name];
		const same = a2aAvailable
			? SURFACES.every((s) => exposure[s] === members[s])
			: SURFACES.every((s) => s === Surface.A2a || exposure[s] === members[s]);
		if (same) return name;
	}
	return Preset.Custom;
}

/** The switches `target` has on and `ceiling` leaves off. */
export function aboveCeiling(target: ExposureSet, ceiling: ExposureSet): Surface[] {
	return SURFACES.filter((s) => target[s] && !ceiling[s]);
}

/** Switch by switch, on only where both are on. */
export function capTo(current: ExposureSet, ceiling: ExposureSet): ExposureSet {
	return ofSurfaces(SURFACES.filter((s) => current[s] && ceiling[s]));
}

export function exposureDiff(
	current: ExposureSet,
	target: ExposureSet,
): { turnedOn: Surface[]; turnedOff: Surface[] } {
	const had = onSet(current);
	const wants = onSet(target);
	return {
		turnedOn: SURFACES.filter((s) => wants.has(s) && !had.has(s)),
		turnedOff: SURFACES.filter((s) => had.has(s) && !wants.has(s)),
	};
}

export function hidesDid(current: ExposureSet, target: ExposureSet): boolean {
	return current.did && !target.did;
}

/** What `GET` and `PUT /agents/{id}/exposure` answer. `ceiling` is null while the rule is off. */
export interface ExposureView {
	exposure: ExposureSet;
	preset: Preset;
	a2a_available: boolean;
	always_on: string[];
	ceiling: ExposureSet | null;
	above_ceiling: Surface[];
}

/** `POST /agents/{id}/exposure/preview`: what a write would do. */
export interface ExposurePlanView {
	current: ExposureSet;
	target: ExposureSet;
	turned_on: Surface[];
	turned_off: Surface[];
	hides_did: boolean;
	invalid: Surface[];
	refused: Surface[];
}

/** `GET /org/exposure`. */
export interface OrgExposureView {
	presets: Record<Preset, number>;
	switches: Record<Surface, number>;
	ceiling: ExposureSet | null;
	above_ceiling: { count: number; ids: string[] };
}

/** A preset name or the four switches, the two shapes the routes and `agent create` take. */
export type ExposureInput = NamedPreset | ExposureSet;
