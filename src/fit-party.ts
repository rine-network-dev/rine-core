import {
	clipToWidth,
	clipWithEllipsis,
	displayWidth,
} from "./terminal-width.js";

const ELLIPSIS = "…";
/** The share of a `#group · sender` row's room the group may take; the sender keeps the rest. */
const GROUP_SHARE = 0.6;
/** The share of a `from → to` row's room the sender may take before the recipient is out of room. */
const PAIR_SHARE = 0.5;

/** Index of the `@` that starts a remote label's domain; -1 for a bare name (a leading or trailing `@` is no domain). */
function domainAt(label: string): number {
	const at = label.lastIndexOf("@");
	return at > 0 && at < label.length - 1 ? at : -1;
}

/** The name characters a clipped remote label keeps in front of its ellipsis: one, or `#` and one for a group. */
function nameFloor(label: string): number {
	return label.startsWith("#") ? 2 : 1;
}

/** The cells a remote label needs to show `x…@…` (`#m…@…` for a group). */
const remoteFloor = (label: string, mark: number): number =>
	nameFloor(label) + 2 * mark + 1;

/** What a label that cannot show `x…@…` keeps: `…@…`, then `…@`, then `@`. The `@` of a remote label never goes. */
function narrowForm(cells: number, ellipsis: string): string {
	if (cells >= 2 * displayWidth(ellipsis) + 1) return `${ellipsis}@${ellipsis}`;
	return cells >= 1 ? `${clipToWidth(ellipsis, cells - 1)}@` : "";
}

/**
 * A handle label fitted to `cells` columns. A bare name clips from the right. A remote `local@domain` label never loses
 * its `@`, so it never reads like an own one, and its name comes before its domain: the local part keeps about half
 * the cells in name characters (everything a short domain leaves, or its whole self when `keepName`) and the domain
 * clips from the right, down to `…`, so `salesteam-europe@fjord21735` in 16 cells reads `salestea…@fjord…`. Below
 * `x…@…` (`#m…@…` for a group, which keeps a name character after its `#`) the label is `…@…`, `…@` at 2 cells, `@`
 * at 1. Not padded. `label` must already be scrubbed (one line, no control or zero-width characters); the twins agree
 * only on scrubbed input.
 */
function fitLabel(
	label: string,
	cells: number,
	ellipsis: string,
	keepName: boolean,
): string {
	if (displayWidth(label) <= cells) return label;
	const at = domainAt(label);
	if (at < 0) return clipWithEllipsis(label, cells, ellipsis);
	const mark = displayWidth(ellipsis);
	if (!keepName && cells < remoteFloor(label, mark))
		return narrowForm(cells, ellipsis);
	const local = label.slice(0, at);
	const localWidth = displayWidth(local);
	const want = keepName
		? localWidth
		: Math.max(
				Math.ceil(cells / 2) + mark,
				cells - 1 - displayWidth(label.slice(at + 1)),
			);
	const localCells = Math.min(
		localWidth,
		cells - 1 - mark,
		Math.max(want, nameFloor(label) + mark),
	);
	const head =
		localCells >= localWidth
			? local
			: clipToWidth(local, localCells - mark) + ellipsis;
	return `${head}@${clipWithEllipsis(label.slice(at + 1), cells - 1 - displayWidth(head), ellipsis)}`;
}

/** `label` fitted to `cells` columns: see `fitLabel`. */
export function fitHandle(
	label: string,
	cells: number,
	ellipsis: string = ELLIPSIS,
): string {
	return fitLabel(label, cells, ellipsis, false);
}

/** The cells a party needs to show its whole name: the whole bare name, or the local part with a clipped domain `name@…`. */
function needOf(label: string, ellipsis: string): number {
	const at = domainAt(label);
	const whole = displayWidth(label);
	return at < 0
		? whole
		: Math.min(
				whole,
				displayWidth(label.slice(0, at)) + 1 + displayWidth(ellipsis),
			);
}

/** The fewest cells a party keeps while the room holds two: `x…@…` for a remote label, as many cells for a bare name. */
function floorOf(label: string, ellipsis: string): number {
	const mark = displayWidth(ellipsis);
	return Math.min(
		displayWidth(label),
		domainAt(label) < 0 ? 2 + 2 * mark : remoteFloor(label, mark),
	);
}

/** A party fitted to the cells its pair gave it; one whose whole name fits keeps it and clips only its domain. */
const fitParty = (label: string, cells: number, ellipsis: string): string =>
	fitLabel(label, cells, ellipsis, needOf(label, ellipsis) <= cells);

/**
 * Two labels sharing `room` columns. When both fit they are left alone. Otherwise the lead takes what the tail does not
 * need to show its whole name, but never more than `share` of the room unless the tail needs less. Each party keeps its
 * floor (see `floorOf`) while the room holds both, so both keep their `@`; a party that gets room for its whole name
 * keeps it and gives up its domain first.
 */
function fitPair(
	lead: string,
	tail: string,
	room: number,
	share: number,
	ellipsis: string,
): [string, string] {
	const leadCells = displayWidth(lead);
	if (leadCells + displayWidth(tail) <= room) return [lead, tail];
	const capped = Math.min(
		leadCells,
		Math.max(Math.floor(room * share), room - needOf(tail, ellipsis)),
	);
	const leadFloor = floorOf(lead, ellipsis);
	const tailFloor = floorOf(tail, ellipsis);
	const leadRoom =
		leadFloor + tailFloor <= room
			? Math.min(Math.max(capped, leadFloor), room - tailFloor)
			: capped;
	return [
		fitParty(lead, leadRoom, ellipsis),
		fitParty(tail, room - leadRoom, ellipsis),
	];
}

/** `[group, sender]` of a `#group · sender` row in `room` columns (the joint excluded): the group takes at most 60 % unless the sender needs less. */
export function fitGroupSender(
	group: string,
	sender: string,
	room: number,
	ellipsis: string = ELLIPSIS,
): [string, string] {
	return fitPair(group, sender, room, GROUP_SHARE, ellipsis);
}

/** `[from, to]` of a `from → to` row in `room` columns (the joint excluded): the recipient gets what it needs, or half. */
export function fitFromTo(
	from: string,
	to: string,
	room: number,
	ellipsis: string = ELLIPSIS,
): [string, string] {
	return fitPair(from, to, room, PAIR_SHARE, ellipsis);
}
