/**
 * Which events are alerts, which summaries and which plain records. Mirrors
 * `rine/core/org_event_signals.py`; both read `test/fixtures/governance-signals.json`.
 */

export const SignalClass = {
	Alert: "alert",
	Summary: "summary",
	Record: "record",
} as const;
export type SignalClass = (typeof SignalClass)[keyof typeof SignalClass];

const ALERT_KINDS: ReadonlySet<string> = new Set([
	"agent.first_external_contact",
	"counterparty.first_seen",
	"counterparty.volume_spike",
	"rule.burst",
]);
const SUMMARY_KINDS: ReadonlySet<string> = new Set([
	"counterparty.inbound_summary",
]);
/** A way out added to an agent: an alert when the agent has no message history. */
const EXIT_ALERT_KINDS: ReadonlySet<string> = new Set([
	"webhook.created",
	"a2a_push.created",
	"funnel.hook_created",
]);
const HISTORY_FIELD = "agent_has_history";
/** `group.postable_changed` is an alert when our agents lost the right to post. */
const POSTABLE_KIND = "group.postable_changed";
const POSTABLE_FIELD = "postable";

/** The class of an event of `kind` whose envelope `detail` is given. */
export function signalClass(kind: string, detail: unknown): SignalClass {
	if (ALERT_KINDS.has(kind)) return SignalClass.Alert;
	if (SUMMARY_KINDS.has(kind)) return SignalClass.Summary;
	const fields = detail as Record<string, unknown> | null | undefined;
	if (EXIT_ALERT_KINDS.has(kind) && fields?.[HISTORY_FIELD] === false)
		return SignalClass.Alert;
	if (kind === POSTABLE_KIND && fields?.[POSTABLE_FIELD] === false)
		return SignalClass.Alert;
	return SignalClass.Record;
}
