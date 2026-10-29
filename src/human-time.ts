const NOW_AGE_MS = 45_000;
const NOW_FUTURE_MS = 120_000;
const MINUTE_MS = 60_000;
const HOUR_MS = 60 * MINUTE_MS;
const WEEK_DAYS = 7;
const MISSING = "—";
const WEEKDAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"] as const;
const MONTHS = [
	"Jan",
	"Feb",
	"Mar",
	"Apr",
	"May",
	"Jun",
	"Jul",
	"Aug",
	"Sep",
	"Oct",
	"Nov",
	"Dec",
] as const;

const pad = (n: number): string => String(n).padStart(2, "0");

/** Whole local calendar days since an arbitrary fixed day; DST never shifts the count. */
const dayNumber = (at: Date): number =>
	Math.floor(
		Date.UTC(at.getFullYear(), at.getMonth(), at.getDate()) / 86_400_000,
	);

/**
 * A timestamp as a short, fixed-English phrase in the local time zone, at most 9 cells: `now`,
 * `5m`, `14:02`, `yesterday`, `Mon`, `12 Oct`, `Oct 2025`. Unparseable input reads `—`.
 */
export function humanTime(iso: string, nowMs: number): string {
	const ms = Date.parse(iso);
	if (Number.isNaN(ms)) return MISSING;
	const age = nowMs - ms;
	if (age < NOW_AGE_MS && age >= -NOW_FUTURE_MS) return "now";
	const at = new Date(ms);
	const today = new Date(nowMs);
	const days = dayNumber(today) - dayNumber(at);
	const clock = `${pad(at.getHours())}:${pad(at.getMinutes())}`;
	const dayMonth = `${at.getDate()} ${MONTHS[at.getMonth()]}`;
	if (age < 0) return days === 0 ? clock : dayMonth;
	if (age < HOUR_MS) return `${Math.max(1, Math.floor(age / MINUTE_MS))}m`;
	if (days === 0) return clock;
	if (days === 1) return "yesterday";
	if (days < WEEK_DAYS) return WEEKDAYS[at.getDay()] ?? MISSING;
	if (at.getFullYear() === today.getFullYear()) return dayMonth;
	return `${MONTHS[at.getMonth()]} ${at.getFullYear()}`;
}
