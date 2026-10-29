/** The envelope every paged reader route answers with. */

/** A page whose envelope is not `{items|rows: [...], next_cursor}`. It carries no server text. */
export class MalformedPageError extends Error {
	constructor() {
		super("the server's page is malformed");
		this.name = "MalformedPageError";
	}
}

export function pageOf(
	value: unknown,
	listField: "items" | "rows",
): { list: readonly unknown[]; next: string | null } {
	const page = value as Record<string, unknown> | null;
	const list = page?.[listField];
	const next = page?.next_cursor ?? null;
	if (!Array.isArray(list) || (next !== null && typeof next !== "string"))
		throw new MalformedPageError();
	return { list, next: next === "" ? null : next };
}

/** A page's items, still as the server sent them: `parseRow` judges each one. */
export interface ActivityPage {
	readonly items: readonly unknown[];
	readonly nextCursor: string | null;
}

export interface EscrowRows {
	readonly rows: readonly unknown[];
	/** False when a page or row cap or a repeated cursor ended the walk before the server's last page. */
	readonly complete: boolean;
}
