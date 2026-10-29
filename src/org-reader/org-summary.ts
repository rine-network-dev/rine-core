import type { WhoAmIRead } from "../api-types.js";
import type { HttpClient } from "../http.js";
import { MalformedPageError } from "./page-envelope.js";

/** The two strings a view titles itself with. Server text: scrub it before drawing it. */
export interface OrgSummary {
	readonly name: string;
	readonly slug: string;
}

/** `GET /whoami` as the reader principal may call it: the org it reads. */
export async function fetchOrgSummary(
	client: Pick<HttpClient, "get">,
): Promise<OrgSummary> {
	const body = (await client.get("/whoami")) as Partial<WhoAmIRead> | null;
	const name: unknown = body?.org?.name;
	const slug: unknown = body?.org?.slug;
	if (typeof name !== "string" || typeof slug !== "string")
		throw new MalformedPageError();
	return { name, slug };
}
