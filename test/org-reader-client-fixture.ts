import { vi } from "vitest";
import type { AssertionSigner } from "../src/assertion.js";
import { PrincipalKind } from "../src/principal.js";

export const READER_SIGNER: AssertionSigner = {
	principal: {
		kind: PrincipalKind.Reader,
		orgId: "22222222-2222-4222-8222-222222222222",
	},
	seed: new Uint8Array(32).fill(9),
};

export function jsonResponse(
	body: unknown,
	status = 200,
	headers: Record<string, string> = {},
): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "content-type": "application/json", ...headers },
	});
}

/** A `fetch` answering by `"<METHOD> <path>"`; an unrouted request is a test bug. */
export function router(
	routes: Record<string, (url: URL, init?: RequestInit) => Response>,
) {
	return vi.fn(
		async (input: Parameters<typeof fetch>[0], init?: RequestInit) => {
			const url = new URL(String(input));
			const handler = routes[`${init?.method ?? "GET"} ${url.pathname}`];
			if (handler === undefined)
				throw new Error(`unrouted ${init?.method ?? "GET"} ${url.pathname}`);
			return handler(url, init);
		},
	) as ReturnType<typeof vi.fn> & typeof fetch;
}
