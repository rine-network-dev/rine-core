import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const FIXTURES = join(
	dirname(fileURLToPath(import.meta.url)),
	"../../../rine-sdk/tests/contract/fixtures",
);

/** A server golden envelope, recorded from the real router by the repo-root contract suite. */
export interface Golden<Body> {
	endpoint: string;
	scenario: string;
	status: number;
	body: Body;
}

/** Read a golden by file name; a missing one is an error, never a skip. */
export function golden<Body>(name: string): Golden<Body> {
	return JSON.parse(readFileSync(join(FIXTURES, name), "utf8")) as Golden<Body>;
}
