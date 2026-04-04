export class RineApiError extends Error {
	constructor(
		public readonly status: number,
		public readonly detail: string,
		public readonly raw?: unknown,
	) {
		super(`${status}: ${detail}`);
		this.name = "RineApiError";
	}
}

export function formatError(err: unknown): string {
	if (err instanceof RineApiError) return err.detail;
	if (err instanceof Error) return err.message;
	return String(err);
}
