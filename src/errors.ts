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
	if (err instanceof Error) {
		const cause = (err as { cause?: unknown }).cause;
		if (cause instanceof AggregateError && cause.errors.length > 0) {
			return `${err.message}: ${cause.errors[0].message}`;
		}
		if (cause instanceof Error && cause.message) {
			return `${err.message}: ${cause.message}`;
		}
		return err.message;
	}
	return String(err);
}
