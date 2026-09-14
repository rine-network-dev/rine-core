/**
 * `GET /messages/{id}`'s pure wire vocabulary: the one request header a caller
 * sets to change what a read *does*.
 *
 * Named after the server module it mirrors — `src/rine/api/message_words.py` —
 * and placed here rather than in `actor.ts` on this package's own `*-words.ts`
 * convention (`group-words`, `handle-words`, `sender-key-words`, `vote-words`,
 * `group-join-words`): `actor.ts` is the actor contract and already far over the
 * file-size budget, and a future message-wire constant needs an obvious home
 * that is not it.
 *
 * 🔴 This module shipped as a constant and no helper, on the argument that two
 * sites sit below this repo's abstract-at-the-third-repetition line — and named
 * the third site as the trigger to extract `withPeekHeader(headers, peek)` here,
 * so it would not be re-debated. The third site arrived in the same pass
 * (`rine-openclaw`'s set-aside sweep, which hand-assembles the header onto a raw
 * `GET /messages/{id}`), so the trigger is honoured below.
 *
 * The extraction is a HEADER-MAP transform and nothing more, which is what makes
 * it writable across the two unrelated HTTP layers the senders sit on
 * (`rine-ts-sdk`'s own `api/http.ts`, and this package's `http.ts` for the CLI):
 * it touches neither client, so neither has to be reachable from the other. The
 * Python SDK's `_with_peek` (`rine-sdk/src/rine/_base_client.py`) is the same
 * shape for the same reason — there, because its sync and async `read()` are
 * independent copies and the one thing they must not each own is the decision.
 *
 * The one mistake that would be SILENT is a wrong header name: sending `0` is
 * equivalent to omitting the header, and any unrecognised spelling is a `422`
 * naming the header. That is what the constant removes, and the helper now
 * removes its companion — a site that spells the TRUTH value some other way, or
 * sends the header unconditionally.
 */

/**
 * The request header a caller sets to read a message WITHOUT consuming it.
 *
 * Boolean-valued and parsed by pydantic through FastAPI on the server, which
 * accepts a wider set than the obvious four: `1`, `true`, `on`, `yes`, `y`, `t`
 * peek; `0`, `false`, `off`, `no`, `n`, `f` do not; anything else is a `422`
 * with `loc = ["header","X-Rine-Peek"]` rather than a guess. An absent header is
 * today's behaviour exactly. It suppresses the delivery mark and NOTHING else —
 * authorisation, the response body and the actor's own `422` are unchanged,
 * which is what makes the opt-out auditable.
 *
 * Both stacks send the literal `"1"`: the server takes every spelling of true,
 * and this is the one that never needs quoting.
 *
 * 🔴 Three deployables spell this, bound by tests rather than by one import —
 * the server owns `rine.api.message_words.PEEK_HEADER`, the Python SDK
 * `rine._constants.PEEK_HEADER`, and this is the TypeScript copy. The bindings
 * are `test/message-words-twin.test.ts` here and
 * `rine-sdk/tests/test_actor_contract.py`'s `TestThePeekHeaderConstant` there. A
 * client that spells it differently from the server consumes every row it
 * believes it is deferring — silently, with no un-mark route, and in the
 * direction that loses work.
 *
 * 🔴 This literal appears in this package ONCE, here. The twin suite asserts
 * that, which is also what keeps `rine-core`'s own two `GET /messages/{id}`
 * callers (`sender-key-recovery.ts`, `x402/quote-ref.ts`) from ever peeking —
 * neither may, and a source-level rule is cheaper than a per-call-site test.
 */
export const PEEK_HEADER = "X-Rine-Peek";

/**
 * Add the peek header to a request's headers when this read is a peek, and
 * change nothing when it is not.
 *
 * 🔴 Absent, never `"0"`. The server parses both as false, so the two are
 * equivalent on the wire — but an absent header is byte-for-byte the request
 * every pre-peek build sent, and that is what makes "a non-peek read behaves
 * exactly as it did" a property of the request rather than of the server's
 * parser. `undefined` in gives `undefined` back for the same reason: a caller
 * that sends no headers at all keeps sending none.
 *
 * The truth spelling is `"1"`, once, here — the server takes every spelling of
 * true (`1`, `true`, `on`, `yes`, `y`, `t`), and this is the one that never
 * needs quoting.
 */
export function withPeekHeader<T extends Record<string, string> | undefined>(
	headers: T,
	peek: boolean | undefined,
): T | Record<string, string> {
	if (peek !== true) return headers;
	return { ...headers, [PEEK_HEADER]: "1" };
}
