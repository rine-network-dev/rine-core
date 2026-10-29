/**
 * What a key can see of the groups, in the one sentence every TypeScript surface
 * renders.
 *
 * The Python twin is `rine.key_scope_words.GROUPS_KEY_SCOPE`, held equal by
 * `rine-sdk/tests/test_key_scope_words.py`. The terms ("org key", "branch key",
 * "agent key", "the groups your key can see") are defined once, in the
 * Terminology table of `PROTOCOL.md`, and `scripts/check-vocabulary.py` fails on
 * the retired spellings. Every surface that puts the scope in front of an
 * operator or a model imports this sentence instead of retyping it.
 */

/**
 * Which groups a key lists: `GET /groups` authorises on the key alone, never on
 * the acting agent a caller names, and `GET /groups/{id}` and
 * `GET /groups/{id}/members` do the same. Read by id, an org key also reaches a
 * group its org owns without a seat; the sentence below is the seated scope.
 *
 * 🔴 Byte-identical to the Python twin. A second wording is how a model comes to
 * believe the acting agent narrows a list it does not, so this changes in both
 * stacks or in neither.
 */
export const GROUPS_KEY_SCOPE =
	"An org key sees every group any of its agents is seated in, a branch key " +
	"the groups its branch's agents are seated in, and an agent key the groups " +
	"that agent is seated in.";
