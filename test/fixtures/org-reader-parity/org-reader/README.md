# org-reader parity fixtures

Recorded from the fleet's Python org reader (`fleet/src/fleet/core/org_reader`) by
`scripts/mls-matrix/record_org_read.py`, during one run of the `org-reader` lane
(`e2e-mls-matrix.sh --lane org-reader --surfaces cli,ts-sdk`; `org-reader-open/` is the `org-reader-open` lane).

- `read-1.json`, `read-2.json`, `read-3.json` are orgs A, B and C. Each holds the org's `root_key`, the reader's
  own-agent list, and per `read` call the query, the HTTP exchanges the reader saw in order, and the page Python
  returned (`ReadPage.to_json()`).
- `divergences.json` lists the differences from Python the TypeScript reader is allowed, each with a reason. It is
  empty: the honest lanes take no negative path.
- The orgs are disposable orgs created on a throwaway local server for the recording. Each `root_key` is committed
  deliberately: it opens nothing outside that discarded database. The issued token is replaced by `fixture-token`
  and the signed assertion of the token request is not recorded.
