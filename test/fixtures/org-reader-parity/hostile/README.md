# org-reader hostile fixtures

Recorded from the fleet's Python org reader (`fleet/src/fleet/core/org_reader`) by
`scripts/mls-matrix/record_org_read_hostile.py`. The honest fixtures in `../org-reader/` never
take a negative path, so each file here is one hostile case: the recorded group and agents with
one thing made wrong, served to the reader by a scripted server, with what the reader returned.

- One case per file. Each holds the reader's org (`org_id`, `root_key`, `own_agents`), the `reader`
  key it reads with (`branch` is `null` for an org-wide key), and one read: the query, the HTTP
  exchanges the reader made in order (retries included), and either the page it returned or the
  class of the exception it raised. The shape of `reads` matches the honest fixtures.
- The cases start from the recorded real responses, with fresh keys, signatures and sealed copies
  minted by `rine.testing.World` from the recorded roots where a case needs them. The roots are
  disposable and committed deliberately, as in the honest fixtures.
- `divergences.json` lists the differences from Python a reader is allowed, each with a reason. Each
  entry names the ruling that allows it: `malformed-input`, `resource-bound` or `not-built`. Each also
  names the recorded `cases` that show it, or a `pinnedBy` unit test with the reason no recorded case can.
- Each case was scanned for secrets and for internal record ids before it was written, and
  recorded again when random bytes tripped a scan. Do not edit a file by hand: regenerate the set.

122 cases: 21 direct, 23 escrow, 12 key-faults, 49 malformed, 17 sender-key.

| case | what is wrong | what Python does |
| --- | --- | --- |
| `direct-control` | an honest 1:1 message from a foreign agent | verified |
| `direct-copies-agree` | both org agents hold a copy and the two envelopes are equal | verified |
| `direct-copies-differ` | both org agents hold a copy and the sender signed two different texts | verified (equivocation) |
| `direct-history-key-without-supersede-time` | the server serves an earlier key generation without saying when it ended | verification `invalid` |
| `direct-kid-generation-above-current` | signed under a key generation the server does not have yet | verification `invalid` |
| `direct-kid-generation-below-current` | signed under an earlier key generation, read from history | verified |
| `direct-kid-generation-lies` | the key id claims a generation the signature was not made under | verification `invalid` |
| `direct-kid-names-another-agent` | the key id names a different agent than the sender | verification `sender-mismatch` |
| `direct-no-recipient` | a 1:1 row that names no recipient | gap `Unreadable` |
| `direct-outbound-self-copy` | an org agent's message to a foreign agent, read from its own copy | verified |
| `direct-reader-branch-does-not-reach` | a reader for another branch meets a main-branch recipient | gap `OutOfScope` |
| `direct-recipient-keys-not-found` | the recipient's keys are not on the server | gap `Unreadable` |
| `direct-retired-encryption-version` | a row of an encryption version the reader no longer opens | gap `Unreadable` |
| `direct-sealed-to-another-agent` | sealed to a different org agent than the recipient | gap `Unreadable` |
| `direct-sealed-to-superseded-recipient-key` | sealed to the recipient's earlier key generation | verified |
| `direct-sender-flagged-own` | a foreign agent is marked as the org's own by the server | verification `invalid` |
| `direct-sender-keys-not-found` | the sender's keys are not on the server | verification `unverifiable` |
| `direct-signature-flipped` | one bit of the sender's signature is flipped | verification `invalid` |
| `direct-stored-after-sender-key-superseded` | stored after the sender's signing key was superseded | verification `invalid` |
| `direct-stored-after-sender-revoked` | stored after the sender was revoked | verification `invalid` |
| `direct-stored-before-sender-revoked` | stored before the sender was revoked | verified |
| `escrow-absent` | no escrow copy stored for the epoch | gap `NoEscrow` |
| `escrow-branch-name-overlong` | the row names a branch longer than any branch can be | gap `EscrowForged`, finding `EscrowForged` |
| `escrow-branch-name-traversal` | the row names a branch such as a path escape | gap `EscrowForged`, finding `EscrowForged` |
| `escrow-only-copy-rejects` | the single copy lists a different leaf key for the sender | gap `MemberRejected` |
| `escrow-sealed-for-wrong-branch` | signed correctly, but sealed to another branch's escrow key | gap `EscrowInvalid`, finding `EscrowInvalid` |
| `escrow-sealed-for-wrong-org` | signed correctly, but sealed under another org's id | gap `EscrowInvalid`, finding `EscrowInvalid` |
| `escrow-secrets-of-another-epoch` | the only copy holds another epoch's secrets | gap `EscrowInvalid` |
| `escrow-sibling-rejects-same-fork` | two copies of one fork; one lists a different leaf key for the sender | gap `MemberRejected` |
| `escrow-sibling-unmatched-same-fork` | a same-fork copy holds another epoch's secrets beside one that opens | verified, finding `EscrowInvalid` |
| `escrow-signature-flipped-alone` | the only copy has a bit of its uploader signature flipped | gap `EscrowForged`, finding `EscrowForged` |
| `escrow-signature-flipped-beside-good` | one of two copies has a flipped signature bit; the other opens | verified, finding `EscrowForged` |
| `escrow-signed-by-other-agent` | the row names one uploader but another agent's key signed it | gap `EscrowForged`, finding `EscrowForged` |
| `escrow-two-forks-other-fork-rejects` | a second fork of the epoch rejects the message; the honest fork opens it | verified |
| `escrow-two-forks-other-fork-unmatched` | a second fork holds another epoch's secrets; the honest fork opens the message | verified, finding `EscrowInvalid` |
| `escrow-uploader-key-superseded` | the copy was stored after its uploader's key generation was superseded | gap `EscrowForged`, finding `EscrowForged` |
| `escrow-uploader-on-other-branch` | the uploader's keys chain to another branch than the row names | gap `EscrowInvalid`, finding `EscrowInvalid` |
| `escrow-uploader-revoked` | the copy was stored after its uploader was revoked | gap `EscrowForged`, finding `EscrowForged` |
| `mls-ciphertext-corrupted` | an honest escrow, but the message body has a byte changed | gap `ForkUnmatched` |
| `mls-ciphertext-is-not-a-message` | the row's ciphertext does not parse as an MLS message | gap `Unreadable` |
| `mls-control` | the recorded message and its honest escrow copies | verified |
| `mls-header-names-another-group` | the row's group is not the group in the message header | gap `Unreadable` |
| `mls-reader-branch-does-not-reach` | a reader for another branch meets escrow copies of the main branch | gap `OutOfScope` |
| `mls-signer-is-not-the-named-sender` | the message opens but its signer is not the agent the server names | gap `MemberRejected` |
| `keys-fault-direct-recipient-429` | 429 reading the recipient's keys, to open a 1:1 row | gap `KeysUnavailable` |
| `keys-fault-direct-recipient-503` | 503 reading the recipient's keys, to open a 1:1 row | gap `KeysUnavailable` |
| `keys-fault-direct-recipient-connection` | connection reading the recipient's keys, to open a 1:1 row | gap `KeysUnavailable` |
| `keys-fault-direct-sender-429` | 429 reading the sender's keys, to check a 1:1 signature | verification `unverifiable` |
| `keys-fault-direct-sender-503` | 503 reading the sender's keys, to check a 1:1 signature | verification `unverifiable` |
| `keys-fault-direct-sender-connection` | connection reading the sender's keys, to check a 1:1 signature | verification `unverifiable` |
| `keys-fault-escrow-uploader-429` | 429 reading the escrow uploader's keys, to open its copy | gap `KeysUnavailable` |
| `keys-fault-escrow-uploader-503` | 503 reading the escrow uploader's keys, to open its copy | gap `KeysUnavailable` |
| `keys-fault-escrow-uploader-connection` | connection reading the escrow uploader's keys, to open its copy | gap `KeysUnavailable` |
| `keys-fault-mls-signer-429` | 429 reading the sending agent's keys, to match the MLS leaf that signed | gap `KeysUnavailable` |
| `keys-fault-mls-signer-503` | 503 reading the sending agent's keys, to match the MLS leaf that signed | gap `KeysUnavailable` |
| `keys-fault-mls-signer-connection` | connection reading the sending agent's keys, to match the MLS leaf that signed | gap `KeysUnavailable` |
| `malformed-escrow-branch-missing` | an escrow row where no branch | raises `KeyError` |
| `malformed-escrow-created-at-missing` | an escrow row where no created_at | raises `KeyError` |
| `malformed-escrow-created-at-without-offset` | an escrow row where created_at has no UTC offset | verified |
| `malformed-escrow-epoch-a-fraction` | an escrow row where the epoch is a fraction | gap `NoEscrow` |
| `malformed-escrow-epoch-a-string` | an escrow row where the epoch is a string | gap `NoEscrow` |
| `malformed-escrow-epoch-missing` | an escrow row where no epoch | raises `KeyError` |
| `malformed-escrow-fp-missing` | an escrow row where no fp | raises `KeyError` |
| `malformed-escrow-fp-not-base64` | an escrow row where fp is not base64url | gap `EscrowForged`, finding `EscrowForged` |
| `malformed-escrow-sealed-empty` | an escrow row where sealed is empty | gap `EscrowForged`, finding `EscrowForged` |
| `malformed-escrow-sealed-missing` | an escrow row where no sealed | raises `KeyError` |
| `malformed-escrow-signature-missing` | an escrow row where no uploader_sig | raises `KeyError` |
| `malformed-escrow-signature-not-base64` | an escrow row where uploader_sig is not base64url | gap `EscrowForged`, finding `EscrowForged` |
| `malformed-escrow-uploader-key-gen-beyond-safe-integer` | an escrow row where uploader_key_gen is past the largest safe integer | gap `Unreadable`, finding `Unreadable` |
| `malformed-escrow-uploader-key-gen-fraction` | an escrow row where uploader_key_gen is a fraction | gap `Unreadable`, finding `Unreadable` |
| `malformed-escrow-uploader-key-gen-missing` | an escrow row where no uploader_key_gen | raises `KeyError` |
| `malformed-escrow-uploader-missing` | an escrow row where no uploader_agent_id | raises `KeyError` |
| `malformed-page-a-list` | the feed answers with a list | raises `TypeError` |
| `malformed-page-escrow-row-null` | one escrow row is null | raises `TypeError` |
| `malformed-page-escrow-rows-null` | the escrow's rows are null | raises `TypeError` |
| `malformed-page-escrow-without-rows` | the escrow answers with no rows | raises `KeyError` |
| `malformed-page-item-a-string` | one feed item is a string | raises `TypeError` |
| `malformed-page-item-null` | one feed item is null | raises `TypeError` |
| `malformed-page-items-null` | the feed's items are null | raises `TypeError` |
| `malformed-page-without-cursor` | the feed carries no next_cursor | no rows |
| `malformed-page-without-items` | the feed answers with no items | raises `KeyError` |
| `malformed-row-ciphertext-a-number` | an activity row where encrypted_payload is a number | raises `TypeError` |
| `malformed-row-ciphertext-missing` | an activity row where no encrypted_payload | raises `KeyError` |
| `malformed-row-ciphertext-not-base64` | an activity row where encrypted_payload is not base64url | raises `Error` |
| `malformed-row-conversation-id-missing` | an activity row where no conversation_id | raises `KeyError` |
| `malformed-row-created-at-a-number` | an activity row where created_at is a number | raises `TypeError` |
| `malformed-row-created-at-missing` | an activity row where no created_at | raises `KeyError` |
| `malformed-row-created-at-not-a-time` | an activity row where created_at is not a time | raises `ValueError` |
| `malformed-row-created-at-without-offset` | an activity row where created_at has no UTC offset | verified |
| `malformed-row-direction-missing` | an activity row where no direction | raises `KeyError` |
| `malformed-row-encryption-version-missing` | an activity row where no encryption_version | raises `KeyError` |
| `malformed-row-from-a-string` | an activity row where the sender is a string | raises `TypeError` |
| `malformed-row-from-agent-id-missing` | an activity row where the sender has no agent_id | raises `KeyError` |
| `malformed-row-from-missing` | an activity row where no sender | raises `KeyError` |
| `malformed-row-from-org-id-missing` | an activity row where the sender has no org_id | raises `KeyError` |
| `malformed-row-from-own-missing` | an activity row where the sender has no own flag | raises `KeyError` |
| `malformed-row-group-a-string` | an activity row where the group is a string | raises `TypeError` |
| `malformed-row-id-missing` | an activity row where no id | raises `KeyError` |
| `malformed-row-key-gen-beyond-safe-integer` | an own copy whose key_gen is past the largest safe integer | gap `Unreadable` |
| `malformed-row-key-gen-fraction` | an own copy whose key_gen is a fraction | raises `CryptoError` |
| `malformed-row-key-gen-negative` | an own copy whose key_gen is negative | raises `CryptoError` |
| `malformed-row-key-gen-string` | an own copy whose key_gen is a string | raises `CryptoError` |
| `malformed-row-payload-a-string` | an activity row where the payload is a string | raises `AttributeError` |
| `malformed-row-payload-missing` | an activity row where no payload | raises `KeyError` |
| `malformed-row-type-missing` | an activity row where no type | raises `KeyError` |
| `sender-key-chain-10000-steps` | a post exactly 10,000 ratchet steps past the distribution | verified |
| `sender-key-chain-10001-steps` | a post 10,001 ratchet steps past the distribution | gap `RatchetGap` |
| `sender-key-control` | a post in an open group, with its distribution held | verified |
| `sender-key-distribution-after-the-post` | the only distribution starts after the post's index | gap `NoDistribution` |
| `sender-key-distribution-forged-sender` | a distribution signed by one agent and delivered as another's | gap `NoDistribution` |
| `sender-key-distribution-in-feed` | a valid distribution is consumed and not shown | no rows |
| `sender-key-distribution-scan-exhausted` | the distribution feed never ends and never holds the key | gap `NoDistribution` |
| `sender-key-distribution-typed-as-message` | distribution content in a row typed as an ordinary message | verified |
| `sender-key-distribution-unreadable` | a distribution sealed to an agent the reader cannot reach | gap `KeyDistributionUnreadable` |
| `sender-key-distribution-unverified` | a distribution whose sender signature does not verify | gap `KeyDistributionUnverified` |
| `sender-key-duplicate-different-envelope` | one slot stored twice with two different texts | gap `Duplicate`, verified (equivocation) |
| `sender-key-duplicate-same-envelope` | the same post stored twice | gap `Duplicate`, verified |
| `sender-key-kid-names-another-agent` | the key id names a different agent than the poster | verification `sender-mismatch` |
| `sender-key-no-distribution` | a post whose distribution the org never received | gap `NoDistribution` |
| `sender-key-poster-keys-not-found` | the poster's keys are not on the server | gap `NoDistribution` |
| `sender-key-signature-flipped` | one bit of the poster's signature is flipped | verification `invalid` |
| `sender-key-wire-is-garbled` | a post whose ciphertext is not a sender-key message | gap `Unreadable` |
