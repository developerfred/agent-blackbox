# agent-blackbox ledger format, version 1

Status: draft 1 (describes what `src/ledger.js` and `src/vault.js` write today).
This document is the source of truth for the event format. The code follows
it; when they disagree, one of them has a bug and the disagreement is tracked
in [Reference implementation notes](#reference-implementation-notes).

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## 1. What this is

A ledger is an append-only list of JSON records that records what an AI agent
did. It has four properties, and nothing else is promised:

1. **Tamper evidence.** Records are linked in a hash chain, so changing,
   removing, inserting or reordering a record is detectable.
2. **Attribution.** Every record is signed with Ed25519, so a chain can be
   tied to one key.
3. **Secrets stay out.** Secret values are replaced by fingerprints before a
   record is written (section 9).
4. **Erasable content.** The sensitive content (payloads and summaries) is
   kept outside the chain, encrypted per session. Destroying a session key
   erases that content for good and leaves the chain valid (sections 7, 8).

A ledger proves that what it holds was not altered. It does not prove that
everything that happened was recorded (section 11).

Verifying a chain needs only this document, SHA-256 and Ed25519. It does not
need the recorder, the policy engine, or any key except the public one.

## 2. Files

A ledger is a UTF-8 text file in JSON Lines form: one record per line, `\n`
as the line terminator, no byte-order mark. A verifier MUST ignore empty
lines and MUST report any other line that is not a JSON object as an error.
Line breaks inside a record are impossible, because JSON strings escape them.

Payload blobs are stored next to the ledger (section 7). A third party who
only has the ledger can still verify the chain (conformance level 1, section
12).

## 3. Records

A record is a JSON object. Every record has these fields:

| field  | type    | meaning |
|--------|---------|---------|
| `v`    | integer | format version; `1` for this document |
| `seq`  | integer | position in the chain, starting at 1, increasing by 1 |
| `ts`   | string  | time of writing, RFC 3339 UTC with milliseconds (`2026-10-04T15:08:46.123Z`) |
| `kind` | string  | what the record is (section 10) |
| `prev` | string  | `hash` of the previous record; 64 zeros for the first |
| `hash` | string  | 64 lowercase hex characters, section 4 |
| `sig`  | string  | standard base64 (with padding) of a 64 byte signature, section 5 |

Records MAY have more fields, defined by their kind or added by extensions.
A verifier MUST NOT reject a record for having a field it does not know: the
unknown field is covered by `hash` like all others.

`ts` is written by the recorder. It is covered by the signature but it is a
claim of the signer, not an independent time source (section 11).

Hex values (`hash`, `prev`, blob digests, key ids) are lowercase. A verifier
MUST compare them as exact strings.

## 4. Canonical form and hash

The hash input is the **canonical form** of the record without `hash` and
`sig`. All other fields, including `prev`, are part of it.

The canonical form is the JSON Canonicalization Scheme, RFC 8785:

- no whitespace between tokens;
- object members sorted by key, comparing UTF-16 code units;
- strings serialized as ECMAScript `JSON.stringify` does: only `"` `\` and
  control characters below U+0020 are escaped, as `\b \t \n \f \r` where
  those exist and as `\u00xx` with lowercase hex otherwise; `/` and
  non-ASCII characters are not escaped; lone surrogates are written as
  `\udxxx` escapes;
- numbers in ECMAScript `Number::toString` form (the shortest representation
  that round-trips). Records written by v1 recorders SHOULD hold only
  integers, strings, booleans, `null`, arrays and objects. Non-finite numbers
  cannot occur in JSON;
- `true`, `false` and `null` as written.

Then:

```
hash = lowercase_hex( SHA-256( UTF-8( canonical(record without hash, sig) ) ) )
```

The hash does not depend on how the stored line is formatted (key order,
spacing, escaping), only on the parsed values. A line that contains the same
key twice is invalid and a verifier MUST report it.

## 5. Signature

```
sig = base64( Ed25519_sign( private_key, bytes_of(hash) ) )
```

The signed message is the **32 raw bytes** of the digest (the hex `hash`
decoded), not the hex text and not the canonical JSON. Ed25519 is the pure
scheme of RFC 8032, with no pre-hash and no context. Because the signature
covers the hash and the hash covers `prev`, a signature on any record vouches
for the whole chain before it.

## 6. Genesis and keys

The first record of a ledger is a `genesis` record: `seq` 1, `prev` equal to
64 zeros. It carries the public key the whole chain is signed with:

| field        | meaning |
|--------------|---------|
| `public_key` | the Ed25519 public key as an SPKI PEM string |
| `key_id`     | first 16 hex characters of SHA-256 of the key's SPKI DER encoding |

Rules:

- `seq` 1 MUST be a `genesis` record and no other record may have kind
  `genesis`. Version 1 defines no key rotation: a chain has exactly one key.
- `key_id` MUST match `public_key`.
- Every record, genesis included, MUST verify against the genesis key.

**Trust.** The genesis key is written by whoever wrote the chain. A verifier
that takes the key from the ledger itself proves only that the chain is
internally consistent. To tie the chain to a signer the verifier MUST be
given the public key out of band (for example from a published anchor or a
release) and MUST then fail if the genesis key differs from it.

## 7. Payload blobs

Content that does not belong in the chain is stored as a blob and referenced
by digest. The record fields `payload`, `request_blob` and `response_blob`
each hold the **SHA-256 hex digest of the plaintext** of one blob. They are
covered by `hash`, so a blob cannot be swapped.

A blob is the UTF-8 bytes of a string, the canonical form (section 4)
of a JSON value, or raw bytes (captured model bodies). Blobs are looked up by digest:

```
blobs/<digest>             unencrypted
blobs/<key>/<digest>       encrypted; <key> is the record's `key` field
```

(The directory layout is informative; the digest rules are normative.)

An encrypted blob is a sealed envelope:

```
"BBX1" (4 bytes) || kid (8 bytes) || iv (12) || tag (16) || ciphertext
```

AES-256-GCM, 12 byte random IV, 16 byte tag, additional authenticated data
`"BBX1" || kid` (12 bytes). `kid` is the key id as 8 raw bytes (the record's
`key` field is the same value as 16 hex characters). The digest in the record
is of the plaintext, so checking a blob needs the session key.

The `key` field names the session data key that sealed the record's blobs.
A record whose blobs are encrypted MUST carry `key`; a record with `key`
MUST have all its blobs sealed under that key.

## 8. Summaries and crypto-erase

Many records carry a one-line `summary` of an event (a prompt, a command, a
path). Summaries can be sensitive, so they live in the chain in sealed form
when encryption is on:

```
summary = "bbx1:" || base64( sealed envelope )     (same envelope as section 7)
```

The chain hashes the sealed text. A summary without the `bbx1:` prefix is
plaintext (encryption off, or a kind that never carries user content).

### Key hierarchy

```
master key (32 bytes, never in the ledger)
  └─ per scope: data key (32 random bytes), stored wrapped under the master key
```

- A **scope** is `session:<session_id>` for records with a session, and
  `month:<YYYY-MM>` (from `ts`) for records without one.
- `kid` = first 8 bytes of `HMAC-SHA256(master, "kid:" || scope)`. Key ids
  therefore do not reveal session ids to someone without the master key.
- The data key is wrapped with AES-256-GCM under the master key, AAD
  `"wrap:" || kid_hex`, stored as `base64( iv(12) || tag(16) || ciphertext )`.

### Erasing

To erase a scope, the recorder destroys the wrapped data key (and SHOULD
delete the blobs) and appends a `purge` record that lists the key ids
(section 10). After that the payloads and summaries of the scope cannot be
read by anyone, including from backups taken before, and the chain still
verifies because it only ever held digests and ciphertext.

A verifier that finds a blob missing or undecryptable because its `key`
appears in the `erased_keys` of a `purge` record anywhere in the ledger MUST
treat that as expected erasure, not as damage. The same absence for a key
that was **not** purged is a warning (blob missing) and a verifier that has
the key and finds the content changed MUST report an error.

A `purge` record is a signed statement by the recorder. It is not proof that
the key was destroyed.

## 9. Secret fingerprints

Before any text is written (summary or blob), the recorder replaces secrets
with markers:

```
[secret:<fp>]        API keys, tokens, KEY=value pairs
[private-key:<fp>]   private key blocks
fp = first 12 hex characters of HMAC-SHA256(salt, value)
```

`salt` is random per installation and is never written. So: the same secret
gives the same fingerprint within one installation (the ledger can say "this
secret was read at #5 and left at #12"), different installations give
unrelated fingerprints, and nobody can test a guessed value against a
ledger without the salt. Fingerprints are not verifiable by a third party and
a verifier MUST NOT try. Records such as `decision` carry the fingerprint in
a `secret` field.

## 10. Record kinds

This table is the registry. A kind or field is part of the format only if it
is listed here. Fields marked `?` are optional.

| kind       | written for | fields (besides the common ones) |
|------------|-------------|----------------------------------|
| `genesis`  | start of a chain | `key_id`, `public_key` |
| `hook`     | one agent lifecycle event | `event`, `session_id`, `prompt_id?`, `agent_id?`, `tool_name?`, `tool_use_id?`, `cwd?`, `summary?`, `payload`, `payload_size`, `key?`, `spooled?`, `received_at?` |
| `decision` | a policy verdict | `decision` (`allow`, `ask`, `deny`, `warn`, `alert`, `note`, `missed`), `rule`, `reason`, `session_id?`, `prompt_id?`, `tool_use_id?`, `tool_name?`, `secret?` |
| `intent`   | hosts named in a user prompt | `session_id`, `prompt_id?`, `hosts` |
| `taint`    | a session became tainted | `session_id`, `tool_use_id?`, `tool_name?`, `flag`, `why` |
| `settings` | integrity of the agent's hook wiring | `via`, `fingerprint`, `problems?`, `previous?` |
| `otel`     | one OpenTelemetry log record from the agent | `event`, `service?`, `session_id?`, `prompt_id?`, `tool_use_id?`, `request_id?`, `summary?`, `payload`, `key?` |
| `api_body` | one raw model request/response pair | `session_id?`, `request_id?`, `message_uuid?`, `model?`, `query_source?`, `request_blob?`, `request_size?`, `response_blob?`, `response_size?`, `key?`, `summary?`, `orphan?`, `file?` |
| `purge`    | crypto-erasure | `erased_keys` (key ids), `erased_blobs`, `erased_raw_bodies`, `purged_session?`, `before?` |

Rules for evolving the registry:

- A verifier MUST accept kinds it does not know and verify them like any
  other record (hash, signature, chain).
- New kinds and new optional fields do not change `v`. Extensions that are
  not part of this document SHOULD name their kind `x-<vendor>.<name>` so
  they cannot clash with a future registry entry.
- The registry is owned by this document. Adapters for other agents and
  mappings to other standards MUST add what they need here (as new optional
  fields or kinds) instead of keeping a private format.

## 11. Verification and what it proves

A conforming verifier performs, for each non-empty line, in order:

1. parse it as a JSON object with no duplicate keys, else error;
2. `v` is `1`, else report the record as unsupported (it cannot be verified);
3. `seq` equals the expected value (1, then previous + 1);
4. `prev` equals the previous record's `hash` (64 zeros for `seq` 1);
5. the hash recomputed from the record (section 4) equals `hash`;
6. the signature (section 5) verifies against the chain key;
7. for `genesis`: it is `seq` 1, `key_id` matches `public_key`, and if a
   trusted key was supplied the genesis key equals it.

A ledger passes if every record passes and it is not empty. The result SHOULD
include the number of records and the head (`seq`, `hash`) so it can be
compared with an anchor.

**Anchors.** A chain head `{ seq, hash, sig, key_id }` published somewhere the
recorder cannot write is an *anchor*. A verifier given an anchor MUST check
that the ledger has a record with that `seq` and that its `hash` equals the
anchored one. This is the only defence against truncation (cutting the last
records) and against a rewrite by someone who holds the signing key. A
ledger with no anchor can be shortened or fully re-signed without detection.

**What a pass does not prove:**

- that everything the agent did was recorded (the recorder can be bypassed,
  disabled or lied to; the `settings` records only make this visible);
- that `ts` is true;
- anything about content that is sealed and whose key you do not have, or
  that was erased;
- that the signer is who you think, unless the key came from outside the
  ledger;
- that a `purge` really destroyed a key.

An attacker who can run as the user that owns the recorder can read the
signing key and rewrite and re-sign the whole chain. That is why anchoring
exists and why the recorder is meant to run as a separate OS user.

## 12. Conformance levels

- **Level 1, chain.** Section 11 steps 1 to 7, plus anchors. Needs only the
  ledger file (and optionally a trusted key or anchor).
- **Level 2, blobs.** Level 1 plus, for every blob digest in a record:
  unencrypted blobs are present and hash to the digest; sealed blobs are
  decrypted with the session key and hash to the digest; erased keys are
  recognized from `purge` records (section 8). Needs the blob directory and
  the key material.

A verifier states which level it implemented. Test vectors for both levels
are kept with this specification (see `docs/spec/vectors/`).

## 13. Versioning

`v` is per record. The same ledger may in future hold records of several
versions only if each carries the data needed to verify it; a verifier that
meets a version it does not know MUST say so and MUST NOT report the ledger
as valid.

`v` changes only for incompatible changes: the canonical form, the hash, the
signature or the meaning of a required field. Adding optional fields or kinds
does not change `v`. Revisions of this document that do not change `v` are
numbered as drafts and then as 1.x with a changelog at the end.

## Reference implementation notes

Where the code in this repository differs from this document today:

- `blackbox verify` accepts a second `genesis` record in the middle of a
  chain as a key change when no trusted key is given. Section 6 forbids it.
- `blackbox verify` does not check that `key_id` matches `public_key`, does
  not reject duplicate keys in a line, and does not check `v`.
- `canon()` in `src/ledger.js` is RFC 8785 for the values that occur in
  records, but it also drops keys whose value is `undefined`, which cannot
  occur in parsed JSON.

## Open questions

Tracked here because they decide the next versions; none changes v1.

- Key rotation (a signed handover record) and key revocation.
- Merkle batching and external anchoring formats (batch root, inclusion
  proofs, anchor targets). Today an anchor is the bare head.
- Mapping to OpenTelemetry GenAI conventions (attribute names for `hook` and
  `otel` records).
- A field that names the agent that produced an event (Claude Code, Codex,
  Cursor, Gemini CLI), for the adapters.
- Hash and signature agility (algorithm identifiers).
