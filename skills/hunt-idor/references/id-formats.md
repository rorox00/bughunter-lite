# id-formats — decode and derive object identifiers

An "unguessable" id often isn't. Before killing an IDOR for "UUID not
enumerable", check whether the id is decodable, predictable, or leaked. Goal:
turn an opaque id into one you can produce for a victim's object.

## Sequential / numeric
- Plain auto-increment ints: enumerate ±1/±N, or `toolbridge.ffuf` a range.
- Ints with a check digit/suffix: recover the checksum rule, then enumerate.
- Offset/obfuscated ints (id + constant, XOR, simple hashids): recover the
  transform from a few of your own ids.

## Encoded, not random
- **Base64 / base64url**: decode — many "tokens" are `Type:123` or JSON.
  (GraphQL Relay global ids are base64 `Type:id`; see `graphql-idor.md`.)
- Hex / decimal re-encodings of a smaller number.

## Time/structure-bearing "random" ids
- **UUIDv1**: embeds timestamp + node/MAC → narrow, sometimes predictable.
- **Mongo ObjectId**: 4-byte timestamp + machine + counter → partially
  predictable from one sample.
- **Snowflake-style**: timestamp + worker + sequence → bounded search.
- UUIDv4 is random — only pursue if it **leaks** (below).

## Leaked / derivable
- Harvested from other responses: list endpoints, search, exports, error
  messages, HTML, JS bundles (`js-analyze` output), emails, webhooks.
- Returned by a **creation** call you can make (create your own object, read
  the id pattern, infer neighbours).
- Exposed in referer, logs, autocomplete, or public profiles.

## Composite / tenant-scoped
- `tenant:object` or `org/id` composites: vary the tenant half while keeping a
  valid object half (cross-tenant), and vice-versa.

Record where the id came from; "derived the victim's id from <source>" is part
of the reproducible proof.
