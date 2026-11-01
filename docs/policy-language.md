# Policy expression language

FilterPolicy `key:` fields and every `outputs:`/`preprocess:` value are `{{ ... }}`
**template expressions**. This is a small custom language — **not JMESPath**. A
template is either a plain literal (no `{{`) that evaluates to itself, or exactly
one `{{ expression }}`.

## Grammar

```
expr   := chain ("||" chain)*
chain  := head ("." name | "[" int "]")*
head   := 'string' | true | false | null
        | func "(" expr ("," expr)* ")"
        | name
name   := ident | "quoted ident"
```

- **`ident`** — a bare name looked up in the record (or `preprocess`), e.g.
  `eventSource`, `preprocess.eventName`.
- **`"quoted ident"`** — a field whose name is not an identifier:
  `requestParameters."x-amz-acl"`.
- **`.name`** — descends into a nested object: `userIdentity.principalId`.
- **`[n]`** — indexes into an array (0-based): `split(principalId, ':')[1]`.
  A non-integer or overflowing index is a **compile-time error**.
- **`'string'`** — a single-quoted string literal. In strings and quoted
  names, `\` escapes the closing quote or a backslash: `'it\'s'`.
- **`true` / `false` / `null`** — boolean and null literals.
- **`a || b`** — returns `a` unless `a` is **falsy**, then `b`. Chains
  left-to-right; commonly used as `{{ userAgent || '' }}` to default a missing
  field to the empty string.

## Functions

| Function | Result |
| --- | --- |
| `trimPrefix(s, prefix)` | `s` with `prefix` removed if present |
| `contains(s, substr)` | `true` if `s` contains `substr` |
| `split(s, sep)` | array of `s` split on `sep` |
| `keys(obj)` | sorted array of `obj`'s field names, e.g. `keys(userIdentity) AllIn [accountId]` (identity has only an account) |

## Literal values

A field value with no `{{` is a literal. Quoting decides its type, as in YAML:
`flag: true` is the boolean `true` and `count: 3` a number, while
`flag: "true"` is the string `"true"`. Use `{{ true }}` or the unquoted form
when a later condition compares against a boolean.

## Comparing values

- `Equals` / set membership compare **two strings exactly**: `"01"` is not
  `"1"`. A number compares numerically against a number or a numeric string
  (`value: 32` matches the JSON number `32` and the string `"32"`).
- **Quote zero-padded identifiers.** Unquoted, YAML reads `012345670123` as
  an octal number (1402433619), so the loader rejects unquoted numbers with a
  leading zero: write account IDs as `"012345670123"`.
- The loader is strict: unknown keys (including inside `when:` blocks and
  conditions) and duplicate field names are errors.

## Evaluation is total (never errors)

All syntax errors are reported at **compile time** (`--validate-only` catches
them), so evaluation on the hot path cannot fail. At runtime:

- A missing field, a type mismatch (e.g. indexing a string), or an out-of-range
  index yields **`null`**, not an error.
- **Falsy** values — for the `||` fallback — are: `null`, `false`, the empty
  string `""`, and an empty array or map. Everything else is truthy.

**Consequence:** a typo in a path (`{{ userIdentiy.principalId }}`) silently
evaluates to `null` rather than erroring. In a condition that reads as an
always-false rule; in an output it produces a missing field. When a rule doesn't
behave as expected, run with `LOG_LEVEL=debug` — the per-record trace shows the
value each condition actually saw.

## Examples

```yaml
# default a missing user agent so NotEquals "" works
{ key: "{{ userAgent || '' }}", operator: NotEquals, value: "" }

# strip a service prefix off the event name in preprocess
value: "{{ trimPrefix(eventName, 'AWSPaymentPortalService.') }}"

# take the human part of an assumed-role principalId "AROA...:jane@example.com"
value: "{{ split(userIdentity.principalId, ':')[1] }}"
```
