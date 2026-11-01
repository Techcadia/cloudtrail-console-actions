# examples/

These `*.json` files are **raw CloudTrail record fixtures** used by the golden
parity test corpus (`internal/engine/golden_test.go`). They are _not_ example
FilterPolicy documents.

For a real, annotated policy to copy and edit, dump the embedded default:

```shell
./bootstrap --dump-default-policy > policy.yaml
```

See [`../internal/policy/default.yaml`](../internal/policy/default.yaml) and the
[policy language reference](../docs/policy-language.md).
