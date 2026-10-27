# Reusable list examples

These files are examples for OpenCDR Core's independent `/lists` API. Lists are
not part of immutable rule releases: update one list once and every rule that
references its `list_id` uses the newly activated version after the evaluator
cache refreshes.

Required fields are `list_id`, `matcher`, and non-empty `values`. `value_type`,
`description`, and `labels` describe the values for operators; `value_type`
does not change matching. `exact` compares strings and `cidr` tests whether an
observed IPv4 or IPv6 address belongs to one of the listed networks.

The examples cover both matchers and every supported value type. Replace the
sample values before using them in production. Rules reference them with:

```json
{ "field": "actor.user_name", "op": "in_list", "list_id": "admin-users" }
```

Use `not_in_list` for an allowlist check. If a referenced list is unavailable,
both operators fail closed and the rule does not match.
