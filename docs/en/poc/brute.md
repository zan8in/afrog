---
title: brute
slug: /docs/poc/brute
lang: en
summary: Iteration modes, defaults, and dynamic-list behavior for brute in afrog PoCs.
status: published
source: docs/zh/poc/brute.md
last_reviewed: 2026-09-16
---

`brute` lets one rule execute repeatedly against a set of candidate values. Typical use cases include path discovery, username/password combinations, and validating extracted IDs one by one.

## Typical use cases

The most common patterns are:

- path dictionary probing
- weak-password or default-credential combinations
- extract many IDs first, then validate each one

## Common fields

- `mode`
- `commit`
- `continue`

Plus one or more iterated variables, for example:

```yaml
brute:
  user:
    - admin
    - test
```

## Default behavior

If you define only brute variables and omit `mode`, `commit`, and `continue`, the default is effectively:

```yaml
brute:
  mode: clusterbomb
  commit: winner
  continue: false
  p:
    - /
    - /jeecg-boot
```

This means:

- iterate with `clusterbomb`
- keep the first successful variable set, request, and response
- stop on first hit
- with only one variable, it behaves like a simple ordered list walk

## `mode`

### `clusterbomb`

Useful for cartesian-product iteration.

If you have:

- multiple usernames
- multiple passwords

it will try all combinations.

### `pitchfork`

Useful for index-aligned iteration.

For example:

- first username with first password
- second username with second password

## `commit`

`commit` controls what is retained after a match.

### `winner`

Keep the first successful variable set, request, and response.

### `first`

Currently behaves the same as `winner` and keeps the first successful result.

### `last`

If multiple matches happen, keep the last successful one.

### `none`

Do not commit brute variables themselves, but still keep the successful request and response. Useful when you care only about the fact of a hit, not the exact iterated value.

## `continue`

- `false`: stop on first hit
- `true`: keep iterating through the entire list

## Reading the combinations

- `winner/first + continue: false`: stop on the first hit and keep that one
- `winner/first + continue: true`: continue iterating, but keep the first hit
- `last + continue: true`: continue iterating and keep the last hit
- `none`: brute variables are not committed to the global variable map

## Static list example

```yaml
rules:
  r0:
    brute:
      mode: clusterbomb
      commit: winner
      continue: false
      user:
        - admin
        - test
        - guest
    request:
      method: GET
      path: /?user={{user}}
    expression: response.status == 200 && response_text.icontains("welcome")

expression: r0()
```

## Dynamic list example

`brute` does not only accept hard-coded YAML lists. It can also consume runtime expression results as long as the final value resolves to a string list.

```yaml
rules:
  r0:
    request:
      method: GET
      path: /api/templates
    expression: response.status == 200
    output:
      id_matches: '"\"id\":\"(?P<tid>[0-9]+)\"".bsubmatchall(response.body)'

  r1:
    brute:
      mode: clusterbomb
      commit: winner
      continue: false
      template_id: id_matches["tid"]
    request:
      method: GET
      path: /api/check?id={{template_id}}
    expression: response.status == 200 && response_text.icontains("success")

expression: r0() && r1()
```

## Usage suggestions

1. If you need only one value, you usually do not need `brute`
2. For Chinese pages or decoded text, prefer extraction with `submatchall(response_text)`
3. Verification-style PoCs usually prefer `continue: false`
4. At the moment, `winner` and `first` can be treated as equivalent

## Related pages

- [PoC Syntax](./syntax.md)
- [PoC Quickstart](./quickstart.md)
