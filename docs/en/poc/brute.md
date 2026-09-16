---
title: brute
slug: /docs/poc/brute
lang: en
summary: afrog brute reference for deciding when to iterate and how mode, commit, and continue work together.
status: published
source: docs/zh/poc/brute.md
last_reviewed: 2026-09-16
---

`brute` lets one rule execute repeatedly against a set of candidate values.

This page is meant to answer three practical questions:

- do I actually need `brute` here
- should I use `clusterbomb` or `pitchfork`
- what result is kept after a hit when `commit` and `continue` are combined

If you only need to test one value, do not reach for `brute` too early. If you need to iterate across a list or combination of inputs, it is the right tool.

## Decide when to use it first

Good fits for `brute`:

- path dictionary probing
- username and password combinations
- extracting many IDs first and validating them one by one
- iterating across a list of candidate parameters

Usually unnecessary when:

- you only need one fixed value
- the first extracted value is enough
- there is no list or combination involved

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

### Quick field lookup

| Field | Commonness | Purpose | Default |
| --- | --- | --- | --- |
| `mode` | common | define how multiple variables are iterated | `clusterbomb` |
| `commit` | common | define which successful result is kept | `winner` |
| `continue` | common | decide whether to keep iterating after a hit | `false` |
| custom variables | required | the candidate lists being iterated | none |

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

## The three core decisions

### 1. Do I need full combinations

- full combinations: `clusterbomb`
- pair values by index: `pitchfork`

### 2. Should it stop on hit

- stop early: `continue: false`
- run the full list: `continue: true`

### 3. Which hit should be retained

- keep the first: `winner` / `first`
- keep the last: `last`
- only care that something matched: `none`

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

### Which one is the better default

Most username-plus-password cases start with `clusterbomb`. `pitchfork` makes more sense only when the two lists are naturally aligned pair by pair.

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

## Two common patterns

### Single-variable iteration

```yaml
rules:
  r0:
    brute:
      p:
        - /
        - /admin
        - /console
    request:
      method: GET
      path: '{{p}}'
    expression: response.status == 200
```

This is basically an ordered walk over a simple list.

### Multi-variable combination

```yaml
rules:
  r0:
    brute:
      mode: clusterbomb
      user:
        - admin
        - test
      pass:
        - admin
        - 123456
    request:
      method: POST
      path: /login
      body: 'u={{user}}&p={{pass}}'
    expression: response.status == 200 && response_text.icontains("welcome")
```

This runs the cartesian product of usernames and passwords.

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

## Common pitfalls

### The extracted result is not actually a list

If the value fed into `brute` is not a string list, the behavior will not match what you expect.

### Using brute when one value was enough

Many PoCs only need `submatch` and a direct follow-up request, not a full iteration layer.

### `continue: true` creates more requests than expected

Once the list is large, `continue: true` means you really are asking the engine to run the whole candidate space.

## Related pages

- [PoC Syntax](./syntax.md)
- [PoC Quickstart](./quickstart.md)
- [Helper Functions](./helper-functions.md)
- [requires](./requires.md)
