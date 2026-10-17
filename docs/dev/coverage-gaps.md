# Coverage Gaps: What Is Not Covered and Why

This page lists the code that the coverage gates do not reach and why no test
reaches it. It also lists the changes that would close each gap. An uncovered
line is often a design signal: a check that cannot fail, a type that permits
invalid states, or a branch two code paths both handle. Fixing the design
usually beats writing a test for it.

Line numbers refer to commit `64f90ce` on the `complete-test-coverage` branch.
Re-measure before acting on them.

---

## What the gates measure

| Gate | Command | Metric enforced | Scope | Floor |
|---|---|---|---|---|
| Python | `./scripts/build.py pytest --coverage` (`pytest --cov=hier_config`) | Statement (line); **no branch coverage** | `hier_config/**/*.py` | 95% |
| Rust core | `cargo llvm-cov --package hier_config_core --fail-under-lines 90` | Lines only; regions and functions are reported but not gated | `crates/hier_config_core/src`, including inline `#[cfg(test)]` modules | 90% |
| PyO3 bindings | — | **Not measured** | `crates/hier_config_py` | — |

The only existing exclusion is `# pragma: no cover` on the optional-import
fallback at `hier_config/platforms/driver_base.py:38`.

## Current numbers

| Gate | Covered / total | Percent |
|---|---:|---:|
| Python statements | 1310 / 1312 | 99.85% |
| Rust-core lines (llvm summary) | 9382 / 9468 | 99.09% |
| Rust-core regions | 15635 / 15890 | 98.40% |
| Rust-core functions | 1241 / 1254 | 98.96% |

The llvm line total counts each monomorphized instantiation of generic code
separately. By distinct source line, 39 Rust lines are uncovered.

These figures are not 100% coverage of the library. The PyO3 crate is not
measured at all, and Python branch coverage is not collected.

## Uncovered lines

### Python (2 statements)

| Location | Why no test reaches it |
|---|---|
| `hier_config/platforms/aruba_aoscx/driver.py:40` | `if not vlan_ids: continue`. `expand_range` (`hier_config/platforms/functions.py:38-64`) never returns an empty tuple: every comma segment appends an int, extends a non-empty range, or raises `ValueError`. |
| `hier_config/platforms/utils.py:32` | Same guard on the same `expand_range` result. |

### Rust core (39 distinct lines)

| Location | Category | Why no test reaches it |
|---|---|---|
| `arena.rs:117, 149, 207` | Invariant guard | `unreachable!` arms for free-list invariants in the node arena. |
| `tree/mod.rs:251, 890, 2070`; `parser.rs:589` | Requires a corrupted tree | These run only on a parentless node or a stale child id. Only direct edits to the public `Tree.arena` produce those; tests that did so were rejected as state corruption. |
| `cisco_xr/mod.rs:46` | Requires a corrupted tree | Skips dead sibling ids; ids read from a live parent are always live. |
| `driver.rs:294` | Data invariant | Every embedded `rules.json` declares its `platform`, so the `None` path never runs. |
| `driver.rs:442` | Duplicate handling | The first loop already returns on any matching `Replace` rule, so the `Replace` arm of the second loop is dead. |
| `formats/value.rs:125-128, 130, 132` | Library-impossible | NaN/Infinity handling; `serde_json::Number` cannot hold non-finite values without `arbitrary_precision`. |
| `formats/xml.rs:425-426` | Library-impossible | quick-xml rejects an unmatched end tag before this check runs. |
| `formats/xml.rs:431-432, 458-459, 474-475, 516-517, 526-527, 552-553` | Library-impossible | UTF-8 decode errors cannot occur on `&str` input with quick-xml's `encoding` feature off. |
| `formats/xml.rs:446-447` | Library-impossible | Unescape never sees `&`: quick-xml emits general references as separate events. |
| `formats/xml.rs:257` | Unpopulated field | No code path ever sets an element tail. **Possible bug — see below.** |
| `formats/xml.rs:565` | Caller invariant | Every caller checks that an element is open first. |
| `platforms/hp_procurve/mod.rs:193, 208` | Redundant guard | Text is trimmed, so a line starting `vlan ` or `untagged `/`tagged ` always has a second word. |
| `view/platforms/hp_procurve.rs:278`; `view/platforms/aruba_aoscx.rs:87` | Redundant guard | Same trimmed-prefix reasoning: the prefix check guarantees the next word exists. |
| `view/platforms/hp_procurve.rs:268` | Infallible | A literal regex always compiles. |

`regex_cache.rs:170` (octal-escape parse) also cannot fail. It shows only in the
per-file totals because the line is inside a closure.

## Recommendations

### High value

1. **Measure the PyO3 crate.** `hier_config_py` is outside both gates and is
   the largest blind spot. Run the Python suite under `cargo llvm-cov show-env`
   to collect coverage for it. Report the number first, and gate on it once it
   is stable.
2. **Make `Tree.arena` private.** Making it `pub(crate)` with accessors removes
   the only way to build parentless or stale nodes. The guards at
   `tree/mod.rs:251/890/2070`, `parser.rs:589` and `cisco_xr/mod.rs:46` can
   then become `debug_assert!` checks or be removed. This changes the core
   crate's API, whose only consumer is `hier_config_py`.
3. **Investigate the XML tail (`xml.rs:257`).** If the tail is never set,
   text after a child element (mixed content) may be dropped silently. Write a
   mixed-content round-trip test first; fix the parser if it fails, or delete
   the branch if mixed content is deliberately unsupported.
4. **Turn on Python branch coverage** (`--cov-branch`). Statement coverage
   alone overstates how much is tested. Measure before setting a floor.

### Simplifications that remove dead branches

5. **Remove the Python `if not vlan_ids` guards**, and add a test showing
   `expand_range` never returns an empty result for valid input.
6. **Use one conversion for XML errors.** Add
   `impl From<quick_xml::Error> for FormatError` and use `?` instead of
   per-site `map_err`. That turns 16 identical error lines into one.
7. **Parse keywords with `strip_prefix`.** For example, take the vlan number
   with `strip_prefix("vlan ")` and the next word. The prefix check then
   guarantees the word exists, so the separate guards at
   `platforms/hp_procurve/mod.rs:193/208` and in the two view files go away.
8. **Compile fixed regexes once.** Use `LazyLock<Regex>` with `expect` for
   literal patterns such as `view/platforms/hp_procurve.rs:268`. Treat the
   octal-escape parse in `regex_cache.rs:170` the same way.
9. **Tighten rules data and negation.** Make `platform` a required field of
   the embedded rules (`driver.rs:294`); an existing test already checks every
   platform's rules. Filter `Replace` rules out of the second loop at
   `driver.rs:442`, or resolve negation in a single pass.
10. **Remove the non-finite number handling in `formats/value.rs:125-132`**,
    after confirming no Python float (for example `float("nan")`) reaches it
    through the bindings.

### Leave alone

- The `unreachable!` arms in `arena.rs` are a correct, cheap safety net for
  internal invariants.

### Caveat

Items 6–9 mostly fold a branch into one expression. That removes uncovered
lines without proving anything new, and region coverage would still show the
gap. Items 1–5 change what is measured or what states are possible.
