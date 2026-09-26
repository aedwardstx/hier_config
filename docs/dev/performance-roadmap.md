# Performance Roadmap: API Changes That Unlock Further Gains

The Rust rewrite retains the main tree/driver/workflow API but includes explicit
[migration breaks](../user/rust-core-changes.md). The measurements below describe
the profiled release build, not a proof that every future optimization requires
an API break. Some measured hot paths are dominated by CPython object construction.

This document records what is *left* to do. It lists the remaining optimisations, what each would cost to unlock, and the measurements that justify them. Work that has already shipped is not tracked here — see `CHANGELOG.md` for history, [Performance & Benchmarks](benchmarks.md) for the 3.x to 4.0 benchmark story, [Architecture](architecture.md#core-tree-model) for the data-layout decisions and invariants that came out of it, and the [3.x → 4.0 migration guide](../user/rust-core-changes.md) for consumer-facing consequences.

---

## Current baseline

Reference figures on an Apple M2 Max, release build (`maturin develop --release`), against the generated 400-interface Cisco IOS config used by the gate. Costs are in **calibration units**, which self-normalise across machines (1 unit ≈ 3.0 ms on this machine).

| Operation | Cost (units) | Wall clock | Gate ceiling | Remaining headroom |
|---|---:|---:|---:|---|
| `deepcopy` | 0.020 | 0.06 ms | 0.03 | ~35%, via [item 5](#5-compile-driver-rules-once-per-driver); ~13% via [item 7](#7-profile-guided-optimisation-for-release-wheels) |
| `iteration` | 0.037 | 0.11 ms | 0.06 | ~0.011 units, via [item 2](#2-expose-a-bulkcolumnar-accessor) |
| `remediation` | 0.123 | 0.37 ms | 0.19 | ~28% via item 5; ~13% via [item 6](#6-replace-siphash-in-the-children-index-with-a-seeded-fast-hasher); ~15% via item 7 |
| `fast_load` | 0.162 | 0.48 ms | 0.24 | Items 5–7 apply; not separately measured |
| `parse` | 0.184 | 0.55 ms | 0.27 | ~10% via item 5; ~12% via item 6; ~13% via item 7; see also [items 3](#3-store-node-text-without-a-per-node-allocation) and [4](#4-simd-byte-scans-in-the-parser) |
| `dump` | 0.266 | 0.80 ms | 0.37 | ~45%, via [item 1](#1-change-dumpline-from-a-pydantic-model-to-a-__slots__-class) |

Re-derive these with `pytest -m benchmark tests/benchmarks/test_perf_regression.py -v -s` rather than trusting any number written down here. The headroom percentages for items 5–7 are separate measurements. They overlap, so do not add them together (see [Realistic ceiling](#realistic-ceiling)).

**Two operations have headroom that is gated on the object model** (items 1 and 2). The other four are Rust-bound, but they still have *compatible* headroom that earlier passes missed. Items 5–9 describe it:

- a fixed per-call cost of re-serialising driver rules, which the split below counts as boundary cost;
- the `SipHash` children index;
- no profile-guided optimisation;
- per-line allocation when rendering text.

`parse` also has the internal refactors in items 3 and 4.

### Where the time goes

Measured against a native Rust harness running the same logical operation with no interpreter involved:

| Operation | Python-visible | Rust core | Spent crossing into CPython |
|---|---:|---:|---:|
| `dump` | 0.941 ms | 0.106 ms | **89%** |
| `iteration` | 0.294 ms | 0.025 ms | **93%** |
| `parse` | 0.672 ms | 0.587 ms | 15% |
| `fast_load` | 0.604 ms | 0.553 ms | 13% |
| `remediation` | 0.392 ms | 0.297 ms | 27% |

!!! note
    These absolute timings predate the optimisation passes and are **not** current; the table is kept for its proportions, which still hold. Use the calibration table above for absolute figures.

The two expensive operations are almost entirely CPython-bound. No amount of Rust optimisation moves them — they are limited by how many Python objects must be allocated and how those objects are shaped, both fixed by the public API. Everything else is dominated by core work. Most of the *algorithmic* headroom there has been taken. The remaining costs are a fixed per-call rule sync (most of the 27% boundary share of `remediation`, see item 5), hashing, and compiler settings.

For calibration, `dump` is already **~2.2x faster than the fastest pure-Python equivalent** (2.103 ms building the same 3223 `DumpLine` objects in a tight Python loop). This is not Rust performance left on the table; it is the cost of the object model.

---

## 1. Change `DumpLine` from a pydantic model to a `__slots__` class

**Gain:** ~45% of `dump` — the largest absolute win available, and the **only** remaining lever on `dump`.
**Cost:** a major version. Breaks every consumer relying on pydantic behaviour.
**Status:** not taken in 4.0 because its decision gate (below) was never run. It now waits for 5.0.

`dump` builds 3223 `DumpLine` instances. The MRO is `['DumpLine', 'BaseModel', 'BaseModel', 'object']` with four real slot descriptors: `__dict__`, `__pydantic_fields_set__`, `__pydantic_extra__`, `__pydantic_private__`. Three of those exist only to satisfy pydantic's internals.

The binding already bypasses pydantic's `__init__` entirely — `object.__new__` followed by direct slot population (`crates/hier_config_py/src/root.rs`). **That is already the fast path**, and the floor was measured directly:

| Construction strategy (×3223) | Cost |
|---|---:|
| `object.__new__(DumpLine)` alone | 0.283 ms |
| `__new__` + dict + 4 × `setattr` (pure Python) | 2.103 ms |
| plain `dict` per row | 0.668 ms |
| **current Rust implementation** | **0.941 ms** |

At ~246 ns per line against a measured floor of ~250 ns for constructing objects of this shape at all, **there is no Rust-side headroom left in `dump`.** A plain `__slots__` class carrying `depth`, `text`, `tags`, `comments`, `new_in_config` needs one allocation and no `__dict__`, which is where the ~45% comes from. Changing the class is the only thing that can move this number.

### What it breaks

`DumpLine` is exported from `hier_config.models`, rendered in [the API reference](api-reference.md), and reachable as `Dump.lines[n]`. On the class itself:

- `.model_dump()`, `.model_dump_json()`, `.model_validate()`, `.model_validate_json()`, `.model_copy()`, `.model_json_schema()`, `.model_fields`, `.model_config`;
- `TypeAdapter(DumpLine)` and `TypeAdapter(Dump)`;
- using `Dump` or `DumpLine` as a field on another pydantic model — which includes FastAPI request/response bodies and `@validate_call` signatures;
- validation on construction: `DumpLine(depth="not an int", ...)` raises `ValidationError` today and would be accepted silently;
- the project-local `BaseModel` behaviours — `frozen=True` (assignment raises) and `extra="forbid"` (unknown kwargs raise).

It does **not** break attribute reads, `config.dump()`, or `get_hconfig_from_dump()`, and the wire shape of a dump is unchanged.

!!! tip "Run this decision gate before committing to the full break"
    A `__slots__` class implementing `__get_pydantic_core_schema__` keeps `TypeAdapter`, nested-model use, and FastAPI interop working while still shedding the four `BaseModel` slots — which is where the ~45% actually comes from. It does not restore the `.model_*` *methods*, so it is still a break, but a far narrower one.

    **Prototype and measure this first.** If it retains most of the gain it is strictly the better trade. This measurement has not been made, and not making it in time is why the item missed 4.0.

---

## 2. Expose a bulk/columnar accessor

**Gain:** workload-dependent; large for analytics-style consumers. Also closes the gap between `iteration`'s measured 0.037 units and the 0.026 that was projected for it.
**Cost:** none — purely additive, so it can ship in any release, including a patch.
**Status:** not taken; nothing is blocking it.

Reading one attribute from every node costs one Python-level call per node, and every traversal constructs one `HConfigChild` per node whether or not the caller reads anything from it. A method returning parallel lists (or a single list of tuples) for a whole subtree would amortise the boundary crossing across the entire tree instead of paying it per node per attribute — and would skip wrapper construction entirely.

This is the natural escape hatch for callers who currently write `[c.text for c in config.descendants()]`.

### Why this is what remains in `iteration`

Traversal used to cost a hash probe, a failed weakref upgrade, a `Py::new`, a `PyWeakrefReference` allocation, and a cache insert per node. Measured split when the cold cost was 0.335 ms — treat these as proportions, not current absolutes:

| Component | Cost | Status |
|---|---:|---|
| `Py::new` + weakref alloc + cache insert | 0.205 ms (~61%) | Weakref and cache removed; **`Py::new` remains** |
| generator wrapper | 0.041 ms (~12%) | Removed |
| `list(iter(objs))` floor | 0.010 ms | Irreducible |

What is left is the `Py::new` per node itself. That is only avoidable by not constructing a Python object per node at all — which is exactly this item.

---

## 3. Store node text without a per-node allocation

**Gain:** the largest remaining lever on `parse`. On the 50k-line IOS benchmark, building and freeing the tree is over 60% of the ~5.0 ms Rust core time.
**Cost:** internal only — no public API change. A sizeable refactor of `crates/hier_config_core/src/tree/`.
**Status:** not taken; unmeasured beyond the profile below.

Every parsed line becomes a node that owns an `Arc<str>` for its text, plus a children `Vec` and a text index once it has children. For the 48,431-line benchmark (42,423 nodes), a release-build profile of the Rust core splits roughly as:

| Phase | Time |
|---|---:|
| Inserting children (index lookup, allocation, `Vec` growth) | ~2.4 ms |
| Freeing the tree | ~0.78 ms |
| Per-line regex substitutions | ~0.8 ms |
| Line splitting, whitespace normalisation, trims | ~1.1 ms |

Storing all line text in one shared buffer (or an arena of string slices) and referencing it by offset would replace tens of thousands of small allocations and frees with a handful of large ones. The hard parts are that the children index keys on `Arc<str>` shared with the node, and that nodes are edited, copied and cloned after parsing, so mutation and `deepcopy` must keep working without the buffer growing unboundedly.

**Measure first:** prototype text storage alone in a native harness, and compare both parse and drop time before touching the index.

---

## 4. SIMD byte scans in the parser

**Gain:** small — an estimated 0.3–0.4 ms (~7%) of the 50k-line parse. Nothing outside the parser benefits.
**Cost:** a new Rust dependency, which needs discussion in an issue first.
**Status:** not taken. The scans already process eight bytes at a time in plain Rust (SWAR).

Only two parser passes scan long runs of bytes in a way that suits vector lanes:

| Pass | Current time (50k lines) | Estimated saving |
|---|---:|---:|
| `splitlines` (`find_line_boundary`) | ~0.5 ms | ~0.25 ms |
| Whitespace-normalisation check (`is_already_normalized`) | ~0.3 ms | ~0.15 ms |

Widening them from 8 bytes to 16–32 bytes per step is the whole opportunity. Indentation measurement and trims touch only a few bytes per line and would not benefit.

`hier_config_core` declares `#![forbid(unsafe_code)]`, which narrows the choice of library:

- **`fearless_simd`** fits best: a 1.0 release, no dependencies in the core crate, a safe API, and runtime selection of the best SIMD level. It keeps `forbid(unsafe_code)` intact.
- **`pulp`** and **`rten-simd`** are comparable alternatives with runtime detection.
- **`wide`** needs CPU features chosen at compile time, which is workable only for the baseline SSE2/NEON level.
- **`std::arch`** needs `unsafe` for vector loads and a separate path per architecture.
- **`std::simd`** requires a nightly compiler unless it has since been stabilised; the project builds on stable Rust.

Item 3 is worth several times more and should be done first. If this item is attempted, prototype both scans on a throwaway branch and confirm the saving before opening the dependency discussion.

---

!!! note "How items 5–9 were measured"
    Items 5–9 were measured on an Apple M2 Max with CPython 3.14 and a `maturin develop --release` build. The workloads were the gate's generated 400-interface Cisco IOS config (3,630 lines; the intended side has 50 changed descriptions) and a 5,000-interface config (40,430 lines, labelled *50k*). Each figure is the best of 15 batches. Per-function shares come from macOS `sample` profiles of the same loops. The absolute timings come from a separate run from the calibration table above, so compare percentages, not milliseconds.

## 5. Compile driver rules once per driver

**Gain:** ~28% of `remediation` and ~35% of `deepcopy` on the gate config, ~10% of `parse`, and ~13% of an end-to-end `WorkflowRemediation`. On small configs the gain is most of the call, and it also improves multi-threaded throughput (see item 9).
**Cost:** internal only — no public API change. Touches `crates/hier_config_py/src/tree.rs`, the binding entry points that call `sync_rules`, and `Driver`/`Tree` in the core.
**Status:** not taken.

The Rust tree cannot see the Python `driver.rules` object. `SharedTree::sync_rules` therefore copies the rules across by calling `model_dump_json()` and deserialising the result into `DriverRules`, then re-validates every regex. For the Cisco IOS driver this costs about 28 µs per sync. About 20 µs of that is `model_dump_json` alone, for a 4.7 KB document.

That cost is paid far more often than the rules change:

| Call | Full syncs per call | Fixed cost, IOS driver | Same call, Generic driver |
|---|---:|---:|---:|
| `config_to_get_to` on two one-line configs | 3 (source, target, result tree) | 95 µs | 9 µs |
| `deep_copy()` of a one-line config | 1 | 31 µs | 3 µs |
| `get_hconfig()` of a one-line config | 1 | 45 µs | 8 µs |
| `WorkflowRemediation.from_strings(...).remediation_config` | 5 | ~140 µs | — |

On the 3,630-line gate config, `config_to_get_to` takes 0.30 ms, so the ~85 µs of rule syncs is ~28% of it. For a fleet of small or mostly compliant devices, rule syncing, not remediation, is the main cost. The profile agrees: `serde_json` deserialisation and CPython attribute access make up ~10% of samples in a remediation loop.

Two things force the repeated syncs:

- **Rules are mutated in place.** `driver.rules.negate_with.append(...)` is documented in the [migration guide](../user/rust-core-changes.md#migrating-removed-hooks). `sync_rules_if_stale` compares only the identity of the `rules` object, so it cannot detect that mutation. `config_to_get_to`, `future`, `deep_copy` and `WorkflowRemediation` therefore call the unconditional `sync_rules` every time.
- **Every tree owns its own `DriverRules`.** `Driver.rules` is stored by value. `Tree::clone` (behind `deep_copy`) and every tree that remediation produces deep-copy the whole rule set, and each new `SharedTree` starts with no sync record, so it deserialises again.

### Proposal

1. **Replace the identity check with a cheap structural fingerprint.** Every rule model (`MatchRule`, `NegationRule`, and the rest) is frozen and holds only tuples and scalars. So the only mutable part of a driver is the set of top-level `list` fields on `HConfigDriverRules`, plus the `negation_prefix` and `declaration_prefix` properties.

    The fingerprint holds the `rules` object, each list field, and each list element as strong references, together with the two prefix strings. Holding the objects is what makes the identity comparisons sound; see the existing `synced_rules` comment. Comparing a fingerprint takes about 17 `getattr` calls and a pointer comparison per rule. That is a few microseconds, against ~28 µs for a sync. It catches `append`, `insert`, `remove`, item assignment, `extend` and reassignment. It also fixes the current inconsistency where an in-place change is picked up by `remediation` but not by `lines()` or `dump_simple()`.
2. **Share the compiled rules through an `Arc`.** Change `Driver.rules` to `Arc<DriverRules>`, or add a separate compiled form. Cache it per driver object, keyed by the fingerprint, so that every tree built from the same driver shares one allocation. `Tree::clone` then becomes a reference-count increment for the rules. A tree produced by remediation inherits the `Arc` and needs no sync.
3. **Resolve the regexes when compiling.** `MatchRule::is_match` looks each pattern up in the process-wide regex cache on every evaluation. Each lookup takes an `RwLock` read and hashes the pattern with `SipHash`. `validate_regexes` already compiles every pattern once, so keep the compiled `MatchRegex` next to the rule. Rule evaluation then does no locking or hashing. Under many threads, this also removes reader-count cache-line traffic on a global lock. `PreparedSubs` in the parser already does this for `per_line_sub`; the same approach applies to lineage rules.

**Architectural constraints.** `post_load_callbacks` and `remediation_transform_callbacks` are Python callables, and they stay outside the compiled form, as they are today. The `MagicMock` driver fallback in `sync_rules` has to keep working. Mutating a rule list *during* a call remains undefined, as it is now. Keep the existing tests for rules that change after a parse, and add one for an in-place `append` followed by `lines()`.

**Measure first:** count syncs per public call before and after the change. The fixed-cost table above can be reproduced with a one-line config on `Platform.CISCO_IOS` and `Platform.GENERIC`.

---

## 6. Replace `SipHash` in the children index with a seeded fast hasher

**Gain:** up to ~12% of `parse` (and of the 50k-line parse), ~13% of `remediation`, and ~12% of end-to-end workflow time. These are upper bounds, measured with the unseeded `FxHashMap`.
**Cost:** a new Rust dependency (`foldhash`), which needs discussion in an issue first. No public API change.
**Status:** not taken.

`Children` keeps its text index as a linear list up to eight entries (`LINEAR_INDEX_MAX`). Above that it promotes to a `std::collections::HashMap` with the default `RandomState` (SipHash-1-3). Keys are attacker-controlled config lines, so a fixed hasher such as `FxHash` would allow hash flooding. The linear tier and the seeded hash were both chosen deliberately.

Even so, `SipHash` is the single hottest non-algorithmic function in both profiles. `Sip13Rounds::write`, together with `hash_one` and the rehash during index growth, accounts for **~12%** of samples in a remediation loop and **~11%** in a parse loop.

Switching the `Mapping` alias to `rustc_hash::FxHashMap` as a throwaway experiment measured:

| Operation | `SipHash` | `FxHash` (upper bound) | Change |
|---|---:|---:|---:|
| `parse` (3,630 lines) | 0.377 ms | 0.331 ms | −12% |
| `parse` (40,430 lines) | 3.79 ms | 3.35 ms | −11% |
| `remediation` | 0.302 ms | 0.262 ms | −13% |
| `WorkflowRemediation` end to end | 1.04 ms | 0.915 ms | −12% |

`FxHash` itself is ruled out because it is unseeded. **`foldhash`** is the replacement to evaluate. It is seeded per process (and per map), has no dependencies, is what `hashbrown` uses by default, and is documented as "minimally DoS-resistant", which is the property the index needs. Keep the linear tier. It avoids hashing entirely for the common case of a parent with a few children, and bounding it keeps the flood resistance.

**Follow-on, larger:** store each node's text hash on the node when it is inserted, and probe with it through `hashbrown::HashTable`. Cross-tree lookups in remediation and `future()` would then use the stored hash instead of rehashing the running-side text. This is only worth doing if item 3 (shared text storage) is already changing the node layout.

**Measure first:** repeat the experiment with `foldhash` in place of Fx. Adopt it only if it keeps most of the gain above, and add a crafted-collision test to the property suite.

---

## 7. Profile-guided optimisation for release wheels

**Gain:** 11–15% across every Rust-bound operation (table below). Nothing changes at runtime except the machine code.
**Cost:** build pipeline only — a second compile and a training run per wheel target in `deploy-pypi.yml`. No source or API change.
**Status:** not taken. `lto = "fat"`, `codegen-units = 1` and `mimalloc` are already enabled.

A local experiment built the extension with `RUSTFLAGS=-Cprofile-generate`. It trained on the `testdata/cases` corpus (30 passes over each case: parse, remediation, rollback, `future()`, `dump()`, `deep_copy()`, render). It then merged the profiles with `llvm-profdata` and rebuilt with `-Cprofile-use`. The timing workloads are *not* in the training set:

| Operation | Baseline | PGO | Change |
|---|---:|---:|---:|
| `parse` (3,630 lines) | 0.377 ms | 0.326 ms | −13% |
| `parse` (40,430 lines) | 3.79 ms | 3.28 ms | −14% |
| `remediation` | 0.302 ms | 0.256 ms | −15% |
| render (`str(config)`) | 0.290 ms | 0.258 ms | −11% |
| `deep_copy()` | 0.077 ms | 0.066 ms | −13% |
| `WorkflowRemediation` end to end | 1.04 ms | 0.898 ms | −14% |

**Architectural constraints.**

- **Training must run on the target machine.** That is easy for the native `x86_64` and `arm64` runners, but the Linux `aarch64` wheels are cross-compiled. Build those targets on native runners, or ship them without PGO. A wheel without PGO is only slower, never wrong.
- **Keep training deterministic.** Use only the committed corpus, so a release cannot be optimised for a stale workload. Note that the corpus covers every platform, but its configs are small.
- **Mismatched profiles fail quietly.** `rustc` warns rather than fails when a profile no longer matches the source. A release build should therefore always generate its profiles from the same commit.
- **Consider `cargo-pgo`** or `maturin-action`'s `before-script-linux`. Either keeps the workflow readable.

Treat PGO as a multiplier on the other items, not a substitute for them. Do it last, so the profiles train the final code.

---

## 8. Render configuration text into one buffer

**Gain:** unmeasured. The profile suggests that up to about half of render time is avoidable. Rendering a config costs about as much as parsing it: `str(config)` on the gate config takes 0.29 ms, against 0.38 ms to parse it. Rendering is not in the gate.
**Cost:** internal only — no public API change.
**Status:** not taken.

`HConfig.__str__` calls `Tree::lines`, which returns one `String` per line. Each line comes from `cisco_style_text`, which builds an indentation string with `" ".repeat(depth)`, walks the parent chain to compute that depth, calls `format!`, and allocates a separate comment string. `__str__` then joins the whole `Vec<String>`. For every section it also evaluates the `sectional_exiting` rules twice: once in `sectional_exit` and again in `sectional_exit_text_parent_level`. `rendered_text_by_tags` has the same per-line `format!`.

A profile of `str(config)` shows `memmove`, `fmt::write`, `format_inner`, `Formatter::pad`, `realloc` and `mi_free` as the leading frames, together over half the samples. Rule matching in `sectional_exit` and `MatchRule::is_match` is another ~17%. The "`indented_text` is quadratic" report does not hold: that method renders a single node, in O(depth). The real cost is this whole-tree rendering.

### Proposal

- Walk depth-first with the depth carried on the stack. Write every line straight into one `String`, pre-sized from the node count and total text length (the approach `rendered_text_by_tags` already starts with).
- Write indentation from a static run of spaces instead of `repeat`, and skip the comment path entirely for `TextStyle::WithoutComments`.
- Evaluate `sectional_exiting` once per node that has children, and return both the exit text and its parent-level flag from that one call. Item 5's pre-resolved regexes make each evaluation cheaper as well.
- Keep `lines()` and `to_lines()` returning one Python `str` per line, as their API requires. Only `__str__` and the whole-text entry points switch to the single buffer. They are what `WorkflowRemediation` consumers render.

**Measure first:** add a render case to the benchmark harness before changing the code, so that the gain, and any later regression, is recorded.

---

## 9. Release the GIL on the remaining core-bound entry points

**Gain:** multi-threaded throughput rather than single-call latency. This matters for fleet runs, such as a Nautobot Golden Config job over many devices.
**Cost:** internal only for the first part. The optional second part is additive API.
**Status:** partly done.

Parsing (`_load_native`, `_load_fast_native`, `_load_file_native`), `WorkflowRemediation.from_strings`, and the `remediation_config` and `rollback_config` computations already run inside `py.detach`. A `ThreadPoolExecutor` running `from_strings(...).remediation_config` on the gate config already scales:

| Threads | Throughput | Speed-up |
|---:|---:|---:|
| 1 | 825 / s | 1.0x |
| 2 | 1,546 / s | 1.9x |
| 4 | 2,613 / s | 3.2x |
| 8 | 2,813 / s | 3.4x |

The machine has 8 performance cores. By Amdahl's law, the plateau at 8 threads implies that about 19% of each job still runs with the GIL held. The known contributors:

- **Rule syncing** (item 5), which runs Python (`model_dump_json`) and holds the GIL for about 140 µs of the ~1.05 ms job.
- **Entry points that never release the GIL.** `HConfig.config_to_get_to`/`remediation`, `future`/`future_with_report`, `difference`, `deep_copy`, and text rendering (`__str__`, `lines`) do all their core work while holding it.
- **Python object construction** for the result `HConfig` and its driver. This part is irreducible.

### Proposal

1. **Wrap the core call of each entry point above in `py.detach`,** following the existing `remediation_config` pattern. Take the `Arc<SharedTree>` clones before detaching, and only touch Python objects after the closure returns. Where one tree is both the source and the delta (the aliasing case in `config_to_get_to`), keep the existing clone-before-lock handling. After item 5 there is less to do here, because rule syncs no longer sit in the middle of these calls.
2. **Optional: a text-in, text-out entry point**, for example `remediation_text(platform, running, intended) -> str`. It would parse, remediate and render in a single `detach` and create no Python objects at all. It can only honour built-in platform behaviour. Python `post_load_callbacks`, `remediation_transform_callbacks`, workflow plugins and custom drivers cannot run inside it. It must therefore reject a custom driver rather than silently ignore it, and its docs must say which contract it drops. Decide on it once step 1 and item 5 have landed. With those done, the gap between it and `from_strings` may be too small to justify a second API.

A native batch API that runs pairs in parallel with `rayon` is **not** proposed. Python threads already reach 3.4x, and the remaining serial share would be the same inside a batch call. The batch API would add a dependency and an API that only duplicates `ThreadPoolExecutor`.

---

## What is not worth attempting

- **More Rust-side work on `dump`.** It is at ~246 ns/line against a ~250 ns CPython floor. Item 1 or nothing.
- **More algorithmic work on `remediation`, `fast_load`, or `deepcopy`.** The work that remains for them is the fixed costs in items 5–8 (rule syncing, hashing, compiler settings, rendering), not the tree walk. Confirm against a native harness before assuming otherwise.
- **SIMD outside the parser's byte scans.** Remediation, `future()` and rollback are hash lookups over the tree, `dump` and iteration are bound by CPython object construction, and the regular expressions already use SIMD inside the `regex` crate. None of these have work shaped for vector lanes.
- **Dropping node interning wholesale** rather than the current conservative split. The extra gain over keeping single-node identity is small, and it breaks the one identity case the suite pins. See [Architecture](architecture.md#core-tree-model).
- **Removing `Dump` / `DumpLine` from the public surface.** Serialising a config is a legitimate documented use case; changing the class shape is justified, deleting the API is not.
- **`panic = "abort"`.** A panic already reaches Python as `PanicException`, which inherits from `BaseException`. That is a catchable error that leaves the interpreter running. `abort` would kill the whole process instead, taking a long-running worker down with it. The release profile in `Cargo.toml` documents this decision.
- **An immutable, lock-free `Arc<Tree>` or `frozen` tree classes.** Config trees are mutable by design (#224). Callbacks, plugins and the `add_child`/`delete` API all mutate them, so a read path without a lock would not be sound. An uncontended `RwLock` read costs a few nanoseconds next to the `Py::new` that dominates iteration (item 2). `frozen` would save only a borrow-flag check per call, and marking a class `frozen` in PyO3 requires its whole `extends` chain to be frozen as well.
- **Interning line text into `u32` symbols.** Remediation compares nodes *across* trees, so the interner would have to be process-wide. That means a lock or sharded map on every insert, and growth that never shrinks in a long-running worker. Every line still has to be hashed once to intern it, and item 6 obtains most of the lookup saving without shared state. Revisit this only as part of item 3's storage redesign.
- **Merkle subtree hashes to skip compliant sections.** Hashing every subtree costs about as much as the single hashed lookup per child that remediation already does, so a one-off remediation breaks even at best. Keeping the hashes up to date as the mutable tree changes would add cost to every edit. The idea only pays off when one tree is compared with many others, and no current API has that shape.
- **One `RegexSet` or Aho-Corasick pass for all rules.** `per_line_sub` already goes through a `RegexSet` prefilter (`PreparedSubs`). The lineage-rule lists are short: the IOS driver has 8 idempotency, 5 ordering and 3 sectional-exit rules, and most are `startswith` checks that cost nanoseconds. Pre-resolving the regexes (item 5, step 3) removes the real overhead, which is the cache lookup, not the matching.
- **Free-threaded CPython builds.** Wheels are built for `abi3-py311`, and the stable ABI does not cover free-threaded interpreters, so this would need a separate wheel matrix. It would also require auditing the Python driver layer. After item 9 the GIL is held for little beyond object construction, so the gain does not justify that yet.
- **Zero-copy `&str` spans into the source text.** A mutable tree outlives its source string, and nodes are added, edited and copied after parsing, so a borrowed span cannot represent node text. The owned-buffer version is item 3.

### Already in place

Several of these suggestions come up repeatedly, so this list records that they are already done:

- `lto = "fat"`, `codegen-units = 1` and `opt-level = 3` (workspace `Cargo.toml`), plus `mimalloc` as the global allocator (`crates/hier_config_py`).
- PyO3 0.27, not 0.24.
- Linear child lookup for up to eight children (`LINEAR_INDEX_MAX`), with a seeded `SipHash` map above that.
- A bounded regex cache: at most 512 entries per engine (`regex_cache.rs`).
- `HConfig` objects are freed. `SharedTree.root_handle` is a weak reference, so no reference cycle survives outside CPython's view. A `weakref` to a dropped `HConfig` is cleared after `gc.collect()`.
- Parsing and workflow remediation already release the GIL (item 9).
- Rule sync is skipped when the `rules` object is unchanged on the hot read paths (`sync_rules_if_stale`). Item 5 extends that check to cover in-place mutation.

---

## Rules for anyone acting on this

1. **Measure before and after, in release mode.** A debug extension is roughly an order of magnitude slower and will mislead you. Always `maturin develop --release` first.
2. **Confirm the build actually succeeded** before trusting numbers. A failed `maturin develop` leaves the *previous* extension installed and produces convincing, wrong results.
3. **Separate Rust cost from boundary cost** before optimising. A native Rust harness exercising the same core operation tells you immediately whether the interpreter or the algorithm is the constraint — both items above only became obvious once that split was measured.
4. **Profile the Python glue too, not just the core.** The largest single win in the pre-4.0 pass (50x on driver construction) was a `model_copy(deep=True)` in `hier_config/platforms/driver_base.py`, found only after the Rust core had already been optimised twice. A native core makes it easy to stop looking at Python.
5. **Re-baseline the gate.** `MAX_COST_UNITS` in `tests/benchmarks/test_perf_regression.py` is set at ~1.5x observed cost. Tighten it after a win so the gain cannot silently regress; see [Testing Conventions](testing.md#benchmarks).
6. **Delete temporary harnesses.** Profiling examples under `crates/hier_config_core/examples/` are build-time cost for every contributor; remove them once the numbers are recorded here.
7. **Check whether an "API break" has actually shipped** before pricing it in. An unreleased interface costs nothing to change, and treating it as expensive has already caused one item to be deferred for no reason.

## Realistic ceiling

Taking items 1 and 2 would land `iteration` at ~0.026 units and `dump` at ~0.15. Items 3 and 4 only move `parse`: together they are unlikely to take more than 1–1.5 ms off the 50k-line benchmark's ~5.0 ms core time.

Items 5–8 are internal and compatible with each other. Their measured gains overlap: PGO speeds up code that items 5 and 6 would delete, and removing rule syncs makes hashing a larger share of what remains. **Estimate**, not a measurement: taken together, they are likely to take 25–40% off `remediation` and `deepcopy`, 20–30% off `parse`, and a similar share off end-to-end workflow time. Measure after each item rather than assuming the sum. Item 9 does not change single-call latency, but it should move 8-thread throughput beyond the current 3.4x.

A blanket "2x across the board" is **not** achievable while the current API holds — that is a measured result, not a prediction. The work already done cleared 1.35–1.86x on the Rust-bound operations and 2.6x on `iteration`, and moved `dump` almost not at all. The large remaining gains are concentrated in exactly two operations, and both are paid for in compatibility or in new API surface. The other operations have smaller headroom that needs no API change (items 3–8).
