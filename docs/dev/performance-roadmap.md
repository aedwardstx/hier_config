# Performance Roadmap: API Changes That Unlock Further Gains

The Rust rewrite retains the main tree/driver/workflow API but includes explicit
[migration breaks](../user/rust-core-changes.md). The measurements below describe
the profiled release build, not a proof that every future optimization requires
an API break. Some measured hot paths are dominated by CPython object construction.

This document records what is *left* to do. It lists the remaining optimisations, what each would cost to unlock, and the measurements that justify them, followed by the ideas that were measured and rejected ([What is not worth attempting](#what-is-not-worth-attempting)). Completed work is not tracked here — see `CHANGELOG.md` for history, [Performance & Benchmarks](benchmarks.md) for the 3.x to 4.0 benchmark story, [Architecture](architecture.md#core-tree-model) for the data-layout decisions and invariants that came out of it, and the [3.x → 4.0 migration guide](../user/rust-core-changes.md) for consumer-facing consequences.

---

## Current baseline

Reference figures on an Apple M2 Max, release build (`maturin develop --release`), against the generated 400-interface Cisco IOS config used by the gate. Costs are in **calibration units**, which self-normalise across machines (1 unit ≈ 3.07–3.23 ms on this machine, CPython 3.14.4). The figures below are the range over two runs of the current code; the same runs fill the ceilings table in [Performance & Benchmarks](benchmarks.md#enforced-ci-ceilings).

| Operation | Cost (units) | Wall clock | Gate ceiling | Remaining headroom |
|---|---:|---:|---:|---|
| `deepcopy` | 0.0145–0.0148 | 0.05 ms | 0.03 | ~35%, via [item 5](#5-compile-driver-rules-once-per-driver); ~13% via [item 7](#7-profile-guided-optimisation-for-release-wheels); [item 12](#12-cheaper-deepcopy-clones) |
| `iteration` | 0.036–0.037 | 0.11–0.12 ms | 0.06 | ~0.011 units, via [item 2](#2-expose-a-bulkcolumnar-accessor) |
| `remediation` | 0.065–0.067 | 0.20–0.21 ms | 0.19 | item 5; [item 6](#6-replace-siphash-in-the-children-index-with-a-seeded-fast-hasher); item 7 |
| `parse` | 0.078 | 0.25 ms | 0.24 | item 5; items 6 and 7; see also [items 3](#3-store-node-text-without-a-per-node-allocation) and [4](#4-simd-byte-scans-in-the-parser) |
| `fast_load` | 0.081–0.082 | 0.25 ms | 0.24 | items 5–7; see also items 3 and 4 |
| `dump` | 0.292–0.302 | 0.93–0.94 ms | 0.45 | ~45%, via [item 1](#1-change-dumpline-from-a-pydantic-model-to-a-__slots__-class) |

Re-derive these with `pytest -m benchmark tests/benchmarks/test_perf_regression.py -v -s` rather than trusting any number written down here. The headroom percentages for items 5–7 are separate, older measurements against a slower build, so read them as proportions. They overlap, so do not add them together (see [Realistic ceiling](#realistic-ceiling)). The gate ceilings have not been tightened to these figures, because no Linux CI measurements are available to calibrate them against.

**Two operations have headroom that is gated on the object model** (items 1 and 2). The other four are Rust-bound, but they still have *compatible* headroom. Items 5–7 describe it:

- a fixed per-call cost of re-serialising driver rules, which the split below counts as boundary cost;
- the `SipHash` children index;
- no profile-guided optimisation.

`parse` also has the internal refactors in items 3 and 4.

### Where the time goes

Python calls on the 10k-line IOS benchmark config against corresponding native Criterion benchmarks (see [Performance & Benchmarks](benchmarks.md#profiling-the-python-ffi-split) for the method and operation differences). Subtraction estimates non-core overhead; it does not profile CPython:

| Operation | Python-visible | Rust core | Estimated non-core share |
|---|---:|---:|---:|
| `dump` | 3.81 ms | 0.14 ms | **96%** |
| `iteration` (`all_children_sorted`) | 0.30 ms | 0.03 ms | **89%** |
| `merge` (into an empty tree) | 3.78 ms | 0.57 ms | **85%** |
| `str` | 0.33 ms | 0.14 ms | 58% |
| `remediation` | 0.39 ms | 0.32 ms | 17% |
| `get_hconfig` (parse) | 0.57 ms | 0.50 ms | 12% |

`dump`, iteration and `merge` show large estimated non-core shares, consistent with substantial object-construction and binding costs. These differences alone do not establish how much runs inside CPython or rule synchronization, nor exclude further Rust improvements. `str` is not an exact-operation comparison: its binding renders sectional exits and joins a vector of line strings, whereas the native benchmark disables exits and returns that vector without joining. Its 58% remainder therefore cannot be assigned solely to Python string construction. Other remaining costs include rule synchronization (see item 5), hashing and compiler settings.

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

**Gain:** measured on a native prototype. Building `(depth, parent, text)` columns in Rust costs **~10 ns per node**, against ~350–480 ns per node for `dump()` and ~200 ns per node to walk `children` from Python. Returned as Python lists, the accessor is bound by `str` construction (~80 ns per node, the `dump_simple()` cost), so it is **~4–5x faster than `dump()`**. Returned as Arrow buffers to a columnar consumer, no Python object is built per cell: the gain is **~20x against walking `children` and 35–50x against `dump()`**. The same shape applied to a view (an interface table) is **~5x** as lists. It also makes extraction scale across threads, which it does not do today (see below). It also closes the gap between `iteration`'s measured 0.037 units and the 0.026 that was projected for it.
**Cost:** purely additive for the list form, so it can ship in any release, including a patch. The Arrow form needs a design decision first (see *Phase 2*).
**Status:** not taken; nothing is blocking the list form.

Reading one attribute from every node costs one Python-level call per node, and every traversal constructs one `HConfigChild` per node whether or not the caller reads anything from it. Consumers such as Nautobot, NetBox, pandas, Polars and DuckDB usually want a flat table across a fleet, for example one interface row per device with `name`, `description`, `ip`, `vlan` and `enabled`. Today they can only get it by building one Python object per node, or per row and attribute.

### Measured extraction paths

The generated Cisco IOS config used below has 400 interfaces (3,206 lines, 2,804 nodes) or 7,000 interfaces (56,006 lines, 49,004 nodes). Each interface has a description, an IPv4 address, an access VLAN and `no shutdown`. Figures are release builds on an Apple M2 Max:

| Path | 400 interfaces | 7,000 interfaces | Per unit |
|---|---:|---:|---:|
| View rows: `(name, description, ipv4_interface, enabled, native_vlan)` per `interface_views` entry | 1.31 ms | 23.7 ms | **3.3 µs / row** |
| `[(line.depth, line.text) for line in config.dump().lines]` | 0.97 ms | 23.5 ms | 350–480 ns / node |
| Walk `children` two levels, reading `.text` | 0.55 ms | 10.1 ms | ~200 ns / node |
| `dump_simple()` (one `str` per node, no other objects) | 0.215 ms | 3.97 ms | ~80 ns / node |
| *Native prototype:* the same five interface columns, Rust only | 0.232 ms | 3.79 ms | 0.54–0.58 µs / row |
| *Native prototype:* `(depth, parent, text)` buffers, Rust only | 0.026 ms | 0.467 ms | **9.5 ns / node** |
| *Python floor:* five pre-built columns of 400 / 7,000 items | 0.019 ms | 0.331 ms | ~48 ns / row |

Three conclusions follow:

- **Tree-shaped columns are almost free natively.** 9.5 ns per node is one string copy into a shared byte buffer plus two integer pushes. Everything above that in `dump()` and iteration is the Python object model.
- **View tables are bound by the attribute logic, not the boundary.** 0.54 µs per interface row natively is five independent child lookups through `MatchRule`, each allocating a `String` (the description) or parsing (the IPv4 address). A columnar entry point can walk each interface's children *once* and fill every requested column in that pass. That should cut the native share well below 0.54 µs per row, but it has not been measured.
- **Extraction does not scale across threads today.** Extracting `(name, description)` from 32 trees of 7,000 interfaces took 52.9 ms serially and 52.8 ms on an 8-thread `ThreadPoolExecutor`. It is entirely GIL-bound object construction. A columnar accessor gathers into Rust vectors inside `py.detach`, so only the final list conversion holds the GIL. With Arrow output, nothing does.

### Proposal

**Phase 1 — lists, no new dependency.**

- `HConfigBase.to_columns(fields=("depth", "text", "parent")) -> dict[str, list]`. Rows are in `all_children_sorted` order, the order `dump()` already uses. `parent` is the row index of the parent, or `-1` for a top-level line, so the tree can be rebuilt or joined without object identity. Optional fields: `tags`, `comments`, `new_in_config`, `order_weight`. Reject unknown field names, and do not build columns the caller did not ask for.
- `HConfigView.interface_table(columns=(...)) -> dict[str, list]`, restricted to the scalar interface properties the view already exposes (`name`, `description`, `enabled`, `ipv4_interface`, `native_vlan`, `vrf`, and so on). Validate that every requested column is supported by the platform's view capabilities before walking the tree.
- Gather inside `py.detach` into Rust `Vec`s, then convert to Python lists with the GIL held. Returning `dict[str, list]` feeds `pandas.DataFrame(...)` and `polars.DataFrame(...)` directly.

**Phase 2 — Arrow, zero Python objects per cell.** Return a small `ColumnBatch` object that implements the [Arrow PyCapsule Interface](https://arrow.apache.org/docs/format/CDataInterface/PyCapsuleInterface.html) (`__arrow_c_stream__` / `__arrow_c_array__`). Libraries that implement the interface (including recent pyarrow, Polars and DuckDB releases) can then import it without a copy, and hier_config gains no runtime dependency. Strings map to Arrow `utf8` (one offsets buffer plus one byte buffer, exactly the prototype layout above), and integers and booleans to primitive arrays. There are two ways to build it:

- a hand-written exporter for the few types needed (`utf8`, `int32`/`int64`, `bool`, validity bitmaps). It is small, but it is FFI and needs `unsafe`. That code must live in `hier_config_py`, because `hier_config_core` is `#![forbid(unsafe_code)]`.
- `arrow-array` (or `pyo3-arrow`), which is safe to use but a large compile-time dependency. A new Rust dependency needs an issue first.

Decide between them in an issue once Phase 1 has shipped and a consumer asks for Arrow.

**Parallelism.** Parallelise extraction across *trees*, with Python threads, which the GIL release in Phase 1 makes effective. Do not parallelise within one tree. Splitting one tree's interface rows with `rayon` measured 1.8x at 400 interfaces and 4.7x at 7,000. In a fleet run every core is already busy with other trees, so the per-tree split would only oversubscribe. A multi-tree batch entry point that concatenates tables is also unnecessary: Arrow consumers concatenate cheaply, and a `device` column can be added by the caller.

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

**Gain:** the largest remaining lever on `parse`, though smaller than before. Native `parse/ios_50k` is now about 2.5 ms. In a profile of it, inserting children (allocating each node, its `Arc<str>` text and its index) is the largest share, freeing the tree is about 9% and `SipHash` about 6% (item 6). Line splitting, normalisation and `per_line_sub` screening are now small: the scans are fused into one pass and most lines skip every substitution after a few byte-table lookups.
**Cost:** internal only — no public API change. A sizeable refactor of `crates/hier_config_core/src/tree/`.
**Status:** not taken. A narrower variant was measured and rejected: storing short text inline in the node (a small-string `Text` type) made the parse about 35% *slower*, because every comparison and hash had to branch on the representation and nodes grew. The hashed index also over-allocates: a parent with many children can reserve up to about 4x the entries it holds, trading memory for fewer rehashes.

Every parsed line becomes a node that owns an `Arc<str>` for its text, plus a children `Vec` and a text index once it has children. Atomic reference counts on that `Arc` show up in both clone and drop profiles.

Storing all line text in one shared buffer (or an arena of string slices) and referencing it by offset would replace tens of thousands of small allocations and frees with a handful of large ones. The hard parts are that the children index keys on `Arc<str>` shared with the node, and that nodes are edited, copied and cloned after parsing, so mutation and `deepcopy` must keep working without the buffer growing unboundedly.

**Measure first:** prototype text storage alone in a native harness, and compare both parse and drop time before touching the index.

---

## 4. SIMD byte scans in the parser

**Gain:** small, and smaller since the scans were fused — at most a few percent of the 50k-line parse. Nothing outside the parser benefits.
**Cost:** a new Rust dependency, which needs discussion in an issue first.
**Status:** not taken. The scans already process eight bytes at a time in plain Rust (SWAR).

Line splitting (`find_line_boundary`) and the whitespace-normalisation check now share one SWAR pass per line, so only that pass would widen. Padding the tail so the last bytes also take the eight-byte path was measured and did not help.

Widening it from 8 bytes to 16–32 bytes per step is the whole opportunity. Indentation measurement and trims touch only a few bytes per line and would not benefit.

`hier_config_core` declares `#![forbid(unsafe_code)]`, which narrows the choice of library:

- **`fearless_simd`** fits best: a 1.0 release, no dependencies in the core crate, a safe API, and runtime selection of the best SIMD level. It keeps `forbid(unsafe_code)` intact.
- **`pulp`** and **`rten-simd`** are comparable alternatives with runtime detection.
- **`wide`** needs CPU features chosen at compile time, which is workable only for the baseline SSE2/NEON level.
- **`std::arch`** needs `unsafe` for vector loads and a separate path per architecture.
- **`std::simd`** requires a nightly compiler unless it has since been stabilised; the project builds on stable Rust.

Item 3 is worth several times more and should be done first. If this item is attempted, prototype the scan on a throwaway branch and confirm the saving before opening the dependency discussion.

---

!!! note "How items 5–8 were measured"
    Items 5–8 were measured on an Apple M2 Max with CPython 3.14 and a `maturin develop --release` build. The workloads were the gate's generated 400-interface Cisco IOS config (3,630 lines; the intended side has 50 changed descriptions) and a 5,000-interface config (40,430 lines, labelled *50k*). Each figure is the best of 15 batches. Per-function shares come from macOS `sample` profiles of the same loops. The absolute timings come from a separate run from the calibration table above, so compare percentages, not milliseconds.

## 5. Compile driver rules once per driver

**Gain:** ~28% of `remediation` and ~35% of `deepcopy` on the gate config, ~10% of `parse`, and ~13% of an end-to-end `WorkflowRemediation`. On small configs the gain is most of the call, and it also improves multi-threaded throughput (see item 8).
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

**Gain:** about 6% of the current native 50k-line parse by profile; earlier upper bounds (below, against a slower build) were ~12% of `parse`, ~13% of `remediation`, and ~12% of end-to-end workflow time. These are upper bounds, measured with the unseeded `FxHashMap`.
**Cost:** a new Rust dependency (`foldhash`), which needs discussion in an issue first. No public API change.
**Status:** not taken. Index keys already carry their seeded hash, so table growth no longer rehashes, but every probe and every insert still hashes the text once with `SipHash`, and the `future()` flat-additions profile is still led by `SipHash` inserts into the large root index. The binding's node-id maps already use `FxHashMap`; that is safe there because the keys are internal arena ids.

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

**Follow-on, larger:** reuse the stored hash for cross-tree lookups in remediation and `future()`, instead of rehashing the running-side text. That needs both trees' indexes to share one hasher seed, or a hash stored on the node rather than in the index. This is only worth doing if item 3 (shared text storage) is already changing the node layout. Native `deepcopy_10k` once read about 3% (3 µs) slower after the hash was cached, within shared-machine variation. Measured against the branch base in alternating Criterion runs, it is about 12% faster overall (133 to 118 µs), so there is no net regression; still measure `deepcopy` with any further growth of the entry.

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

## 8. Release the GIL on the remaining core-bound entry points

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

### Measured ceiling: threads, processes and a native batch

To see how much of the plateau is the GIL, the same fleet job was run under each concurrency model. The job remediates a 400-interface running config (3,206 lines) against an intended config with ~10% of descriptions changed and ~4% of interfaces shut, 256 jobs per run, best of three, release build, Apple M2 Max (8 performance and 4 efficiency cores):

| Model | 1 worker | 8 workers | 12 workers |
|---|---:|---:|---:|
| Threads: `from_strings(...).remediation_text()` | 949 / s | 3,233 / s (3.4x) | 3,245 / s |
| Threads: two `get_hconfig()` calls, `WorkflowRemediation`, `str(remediation_config)` | 889 / s | 2,482 / s (2.8x) | 2,570 / s |
| `asyncio.to_thread`, text path, 8-thread default executor | 947 / s | 2,763 / s | — |
| `ProcessPoolExecutor`, text in and text out, `chunksize=8` | 1,076 / s | **7,496 / s (7.0x)** | — |
| Native Rust with `rayon`, same job, `mimalloc` (the ceiling) | 1,200 / s | **6,693 / s (5.6x)** | 7,339 / s |
| Native Rust with `rayon`, same job, system allocator | 968 / s | 4,034 / s (4.2x) | 4,917 / s |

What this shows:

- **The thread plateau is the GIL, not the core.** The same job scales to 5.6x on 8 threads natively, and to 7.0x across processes, which each have their own GIL. It is capped at 3.4x only inside one interpreter. A `cProfile` of the text path puts five `model_dump_json` calls per job at ~110 µs of the ~0.88 ms job, all with the GIL held (item 5). A GIL probe measured about 150 µs held per `from_strings` call. That is the serial share Amdahl's law predicts from the plateau.
- **The allocator matters as much as the lock.** With the system allocator the native ceiling drops from 5.6x to 4.2x. `mimalloc` is already the global allocator in `hier_config_py`; keep it.
- **The process-wide regex cache is not what caps scaling.** The native batch goes through the same `RwLock`-guarded cache and still reaches 5.6x. Item 5, step 3 still removes that lock from the hot path, but it will not by itself move the thread plateau.
- **Processes win today, by 2.3x.** Until step 1 and item 5 land, a `ProcessPoolExecutor` that ships *text* in and out is the fastest fleet model. That is a statement about the current GIL-held share, not a design goal; see item 9.

### Proposal

1. **Wrap the core call of each entry point above in `py.detach`,** following the existing `remediation_config` pattern. Take the `Arc<SharedTree>` clones before detaching, and only touch Python objects after the closure returns. Where one tree is both the source and the delta (the aliasing case in `config_to_get_to`), keep the existing clone-before-lock handling. After item 5 there is less to do here, because rule syncs no longer sit in the middle of these calls.
2. **Optional: a text-in, text-out entry point**, for example `remediation_text(platform, running, intended) -> str`. It would parse, remediate and render in a single `detach` and create no Python objects at all. It can only honour built-in platform behaviour. Python `post_load_callbacks`, `remediation_transform_callbacks`, workflow plugins and custom drivers cannot run inside it. It must therefore reject a custom driver rather than silently ignore it, and its docs must say which contract it drops. Decide on it once step 1 and item 5 have landed, using this gate: if 8 threads running `from_strings(...).remediation_text()` then reach at least 80% of the native ceiling above (about 5,400 jobs/s on the reference machine), do not add it.

A native batch API that runs pairs in parallel with `rayon`, such as `remediate_batch(pairs) -> list[str]`, is **not** proposed. The measurements above explain why. A batch call would reach the native ceiling only because it would skip the Python driver and its rule syncs, which is exactly what step 2 does, one pair at a time, under an ordinary `ThreadPoolExecutor`. The remaining differences all favour threads:

- **Throughput.** Equal once the GIL-held share is gone. Both run the same core code on the same cores.
- **Memory.** A batch call must hold every input and output string until the last pair finishes. A thread pool streams: `executor.map` or `as_completed` can write each result to disk or a database as it arrives.
- **Ergonomics.** A batch call reports errors per call, not per device, and cannot be cancelled, time-limited or given progress reporting pair by pair. It also brings a second thread pool into the process, which oversubscribes the cores when the caller already runs its own (Celery, Nornir, `asyncio`).
- **Contract.** It would have to reject custom drivers and callbacks exactly as step 2 does, while adding a `rayon` dependency.

---

## 9. Document the supported concurrency model

**Gain:** none in the library. For users, it prevents the slow patterns in the tables above: up to 2.3x of fleet throughput today, and more for callers who ship `HConfig` objects between processes.
**Cost:** documentation only.
**Status:** not taken.

No user-facing page says how to run hier_config across many devices. The only mention is the 3.x-to-4.0 story in [Performance & Benchmarks](benchmarks.md#real-world-operational-impact). Add a short "Concurrency" section to the user guide that records the following, with the measurements from item 8:

- **Threads are the default.** Use `concurrent.futures.ThreadPoolExecutor` and parse inside the worker, preferably with `WorkflowRemediation.from_strings(...)`, which parses both configs in one GIL release. The call releases the GIL for its core work. Say plainly that scaling is ~3.4x on 8 cores until items 5 and 8 land, and update the figure when they do.
- **`asyncio` applications use `asyncio.to_thread`** (or `loop.run_in_executor`). hier_config does no I/O, so a native `async def` API would only move the same thread hop inside the library. The hop costs ~36 µs per call, about 4% of a 0.9 ms job. Callers with very small configs should hand several devices to one `to_thread` call.
- **Processes are valid only with text across the boundary.** Send config text in and remediation text out. Never send `HConfig`, `HConfigChild` or `WorkflowRemediation`. They pickle through `dump()`: a 3,206-line `HConfig` takes 3.4 ms to pickle and 3.4 ms to unpickle, and is 342 KiB on the wire, against 0.32 ms to re-parse its 77 KiB of text. That is ~20x the cost of sending the text. Each worker process also costs ~44 MiB resident after importing hier_config and running jobs, against ~16 MiB for a bare interpreter.
- **Sharing trees between threads.** State what is guaranteed: each tree is guarded by one `RwLock` in `hier_config_py`, so concurrent reads of one tree are safe and a mutation serialises with them. Say that driver rules must not be mutated while another thread uses them, which matches item 5's existing constraint. Pin the read-sharing guarantee with a test under `tests/native/` before documenting it.
- **Do not add a second pool.** Celery and Nornir workers already run jobs concurrently. Size a thread pool to the cores the worker actually owns.

Keep the thread-pool claim in [Performance & Benchmarks](benchmarks.md#real-world-operational-impact) consistent with the same figures.

## 10. Memoise per-lineage rule decisions while parsing

**Gain:** unmeasured. In a profile of the 10k-line IOS-XR parse, `MatchRegex::is_match` was the top leaf frame by a wide margin even with the linear prefilter, followed by `fancy_regex` state saves.
**Cost:** internal only — no public API change.
**Status:** not taken.

Indent-adjust and sectional-exit rules are evaluated for every line, but many of them depend only on the parent lineage, which repeats across thousands of sibling sections. Caching the decision per (rule set, parent lineage shape) would skip most evaluations. Item 5's compiled rule form is the natural place to hold the cache; mutating a rule list must still invalidate it, as item 5 requires.

**Measure first:** count rule evaluations per parsed line on the XR benchmark, and how many distinct lineage shapes they cover.

---

## 11. Intern tags

**Gain:** unmeasured. In a profile of `future()` on the 1,000-interface benchmark, dropping `BTreeSet<String>` tag sets and `Tree::tags` were prominent leaf frames, alongside `SipHash`.
**Cost:** internal only — no public API change.
**Status:** not taken.

Intern tag strings once per tree and store each node's tags as a small sorted id set (or a bitset when a tree has few distinct tags). Convert to strings only at the Python boundary and in serialised output, so the wire form does not change.

---

## 12. Cheaper `deepcopy` clones

**Gain:** unmeasured. Native `deepcopy_10k` is about 0.12 ms, roughly 12 ns per node.
**Cost:** internal only. Tied to the node layout ([item 3](#3-store-node-text-without-a-per-node-allocation)).
**Status:** not taken.

`Tree::clone` is dominated by allocator calls and `Arc` reference-count increments for each node's text, child vector and index. Native clone timings differed by about 3% after caching each index key's hash, within the reported ~5% noise; against the branch base, `deepcopy_10k` is about 12% faster overall. No difference was visible from Python. Flattening children into the arena, or sharing immutable index tables copy-on-write, would cut the allocations. Both are layout changes that belong with item 3.

---

## What is not worth attempting

- **More Rust-side work on `dump`.** It is at ~246 ns/line against a ~250 ns CPython floor. Item 1 or nothing.
- **More algorithmic work on `remediation`, `fast_load`, or `deepcopy`.** The work that remains for them is the fixed costs in items 5–7 (rule syncing, hashing, compiler settings), not the tree walk. Confirm against a native harness before assuming otherwise.
- **SIMD outside the parser's byte scans.** Remediation, `future()` and rollback are hash lookups over the tree, `dump` and iteration are bound by CPython object construction, and the regular expressions already use SIMD inside the `regex` crate. None of these have work shaped for vector lanes.
- **Dropping node interning wholesale** rather than the current conservative split. The extra gain over keeping single-node identity is small, and it breaks the one identity case the suite pins. See [Architecture](architecture.md#core-tree-model).
- **Removing `Dump` / `DumpLine` from the public surface.** Serialising a config is a legitimate documented use case; changing the class shape is justified, deleting the API is not.
- **`panic = "abort"`.** A panic already reaches Python as `PanicException`, which inherits from `BaseException`. That is a catchable error that leaves the interpreter running. `abort` would kill the whole process instead, taking a long-running worker down with it. The release profile in `Cargo.toml` documents this decision.
- **An immutable, lock-free `Arc<Tree>` or `frozen` tree classes.** Config trees are mutable by design (#224). Callbacks, plugins and the `add_child`/`delete` API all mutate them, so a read path without a lock would not be sound. An uncontended `RwLock` read costs a few nanoseconds next to the `Py::new` that dominates iteration (item 2). `frozen` would save only a borrow-flag check per call, and marking a class `frozen` in PyO3 requires its whole `extends` chain to be frozen as well.
- **Interning line text into `u32` symbols.** Remediation compares nodes *across* trees, so the interner would have to be process-wide. That means a lock or sharded map on every insert, and growth that never shrinks in a long-running worker. Every line still has to be hashed once to intern it, and item 6 obtains most of the lookup saving without shared state. Revisit this only as part of item 3's storage redesign.
- **Merkle subtree hashes to skip compliant sections.** Hashing every subtree costs about as much as the single hashed lookup per child that remediation already does, so a one-off remediation breaks even at best. Keeping the hashes up to date as the mutable tree changes would add cost to every edit. The idea only pays off when one tree is compared with many others, and no current API has that shape.
- **One `RegexSet` or Aho-Corasick pass for all rules.** `per_line_sub` already goes through a `RegexSet` prefilter (`PreparedSubs`). The lineage-rule lists are short: the IOS driver has 8 idempotency, 5 ordering and 3 sectional-exit rules, and most are `startswith` checks that cost nanoseconds. Pre-resolving the regexes (item 5, step 3) removes the real overhead, which is the cache lookup, not the matching.
- **Free-threaded CPython builds.** Wheels are built for `abi3-py311`, and the stable ABI does not cover free-threaded interpreters, so this would need a separate wheel matrix. It would also require auditing the Python driver layer. After item 8 the GIL is held for little beyond object construction, so the gain does not justify that yet.
- **Zero-copy `&str` spans into the source text.** A mutable tree outlives its source string, and nodes are added, edited and copied after parsing, so a borrowed span cannot represent node text. The owned-buffer version is item 3.

- **Faster `lines()` / `to_lines()` from Python.** Rendering already walks the tree once into reused buffers; native `render/to_lines_10k` is about 0.14 ms. Python calls additionally create one `str` per line, which the API requires. `str(config)` returns one Python string, but first builds native line strings and joins them in the binding; it is not a single-buffer renderer. Profile the exact operation before ruling out further native work.
- **Lazily materialised `Instance` records in Python `merge()`.** Each copied node needs its own `instances` list; nodes with identical comments and tags already share one frozen `Instance`. Creating the lists on first access was considered and rejected: the binding's per-node Python lists are the authoritative store, read directly by instance syncing, `deepcopy` and pickling, so laziness would change when and whether they exist. What is left of `merge()` (~84% boundary share) is that per-node list, garbage-collector tracking and dictionary inserts.
- **Removing the remaining per-line C-API cost of `from_lines()` on a list or tuple.** Each line still costs an item access, a type check and `PyUnicode_AsUTF8AndSize`. Tuple items are already borrowed without a reference-count round trip, because a tuple cannot change while the GIL is released; list items keep a `PyBackedStr`, because another thread may mutate the list. On the 8,431-line benchmark config, `from_lines()` on a tuple measured 1.06–1.10x the time of `from_text()` on the joined text (median about 1.08x, shared machine), and a list costs more. In Criterion the Rust loader is no slower on pre-split lines (`parse/fast_load_ios_10k`) than on one string (`parse/fast_load_text_ios_10k`), so the gap is this boundary cost. Avoiding the rest needs direct access to the tuple's item array or the string data, which the stable ABI (`abi3`) does not offer. Callers that already hold the text should pass it as one `str`, which is split natively.
- **Pre-sizing a line copy buffer in `from_lines()`.** A separate length pass to size the buffer made the call slower (0.92 to 1.00 ms on the 10k config); borrowing each line with `PyBackedStr` removed the copy instead.

- **Parser micro-optimisations that were measured and reverted.** Each of these was neutral or slower on `parse/ios_10k` and `parse/ios_50k`, in paired runs of the Criterion suite:
    - dispatching `per_line_sub` rules on the first byte alone (the per-position byte tables already reject most lines in two or three lookups);
    - merging the plain-`^` and `^\s*` prefix tables into one;
    - padding the SWAR scan's tail so the last bytes also take the eight-byte path;
    - looking small children up through the arena instead of the parent's own linear index, or inlining the linear index into `Node`;
    - caching depth or indentation on `ParserCursor` (its fields are public, so the cache could go stale);
    - passing the already-measured indent through to `apply_indented` in the fast loader;
    - a single-lookup loop for walking up to the parent of a dedented line;
    - adding `#[inline]` hints to the hot parser and tree functions (the release profile already uses fat LTO);
    - an O(n) `LinearIndex::len()` to shrink the index, which slowed `get_at` and `unified_diff`.
- **Skipping the IOS sectional-exit walk after parsing.** Leaving the `exit` handling to later passes only moved the cost into dropping the tree; the walk now runs fused with the other IOS post-load fixes and only on configs that can contain a sectional exit.
- **A small-string inline `Text` type.** See item 3: about 35% slower.

- **Parallelism inside one tree, and a native `rayon` batch API.** See [Concurrency patterns that do not pay](#concurrency-patterns-that-do-not-pay) below and item 8.
- **Native `async def` bindings, and `pickle`-based multiprocessing of trees.** See the same section.

### Concurrency patterns that do not pay

These were measured with a throwaway Rust harness linked against `hier_config_core`, with `rayon` and the release profile, on the same generated IOS configs as item 2. The harness lived outside the repository and has been deleted.

**Parsing one config on several threads.** The prototype split the text at top-level boundaries into *k* chunks and parsed them with `rayon`:

| Lines | Serial parse | *k* = 4, chunks only | *k* = 4, then merged into one tree |
|---:|---:|---:|---:|
| 3,206 | 0.36 ms | 0.26 ms | 0.71 ms |
| 8,006 | 0.79 ms | 0.44 ms | 1.58 ms |
| 56,006 | 5.50 ms | 2.96 ms | 11.96 ms |

Even the unmerged chunks scale only ~1.9x at 4 threads, and 8 chunks are no faster than 4: parsing is bound by allocation and memory traffic, not arithmetic. Merging through `Tree::merge` deep-copies every node, and costs more than the whole serial parse. A usable version would need arena splicing with `NodeId` rebasing. It would also have to merge duplicate top-level sections that straddle a chunk boundary and run post-load callbacks over the whole tree afterwards. The split itself must also respect banners, multi-line blocks and platform preprocessors. The best case is ~2.5 ms saved on a 56k-line config, and nothing in a fleet run, where every core is already parsing another device. Rejected.

**Remediating one pair on several threads.** Remediating *k* = 4 pre-partitioned chunk pairs in parallel, without merging the results and ignoring every rule that crosses a chunk, measured:

| Lines | Serial | *k* = 4 (idealised) | Speed-up |
|---:|---:|---:|---:|
| 3,206 | 0.237 ms | 0.150 ms | 1.6x |
| 8,006 | 0.510 ms | 0.231 ms | 2.2x |
| 56,006 | 3.79 ms | 1.23 ms | 3.1x |

These are upper bounds. Top-level siblings interact: an idempotency rule lets `hostname NEW` replace `hostname OLD` without a negation, because `idempotent_for` compares a line against its siblings. Sectional overwrite and order weights also cross partitions. Only *matched top-level sections*, whose subtrees are independent, could safely run in parallel. Dispatch also costs something at this scale. A `rayon::join` issued from a thread outside the pool, which is what a Python thread calling into the extension would be, measured ~16 µs per call while the pool wakes up, against ~12 ns inside a warm pool. So work below ~50–100 µs loses outright. The crossover is therefore around 10–20k lines for single-device latency, and never for fleet throughput. Revisit only if a concrete single-device latency requirement appears (for example an interactive tool on 50k-line configs), and then as an opt-in that parallelises matched top-level sections only.

**Native `async def` bindings or async generators.** hier_config does no I/O; every operation is CPU-bound. An `async def` binding would still have to run the work on a thread to avoid blocking the event loop, which is what `asyncio.to_thread` already does. Measured: 2,763 jobs/s on an 8-thread default executor, with ~36 µs of overhead per call. Streaming results through an async generator does not help either: remediation is computed for the whole tree before any line of it is known to be final (ordering weights and sectional exits are applied at the end), and the output is small. Document `asyncio.to_thread` instead (item 9).

**Multiprocessing with trees as the payload, and shared memory.** In 3.x, the pure-Python engine held the GIL for all of its work, so processes were the only way to use more than one core. They remain valid in 4.0, and are currently faster than threads (item 8), but only with *text* as the payload. Pickling an `HConfig` goes through `dump()` and costs ~20x a re-parse (item 9). Shared memory does not remove that cost. The arena holds heap-allocated `String`s, child vectors and hash indexes, none of which is position-independent. Sharing a tree would mean a flat serialised form that the reader has to rebuild into an arena, which costs about as much as parsing the text. Text is already the compact, position-independent form. Putting the *input text* in `multiprocessing.shared_memory` would save one copy of ~77 KiB per job, which is noise against a 0.9 ms job. Rejected.

### Already in place

Several of these suggestions come up repeatedly, so this list records that they are already done:

- `lto = "fat"`, `codegen-units = 1` and `opt-level = 3` (workspace `Cargo.toml`), plus `mimalloc` as the global allocator (`crates/hier_config_py`).
- PyO3 0.27, not 0.24.
- Linear child lookup for up to eight children (`LINEAR_INDEX_MAX`), with a seeded `SipHash` map above that whose keys cache their hash.
- Remediation, rollback and `difference` create delta sections lazily; rendering and `dump()` walk the tree once; copies share node text.
- `from_lines()` borrows its input lines (tuple items directly, list items through `PyBackedStr`) and splits an exact `str` natively via `load_fast_text`, which splits, trims and inserts in one pass. String subclasses retain Python `splitlines()` dispatch. `from_text()` and `get_hconfig()` copy the input with `config_raw.to_owned()` in `_load_native` before releasing the GIL and calling `parse_into_tree`; they do not use `load_fast_text`.
- The parser scans each line once with eight-byte (SWAR) steps for the line boundary, indentation and whitespace normalisation, and screens `per_line_sub` rules through literal-prefix byte tables, so most lines run no regex at all. Rules a prefix fully describes (such as stripping `!` comment lines) substitute without a regex.
- The text loaders size the node arena from the input's byte length (about 25 bytes per line) rather than a line-counting pass, which measured 4–10% slower on the parse benchmarks. When the estimate overshoots by more than 2x, as with a few very long lines or a large banner, the unused slots are released once loading finishes.
- Parsed children are inserted with one index lookup, the hashed index is reserved ahead of growth, and the Cisco IOS post-load fixes run in one fused callback walk. Sectional-exit removal is a separate `delete_sectional_exit_recursive` pass over parents; it screens their last children against possible exit texts before resolving lineage rules, rather than skipping the pass globally.
- The Criterion suite installs `mimalloc` as its global allocator, matching the extension, so native and Python measurements see the same allocator.
- A bounded regex cache: at most 512 entries per engine (`regex_cache.rs`).
- `HConfig` objects are freed. `SharedTree.root_handle` is a weak reference, so no reference cycle survives outside CPython's view. A `weakref` to a dropped `HConfig` is cleared after `gc.collect()`.
- Parsing and workflow remediation already release the GIL (item 8).
- Rule sync is skipped when the `rules` object is unchanged on the hot read paths (`sync_rules_if_stale`). Item 5 extends that check to cover in-place mutation.

---

## Rules for anyone acting on this

1. **Measure before and after, in release mode.** A debug extension is roughly an order of magnitude slower and will mislead you. Always `maturin develop --release` first.
2. **Confirm the build actually succeeded** before trusting numbers. A failed `maturin develop` leaves the *previous* extension installed and produces convincing, wrong results.
3. **Separate Rust cost from boundary cost** before optimising. A native Rust harness exercising the same core operation tells you immediately whether the interpreter or the algorithm is the constraint — both items above only became obvious once that split was measured.
4. **Profile the Python glue too, not just the core.** The largest single win in the pre-4.0 pass (50x on driver construction) was a `model_copy(deep=True)` in `hier_config/platforms/driver_base.py`, found only after the Rust core had already been optimised twice. A native core makes it easy to stop looking at Python.
5. **Re-baseline the gate.** `MAX_COST_UNITS` in `tests/benchmarks/test_perf_regression.py` is set at ~1.5x observed cost. Tighten it after a win so the gain cannot silently regress; see [Testing Conventions](testing.md#benchmarks).
6. **Delete temporary harnesses.** Profiling examples under `crates/hier_config_core/examples/` are build-time cost for every contributor; remove them once the numbers are recorded here.
7. **Use the native benchmark suite for Rust changes.** `cargo bench -p hier_config_core --bench workflows -- --save-baseline before` on the old code, then `-- --baseline before` on the new, compares the Rust core without Python overhead; see [Native Benchmarks with Criterion](benchmarks.md#native-benchmarks-with-criterion). Confirm end-to-end Python gains separately.
8. **Check whether an "API break" has actually shipped** before pricing it in. An unreleased interface costs nothing to change, and treating it as expensive has already caused one item to be deferred for no reason.

## Realistic ceiling

Taking items 1 and 2 would land `iteration` at ~0.026 units and `dump` at ~0.15. Items 3 and 4 only move `parse`: together they are unlikely to take more than about a fifth off the 50k-line benchmark's ~2.5 ms core time, most of it from item 3.

Items 5–7 are internal and compatible with each other. Their measured gains overlap: PGO speeds up code that items 5 and 6 would delete, and removing rule syncs makes hashing a larger share of what remains. **Estimate**, not a measurement: taken together, they are likely to take 25–40% off `remediation` and `deepcopy`, 20–30% off `parse`, and a similar share off end-to-end workflow time. Measure after each item rather than assuming the sum. Item 8 does not change single-call latency, but together with item 5 it should move 8-thread throughput from the current 3.4x towards the 5.6x native ceiling measured for the same job. Item 2 is the one large gain available to extraction workloads: ~4–5x over `dump()` as lists, and far more as Arrow.

A blanket "2x across the board" is **not** achievable while the current API holds. Parsing, `deepcopy`, `dump()` and `all_children_sorted()` have resisted repeated profiling-led work, and the boundary split above shows why `dump()` and iteration cannot move without items 1 and 2. The large remaining gains are concentrated in exactly those two operations, and both are paid for in compatibility or in new API surface. The other operations have smaller headroom that needs no API change (items 3–7 and 10–12).
