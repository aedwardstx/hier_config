# Performance Roadmap: API Changes That Unlock Further Gains

The Rust rewrite retains the main tree/driver/workflow API but includes explicit
[migration breaks](../user/rust-core-changes.md). The measurements below describe
the profiled release build, not a proof that every future optimization requires
an API break. Some measured hot paths are dominated by CPython object construction.

This document records what is *left* to do. It lists the remaining optimisation opportunities, what each would cost to unlock, and the measurements that justify them. Items 1–2 are bounded by the Python object model; items 3–11 are Rust-side leads from profiling. Work that has already shipped is not tracked here — see `CHANGELOG.md` for history, [Performance & Benchmarks](benchmarks.md) for the 3.x to 4.0 benchmark story, [Architecture](architecture.md#core-tree-model) for the data-layout decisions and invariants that came out of it, and the [3.x → 4.0 migration guide](../user/rust-core-changes.md) for consumer-facing consequences.

---

## Current baseline

Reference figures on an Apple M2 Max, release build (`maturin develop --release`), against the generated 400-interface Cisco IOS config used by the gate. Costs are in **calibration units**, which self-normalise across machines (1 unit ≈ 3.0 ms on this machine).

| Operation | Cost (units) | Wall clock | Gate ceiling | Remaining headroom |
|---|---:|---:|---:|---|
| `deepcopy` | 0.015 | 0.05 ms | 0.03 | Little — mostly index clones and drops |
| `iteration` | 0.049 | 0.15 ms | 0.06 | ~0.011 units, via [item 2](#2-expose-a-bulkcolumnar-accessor) |
| `remediation` | 0.124 | 0.38 ms | 0.19 | Small on this workload; see below |
| `fast_load` | 0.203 | 0.62 ms | 0.24 | Rust-bound; see below |
| `parse` | 0.162 | 0.49 ms | 0.24 | Rust-bound; see below |
| `dump` | 0.308 | 0.94 ms | 0.45 | ~45%, via [item 1](#1-change-dumpline-from-a-pydantic-model-to-a-__slots__-class) |

Re-derive these with `pytest -m benchmark tests/benchmarks/test_perf_regression.py -v -s` rather than trusting any number written down here.

**The two CPython-bound operations are gated on the object model.** `parse`, `fast_load`, `deepcopy`, and `remediation` are Rust-bound. An earlier version of this page said their headroom had been collected. [Pass 6](benchmarks.md#pass-6-rust-hot-path-profiling-against-the-comparison-workloads) then cut parse time by 31–38% and remediation time on wide sections by 75–88% without any API change, so treat "Rust-bound" as "needs a profile", not "finished". The Rust-side leads that profiling still shows are listed under [Rust-side opportunities](#rust-side-opportunities).

### Why the rest is finished

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

The two expensive operations are almost entirely CPython-bound. No amount of Rust optimisation moves them — they are limited by how many Python objects must be allocated and how those objects are shaped, both fixed by the public API. Everything else is dominated by core work, where the headroom has already been taken.

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

## Rust-side opportunities

These come from `sample` profiles of the release extension and from the Criterion suite in `crates/hier_config_core/benches/workflows.rs` (see [Native Benchmarks with Criterion](benchmarks.md#native-benchmarks-with-criterion)). None changes the public API. They are leads, not validated gains: re-profile on the current tree, prototype, and keep a change only if a saved Criterion baseline shows a gain worth its complexity.

Current native figures (Apple M2 Max, Criterion median):

| Workload | Native time | Main remaining cost |
|---|---:|---|
| `parse/ios_10k` | 1.46 ms | Parser loop, `SipHash`, substitutions, whitespace trims |
| `parse/xr_10k` | 2.76 ms | Rule regex matching (`MatchRegex::is_match`, `fancy_regex`) |
| `remediation/50k` | 5.47 ms | Child-index hashing, `Children::rebuild_mapping` |
| `future_1000_interfaces` | 0.83 ms | `SipHash`, tag `BTreeSet<String>` churn, shallow copies |
| `deepcopy_10k` | 0.15 ms | Per-node index clones and drops |
| `merge_10k` | 0.93 ms | Per-node copy and index insert |

### 3. Use a faster seeded hasher for child indexes

**Evidence:** `SipHash` (`Sip13Rounds::write`) is among the top two leaf frames in IOS parse, 50k remediation and future, and `hashbrown` entry lookup is the top frame in remediation.
**Cost:** a new hashing crate (for example `foldhash`) is a new dependency of the shipped extension, so it needs an issue first. The hasher must stay randomly seeded per process so wide sections keep their hash-flooding resistance.
**Note:** the small-section vector index already skips hashing for sections of up to eight children; this item is about wide sections.

### 4. Cache rule-match results per lineage

**Evidence:** in IOS-XR parsing, `MatchRegex::is_match` is the top leaf frame by a wide margin, followed by `fancy_regex` state saves. Sectional-exit and indent rules are re-evaluated for many lines whose lineage shape repeats.
**Approach:** compile each driver's rules once into a shared, immutable matcher (keyed by driver rules identity and invalidated on mutation), and memoise per-parent decisions where a rule depends only on the parent lineage.
**Constraint:** `HConfigDriverRules` lists are mutable by design (#286). Any cache must observe mutations, or be rebuilt per operation as today.

### 5. Skip per-line substitutions that cannot match

**Evidence:** `PreparedSubs::apply` and `Regex::replacen` are both visible leaf frames in IOS parsing, alongside `trim_start_matches`/`trim_matches`.
**Approach:** test all substitution patterns with one `RegexSet` (or a literal prefilter) per line and only run `replacen` for the patterns that hit; fold leading and trailing whitespace trimming into the line-boundary scan the parser already performs.

### 6. Maintain child indexes incrementally on delete

**Evidence:** `Children::rebuild_mapping` is the top hier_config frame in 50k remediation after hashing.
**Approach:** update the index in place (swap-remove with position fix-up, or tombstones compacted lazily) instead of rebuilding after deletions. Child order and `Children` equality must be preserved.

### 7. Intern tags

**Evidence:** in future projection, dropping `BTreeSet<String>` tag sets and `Tree::tags` are prominent leaf frames.
**Approach:** intern tag strings per tree and store small sorted id sets or bitsets on nodes; materialise strings only at the Python boundary.

### 8. Cheaper tree clone and drop

**Evidence:** `deepcopy` time is split between `Tree::clone`/`Children::clone` and dropping per-node `HashMap` boxes and `NodeExtras`.
**Approach:** rebuild large-section indexes lazily on first lookup after a clone, or share immutable text and extras behind reference counts with copy-on-write. Only matters for workloads that clone in a loop; absolute cost is already small.

### 9. Profile-guided optimisation for release wheels

**Approach:** build wheels with PGO trained on the Criterion workloads (`cargo pgo` or manual `-Cprofile-generate`/`-Cprofile-use`). Gains are typically single to low double digits for branchy parsers.
**Cost:** CI complexity and longer release builds; measure with the Criterion suite against a non-PGO build before adopting.

### 10. Release the GIL for long native operations

**Approach:** wrap parse, remediation and diff in `Python::allow_threads` where the native work does not touch Python objects. This does not cut single-call latency; it lets multi-threaded callers run devices in parallel.
**Constraint:** operations that invoke Python callbacks or custom rule hooks must re-acquire the GIL, and handles must not be borrowed across the release.

### 11. Batch `Instance` construction in Python `merge`

**Evidence:** after the native cross-tree copy, about 8 ms of the ~18 ms Python `merge` of a 10k-line config is pydantic `Instance` construction, one per copied node (`_PyObject_Malloc`/`_Free` and GC dominate the profile). `model_construct` was measured and was slower.
**Approach:** share one `Instance` per merge where the per-node fields are identical, or store instances natively and materialise them lazily. Either changes object identity of `Instance` values, so check the public contract first; this sits with items 1–2 as an object-model question.

---

## What is not worth attempting

- **More Rust-side work on `dump`.** It is at ~246 ns/line against a ~250 ns CPython floor. Item 1 or nothing.
- **Rust-side work on `iteration` or `all_children_sorted`.** Pass 6 profiles show that both are dominated by CPython allocation, like `dump`.
- **Dropping node interning wholesale** rather than the current conservative split. The extra gain over keeping single-node identity is small, and it breaks the one identity case the suite pins. See [Architecture](architecture.md#core-tree-model).
- **Removing `Dump` / `DumpLine` from the public surface.** Serialising a config is a legitimate documented use case; changing the class shape is justified, deleting the API is not.

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

Taking items 1 and 2 would land `iteration` at ~0.026 units and `dump` at ~0.15. Neither affects the Rust-bound operations.

`dump`, `iteration` and `all_children_sorted` are bounded by CPython object construction while the current API holds; Rust-side work does not move them. The remaining gains there are paid for in compatibility or in new API surface. The Rust-bound operations still have the leads above, and their size is unknown until each is prototyped and measured.
