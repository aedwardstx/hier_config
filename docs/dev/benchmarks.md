# Performance & Benchmarks: The 3.x to 4.0 Story

hier_config 4.0 introduces an arena-backed Rust core engine (`hier_config_core`)
exposed to Python through native PyO3 bindings. This replaced the 3.x
pure-Python tree implementation to eliminate the performance and scaling
bottlenecks that network automation pipelines encountered when processing
thousands of large configurations.

This document tells the 3.x to 4.0 performance improvement story: the
architectural bottlenecks of the pure-Python engine, the empirical benchmark
measurements across configuration sizes, the structural reality of the CPython
object allocation boundary, the iterative optimization passes that tuned the hot
paths, and the automated calibration-unit regression guardrails protecting these
gains in CI.

---

## Executive Summary

On a 10,000-line Cisco IOS configuration (8,823 nodes), hier_config 4.0 achieves
**5.4x to ~1,000x speedups** across core operations compared to the pure-Python
3.x baseline:

| Operation | 4.0 (Rust Core) | 3.x (Pure Python) | Speedup | Result Category |
|---|---:|---:|---:|---|
| **`copy.deepcopy()`** | **0.12 ms** | 128.63 ms | **~1,000x** | New tree / memory clone |
| **`str()`** | **0.33 ms** | 32.86 ms | **100x** | Single string |
| **`difference()`** | **0.19 ms** | 18.41 ms | **98x** | New difference tree |
| **`get_hconfig` (50k lines)** | **4.31 ms** | 357.91 ms | **83x** | Scalar / tree creation |
| **`get_hconfig` (10k lines)** | **0.90 ms** | 60.08 ms | **67x** | Scalar / tree creation |
| **`get_hconfig` (IOS-XR, 10k lines)** | **1.41 ms** | 85.68 ms | **61x** | Scalar / tree creation |
| **`get_hconfig` (1k lines)** | **0.15 ms** | 7.26 ms | **49x** | Scalar / tree creation |
| **`unified_diff()`** | **0.10 ms** | 4.94 ms | **48x** | Diff lines |
| **`config_to_get_to` (50k lines)** | **1.53 ms** | 56.84 ms | **37x** | New remediation tree |
| **`config_to_get_to` (remediation)** | **0.39 ms** | 12.22 ms | **31x** | New remediation tree |
| **`rollback_config`** | **0.37 ms** | 11.56 ms | **31x** | New rollback tree |
| **`future()`** | **0.47 ms** | 12.55 ms | **26x** | New projected tree |
| **`all_children_sorted()`** | **0.29 ms** | 2.53 ms | **8.6x** | *N* Python objects |
| **`merge()`** | **3.72 ms** | 26.24 ms | **7.1x** | *N* copied nodes |
| **`dump()`** | **3.52 ms** | 18.98 ms | **5.4x** | *N* Python objects |

*Measured on Apple Silicon (Apple M2 Max), CPython 3.12.13, 4.0.0b4 release
wheel versus hier-config 3.7.0 from PyPI, same interpreter and machine. See
[Methodology](#methodology) for workloads and sampling.*

### Real-World Operational Impact

In large-scale network automation pipelines evaluating fleets of edge routers,
data center switches, and route reflectors:

1. **Minutes become seconds**: Processing 1,000 devices with 10k-line
   configurations previously required over a minute of pure CPU time just for
   parsing and remediation diffing. In 4.0, the core computation finishes in
   under 2 seconds.
2. **Elimination of multiprocessing overhead**: In 3.x, CPU-bound tree diffing
   held the Python Global Interpreter Lock (GIL). Parallelizing workloads across
   cores required `multiprocessing`, incurring high memory overhead and
   inter-process serialization costs. The 4.0 Rust core releases the GIL during
   heavy native diffing and parsing, allowing standard Python thread pools
   (`concurrent.futures.ThreadPoolExecutor`) to scale across cores with a
   shared memory footprint: ~3.4x on 8 performance cores today, limited by the
   work that still holds the GIL (see
   [Performance Roadmap](performance-roadmap.md#9-release-the-gil-on-the-remaining-core-bound-entry-points)).
3. **Sub-millisecond rollbacks and simulations**: Complex simulation workflows
   calling `future()` and computing inverse rollbacks frequently duplicate
   trees. `deepcopy` is now ~1,000x faster, and a complete rollback (remediation,
   future projection and inverse diff) takes 0.37 ms instead of 11.56 ms.

---

## Why Pure Python Hit a Wall (The 3.x Bottlenecks)

The pure-Python 3.x architecture organized configuration lines into a tree of
`HConfig` and `HConfigChild` objects, backed by `HConfigChildren` collections.
While flexible and idiomatic, this architecture faced fundamental CPython
overhead at scale:

### 1. Object Explosion and Allocator Pressure

A 10,000-line network configuration contains roughly 8,800 distinct hierarchical
nodes. In 3.x, every single node was an independent Python object instance:

- Each node allocated its own `__dict__`, a child list, sets for tags and
  comments, an integer order weight, and references to parent and driver objects.
- Parsing a single large configuration resulted in tens of thousands of heap
  allocations managed by the CPython memory allocator and garbage collector.
- Walking the tree meant chasing pointers across scattered memory, destroying
  CPU cache locality.

### 2. Recursive Lineage and Pattern Matching in Bytecode

Remediation calculation (`config_to_get_to`) requires comparing two trees node
by node. For every candidate difference, the engine must evaluate:

- Driver lineage matchers (`MatchRule` tuples) against the node's ancestor path.
- Regular expressions for idempotency, sectional exits, and ordering.
- Sorting child nodes by `order_weight` and insertion index.

In 3.x, all of this executed in Python bytecode. Ancestor paths were
constructed as temporary Python tuples, regex patterns were evaluated via the
`re` module, and sorting required allocating intermediate lists at every level of
the tree.

### 3. The `deepcopy` Nightmare

Network remediation often projects future configurations (`future()`) and
validates rollbacks by cloning the running or remediation tree.

In Python, `copy.deepcopy` is notoriously slow: it recursively inspects each
object, looks up its class, checks for `__deepcopy__`, allocates a new instance,
and maintains a memo dictionary of already-copied references to guard against
cycles. For an 8,823-node tree, `copy.deepcopy` spent **123.57 ms** just
duplicating Python objects.

---

## The 4.0 Architecture Shift

hier_config 4.0 re-architected the entire tree, parsing, and diffing pipeline
around native Rust primitives:

```
┌────────────────────────────────────────────────────────┐
│                   Python Consumer                      │
│      (WorkflowRemediation, get_hconfig, Views)         │
└───────────────────────────┬────────────────────────────┘
                            │ PyO3 Native FFI
┌───────────────────────────▼────────────────────────────┐
│                    hier_config_py                      │
│   (PyHConfig, PyHConfigChild, Handle Lifecycle)        │
└───────────────────────────┬────────────────────────────┘
                            │ Native Rust Calls
┌───────────────────────────▼────────────────────────────┐
│                   hier_config_core                     │
│  ├── Arena<Node> (Contiguous node vector)              │
│  ├── NodeId (Generational indices, 0-cost handles)     │
│  ├── Arc<str> (Zero-copy shared string slices)         │
│  ├── Native Parser (Fast indentation & banner parser)  │
│  ├── Compiled Regex Sets (Pre-compiled driver rules)   │
│  └── Remediation Diff Engine (Single-pass tree diff)   │
└────────────────────────────────────────────────────────┘
```

### Key Architectural Invariants

1. **Generational Arena Allocation (`Arena<Node>`, `NodeId`)**:
   Instead of allocating thousands of individual heap objects, trees are stored
   in contiguous arrays. A `NodeId` is a lightweight generational index (index +
   generation counter) that guarantees safe, constant-time O(1) lookups with
   perfect cache locality.
2. **Zero-Copy String Sharing (`Arc<str>`)**:
   Configuration lines, tags, and comment strings are stored as immutable
   atomic reference-counted string slices (`Arc<str>`). Node operations,
   traversals, and tree clones do not re-allocate strings.
3. **Instantaneous Tree Duplication**:
   Because nodes live in an arena and strings are immutable `Arc<str>`
   references, `deepcopy` in 4.0 simply clones the arena's underlying vector and
   increments string reference counts in native code. What took 123.57 ms in
   Python takes **0.12 ms** in Rust (**0.06 ms** on the smaller 400-interface
   configuration used by the CI regression gate).
4. **Pre-Compiled Rule Engines**:
   Driver rules, lineage patterns, and sectional overwrite rules are compiled
   into optimized native matchers and regex sets at driver initialization,
   removing regex overhead from per-line diff loops.
5. **Whole-Program Optimization (`[profile.release]`)**:
   The workspace is configured with `lto = "fat"` and `codegen-units = 1`. This
   enables link-time optimization and cross-crate inlining across the
   `hier_config_core` and `hier_config_py` boundary, allowing native methods to
   inline directly into PyO3 binding wrappers.

---

## Detailed Benchmark Suite

### 1. Scaling Across Configuration Sizes

To measure scaling characteristics across small, medium, and massive router
configurations, the test harness measured Cisco IOS configurations of varying
sizes:

| Benchmark Target | Line Count | Node Count | 4.0 Time | 3.x Time | Speedup |
|---|---:|---:|---:|---:|---:|
| **Parse (1k lines)** | 1,231 | 1,103 | **0.15 ms** | 7.26 ms | **49.1x** |
| **Parse (10k lines)** | 10,031 | 8,823 | **0.90 ms** | 60.08 ms | **66.7x** |
| **Parse (50k lines)** | 48,431 | 42,423 | **4.31 ms** | 357.91 ms | **83.1x** |
| **Parse IOS-XR (10k lines)** | 10,009 | 9,007 | **1.41 ms** | 85.68 ms | **60.8x** |
| **Remediation (10k lines)** | 10,031 | 8,823 | **0.39 ms** | 12.22 ms | **31.3x** |
| **Remediation (50k lines)** | 48,431 | 42,423 | **1.53 ms** | 56.84 ms | **37.2x** |

As configuration size grows from 1k to 50k lines, pure Python's per-line parse
cost rises by about 25% (5.9 µs to 7.4 µs per line) under allocator and
garbage-collection pressure, while the Rust arena stays flat at roughly
0.09 µs per line. The speedup therefore widens with configuration size.

IOS-XR parsing costs more than IOS in both versions because its driver adjusts
indentation with a lookahead regular expression evaluated on every line. The
4.0 regex cache screens each line with a linear-time prefilter derived from
that expression, so the backtracking engine runs only on candidate lines.

### 2. Operational Breakdown on 10k-Line Benchmark

Wall-clock timings on the generated 10,000-line Cisco IOS configuration
(8,823 nodes), plus the future/rollback workload described in
[Methodology](#methodology), comparing the 4.0 release build against the 3.x
baseline:

```
Operation          4.0 (Rust)        3.x (Python)     Speedup
─────────────────────────────────────────────────────────────
deepcopy              0.12 ms          128.63 ms      ~1000x   ████████████████████
str()                 0.33 ms           32.86 ms       100.5x  ██
difference()          0.19 ms           18.41 ms        97.9x  ██
get_hconfig (50k)     4.31 ms          357.91 ms        83.1x  █▋
get_hconfig (10k)     0.90 ms           60.08 ms        66.7x  █▎
get_hconfig (XR 10k)  1.41 ms           85.68 ms        60.8x  █▏
unified_diff()        0.10 ms            4.94 ms        47.5x  █
config_to_get_to      0.39 ms           12.22 ms        31.3x  ▋
rollback_config       0.37 ms           11.56 ms        31.2x  ▋
future()              0.47 ms           12.55 ms        26.5x  ▌
all_children_sorted   0.29 ms            2.53 ms         8.6x  ▏
merge()               3.72 ms           26.24 ms         7.1x  ▏
dump()                3.52 ms           18.98 ms         5.4x  ▏
```

### Methodology

- **Environments**: two fresh CPython 3.12.13 virtual environments on the same
  machine, one with `hier-config==3.7.0` from PyPI and one with the 4.0 release
  wheel (`maturin build --release --locked`). Scripts run from outside the
  repository so the source tree cannot shadow either install.
- **Workloads**: configurations come from `_generate_large_ios_config()` and
  `_generate_large_xr_config()` in `tests/benchmarks/test_benchmarks.py`. The
  1k, 10k and 50k IOS configurations use 120, 1,200 and 6,000 interfaces.
  Remediation changes the OSPF cost on 100 (10k) or 200 (50k) interfaces.
  `future()` and `rollback_config` use the 1,000-interface (8,431-line)
  configuration with 100 changed interfaces; rollback builds a fresh
  `WorkflowRemediation` per sample so nothing is cached. `unified_diff()` and
  `difference()` compare that same running/intended pair. `deepcopy`,
  `all_children_sorted()`, `dump()`, `str()` and `merge()` use the 10k
  configuration; `merge()` copies it into a freshly created empty tree.
- **Sampling**: minimum of 25 samples per operation (5 for `deepcopy` and the
  50k cases) after one warm-up call, taking the best of three complete runs for
  4.0 and two for 3.x, with the runs alternated between installs. For 4.0,
  rounds agreed within 4% for every operation except `dump()` (5%) and the 50k
  remediation (3% for this build; 6% for the previous one).

---

## The CPython Allocation Boundary

Notice that the speedups range from **5.4x** to **~1,000x**. Why is the spread
not uniform?

The answer lies in **what an operation returns** and whether it crosses the
CPython allocation boundary.

### Rust-Bound vs. CPython-Bound Operations

| Category | Operations | What Returns to Python | Primary Cost Driver | Speedup Range |
|---|---|---|---|---|
| **Rust-Bound** | `parse`, `deepcopy`, `remediation`, `future`, `rollback`, `str`, `unified_diff`, `difference` | A single scalar, string, or root handle | Native Rust execution | **26x – ~1,000x** |
| **CPython-Bound** | `dump()`, `all_children_sorted()`, `merge()` | *N* individual Python objects (one per node) | CPython object allocation & GC | **5.4x – 8.6x** |

### The Math of Object Materialization

In an 8,823-node configuration:

- In 3.x, the `HConfigChild` objects were *already* in Python memory. An
  operation like `all_children_sorted()` merely yielded references to objects
  that had already been allocated during parsing.
- In 4.0, nodes live in the Rust arena. When Python calls
  `all_children_sorted()`, the Rust engine must allocate 8,823 `HConfigChild`
  Python handle objects to give Python code access to each node.

How fast can CPython allocate 8,823 objects?

Direct micro-benchmarks measuring pure CPython allocation show:
- Allocating 8,823 *empty* Python `__slots__` objects (`object.__new__`) costs
  **0.537 ms**.
- The entire pure-Python 3.x traversal took 2.348 ms in that experiment.

$$\text{Theoretical Speedup Ceiling} = \frac{2.348\text{ ms}}{0.537\text{ ms}} \approx 4.4\text{x}$$

Even if the native Rust traversal and sorting took **0.000 ms** (infinitely
fast), the end-to-end Python call could not exceed ~4.4x if it interned full
Python objects, purely because CPython must allocate memory for 8,823 handles!

### Profiling the Python FFI Split

Profiling the 4.0 hot paths with native probes revealed where time is spent:

| Operation | Python-Visible Wall Clock | Pure Rust Core Time | Spent Crossing into CPython |
|---|---:|---:|---:|
| **`dump()`** | 0.941 ms | 0.106 ms | **89%** |
| **`all_children_sorted()`** | 0.294 ms | 0.025 ms | **93%** |
| **`remediation`** | 0.392 ms | 0.297 ms | 24% |
| **`get_hconfig` (parse)** | 0.672 ms | 0.587 ms | 13% |
| **`fast_load`** | 0.604 ms | 0.553 ms | 8% |

These figures were measured before Pass 6 and Pass 7 and are kept for their
proportions. After Pass 7, native `dump_10k` takes 0.24 ms against 3.52 ms for
Python `dump()` on the same config, so the split for `dump()` still holds.

For `dump()` and iteration, **89% to 93% of the execution time is spent inside
the CPython runtime** allocating objects, setting dictionary keys, and creating
tuples. The Rust computation is virtually instant (25 microseconds for
iteration; 106 microseconds for dump serialization).

### Beating the Python Construction Floor in `dump()`

`HConfig.dump()` produces a collection of `DumpLine` objects representing the
entire configuration tree as structured records.

In pure Python:
- Constructing 8,823 `DumpLine` models via standard Pydantic validation took
  **12.45 ms**.
- Pydantic v2's `model_construct()` was actually slower (**12.93 ms**).
- The fastest possible pure-Python construction (`object.__new__` plus slot
  assignment, sharing an empty frozenset) took **3.86 ms**.

In 4.0, Rust populates the underlying Python instance dictionaries directly
via the Python C-API without executing Python bytecode. As a result, 4.0
achieves **3.52 ms** for `dump()` — still below the 3.86 ms pure-Python
construction floor, and 5.4x faster than 3.x.

---

## Iterative Optimization Passes

The headline numbers were not achieved in a single pass. Achieving them required
systematic profiling and tuning across seven distinct phases:

### Pass 1: The Initial Rust Core & Binding
The initial migration implemented the arena allocator, regex matching, and
remediation diff in Rust. This established the baseline 10x–30x speedups for
parsing and diffing, but revealed that `dump()` was initially slower than pure
Python due to per-node Pydantic validation crossing the FFI boundary.

### Pass 2: Compiler Flags & Cross-Crate LTO
Cargo's stock release profile disables Link-Time Optimization (LTO) and compiles
16 separate codegen units. Because `hier_config_core` and `hier_config_py` are
distinct crates, hot-path functions could not be inlined across the crate
boundary.
Enabling `[profile.release]` with `lto = "fat"`, `codegen-units = 1`, and
`opt-level = 3` yielded an immediate **15% to 25% throughput gain** across all
operations.

### Pass 3: Memory Sizing & Hot-Path Allocation Pruning
Profiling with native allocation profilers exposed hidden vector re-allocations:
- **Arena capacity reservation**: `load_fast` was modified to call
  `tree.arena.reserve(lines.len())` upfront. Previously, large parses grew the
  arena repeatedly, copying 208-byte node structs on each expansion.
- **Ordered child optimization**: `collect_all_children_sorted` previously
  allocated and sorted a temporary `Vec` at every level of the tree. Because
  `order_weight` is left at default (0) on over 99% of nodes, a fast-path
  `children_already_ordered()` check was added. When children are already in
  order, the walk iterates the existing slice directly, eliminating thousands of
  heap allocations per traversal.
- **Sized traversal hints**: Traversal algorithms were updated to reserve
  capacity based on exact tree size hints, preventing repeated reallocations
  during whole-tree walks.

### Pass 4: Entry API Caching
The PyO3 handle interning cache initially used `cache.get()` followed by
`cache.insert()`, hashing every `NodeId` twice on cache misses. Switching to
the standard library `Entry` API eliminated the redundant hash lookup for every
child handle created.

### Pass 5: Non-Interning Bulk Traversals
During the rewrite's optimization experiments, bulk tree traversals were
measured using eager native tuples rather than lazy Python generators.
Furthermore, handles created during bulk traversals bypass the persistent
interning cache, eliminating weakref tracking overhead and allowing CPython to
reclaim handle memory immediately after use. This reduced iteration time by
another **61%** in that experiment. These are historical measurements, not
a blanket API return-type promise; consult the
[migration reference](../user/rust-core-changes.md#traversal-return-types)
and current stubs for the supported iterator/collection contracts.

### Pass 6: Rust Hot-Path Profiling Against the Comparison Workloads
A later pass profiled every workload in this document against a release build
and changed only the Rust core and its bindings. Each change came with a test
and was kept only if it showed a measured gain:

- **Detached scratch nodes.** Remediation, rollback and `difference` used to add
  a section to the delta and delete it again when it had no changes. Deleting a
  child rebuilt the parent's text index, so every unchanged section cost O(n).
  Sections are now built detached and attached only when they have changes.
- **Linear prefilter for lookaround rules.** Rule regexes that need
  `fancy-regex` (lookaround, atomic groups, `\b`) first run a linear `regex`
  version of the pattern with the lookarounds relaxed. Lines it rejects skip the
  backtracking engine.
- **Word-at-a-time scans.** Line splitting, indentation measurement and the
  whitespace check work on eight-byte words and jump to the first candidate
  byte. Property tests pin line splitting to Python's `str.splitlines` on
  arbitrary Unicode.
- **Small-section child index.** Sections with up to eight distinct child texts
  are indexed by a short vector instead of a `SipHash` map, and each new child
  is indexed with a single lookup. Larger sections keep the randomly seeded map.
  Equality and the serde form of `Children` do not depend on the representation.
- **Native cross-tree copies.** `HConfig.merge()` and `add_deep_copy_of()` from
  another tree run in one native pass instead of recursing through Python.

The historical native before/after for this pass is in
[Native Benchmarks with Criterion](#native-benchmarks-with-criterion). Pass 7
superseded the end-to-end figures.

### Native Benchmarks with Criterion

The Rust core has its own benchmark suite,
`crates/hier_config_core/benches/workflows.rs`, built on
[Criterion](https://bheisler.github.io/criterion.rs/book/). It covers every
operation in the comparison above, plus `fast_load`, rendering (`lines()` and
`to_lines()`), a remediation where every interface changes, a remediation
between disjoint configs, flat `future()` additions, and two non-ASCII
workloads. Its config generators reproduce the
Python generators in `tests/benchmarks/test_benchmarks.py` byte for byte, so
both suites time the same work.

The suite times the Rust core only. It does not include PyO3 handles, Python
object construction or interpreter overhead, so its numbers are a lower bound
for the Python API. Use the Python suites for end-to-end figures and the CI
gate.

```bash
# Run everything (bench builds inherit the release profile: fat LTO, 1 CGU)
cargo bench -p hier_config_core --bench workflows

# One group or benchmark, by regex filter
cargo bench -p hier_config_core --bench workflows -- parse/

# Save a baseline before a change, then compare against it afterwards
cargo bench -p hier_config_core --bench workflows -- --save-baseline before
cargo bench -p hier_config_core --bench workflows -- --baseline before

# Smoke-test every benchmark once without timing it
cargo bench -p hier_config_core --bench workflows -- --test
```

Criterion stores results under `target/criterion`. To compare two checkouts,
for example a branch against `next`, point both at one results directory with
`CRITERION_HOME`, then save a baseline from each and compare. Alternate the runs
so drift (thermal state, background load) affects both builds equally.

Historical native before/after for Pass 6 (superseded by
[Pass 7](#pass-7-lazy-deltas-single-walk-rendering-and-cheaper-copies)):
Apple M2 Max, rustc 1.98.1. The baseline was
`e86911d` on `next`, with the same benchmark file added. Builds ran
alternately, two rounds each, with Criterion's default 100 samples per
benchmark. The table shows the lower of the two rounds' median estimates.
Within each build, the two rounds agreed to within 6% (`parse/ios_50k`) and
otherwise to within 3%.

| Benchmark | Before | After | Time reduction |
|---|---:|---:|---:|
| `parse/ios_1k` | 0.281 ms | 0.148 ms | 47% |
| `parse/ios_10k` | 2.151 ms | 1.094 ms | 49% |
| `parse/ios_50k` | 10.375 ms | 5.395 ms | 48% |
| `parse/xr_10k` | 7.957 ms | 2.177 ms | 73% |
| `parse/unicode_10k` | 2.310 ms | 1.243 ms | 46% |
| `deepcopy_10k` | 0.153 ms | 0.153 ms | 0% |
| `remediation/10k` | 3.732 ms | 0.662 ms | 82% |
| `remediation/50k` | 32.203 ms | 3.139 ms | 90% |
| `remediation/unicode_10k` | 3.788 ms | 0.650 ms | 83% |
| `future_1000_interfaces` | 1.362 ms | 0.719 ms | 47% |
| `rollback_1000_interfaces` | 3.155 ms | 0.580 ms | 82% |
| `all_children_sorted_10k` | 0.039 ms | 0.040 ms | −3% |
| `dump_10k` | 0.350 ms | 0.370 ms | −6% |
| `merge_10k` | 1.399 ms | 0.808 ms | 42% |
| `diff/unified_diff_10k` | 0.426 ms | 0.288 ms | 32% |
| `diff/unified_diff_unicode_10k` | 0.442 ms | 0.286 ms | 35% |
| `diff/difference_10k` | 3.436 ms | 0.463 ms | 87% |
| `diff/difference_unicode_10k` | 3.450 ms | 0.450 ms | 87% |

Caveats:

- `deepcopy_10k`, `all_children_sorted_10k` and `dump_10k` did not improve;
  the 3–6% swings on the latter two are comparable to run-to-run drift for
  sub-millisecond benchmarks. Native `dump_10k` builds the `Dump` struct in
  about 0.35 ms, while Python `dump()` spends almost all of its ~3.4 ms
  building Python objects.
- Native `all_children_sorted` is a walk that returns node ids. The Python
  traversal cost is in creating handles, and that is outside this suite.
- Python `HConfig.merge()` used to recurse through Python method calls for
  every node. The native core merge above was never the bottleneck. Copying a
  stock `HConfig` from another tree now runs in one native pass, and merging a
  10k-line config into a freshly parsed one dropped from about 38 ms to about
  18 ms end to end (three alternating rounds of 15 samples), roughly half.
  The rest is mostly pydantic `Instance` construction, one per copied node.
  `HConfig` subclasses and same-tree merges keep the overridable per-node path.
  Pass 7 removed most of the remaining `Instance` cost.

### Pass 7: Lazy Deltas, Single-Walk Rendering and Cheaper Copies

The next pass profiled every Criterion and Python benchmark against a release
build of the Pass 6 code and again changed only the Rust core and its bindings.
Regression tests were written before each change:

- **Lazy remediation sections.** Remediation, rollback and `difference` used to
  create a scratch child for every matched section and delete it when nothing
  beneath it changed. Pending sections are now created on the first change, in
  the same sibling order. Renaming the last child, which happens for each
  negation, now updates the parent index in place instead of rebuilding it.
  That rebuild made remediating two completely different configurations
  quadratic.
- **One walk per render.** `lines()` (behind `to_lines()` and `str()`) used to
  re-walk each node's ancestors to compute indentation, and `dump()` recomputed
  depth and a recursive tag union for every node. Both now carry depth down a
  single walk, reuse already-ordered child slices and evaluate the
  sectional-exit rule once.
- **Positional `unified_diff`.** Aligned configurations meet the same child
  text at the same position, so a positional check now precedes the hash
  lookup when sibling texts are unique. Output goes into one buffer instead of
  nested vectors.
- **Cheaper copies.** Copies share the source node's text when no trimming is
  needed, and merged deep copies build tag unions bottom-up from their
  children instead of re-walking each subtree.
- **Cached child-index hashes.** Child-index keys carry their hash from the
  index's randomly seeded state, so growing a large section no longer rehashes
  every child text. Lookups still hash the probe once, so flooding resistance
  is unchanged.
- **Shared `Instance` records in Python `merge()`.** Nodes with identical
  comments and tags share one immutable pydantic record (each node still gets
  its own list), and the binding's node-keyed maps use a faster
  non-cryptographic hasher. The keys are internal arena ids, so they cannot be
  chosen by an attacker.

`HConfig` subclasses and same-tree copies still take the overridable Python
path. `Children` equality and its serialized form are unchanged.

Native Criterion before/after: Apple M2 Max, rustc 1.98.1. The baseline was
`83d3906` (Pass 6) with the current benchmark file added. Builds ran
alternately, three rounds each, with a 1 s warm-up and 3 s of measurement per
benchmark. The first round overlapped a wheel build and was discarded. The
table shows the lower of the remaining two rounds' median estimates. Within each
build those rounds agreed to within 4%.

| Benchmark | Before | After | Time reduction |
|---|---:|---:|---:|
| `parse/ios_1k` | 0.145 ms | 0.134 ms | 7% |
| `parse/ios_10k` | 1.053 ms | 1.005 ms | 5% |
| `parse/ios_50k` | 5.025 ms | 4.829 ms | 4% |
| `parse/xr_10k` | 2.071 ms | 2.012 ms | 3% |
| `parse/unicode_10k` | 1.195 ms | 1.144 ms | 4% |
| `parse/fast_load_ios_10k` | 1.019 ms | 0.968 ms | 5% |
| `deepcopy_10k` | 0.146 ms | 0.150 ms | −3% |
| `all_children_sorted_10k` | 0.039 ms | 0.031 ms | 21% |
| `dump_10k` | 0.352 ms | 0.241 ms | 32% |
| `render/lines_10k` | 1.054 ms | 0.393 ms | 63% |
| `render/to_lines_10k` | 0.796 ms | 0.238 ms | 70% |
| `merge_10k` | 0.764 ms | 0.597 ms | 22% |
| `remediation/10k` | 0.641 ms | 0.338 ms | 47% |
| `remediation/50k` | 2.926 ms | 1.527 ms | 48% |
| `remediation/unicode_10k` | 0.623 ms | 0.340 ms | 45% |
| `remediation/10k_all_changed` | 1.188 ms | 0.851 ms | 28% |
| `remediation/disjoint_500` | 7.819 ms | 0.418 ms | 95% |
| `future_1000_interfaces` | 0.682 ms | 0.437 ms | 36% |
| `future_flat_additions_4000` | 1.041 ms | 0.646 ms | 38% |
| `rollback_1000_interfaces` | 0.553 ms | 0.302 ms | 45% |
| `diff/unified_diff_10k` | 0.279 ms | 0.123 ms | 56% |
| `diff/unified_diff_unicode_10k` | 0.280 ms | 0.126 ms | 55% |
| `diff/difference_10k` | 0.448 ms | 0.191 ms | 57% |
| `diff/difference_unicode_10k` | 0.437 ms | 0.190 ms | 56% |

Python end-to-end before/after: two CPython 3.12.13 virtual environments with
release wheels of `83d3906` and this pass, timed with the
[Methodology](#methodology) workloads and sampling. The table shows the best of
three alternated rounds.

| Operation | Before | After | Time reduction |
|---|---:|---:|---:|
| `get_hconfig` (1k) | 0.159 ms | 0.148 ms | 7% |
| `get_hconfig` (10k) | 0.941 ms | 0.901 ms | 4% |
| `get_hconfig` (50k) | 4.537 ms | 4.308 ms | 5% |
| `get_hconfig` (IOS-XR 10k) | 1.473 ms | 1.409 ms | 4% |
| `config_to_get_to` (10k) | 0.593 ms | 0.391 ms | 34% |
| `config_to_get_to` (50k) | 2.561 ms | 1.530 ms | 40% |
| `future()` | 0.644 ms | 0.474 ms | 26% |
| `rollback_config` | 0.532 ms | 0.370 ms | 30% |
| `copy.deepcopy()` | 0.124 ms | 0.123 ms | 1% |
| `all_children_sorted()` | 0.302 ms | 0.294 ms | 3% |
| `dump()` | 3.646 ms | 3.519 ms | 3% |
| `unified_diff()` | 0.226 ms | 0.104 ms | 54% |
| `difference()` | 0.344 ms | 0.188 ms | 45% |
| `merge()` | 14.145 ms | 3.719 ms | 74% |
| `str()` | 0.788 ms | 0.327 ms | 59% |

Caveats:

- Parsing improved only 3–7%. About a quarter of a 10k IOS parse is
  per-line substitution regexes, and comment lines run three regex passes. See
  the [roadmap](performance-roadmap.md) for the options.
- `deepcopy_10k` is about 3% (3 µs) slower natively. The cached hash makes each
  child-index entry larger to clone. The Python figure is unchanged within
  noise, and the trade pays off in every build-heavy workload above.
- Python `dump()` and `all_children_sorted()` barely moved because almost all
  of their time is spent creating Python objects (see
  [The CPython Allocation Boundary](#the-cpython-allocation-boundary)).
- Python `merge()` is still about six times its native cost. The remainder is
  Python object allocation, garbage-collector tracking and dictionary inserts
  at the binding boundary.

### Pass 7 follow-up: `from_lines` marshalling

`HConfig.from_lines()` took 1.16–1.18x as long as `HConfig.from_text()` on the
same config, which made `test_fast_load_vs_get_hconfig` (bound: 1.1x) fail
intermittently. The core fast-load loop was not the problem: natively it was
already slightly faster than the full parser. The extra time was in moving the
lines across the boundary:

- The Python constructor split a `str` into Python strings and copied every
  list or tuple with `list()`. Now a `str` goes to the binding unchanged and is
  split in Rust on exactly the `str.splitlines()` boundaries, and an exact
  `list` or `tuple` is passed as-is. Other iterables, including list
  subclasses that override `__iter__`, are still materialised with `list()`.
- The binding copied each line into one buffer before releasing the GIL. It now
  holds a `PyBackedStr` per line, which keeps the Python string alive and
  borrows its UTF-8 data, so the parse still runs without the GIL but without
  the copy. The references are dropped after the GIL is re-acquired.
- The fast-load loop scanned each line's leading whitespace three times with
  Unicode-aware trims. It now scans once, using the ASCII fast path of the
  indentation helper, and reuses the result unless a `per_line_sub` rule
  rewrote the line.

Python end-to-end: release wheels of the previous commit and this change in two
CPython 3.14.4 virtual environments, three alternated rounds of best-of-200 on
the 10k-line IOS benchmark config. The table shows the median round. Rounds
agreed to within 3%.

| Operation | Before | After | Time reduction |
|---|---:|---:|---:|
| `from_text` (reference) | 0.772 ms | 0.778 ms | −1% (noise) |
| `from_lines` (tuple) | 0.910 ms | 0.820 ms | 10% |
| `from_lines` (list) | 0.899 ms | 0.825 ms | 8% |
| `from_lines` (str) | 1.103 ms | 0.759 ms | 31% |
| `from_lines` (generator) | 1.003 ms | 0.938 ms | 6% |
| `from_lines` / `from_text` (tuple) | 1.17x | 1.05x | |

Native Criterion `parse/fast_load_ios_10k`, three alternated rounds: 0.973–0.984
ms before and 0.950–0.960 ms after (about 3%). `get_hconfig_fast_load()` with a
`str`, as used by the CI gate, fell from 0.169 to 0.109–0.113 calibration units.

Limits: a tuple or list still pays a few Python C-API calls per line (item
access, type check and `PyUnicode_AsUTF8AndSize`), about 60 µs for 8,400 lines,
so `from_lines()` on a pre-split sequence remains slightly slower than
`from_text()` on the joined text. Passing the text as a `str` avoids that cost.

---

## Performance Guardrails in CI

Performance gains can easily regress if a future PR introduces accidental
allocations, disables compiler inlining, or adds redundant FFI crossings.

To protect these gains, hier_config enforces an automated performance gate in
CI (`tests/benchmarks/test_perf_regression.py`).

### The Problem with Millisecond Thresholds

Absolute wall-clock thresholds are sensitive to load and hardware differences
on shared CI runners. A workstation-only threshold is not evidence of a useful
budget on a different runner.

### The Calibration Unit Solution

Instead of measuring milliseconds, the regression test measures operations in
**calibration units**:

1. In the same test process, a fixed lump of pure-Python interpreter work
   (dictionary churn, string manipulation, and list joins) is timed. This
   establishes the machine's current execution speed as 1 unit:

   $$\text{1 Unit} = \text{Time to execute standardized Python calibration workload}$$

   The duration is measured for each run rather than assumed from a reference
   workstation.

2. Each hier_config operation is timed and divided by the calibration unit:

   $$\text{Cost in Units} = \frac{\text{Operation Elapsed Time (ms)}}{\text{Calibration Unit (ms)}}$$

This ratio can reduce common load effects, but native code and Python bytecode
do not necessarily scale proportionally across CPUs, operating systems or
architectures. A passing local Apple Silicon run does not establish that the
Linux CI budget is calibrated. Verify results on the actual runner before
claiming cross-platform calibration.

### Enforced CI Ceilings

The CI regression suite asserts upper bounds (`MAX_COST_UNITS`) against
a 400-interface configuration. The following figures are the range over two
local runs after Pass 7 (Apple M2 Max, CPython 3.14.4, 1 unit ≈ 3.05 ms). The
`fast_load` row was re-measured after the
[`from_lines` marshalling change](#pass-7-follow-up-from_lines-marshalling)
(1 unit ≈ 3.20 ms in those runs). Current code and CI logs are authoritative:

| Operation | Observed 4.0 Cost | CI Ceiling (`MAX_COST_UNITS`) | Safety Margin |
|---|---:|---:|---|
| **`deepcopy`** | **0.014–0.015 units** (0.05 ms) | 0.030 units | 2.0x |
| **`iteration`** | **0.037 units** (0.11–0.12 ms) | 0.060 units | 1.6x |
| **`remediation`** | **0.070–0.071 units** (0.21–0.22 ms) | 0.190 units | 2.7x |
| **`fast_load`** | **0.109–0.113 units** (0.35–0.36 ms) | 0.240 units | 2.1x |
| **`parse`** | **0.114–0.119 units** (0.35–0.36 ms) | 0.240 units | 2.0x |
| **`dump`** | **0.297–0.307 units** (0.91–0.95 ms) | 0.450 units | 1.5x |

The ceilings were not tightened after Pass 7: they need Linux CI measurements
to calibrate against, and this machine is not the CI runner.

The gate detects costs exceeding those budgets. It does not guarantee that
every regression will be detected or attribute a failure to code rather than
runner effects.

---

## Future and Rollback Regression Checks

Build the release extension before measuring; use `--no-sync` afterward so uv
does not replace it with a cached build:

```bash
uv run --no-sync maturin develop --release --locked
uv run --no-sync pytest -m benchmark tests/benchmarks/test_benchmarks.py -v -s
```

The future and rollback cases use 1,000 IOS interfaces (8,431 input lines),
changing the OSPF cost on 100 interfaces. Future timing excludes remediation
generation. Rollback timing creates a fresh `WorkflowRemediation` each time,
including remediation generation and future projection rather than reading
a warmed rollback cache. Correctness assertions run outside the timed region.

A separate Generic-platform test projects 1,000 and 4,000 new top-level lines
onto equally sized running configs. Four times the input may take at most
eight times as long: this tolerates timing noise while detecting a quadratic
negated-counterpart sibling scan. Indexed exact-text lookup must remain indexed
even when reducing temporary string allocations.

For before/after comparisons, keep the pre-change release binary and run both
builds in alternation on the same interpreter and machine. Differences within
about 2% are run-to-run noise.

## Where to Look Next

- [Performance Roadmap](performance-roadmap.md) — The theoretical headroom
  remaining, and the future API changes (such as converting `DumpLine` to a
  `__slots__` class) planned for 5.0.
- [Architecture Overview](architecture.md) — The internal design of the Rust
  core, memory layout, and PyO3 handle lifecycle.
- [3.x to 4.0 Migration Guide](../user/rust-core-changes.md) — Guide for
  upgrading existing codebases to hier_config 4.0.
