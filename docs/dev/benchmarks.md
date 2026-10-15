# Performance & Benchmarks: The 3.x to 4.0 Story

hier_config 4.0 introduces an arena-backed Rust core engine (`hier_config_core`)
exposed to Python through native PyO3 bindings. This replaced the 3.x
pure-Python tree implementation to eliminate the performance and scaling
bottlenecks that network automation pipelines encountered when processing
thousands of large configurations.

This document tells the 3.x to 4.0 performance improvement story: the
architectural bottlenecks of the pure-Python engine, the empirical benchmark
measurements across configuration sizes, the structural reality of the CPython
object allocation boundary, the native Rust benchmark suite, and the automated
calibration-unit regression guardrails protecting these gains in CI. Remaining
optimisation opportunities and known dead ends are tracked in the
[Performance Roadmap](performance-roadmap.md).

---

## Executive Summary

On a 10,000-line Cisco IOS configuration (8,823 nodes), hier_config 4.0 achieves
**5.4x to ~1,100x speedups** across core operations compared to the pure-Python
3.x baseline:

| Operation | 4.0 (Rust Core) | 3.x (Pure Python) | Speedup | Result Category |
|---|---:|---:|---:|---|
| **`copy.deepcopy()`** | **0.12 ms** | 138.99 ms | **~1,100x** | New tree / memory clone |
| **`get_hconfig` (50k lines)** | **2.58 ms** | 377.93 ms | **146x** | Scalar / tree creation |
| **`get_hconfig` (10k lines)** | **0.57 ms** | 61.02 ms | **107x** | Scalar / tree creation |
| **`difference()`** | **0.18 ms** | 19.28 ms | **105x** | New difference tree |
| **`str()`** | **0.33 ms** | 33.58 ms | **102x** | Single string |
| **`get_hconfig` (IOS-XR, 10k lines)** | **1.21 ms** | 88.71 ms | **73x** | Scalar / tree creation |
| **`get_hconfig` (1k lines)** | **0.12 ms** | 7.25 ms | **58x** | Scalar / tree creation |
| **`unified_diff()`** | **0.11 ms** | 5.08 ms | **48x** | Diff lines |
| **`config_to_get_to` (50k lines)** | **1.55 ms** | 59.73 ms | **39x** | New remediation tree |
| **`rollback_config`** | **0.36 ms** | 11.72 ms | **33x** | New rollback tree |
| **`config_to_get_to` (remediation)** | **0.39 ms** | 12.59 ms | **32x** | New remediation tree |
| **`future()`** | **0.46 ms** | 13.06 ms | **28x** | New projected tree |
| **`all_children_sorted()`** | **0.30 ms** | 2.60 ms | **8.6x** | *N* Python objects |
| **`merge()`** | **3.78 ms** | 27.23 ms | **7.2x** | *N* copied nodes |
| **`dump()`** | **3.81 ms** | 20.39 ms | **5.4x** | *N* Python objects |

*Measured on Apple Silicon (Apple M2 Max), CPython 3.12.13, a 4.0 release
wheel of the current code versus hier-config 3.7.0 from PyPI, same interpreter
and machine. See [Methodology](#methodology) for workloads and sampling.*

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
   [Performance Roadmap](performance-roadmap.md#8-release-the-gil-on-the-remaining-core-bound-entry-points)).
3. **Sub-millisecond rollbacks and simulations**: Complex simulation workflows
   calling `future()` and computing inverse rollbacks frequently duplicate
   trees. `deepcopy` is now ~1,100x faster, and a complete rollback (remediation,
   future projection and inverse diff) takes 0.36 ms instead of 11.72 ms.

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
cycles. For an 8,823-node tree, `copy.deepcopy` spent **138.99 ms** just
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
   increments string reference counts in native code. What took 138.99 ms in
   Python takes **0.12 ms** in Rust (**0.05 ms** on the smaller 400-interface
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
| **Parse (1k lines)** | 1,231 | 1,103 | **0.12 ms** | 7.25 ms | **58.4x** |
| **Parse (10k lines)** | 10,031 | 8,823 | **0.57 ms** | 61.02 ms | **107.4x** |
| **Parse (50k lines)** | 48,431 | 42,423 | **2.58 ms** | 377.93 ms | **146.3x** |
| **Parse IOS-XR (10k lines)** | 10,009 | 9,007 | **1.21 ms** | 88.71 ms | **73.4x** |
| **Remediation (10k lines)** | 10,031 | 8,823 | **0.39 ms** | 12.59 ms | **32.1x** |
| **Remediation (50k lines)** | 48,431 | 42,423 | **1.55 ms** | 59.73 ms | **38.5x** |

As configuration size grows from 1k to 50k lines, pure Python's per-line parse
cost rises by about 33% (5.9 µs to 7.8 µs per line) under allocator and
garbage-collection pressure, while the Rust arena holds at about 0.05–0.06 µs per
line from 10k lines up (0.10 µs at 1k lines, where the fixed per-call cost
shows). The speedup therefore widens with configuration size.

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
deepcopy              0.12 ms          138.99 ms      ~1100x   ████████████████████
get_hconfig (50k)     2.58 ms          377.93 ms       146.3x  ██▋
get_hconfig (10k)     0.57 ms           61.02 ms       107.4x  █▉
difference()          0.18 ms           19.28 ms       105.0x  █▉
str()                 0.33 ms           33.58 ms       101.8x  █▊
get_hconfig (XR 10k)  1.21 ms           88.71 ms        73.4x  █▎
unified_diff()        0.11 ms            5.08 ms        48.0x  ▉
rollback_config       0.36 ms           11.72 ms        32.9x  ▋
config_to_get_to      0.39 ms           12.59 ms        32.1x  ▋
future()              0.46 ms           13.06 ms        28.4x  ▌
all_children_sorted   0.30 ms            2.60 ms         8.6x  ▏
merge()               3.78 ms           27.23 ms         7.2x  ▏
dump()                3.81 ms           20.39 ms         5.4x  ▏
```

### Methodology

- **Environments**: two fresh CPython 3.12.13 virtual environments on the same
  machine, one with `hier-config==3.7.0` from PyPI and one with a 4.0 release
  wheel of the current code (`maturin build --release --locked`, rustc 1.98.1). Scripts run from outside the
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
  50k cases) after one warm-up call, taking the best of three complete runs per
  install, with the runs alternated between installs. For 4.0, the three runs
  agreed within 6% for every operation except the 1k parse (7%); most agreed
  within 4%. The machine was shared and loaded, so treat differences of a few
  percent as noise.

---

## The CPython Allocation Boundary

Notice that the speedups range from **5.4x** to **~1,100x**. Why is the spread
not uniform?

The answer lies in **what an operation returns** and whether it crosses the
CPython allocation boundary.

### Rust-Bound vs. CPython-Bound Operations

| Category | Operations | What Returns to Python | Primary Cost Driver | Speedup Range |
|---|---|---|---|---|
| **Rust-Bound** | `parse`, `deepcopy`, `remediation`, `future`, `rollback`, `str`, `unified_diff`, `difference` | A single scalar, string, or root handle | Native Rust execution | **28x – ~1,100x** |
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

Comparing each Python call with the matching native Criterion benchmark (see
[Native Benchmarks with Criterion](#native-benchmarks-with-criterion)) on the
same 10k-line workloads shows where the time goes:

| Operation | Python-Visible Wall Clock | Rust Core (Criterion) | Spent Crossing into CPython |
|---|---:|---:|---:|
| **`dump()`** | 3.81 ms | 0.14 ms | **96%** |
| **`all_children_sorted()`** | 0.30 ms | 0.03 ms | **89%** |
| **`merge()`** (into an empty tree) | 3.78 ms | 0.57 ms | **85%** |
| **`str()`** | 0.33 ms | 0.14 ms | 58% |
| **`config_to_get_to`** | 0.39 ms | 0.32 ms | 17% |
| **`get_hconfig`** | 0.57 ms | 0.50 ms | 12% |

`str()` is compared with `render/to_lines_10k`, the same single-buffer render,
and `get_hconfig` with `parse/ios_10k`. Both the Python extension and the
Criterion suite use `mimalloc` as their global allocator, so the columns are
directly comparable.

For `dump()`, iteration and `merge()`, **85% to 96% of the execution time is
spent inside the CPython runtime** allocating objects, setting dictionary keys,
and creating tuples. The Rust computation is a small fraction (32 microseconds
for iteration; 136 microseconds for dump serialization).

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
achieves **3.81 ms** for `dump()` — at the 3.86 ms pure-Python construction
floor, and 5.4x faster than 3.x.

---

## Native Benchmarks with Criterion

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

Current figures: Apple M2 Max, rustc 1.98.1, four rounds with a 1 s warm-up
and 3 s of measurement per benchmark. The machine was shared and heavily loaded
(load average 7–11), so the table shows the lowest of the four rounds' median
estimates. Most benchmarks agreed across rounds within 5%; the parse benchmarks
varied by up to 15% and one `fast_load` round by more. Run in isolation
under the same load, `parse/ios_50k` measured 2.45–2.49 ms.

| Benchmark | Workload | Time |
|---|---|---:|
| `parse/ios_1k` | Parse 1,231 IOS lines | 0.086 ms |
| `parse/ios_10k` | Parse 10,031 IOS lines | 0.517 ms |
| `parse/ios_50k` | Parse 48,431 IOS lines | 2.533 ms |
| `parse/xr_10k` | Parse 10,009 IOS-XR lines | 1.521 ms |
| `parse/unicode_10k` | Parse the 10k IOS config with non-ASCII text | 0.699 ms |
| `parse/fast_load_ios_10k` | `fast_load` of the 10k IOS lines | 0.483 ms |
| `deepcopy_10k` | Clone the 10k tree | 0.123 ms |
| `all_children_sorted_10k` | Ordered walk of the 10k tree | 0.032 ms |
| `dump_10k` | Build the `Dump` of the 10k tree | 0.138 ms |
| `render/lines_10k` | `lines()` of the 10k tree | 0.277 ms |
| `render/to_lines_10k` | `to_lines()` of the 10k tree | 0.136 ms |
| `merge_10k` | Merge the 10k tree into an empty tree | 0.588 ms |
| `remediation/10k` | 100 of 1,200 interfaces changed | 0.336 ms |
| `remediation/50k` | 200 of 6,000 interfaces changed | 1.572 ms |
| `remediation/unicode_10k` | As `remediation/10k`, non-ASCII text | 0.333 ms |
| `remediation/10k_all_changed` | Every interface changed | 0.725 ms |
| `remediation/disjoint_500` | Two configs with no common lines | 0.317 ms |
| `future_1000_interfaces` | 100 of 1,000 interfaces changed | 0.415 ms |
| `future_flat_additions_4000` | 4,000 new top-level lines | 0.633 ms |
| `rollback_1000_interfaces` | Remediation, future and rollback | 0.297 ms |
| `diff/unified_diff_10k` | Unified diff, 1,000 interfaces | 0.132 ms |
| `diff/unified_diff_unicode_10k` | As above, non-ASCII text | 0.132 ms |
| `diff/difference_10k` | `difference`, 1,000 interfaces | 0.199 ms |
| `diff/difference_unicode_10k` | As above, non-ASCII text | 0.198 ms |

Notes:

- Native `dump_10k`, `all_children_sorted_10k` and `merge_10k` are a small
  fraction of the matching Python calls; the rest is Python object
  construction (see
  [The CPython Allocation Boundary](#the-cpython-allocation-boundary)).
- The suite installs `mimalloc` as its global allocator (a bench-only
  dev-dependency), matching the Python extension, so allocation-heavy
  benchmarks time the same allocator that Python users get. On the system
  allocator, parsing is about 10% slower (`parse/ios_50k` about 2.6 ms) and
  `dump_10k` and the render benchmarks 30–45% slower.

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
local runs of the current code (Apple M2 Max, CPython 3.14.4, 1 unit ≈
3.07–3.23 ms). Current code and CI logs are authoritative:

| Operation | Observed 4.0 Cost | CI Ceiling (`MAX_COST_UNITS`) | Safety Margin |
|---|---:|---:|---|
| **`deepcopy`** | **0.0145–0.0148 units** (0.05 ms) | 0.030 units | 2.0x |
| **`iteration`** | **0.036–0.037 units** (0.11–0.12 ms) | 0.060 units | 1.6x |
| **`remediation`** | **0.065–0.067 units** (0.20–0.21 ms) | 0.190 units | 2.8x |
| **`fast_load`** | **0.081–0.082 units** (0.25 ms) | 0.240 units | 2.9x |
| **`parse`** | **0.078 units** (0.25 ms) | 0.240 units | 3.1x |
| **`dump`** | **0.292–0.302 units** (0.93–0.94 ms) | 0.450 units | 1.5x |

The ceilings have not been tightened to these figures: that needs measurements
from the Linux CI runner, and this machine is not it.

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
builds in alternation on the same interpreter and machine. On a quiet machine,
differences within about 2% are run-to-run noise; on a shared, loaded machine
expect 5–10%.

## Where to Look Next

- [Performance Roadmap](performance-roadmap.md) — The theoretical headroom
  remaining, and the future API changes (such as converting `DumpLine` to a
  `__slots__` class) planned for 5.0.
- [Architecture Overview](architecture.md) — The internal design of the Rust
  core, memory layout, and PyO3 handle lifecycle.
- [3.x to 4.0 Migration Guide](../user/rust-core-changes.md) — Guide for
  upgrading existing codebases to hier_config 4.0.
