//! Criterion benchmarks for the native workflows in `docs/dev/benchmarks.md`.
//!
//! The configs have the same generator shape as `_generate_large_ios_config` /
//! `_generate_large_xr_config` in `tests/benchmarks/test_benchmarks.py`, but the
//! interface counts differ (120, 1200 and 6000 IOS interfaces give ~1k, ~10k and
//! ~50k lines here; see the Notes in `docs/dev/benchmarks.md`). These time the
//! Rust core only; Python handle, conversion and interpreter costs are measured
//! by the Python benchmarks.
//!
//! ```text
//! cargo bench -p hier_config_core --bench workflows -- --save-baseline before
//! cargo bench -p hier_config_core --bench workflows -- --baseline before
//! ```

use std::fmt::Write as _;
use std::hint::black_box;
use std::time::Duration;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use hier_config_core::{Platform, Tree, WorkflowRemediation, load_fast};

// Matches the Python extension's allocator, so native and Python timings see
// the same allocation costs.
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

const IOS: Platform = Platform::CiscoIos;
const OSPF_COST: &str = " ip ospf cost 100";
const OSPF_COST_CHANGED: &str = " ip ospf cost 200";
const WRITE: &str = "writing to a String cannot fail";

fn ios_config(interfaces: usize) -> String {
    let mut out = String::from(
        "hostname LARGE-ROUTER\n!\nip name-server 8.8.8.8\nip name-server 8.8.4.4\n!\n\
         aaa new-model\naaa authentication login default local\n\
         aaa authorization exec default local\n!\nip access-list extended MGMT_ACL\n \
         10 permit tcp 10.0.0.0 0.255.255.255 any eq 22\n \
         20 permit tcp 172.16.0.0 0.15.255.255 any eq 22\n 30 deny ip any any log\n!\n\
         ip prefix-list DEFAULT_ONLY seq 10 permit 0.0.0.0/0\n!\n",
    );
    for i in 0..interfaces {
        let (hi, lo) = (i / 256, i % 256);
        writeln!(
            out,
            "interface GigabitEthernet0/{i}\n description Link to device {i}\n \
             ip address 10.{hi}.{lo}.1 255.255.255.252\n ip ospf cost 100\n \
             ip ospf network point-to-point\n no shutdown\n!"
        )
        .expect(WRITE);
    }
    out.push_str("router ospf 1\n router-id 10.0.0.1\n auto-cost reference-bandwidth 100000\n");
    for i in 0..interfaces {
        writeln!(out, " network 10.{}.{}.0 0.0.0.3 area 0", i / 256, i % 256).expect(WRITE);
    }
    out.push_str("!\nrouter bgp 65000\n bgp router-id 10.0.0.1\n bgp log-neighbor-changes\n");
    for i in 0..interfaces.min(200) {
        let (hi, lo) = (i / 256, i % 256);
        writeln!(
            out,
            " neighbor 10.{hi}.{lo}.2 remote-as 6500{i}\n \
             neighbor 10.{hi}.{lo}.2 description Peer-{i}"
        )
        .expect(WRITE);
    }
    out.push_str(
        "!\nline con 0\n exec-timeout 5 0\n logging synchronous\nline vty 0 4\n \
         access-class MGMT_ACL in\n transport input ssh\n!",
    );
    out
}

fn xr_config(interfaces: usize) -> String {
    let mut out = String::from(
        "hostname LARGE-XR-ROUTER\nlogging console informational\n\
         logging source-interface Loopback0\n",
    );
    for i in 0..interfaces {
        let (hi, lo) = (i / 256, i % 256);
        writeln!(
            out,
            "interface GigabitEthernet0/0/0/{i}\n description Link to device {i}\n \
             ipv4 address 10.{hi}.{lo}.1 255.255.255.252\n mtu 9000\n load-interval 30\n!"
        )
        .expect(WRITE);
    }
    out.push_str("router bgp 65000\n bgp router-id 10.0.0.1\n");
    for i in 0..interfaces {
        let (hi, lo) = (i / 256, i % 256);
        writeln!(
            out,
            " neighbor 10.{hi}.{lo}.2\n  remote-as 6500{i}\n  description Peer {i}"
        )
        .expect(WRITE);
    }
    out.push_str("!\nrouter ospf 1\n router-id 10.0.0.1\n");
    for i in 0..interfaces {
        writeln!(out, " area 0 interface GigabitEthernet0/0/0/{i} cost 100").expect(WRITE);
    }
    out.push('!');
    out
}

/// The IOS config with multi-byte UTF-8 (Latin, punctuation and CJK) in every
/// description, so byte- and char-oriented paths both get exercised.
fn unicode_config(interfaces: usize) -> String {
    ios_config(interfaces)
        .replace("Link to device", "Liaison vers l'équipement — 设备")
        .replace("Peer-", "Pair-ü-")
}

fn parse(text: &str) -> Tree {
    Tree::from_str(IOS, text).expect("benchmark config parses")
}

/// Running and generated trees where the first `changes` interfaces get a new
/// OSPF cost.
fn remediation_pair(text: &str, changes: usize) -> (Tree, Tree) {
    let generated = text.replacen(OSPF_COST, OSPF_COST_CHANGED, changes);
    (parse(text), parse(&generated))
}

fn bench_parse(c: &mut Criterion) {
    let mut group = c.benchmark_group("parse");
    for (name, platform, text) in [
        ("ios_1k", IOS, ios_config(120)),
        ("ios_10k", IOS, ios_config(1200)),
        ("ios_50k", IOS, ios_config(6000)),
        ("xr_10k", Platform::CiscoXr, xr_config(1250)),
        ("unicode_10k", IOS, unicode_config(1200)),
    ] {
        group.bench_function(name, |b| {
            b.iter(|| Tree::from_str(platform, black_box(&text)).expect("parses"));
        });
    }
    // `HConfig.from_lines`: pre-split lines, only `per_line_sub` preprocessing.
    let text = ios_config(1200);
    let lines: Vec<&str> = text.lines().collect();
    group.bench_function("fast_load_ios_10k", |b| {
        b.iter(|| {
            let mut tree = Tree::for_platform(IOS);
            load_fast(&mut tree, black_box(&lines), true).expect("loads");
            tree
        });
    });
    // `HConfig.from_lines` given one string: split in Rust, same loader as above.
    group.bench_function("fast_load_text_ios_10k", |b| {
        b.iter(|| {
            let mut tree = Tree::for_platform(IOS);
            hier_config_core::parser::load_fast_text(&mut tree, black_box(&text), true)
                .expect("loads");
            tree
        });
    });
    group.finish();
}

fn bench_tree(c: &mut Criterion) {
    let tree = parse(&ios_config(1200));
    c.bench_function("deepcopy_10k", |b| b.iter(|| black_box(&tree).clone()));
    c.bench_function("all_children_sorted_10k", |b| {
        b.iter(|| black_box(&tree).all_children_sorted(tree.root));
    });
    c.bench_function("dump_10k", |b| b.iter(|| black_box(&tree).dump()));
    // `str(config)` renders with sectional exits; `to_lines()` renders without.
    c.bench_function("render/lines_10k", |b| {
        b.iter(|| black_box(&tree).lines(tree.root, true));
    });
    c.bench_function("render/to_lines_10k", |b| {
        b.iter(|| black_box(&tree).dump_simple(false));
    });
    c.bench_function("merge_10k", |b| {
        b.iter_batched(
            || Tree::new(tree.driver.clone()),
            |mut target| {
                target.merge(black_box(&tree)).expect("merges");
                target
            },
            BatchSize::LargeInput,
        );
    });
}

fn bench_remediation(c: &mut Criterion) {
    let mut group = c.benchmark_group("remediation");
    for (name, text, changes) in [
        ("10k", ios_config(1200), 100),
        ("50k", ios_config(6000), 200),
        ("unicode_10k", unicode_config(1200), 100),
        ("10k_all_changed", ios_config(1200), usize::MAX),
    ] {
        let (running, generated) = remediation_pair(&text, changes);
        group.bench_function(name, |b| {
            b.iter(|| black_box(&running).config_to_get_to(black_box(&generated)));
        });
    }
    // Mirrors `test_remediation_completely_different`: nothing in common.
    let disjoint_running = parse(&ios_config(500));
    let mut other = String::from("hostname OTHER-ROUTER\n");
    for i in 0..500 {
        writeln!(
            other,
            "interface Loopback{i}\n description Loopback {i}\n \
             ip address 192.168.{}.{} 255.255.255.255",
            i / 256,
            i % 256
        )
        .expect(WRITE);
    }
    let disjoint_generated = parse(&other);
    group.bench_function("disjoint_500", |b| {
        b.iter(|| black_box(&disjoint_running).config_to_get_to(black_box(&disjoint_generated)));
    });
    group.finish();

    let (running, generated) = remediation_pair(&ios_config(1000), 100);
    let remediation = running
        .config_to_get_to(&generated)
        .expect("remediation succeeds");
    assert_eq!(
        remediation.arena[remediation.root].children.len(),
        100,
        "each changed interface yields one remediation section"
    );
    c.bench_function("future_1000_interfaces", |b| {
        b.iter(|| black_box(&running).future(black_box(&remediation), false));
    });
    // Mirrors `test_future_flat_additions_scale_linearly` at its larger size.
    let flat = |prefix: &str| {
        let lines: Vec<String> = (0..4000).map(|i| format!("{prefix} {i}")).collect();
        let mut tree = Tree::for_platform(Platform::Generic);
        let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
        load_fast(&mut tree, &refs, true).expect("loads");
        tree
    };
    let (flat_running, flat_changes) = (flat("existing"), flat("new"));
    c.bench_function("future_flat_additions_4000", |b| {
        b.iter(|| black_box(&flat_running).future(black_box(&flat_changes), false));
    });
    c.bench_function("rollback_1000_interfaces", |b| {
        b.iter(|| {
            let workflow =
                WorkflowRemediation::from_borrowed(black_box(&running), black_box(&generated))
                    .expect("same platform");
            black_box(workflow.rollback_config().expect("rollback succeeds"));
        });
    });
}

fn bench_diff(c: &mut Criterion) {
    let mut group = c.benchmark_group("diff");
    for (name, text) in [
        ("10k", ios_config(1200)),
        ("unicode_10k", unicode_config(1200)),
    ] {
        let (running, generated) = remediation_pair(&text, 100);
        group.bench_function(format!("unified_diff/{name}"), |b| {
            b.iter(|| black_box(&running).unified_diff(black_box(&generated)));
        });
        group.bench_function(format!("difference/{name}"), |b| {
            b.iter(|| black_box(&running).difference(black_box(&generated)));
        });
    }
    group.finish();
}

fn config() -> Criterion {
    Criterion::default()
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(3))
}

criterion_group! {
    name = benches;
    config = config();
    targets = bench_parse, bench_tree, bench_remediation, bench_diff
}
criterion_main!(benches);
