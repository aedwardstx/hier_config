"""Performance benchmarks for hier_config.

These tests are skipped by default. Run with:
    uv run pytest -m benchmark -v
"""

import time
from collections.abc import Callable
from functools import partial

import pytest

from hier_config import HConfig
from hier_config.models import Platform
from hier_config.workflows import WorkflowRemediation

pytestmark = pytest.mark.benchmark


def _generate_large_ios_config(num_interfaces: int = 1000) -> str:
    """Generate a large Cisco IOS-style config (~10k+ lines at default)."""
    lines = [
        "hostname LARGE-ROUTER",
        "!",
        "ip name-server 8.8.8.8",
        "ip name-server 8.8.4.4",
        "!",
        "aaa new-model",
        "aaa authentication login default local",
        "aaa authorization exec default local",
        "!",
        "ip access-list extended MGMT_ACL",
        " 10 permit tcp 10.0.0.0 0.255.255.255 any eq 22",
        " 20 permit tcp 172.16.0.0 0.15.255.255 any eq 22",
        " 30 deny ip any any log",
        "!",
        "ip prefix-list DEFAULT_ONLY seq 10 permit 0.0.0.0/0",
        "!",
    ]
    for i in range(num_interfaces):
        lines.extend(
            [
                f"interface GigabitEthernet0/{i}",
                f" description Link to device {i}",
                f" ip address 10.{i // 256}.{i % 256}.1 255.255.255.252",
                " ip ospf cost 100",
                " ip ospf network point-to-point",
                " no shutdown",
                "!",
            ]
        )
    lines.extend(
        [
            "router ospf 1",
            " router-id 10.0.0.1",
            " auto-cost reference-bandwidth 100000",
        ]
    )
    lines.extend(
        f" network 10.{i // 256}.{i % 256}.0 0.0.0.3 area 0"
        for i in range(num_interfaces)
    )
    lines.extend(
        [
            "!",
            "router bgp 65000",
            " bgp router-id 10.0.0.1",
            " bgp log-neighbor-changes",
        ]
    )
    for i in range(min(num_interfaces, 200)):
        lines.extend(
            [
                f" neighbor 10.{i // 256}.{i % 256}.2 remote-as 6500{i}",
                f" neighbor 10.{i // 256}.{i % 256}.2 description Peer-{i}",
            ]
        )
    lines.extend(
        [
            "!",
            "line con 0",
            " exec-timeout 5 0",
            " logging synchronous",
            "line vty 0 4",
            " access-class MGMT_ACL in",
            " transport input ssh",
            "!",
        ]
    )
    return "\n".join(lines)


def _generate_large_xr_config(num_interfaces: int = 1000) -> str:
    """Generate a large Cisco IOS-XR-style config (~10k+ lines at default)."""
    lines = [
        "hostname LARGE-XR-ROUTER",
        "logging console informational",
        "logging source-interface Loopback0",
    ]
    for i in range(num_interfaces):
        lines.extend(
            [
                f"interface GigabitEthernet0/0/0/{i}",
                f" description Link to device {i}",
                f" ipv4 address 10.{i // 256}.{i % 256}.1 255.255.255.252",
                " mtu 9000",
                " load-interval 30",
                "!",
            ]
        )
    lines.extend(
        [
            "router bgp 65000",
            " bgp router-id 10.0.0.1",
        ]
    )
    for i in range(num_interfaces):
        lines.extend(
            [
                f" neighbor 10.{i // 256}.{i % 256}.2",
                f"  remote-as 6500{i}",
                f"  description Peer {i}",
            ]
        )
    lines.extend(
        [
            "!",
            "router ospf 1",
            " router-id 10.0.0.1",
        ]
    )
    lines.extend(
        f" area 0 interface GigabitEthernet0/0/0/{i} cost 100"
        for i in range(num_interfaces)
    )
    lines.append("!")
    return "\n".join(lines)


def _time_fn(fn: Callable[[], object], iterations: int = 3) -> float:
    """Return the best elapsed time in seconds over multiple iterations."""
    best = float("inf")
    for _ in range(iterations):
        start = time.perf_counter()
        fn()
        elapsed = time.perf_counter() - start
        best = min(best, elapsed)
    return best


def _time_pair(
    first: Callable[[], object],
    second: Callable[[], object],
    iterations: int = 30,
) -> tuple[float, float]:
    """Return the best elapsed time in seconds of each function, sampled alternately.

    A sub-millisecond call needs many samples for its minimum to be stable, and
    alternating the two keeps machine-wide drift from favouring either one.
    """
    best_first = best_second = float("inf")
    for _ in range(iterations):
        best_first = min(best_first, _time_fn(first, iterations=1))
        best_second = min(best_second, _time_fn(second, iterations=1))
    return best_first, best_second


class TestParsingBenchmarks:
    """Benchmarks for config parsing."""

    @staticmethod
    def test_parse_large_ios_config() -> None:
        """Parse a ~10k line IOS config via get_hconfig."""
        config_text = _generate_large_ios_config()
        elapsed = _time_fn(lambda: HConfig.from_text(Platform.CISCO_IOS, config_text))
        line_count = config_text.count("\n")
        print(f"\nget_hconfig: {line_count} lines in {elapsed:.4f}s")
        assert elapsed < 5.0, f"Parsing took {elapsed:.2f}s, expected < 5s"

    @staticmethod
    def test_parse_large_xr_config() -> None:
        """Parse a ~10k line XR config via get_hconfig."""
        config_text = _generate_large_xr_config()
        elapsed = _time_fn(lambda: HConfig.from_text(Platform.CISCO_XR, config_text))
        line_count = config_text.count("\n")
        print(f"\nget_hconfig (XR): {line_count} lines in {elapsed:.4f}s")
        assert elapsed < 5.0, f"Parsing took {elapsed:.2f}s, expected < 5s"

    @staticmethod
    def test_fast_load_large_ios_config() -> None:
        """Parse a ~10k line IOS config via get_hconfig_fast_load."""
        config_text = _generate_large_ios_config()
        config_lines = tuple(config_text.splitlines())
        elapsed = _time_fn(
            lambda: HConfig.from_lines(Platform.CISCO_IOS, config_lines),
        )
        print(f"\nget_hconfig_fast_load: {len(config_lines)} lines in {elapsed:.4f}s")
        assert elapsed < 5.0, f"Fast load took {elapsed:.2f}s, expected < 5s"

    @staticmethod
    def test_fast_load_vs_get_hconfig() -> None:
        """Fast load should not be slower than get_hconfig on the same input.

        Both calls receive the same ``str`` so the comparison isolates the two
        native load paths. A tuple or list of lines additionally pays per-line
        Python-to-Rust string conversion that ``from_text`` never performs, and
        ``test_fast_load_large_ios_config`` covers that input shape.
        """
        config_text = _generate_large_ios_config()

        time_full, time_fast = _time_pair(
            lambda: HConfig.from_text(Platform.CISCO_IOS, config_text),
            lambda: HConfig.from_lines(Platform.CISCO_IOS, config_text),
        )
        ratio = time_full / time_fast if time_fast > 0 else float("inf")
        print(
            f"\nget_hconfig: {time_full:.4f}s, "
            f"fast_load: {time_fast:.4f}s, "
            f"ratio: {ratio:.1f}x"
        )
        # fast_load should not be significantly slower (allow 10% variance for CI noise)
        assert time_fast <= time_full * 1.1, (
            "fast_load should not be slower than get_hconfig"
        )


class TestRemediationBenchmarks:
    """Benchmarks for remediation remediation."""

    @staticmethod
    def test_remediation_small_diff() -> None:
        """Remediation with ~5% of interfaces changed."""
        running_text = _generate_large_ios_config()
        running = HConfig.from_text(Platform.CISCO_IOS, running_text)

        # Modify 50 interfaces in generated config
        generated_text = running_text.replace(
            " ip ospf cost 100", " ip ospf cost 200", 50
        )
        generated = HConfig.from_text(Platform.CISCO_IOS, generated_text)

        elapsed = _time_fn(lambda: running.remediation(generated))
        print(f"\nRemediation (10% diff): {elapsed:.4f}s")
        assert elapsed < 5.0, f"Remediation took {elapsed:.2f}s, expected < 5s"

    @staticmethod
    def test_remediation_large_diff() -> None:
        """Remediation with ~100% of interfaces changed."""
        running = HConfig.from_text(Platform.CISCO_IOS, _generate_large_ios_config())
        generated_text = _generate_large_ios_config().replace(
            " ip ospf cost 100", " ip ospf cost 200"
        )
        generated = HConfig.from_text(Platform.CISCO_IOS, generated_text)

        elapsed = _time_fn(lambda: running.remediation(generated))
        print(f"\nRemediation (100% diff): {elapsed:.4f}s")
        assert elapsed < 10.0, f"Remediation took {elapsed:.2f}s, expected < 10s"

    @staticmethod
    def test_remediation_completely_different() -> None:
        """Remediation between two entirely different configs."""
        running = HConfig.from_text(Platform.CISCO_IOS, _generate_large_ios_config(500))
        # Generate a completely different config
        lines = ["hostname OTHER-ROUTER"]
        for i in range(500):
            lines.extend(
                [
                    f"interface Loopback{i}",
                    f" description Loopback {i}",
                    f" ip address 192.168.{i // 256}.{i % 256} 255.255.255.255",
                ]
            )
        generated = HConfig.from_text(Platform.CISCO_IOS, "\n".join(lines))

        elapsed = _time_fn(lambda: running.remediation(generated))
        print(f"\nRemediation (completely different): {elapsed:.4f}s")
        assert elapsed < 10.0, f"Remediation took {elapsed:.2f}s, expected < 10s"

    @staticmethod
    def test_future_config_large() -> None:
        """Compute future config from running and remediation."""
        running_text = _generate_large_ios_config()
        running = HConfig.from_text(Platform.CISCO_IOS, running_text)
        generated_text = running_text.replace(
            " ip ospf cost 100", " ip ospf cost 200", 100
        )
        generated = HConfig.from_text(Platform.CISCO_IOS, generated_text)
        remediation = running.remediation(generated)
        assert len(remediation.children) == 100
        assert not tuple(running.future(remediation).unified_diff(generated))

        elapsed = _time_fn(lambda: running.future(remediation))
        print(f"\nFuture config (100 modified interfaces): {elapsed:.4f}s")
        assert elapsed < 5.0, (
            f"Future config calculation took {elapsed:.2f}s, expected < 5s"
        )

    @staticmethod
    def test_rollback_workflow_large() -> None:
        """Compute rollback config via WorkflowRemediation."""
        running_text = _generate_large_ios_config()
        running = HConfig.from_text(Platform.CISCO_IOS, running_text)
        generated_text = running_text.replace(
            " ip ospf cost 100", " ip ospf cost 200", 100
        )
        generated = HConfig.from_text(Platform.CISCO_IOS, generated_text)
        workflow = WorkflowRemediation(running, generated)
        projected = running.future(workflow.remediation_config)
        assert not tuple(
            projected.future(workflow.rollback_config).unified_diff(running)
        )

        def run_workflow() -> None:
            wf = WorkflowRemediation(running, generated)
            _ = wf.rollback_config

        elapsed = _time_fn(run_workflow)
        print(f"\nWorkflowRemediation rollback_config: {elapsed:.4f}s")
        assert elapsed < 5.0, f"Rollback workflow took {elapsed:.2f}s, expected < 5s"

    @staticmethod
    def test_future_flat_additions_scale_linearly() -> None:
        """Reject a per-addition sibling scan in future negated-counterpart lookup."""
        timings: list[float] = []
        for size in (1000, 4000):
            running = HConfig.from_lines(
                Platform.GENERIC, tuple(f"existing {i}" for i in range(size))
            )
            changes = HConfig.from_lines(
                Platform.GENERIC, tuple(f"new {i}" for i in range(size))
            )
            expected = changes.to_lines() + running.to_lines()
            assert running.future(changes).to_lines() == expected
            elapsed = _time_fn(partial(running.future, changes), iterations=7)
            timings.append(elapsed)
            print(f"\nFuture flat additions ({size} + {size} lines): {elapsed:.6f}s")

        # Four times the input permits 2x headroom, but not quadratic (~16x) growth.
        assert timings[1] <= timings[0] * 8, (
            f"Flat future scaling is superlinear: {timings[1] / timings[0]:.2f}x"
        )


class TestIterationBenchmarks:
    """Benchmarks for tree traversal and iteration."""

    @staticmethod
    def test_all_children_sorted() -> None:
        """Iterate all_children_sorted on a large config."""
        config = HConfig.from_text(Platform.CISCO_IOS, _generate_large_ios_config())

        elapsed = _time_fn(lambda: list(config.all_children_sorted()))
        child_count = len(list(config.all_children()))
        print(f"\nall_children_sorted: {child_count} nodes in {elapsed:.4f}s")
        assert elapsed < 2.0, f"Iteration took {elapsed:.2f}s, expected < 2s"

    @staticmethod
    def test_to_lines() -> None:
        """Dump a large config to simple text."""
        config = HConfig.from_text(Platform.CISCO_IOS, _generate_large_ios_config())

        elapsed = _time_fn(config.to_lines)
        line_count = len(config.to_lines())
        print(f"\nto_lines: {line_count} lines in {elapsed:.4f}s")
        assert elapsed < 2.0, f"to_lines took {elapsed:.2f}s, expected < 2s"

    @staticmethod
    def test_deep_copy() -> None:
        """Deep copy a large config tree."""
        config = HConfig.from_text(Platform.CISCO_IOS, _generate_large_ios_config())

        elapsed = _time_fn(config.deep_copy)
        print(f"\ndeep_copy: {elapsed:.4f}s")
        assert elapsed < 5.0, f"deep_copy took {elapsed:.2f}s, expected < 5s"

    @staticmethod
    def test_str_render() -> None:
        """Render a large config with sectional exits, as ``str()`` does."""
        config = HConfig.from_text(Platform.CISCO_IOS, _generate_large_ios_config())
        rendered = str(config)
        assert rendered.splitlines() == list(config.to_lines(sectional_exiting=True))

        elapsed = _time_fn(partial(str, config))
        print(f"\nstr: {rendered.count(chr(10)) + 1} lines in {elapsed:.4f}s")
        assert elapsed < 2.0, f"str took {elapsed:.2f}s, expected < 2s"

    @staticmethod
    def test_dump() -> None:
        """Serialise a large config to a ``Dump`` model."""
        config = HConfig.from_text(Platform.CISCO_IOS, _generate_large_ios_config())
        assert len(config.dump().lines) == len(tuple(config.all_children()))

        elapsed = _time_fn(config.dump)
        print(f"\ndump: {elapsed:.4f}s")
        assert elapsed < 2.0, f"dump took {elapsed:.2f}s, expected < 2s"


class TestComparisonBenchmarks:
    """Benchmarks for comparing and combining large configs."""

    @staticmethod
    def _changed_pair() -> tuple[HConfig, HConfig]:
        running_text = _generate_large_ios_config()
        generated_text = running_text.replace(
            " ip ospf cost 100", " ip ospf cost 200", 100
        )
        return (
            HConfig.from_text(Platform.CISCO_IOS, running_text),
            HConfig.from_text(Platform.CISCO_IOS, generated_text),
        )

    @staticmethod
    def test_unified_diff() -> None:
        """Unified diff of two large configs with 100 changed interfaces."""
        running, generated = TestComparisonBenchmarks._changed_pair()
        diff = tuple(running.unified_diff(generated))
        # Each changed interface yields its header plus a removed and added line.
        assert len(diff) == 300

        elapsed = _time_fn(lambda: tuple(running.unified_diff(generated)))
        print(f"\nunified_diff: {len(diff)} lines in {elapsed:.4f}s")
        assert elapsed < 2.0, f"unified_diff took {elapsed:.2f}s, expected < 2s"

    @staticmethod
    def test_difference() -> None:
        """Difference of two large configs with 100 changed interfaces."""
        running, generated = TestComparisonBenchmarks._changed_pair()
        difference = running.difference(generated)
        assert len(difference.children) == 100

        elapsed = _time_fn(partial(running.difference, generated))
        print(f"\ndifference: {elapsed:.4f}s")
        assert elapsed < 2.0, f"difference took {elapsed:.2f}s, expected < 2s"

    @staticmethod
    def test_merge() -> None:
        """Merge a large config into an empty one."""
        config = HConfig.from_text(Platform.CISCO_IOS, _generate_large_ios_config())
        merged = HConfig.from_text(Platform.CISCO_IOS, "").merge(config)
        assert merged.to_lines() == config.to_lines()

        elapsed = _time_fn(
            lambda: HConfig.from_text(Platform.CISCO_IOS, "").merge(config)
        )
        print(f"\nmerge: {elapsed:.4f}s")
        assert elapsed < 5.0, f"merge took {elapsed:.2f}s, expected < 5s"
