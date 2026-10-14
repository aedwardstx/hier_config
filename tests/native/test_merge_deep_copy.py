"""Contracts for `merge()` and cross-tree `add_deep_copy_of()`.

Both run natively when copying between distinct trees. These tests pin the
observable result (structure, comments, tags, order weights and the Python
`Instance` records a merge leaves behind) and check it against the overridable
Python dispatch path that `HConfig` subclasses still take.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from hier_config import HConfig, get_hconfig, get_hconfig_driver
from hier_config.exceptions import DuplicateChildError
from hier_config.models import Instance, Platform

if TYPE_CHECKING:
    from hier_config.child import HConfigChild

InstanceRecord = tuple[int, tuple[str, ...], tuple[str, ...]]
NodeRecord = tuple[
    tuple[str, ...], int, tuple[str, ...], tuple[str, ...], tuple[InstanceRecord, ...]
]


def _source(hostname: str, extra: str) -> HConfig:
    config = get_hconfig(
        Platform.CISCO_IOS,
        f"hostname {hostname}\n"
        "interface Ethernet1\n"
        " description uplink\n"
        f" {extra}\n"
        "router bgp 65000\n"
        " neighbor 192.0.2.1 remote-as 65001\n",
    )
    interface = config.get_child(equals="interface Ethernet1")
    assert interface is not None
    interface.comments.add(f"from {hostname}")
    interface.order_weight = 7
    description = interface.get_child(equals="description uplink")
    assert description is not None
    description.tags_add(f"tag-{hostname}")
    return config


def _snapshot(config: HConfig) -> tuple[NodeRecord, ...]:
    return tuple(
        (
            tuple(child.path()),
            child.order_weight,
            tuple(sorted(child.comments)),
            tuple(sorted(child.tags)),
            tuple(
                (item.id, tuple(sorted(item.comments)), tuple(sorted(item.tags)))
                for item in child.instances
            ),
        )
        for child in config.all_children()
    )


def _interface(config: HConfig) -> HConfigChild:
    interface = config.get_child(equals="interface Ethernet1")
    assert interface is not None
    return interface


def test_merge_records_one_instance_per_source() -> None:
    first, second = _source("r1", "shutdown"), _source("r2", "mtu 9000")
    merged = get_hconfig(Platform.CISCO_IOS)

    assert merged.merge([first, second]) is merged

    interface = _interface(merged)
    assert [child.text for child in interface.children] == [
        "description uplink",
        "shutdown",
        "mtu 9000",
    ]
    assert interface.order_weight == 7
    assert set(interface.comments) == {"from r1", "from r2"}
    assert interface.instances == [
        Instance(
            id=id(first), comments=frozenset({"from r1"}), tags=frozenset({"tag-r1"})
        ),
        Instance(
            id=id(second), comments=frozenset({"from r2"}), tags=frozenset({"tag-r2"})
        ),
    ]
    description = interface.get_child(equals="description uplink")
    assert description is not None
    assert description.tags == frozenset({"tag-r1", "tag-r2"})
    assert [item.tags for item in description.instances] == [
        frozenset({"tag-r1"}),
        frozenset({"tag-r2"}),
    ]
    shutdown = interface.get_child(equals="shutdown")
    assert shutdown is not None
    assert [item.id for item in shutdown.instances] == [id(first)]
    assert "!2 instances" in interface.cisco_style_text(style="merged")


def test_merge_matches_the_overridable_python_path() -> None:
    calls: list[str] = []

    class TracingConfig(HConfig):
        """Overrides `add_deep_copy_of`, which forces the Python dispatch path."""

        def add_deep_copy_of(
            self, child_to_add: HConfigChild, *, merged: bool = False
        ) -> HConfigChild:
            calls.append(child_to_add.text)
            return super().add_deep_copy_of(child_to_add, merged=merged)

    first, second = _source("r1", "shutdown"), _source("r2", "mtu 9000")
    native = get_hconfig(Platform.CISCO_IOS)
    native.merge([first, second])
    traced = TracingConfig(get_hconfig_driver(Platform.CISCO_IOS))
    traced.merge([first, second])

    assert calls == [child.text for child in (*first.children, *second.children)]
    assert _snapshot(native) == _snapshot(traced)
    assert native.to_lines() == traced.to_lines()
    assert [
        child.cisco_style_text(style="merged") for child in native.all_children()
    ] == [child.cisco_style_text(style="merged") for child in traced.all_children()]


def test_merge_appends_to_instance_lists_already_read_from_python() -> None:
    first, second = _source("r1", "shutdown"), _source("r2", "mtu 9000")
    merged = get_hconfig(Platform.CISCO_IOS).merge(first)
    instances = _interface(merged).instances
    instances.append(Instance(id=1, comments=frozenset(), tags=frozenset({"manual"})))

    merged.merge(second)

    assert _interface(merged).instances is instances
    assert [item.id for item in instances] == [id(first), 1, id(second)]
    assert "!3 instances" in _interface(merged).cisco_style_text(style="merged")


def test_cross_tree_deep_copy_keeps_metadata_without_instances() -> None:
    source = _source("r1", "shutdown")
    target = get_hconfig(Platform.CISCO_IOS, "hostname target")

    copied = target.add_deep_copy_of(_interface(source))

    assert copied.parent is target
    assert copied.order_weight == 7
    assert set(copied.comments) == {"from r1"}
    assert [child.text for child in copied.children] == [
        "description uplink",
        "shutdown",
    ]
    assert all(not child.instances for child in target.all_children())
    description = copied.get_child(equals="description uplink")
    assert description is not None
    assert description.tags == frozenset({"tag-r1"})
    with pytest.raises(DuplicateChildError):
        target.add_deep_copy_of(_interface(source))


def test_deep_copy_into_a_child_and_within_one_tree() -> None:
    source = _source("r1", "shutdown")
    target = get_hconfig(Platform.CISCO_IOS, "interface Ethernet2")
    parent = target.get_child(equals="interface Ethernet2")
    assert parent is not None

    nested = parent.add_deep_copy_of(_interface(source), merged=True)

    assert tuple(nested.path()) == ("interface Ethernet2", "interface Ethernet1")
    assert [item.id for item in nested.instances] == [id(source)]

    bgp = source.get_child(equals="router bgp 65000")
    assert bgp is not None
    within = _interface(source).add_deep_copy_of(bgp)
    assert tuple(within.path()) == ("interface Ethernet1", "router bgp 65000")
    assert [child.text for child in within.children] == [
        "neighbor 192.0.2.1 remote-as 65001"
    ]
