from hier_config import HConfig, Platform
from hier_config.platforms.aruba_aoscx.driver import (
    HConfigDriverArubaAOSCX,
    split_interface_vlan_trunk_allowed,
)
from hier_config.platforms.utils import split_vlan_id_lists


def test_default_post_load_callbacks_are_public() -> None:
    """Built-in AOS-CX post-load callbacks are public, pinned by identity (#286)."""
    callbacks = HConfigDriverArubaAOSCX().rules.post_load_callbacks

    assert split_vlan_id_lists in callbacks
    assert split_interface_vlan_trunk_allowed in callbacks


def test_split_trunk_allowed_leaves_python_only_whitespace_spec_untouched() -> None:
    r"""A trailing ``\x1f`` survives Rust trimming but is whitespace to Python.

    The line therefore splits into only three words in Python; the callback
    must leave it alone, exactly as the native load does.
    """
    lines = ("interface 1/1/1", "  vlan trunk allowed \x1f")
    config = HConfig.from_lines(Platform.ARUBA_AOSCX, ["interface 1/1/1"])
    interface = config.get_child(equals="interface 1/1/1")
    assert interface is not None
    interface.add_child("vlan trunk allowed \x1f")

    split_interface_vlan_trunk_allowed(config)

    assert config.dump_simple() == lines
    assert HConfig.from_text(Platform.ARUBA_AOSCX, "\n".join(lines)).dump_simple() == (
        lines
    )
