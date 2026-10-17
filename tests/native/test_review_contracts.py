"""Regression coverage for the v4 extension and optional-loader contracts."""

from __future__ import annotations

import sys
from importlib.abc import MetaPathFinder
from typing import TYPE_CHECKING

import pytest

from hier_config import Platform, get_hconfig
from hier_config.platforms.cisco_ios.driver import HConfigDriverCiscoIOS
from hier_config.utils import load_driver_rules, load_hier_config_tags, load_tag_rules

if TYPE_CHECKING:
    from collections.abc import Sequence
    from importlib.machinery import ModuleSpec
    from pathlib import Path
    from types import ModuleType


def test_custom_preprocessor_cannot_be_silently_ignored() -> None:
    def redact(config_text: str) -> str:
        return config_text.replace("SECRET", "REDACTED")

    with pytest.raises(TypeError, match=r"config_preprocessor.*before"):
        type(
            "RedactingDriver",
            (HConfigDriverCiscoIOS,),
            {"config_preprocessor": staticmethod(redact)},
        )


def test_yaml_loaders_report_missing_optional_dependency(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    tags_file = tmp_path / "tags.yml"
    tags_file.write_text("[]", encoding="utf-8")
    monkeypatch.setitem(sys.modules, "yaml", None)

    with pytest.raises(ImportError, match=r"hier-config\[yaml\]"):
        load_hier_config_tags(str(tags_file))
    with pytest.raises(ImportError, match=r"hier-config\[yaml\]"):
        load_tag_rules(str(tags_file))
    with pytest.raises(ImportError, match=r"hier-config\[yaml\]"):
        load_driver_rules(str(tags_file), Platform.GENERIC)

    assert not load_tag_rules([])
    config = get_hconfig(load_driver_rules({}, Platform.GENERIC), "hostname router")
    assert config.to_lines() == ("hostname router",)


class _BrokenYamlFinder(MetaPathFinder):
    """Simulate an installed PyYAML whose own dependency is missing."""

    def __init__(self, missing_dependency: str) -> None:
        self.missing_dependency = missing_dependency

    def find_spec(
        self,
        fullname: str,
        path: Sequence[str] | None,
        target: ModuleType | None = None,
    ) -> ModuleSpec | None:
        del path, target
        if fullname != "yaml":
            return None
        message = f"No module named {self.missing_dependency!r}"
        raise ModuleNotFoundError(message, name=self.missing_dependency)


def test_yaml_loaders_propagate_unrelated_missing_module(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A broken PyYAML install is not misreported as the optional extra missing."""
    tags_file = tmp_path / "tags.yml"
    tags_file.write_text("[]", encoding="utf-8")
    monkeypatch.delitem(sys.modules, "yaml", raising=False)
    monkeypatch.setattr(
        sys, "meta_path", [_BrokenYamlFinder("yaml_backend"), *sys.meta_path]
    )

    with pytest.raises(ModuleNotFoundError, match="yaml_backend") as excinfo:
        load_tag_rules(str(tags_file))
    assert excinfo.value.name == "yaml_backend"
