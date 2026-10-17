from unittest.mock import patch

import pytest

from hier_config import HConfig, get_hconfig_driver
from hier_config.child import HConfigChild
from hier_config.models import Platform
from hier_config.platforms.arista_eos.driver import HConfigDriverAristaEOS
from hier_config.platforms.aruba_aoscx.driver import HConfigDriverArubaAOSCX
from hier_config.platforms.cisco_ios.driver import HConfigDriverCiscoIOS
from hier_config.platforms.cisco_nxos.driver import HConfigDriverCiscoNXOS
from hier_config.platforms.cisco_xr.driver import HConfigDriverCiscoIOSXR
from hier_config.platforms.driver_base import (
    HConfigDriverBase,
    clear_rules_cache,
    load_platform_rules,
)
from hier_config.platforms.generic.driver import HConfigDriverGeneric
from hier_config.platforms.hp_comware5.driver import HConfigDriverHPComware5
from hier_config.platforms.hp_procurve.driver import HConfigDriverHPProcurve
from hier_config.platforms.vyos.driver import HConfigDriverVYOS


def test_get_hconfig_driver() -> None:
    assert isinstance(get_hconfig_driver(Platform.ARUBA_AOSCX), HConfigDriverArubaAOSCX)
    assert isinstance(get_hconfig_driver(Platform.ARISTA_EOS), HConfigDriverAristaEOS)
    assert isinstance(get_hconfig_driver(Platform.CISCO_IOS), HConfigDriverCiscoIOS)
    assert isinstance(get_hconfig_driver(Platform.CISCO_NXOS), HConfigDriverCiscoNXOS)
    assert isinstance(get_hconfig_driver(Platform.CISCO_XR), HConfigDriverCiscoIOSXR)
    assert isinstance(get_hconfig_driver(Platform.GENERIC), HConfigDriverGeneric)
    assert isinstance(get_hconfig_driver(Platform.HP_PROCURVE), HConfigDriverHPProcurve)
    assert isinstance(get_hconfig_driver(Platform.HP_COMWARE5), HConfigDriverHPComware5)
    assert isinstance(get_hconfig_driver(Platform.VYOS), HConfigDriverVYOS)


def test_driver_base_properties() -> None:
    """Negation prefixes are driver metadata the Rust core reads."""
    driver = get_hconfig_driver(Platform.GENERIC)

    assert not driver.declaration_prefix
    assert driver.negation_prefix == "no "

    vyos = get_hconfig_driver(Platform.VYOS)
    assert vyos.declaration_prefix == "set "
    assert vyos.negation_prefix == "delete "


def test_negation_swapping_is_owned_by_the_core() -> None:
    """The core, not the driver, swaps negation on a child."""
    config = HConfig.from_text(Platform.GENERIC)
    child = HConfigChild(config, "interface GigabitEthernet0/0")
    assert child.negate().text == "no interface GigabitEthernet0/0"

    child2 = HConfigChild(config, "no interface GigabitEthernet0/1")
    assert child2.negate().text == "interface GigabitEthernet0/1"


def test_driver_base_requires_subclasses_to_supply_rules() -> None:
    """The base driver has no rules of its own, so constructing it fails clearly."""
    with pytest.raises(NotImplementedError, match="must implement _instantiate_rules"):
        HConfigDriverBase()


def test_driver_base_config_preprocessor_returns_text_unchanged() -> None:
    """The default preprocessor is the identity, including for Unicode text."""
    config_text = "hostname r\u00e9seau\n description caf\u00e9 \u2014 \U0001f600\n"

    assert HConfigDriverBase.config_preprocessor(config_text) == config_text


def test_load_platform_rules_falls_back_to_disk_for_unknown_native_platform() -> None:
    """A platform the extension rejects is read from the checked-in rules file."""
    native_rules = load_platform_rules(Platform.CISCO_IOS)

    def reject(platform_name: str) -> str:
        message = f"unknown platform {platform_name!r}"
        raise ValueError(message)

    clear_rules_cache()
    with patch("hier_config.platforms.driver_base.get_platform_rules_json", reject):
        try:
            disk_rules = load_platform_rules(Platform.CISCO_IOS)
        finally:
            clear_rules_cache()

    assert disk_rules.model_dump(exclude={"post_load_callbacks"}) == (
        native_rules.model_dump(exclude={"post_load_callbacks"})
    )
