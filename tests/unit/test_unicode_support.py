"""Tests asserting Unicode support across Python entrypoints and operations.

Validates that UTF-8 multi-byte characters, accented letters, CJK characters,
emoji, and Unicode whitespace are properly ingested, manipulated, remediated,
and serialized across all Python entrypoints:
- `HConfig.from_text` (str and Path with utf-8)
- `HConfig.from_lines`
- `HConfig.from_dump` / `HConfig.dump`
- `HConfig.from_json` / `HConfig.to_json`
- `HConfig.from_xml` / `HConfig.to_xml`
- `HConfig.remediation`
- `HConfig.future`
- `HConfig.rollback`
- `HConfigViewBase` and platform view accessors
"""

import tempfile
from pathlib import Path

from hier_config import (
    HConfig,
    Platform,
    WorkflowRemediation,
    get_hconfig_driver,
    get_hconfig_view,
)


def test_python_entrypoints_support_unicode_text_and_lines() -> None:
    running_text = (
        "interface GigabitEthernet1/0/1\n"
        "  description Café au Lait ☕ / 東京Uplink ( rack-① )\n"
        "  shutdown\n"
        "interface GigabitEthernet1/0/2\n"
        "  description Старый маршрут 🚀\n"
    )

    intended_text = (
        "interface GigabitEthernet1/0/1\n"
        "  description Café au Lait ☕ / 東京Uplink ( rack-① )\n"
        "  no shutdown\n"
        "interface GigabitEthernet1/0/2\n"
        "  description Новый маршрут ✨ / 5G基地局\n"
    )

    # 1. Ingestion via HConfig.from_text with str
    running = HConfig.from_text(Platform.CISCO_IOS, running_text)
    intended = HConfig.from_text(Platform.CISCO_IOS, intended_text)

    # Verify children with exact Unicode strings
    child1 = running.get_child(equals="interface GigabitEthernet1/0/1")
    assert child1 is not None
    desc1 = child1.get_child(
        equals="description Café au Lait ☕ / 東京Uplink ( rack-① )"
    )
    assert desc1 is not None
    assert desc1.text == "description Café au Lait ☕ / 東京Uplink ( rack-① )"

    # 2. Ingestion via HConfig.from_text with file Path
    with tempfile.NamedTemporaryFile("w+", encoding="utf-8", delete=False) as tmp:
        tmp.write(running_text)
        tmp_path = Path(tmp.name)
    try:
        file_running = HConfig.from_text(Platform.CISCO_IOS, tmp_path)
    finally:
        tmp_path.unlink()
    assert tuple(file_running.to_lines()) == tuple(running.to_lines())

    # 3. Ingestion via HConfig.from_lines
    lines_running = HConfig.from_lines(
        Platform.CISCO_IOS, running_text.strip().splitlines()
    )
    assert tuple(lines_running.to_lines()) == tuple(running.to_lines())

    # 4. Dump and from_dump round-trip
    dump_data = running.dump()
    reconstructed = HConfig.from_dump(Platform.CISCO_IOS, dump_data)
    assert tuple(reconstructed.to_lines()) == tuple(running.to_lines())

    # 5. Remediation with Unicode
    remediation = running.remediation(intended)
    assert tuple(remediation.to_lines()) == (
        "interface GigabitEthernet1/0/1",
        "  no shutdown",
        "interface GigabitEthernet1/0/2",
        "  description Новый маршрут ✨ / 5G基地局",
    )

    # 6. Future config with Unicode
    future = running.future(remediation)
    assert tuple(future.to_lines()) == (
        "interface GigabitEthernet1/0/1",
        "  description Café au Lait ☕ / 東京Uplink ( rack-① )",
        "interface GigabitEthernet1/0/2",
        "  description Новый маршрут ✨ / 5G基地局",
    )

    # 7. Rollback with Unicode via WorkflowRemediation
    workflow = WorkflowRemediation(running, intended)
    rollback = workflow.rollback_config
    assert tuple(rollback.to_lines()) == (
        "interface GigabitEthernet1/0/1",
        "  shutdown",
        "interface GigabitEthernet1/0/2",
        "  description Старый маршрут 🚀",
    )


def test_python_entrypoints_support_unicode_structured_formats() -> None:
    driver = get_hconfig_driver(Platform.GENERIC)

    # JSON round-trip with Unicode
    json_doc = (
        "{\n"
        '  "interfaces": {\n'
        '    "interface": [\n'
        "      {\n"
        '        "name": "GigabitEthernet1/0/1",\n'
        '        "description": "Café ☕ / 東京Uplink ( rack-① )",\n'
        '        "enabled": true\n'
        "      }\n"
        "    ]\n"
        "  }\n"
        "}"
    )

    tree_from_json = HConfig.from_json(driver, json_doc)
    dumped_json = tree_from_json.to_json(indent=2)
    # Reload to verify Unicode preserved across serialization
    reloaded_json_tree = HConfig.from_json(driver, dumped_json)
    assert tuple(reloaded_json_tree.to_lines()) == tuple(tree_from_json.to_lines())

    # XML round-trip with Unicode
    xml_doc = (
        '<config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">\n'
        "  <interfaces>\n"
        "    <interface>\n"
        "      <name>GigabitEthernet1/0/1</name>\n"
        "      <description>Café ☕ / 東京Uplink ( rack-① )</description>\n"
        "      <enabled>true</enabled>\n"
        "    </interface>\n"
        "  </interfaces>\n"
        "</config>"
    )

    tree_from_xml = HConfig.from_xml(driver, xml_doc)
    dumped_xml = tree_from_xml.to_xml()
    assert "Café ☕ / 東京Uplink ( rack-① )" in dumped_xml
    reloaded_xml_tree = HConfig.from_xml(driver, dumped_xml)
    assert tuple(reloaded_xml_tree.to_lines()) == tuple(tree_from_xml.to_lines())


def test_python_view_supports_unicode() -> None:
    config = HConfig.from_text(
        Platform.CISCO_IOS,
        "hostname café-core-01\n"
        "interface GigabitEthernet1/0/1\n"
        "  description 東京Uplink\n",
    )
    view = get_hconfig_view(config)
    assert view.hostname == "café-core-01"
    ifaces = list(view.interface_views)
    assert len(ifaces) == 1
    assert ifaces[0].description == "東京Uplink"
