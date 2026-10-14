//! Unicode support acceptance tests for Rust entrypoints.
//!
//! Validates that UTF-8 multi-byte characters, accented letters, CJK characters,
//! emoji, and Unicode whitespace are properly ingested, manipulated, remediated,
//! and serialized across all Rust core entrypoints:
//! - `config_from_text`
//! - `Tree::from_str` / `parse_tree`
//! - `Tree::from_lines` / `parse_fast`
//! - `from_json` / `to_json`
//! - `from_xml` / `to_xml`
//! - `remediation` / `future` / `difference`

use hier_config_core::remediation::future;
use hier_config_core::{
    Driver, Platform, WorkflowRemediation, config_from_text, from_json, from_xml, parse_fast,
    parse_tree, to_json, to_xml,
};

#[test]
fn rust_entrypoints_support_unicode_text_and_lines() {
    let running_text = "\
interface GigabitEthernet1/0/1
  description Café au Lait ☕ / 東京Uplink ( rack-① )
  shutdown
interface GigabitEthernet1/0/2
  description Старый маршрут 🚀
";

    let intended_text = "\
interface GigabitEthernet1/0/1
  description Café au Lait ☕ / 東京Uplink ( rack-① )
  no shutdown
interface GigabitEthernet1/0/2
  description Новый маршрут ✨ / 5G基地局
";

    // 1. Ingestion via config_from_text
    let running = config_from_text(Platform::CiscoIos, running_text)
        .expect("config_from_text parses unicode text");
    let intended = config_from_text(Platform::CiscoIos, intended_text)
        .expect("config_from_text parses unicode text");

    // Check tree contains exact unicode strings
    let child1 = running.arena[running.root]
        .children
        .get("interface GigabitEthernet1/0/1")
        .expect("interface found");
    assert!(
        running.arena[child1]
            .children
            .get("description Café au Lait ☕ / 東京Uplink ( rack-① )")
            .is_some()
    );

    // 2. Ingestion via Tree::from_lines / parse_fast
    let running_lines: Vec<&str> = running_text.lines().collect();
    let fast_running = parse_fast(
        Driver::for_platform(Platform::CiscoIos),
        &running_lines,
        true,
    )
    .expect("parse_fast parses unicode lines");
    assert_eq!(running.dump_simple(false), fast_running.dump_simple(false));

    // 3. Ingestion via parse_tree
    let parsed_tree = parse_tree(Driver::for_platform(Platform::CiscoIos), running_text)
        .expect("parse_tree parses unicode text");
    assert_eq!(running.dump_simple(false), parsed_tree.dump_simple(false));

    // 4. Remediation workflow with Unicode
    let workflow = WorkflowRemediation::new(running.clone(), intended)
        .expect("WorkflowRemediation creates with unicode trees");
    let remediation = workflow
        .remediation_config()
        .expect("remediation computes with unicode");

    let remediation_lines = remediation.dump_simple(false);
    assert_eq!(
        remediation_lines,
        vec![
            "interface GigabitEthernet1/0/1".to_owned(),
            "  no shutdown".to_owned(),
            "interface GigabitEthernet1/0/2".to_owned(),
            "  description Новый маршрут ✨ / 5G基地局".to_owned(),
        ]
    );

    // 5. Future config projection with Unicode
    let future_tree = future(&running, remediation, false).expect("future config projects unicode");
    assert_eq!(
        future_tree.dump_simple(false),
        vec![
            "interface GigabitEthernet1/0/1",
            "  description Café au Lait ☕ / 東京Uplink ( rack-① )",
            "interface GigabitEthernet1/0/2",
            "  description Новый маршрут ✨ / 5G基地局",
        ]
    );

    // 6. Rollback workflow with Unicode
    let rollback = workflow
        .rollback_config()
        .expect("rollback config computes unicode");
    let rollback_lines = rollback.dump_simple(false);
    assert_eq!(
        rollback_lines,
        vec![
            "interface GigabitEthernet1/0/1".to_owned(),
            "  shutdown".to_owned(),
            "interface GigabitEthernet1/0/2".to_owned(),
            "  description Старый маршрут 🚀".to_owned(),
        ]
    );
}

#[test]
fn rust_entrypoints_support_unicode_structured_formats() {
    let driver = Driver::for_platform(Platform::Generic);

    // JSON format with Unicode
    let json_doc = r#"{
  "interfaces": {
    "interface": [
      {
        "name": "GigabitEthernet1/0/1",
        "description": "Café ☕ / 東京Uplink ( rack-① )",
        "enabled": true
      }
    ]
  }
}"#;

    let tree_from_json =
        from_json(driver.clone(), json_doc, None).expect("from_json parses unicode");
    let dumped_json = to_json(&tree_from_json, Some(2));
    // to_json escapes non-ASCII characters to \uXXXX for python json.dumps parity
    let parsed_back: serde_json::Value = serde_json::from_str(&dumped_json).expect("valid json");
    assert_eq!(
        parsed_back["interfaces"]["interface"][0]["description"],
        "Café ☕ / 東京Uplink ( rack-① )"
    );

    // XML format with Unicode
    let xml_doc = r#"<config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
  <interfaces>
    <interface>
      <name>GigabitEthernet1/0/1</name>
      <description>Café ☕ / 東京Uplink ( rack-① )</description>
      <enabled>true</enabled>
    </interface>
  </interfaces>
</config>"#;

    let tree_from_xml = from_xml(driver, xml_doc, None).expect("from_xml parses unicode");
    let dumped_xml = to_xml(&tree_from_xml).expect("to_xml succeeds");
    assert!(dumped_xml.contains("Café ☕ / 東京Uplink ( rack-① )"));

    // View with Unicode
    let cisco_tree = config_from_text(
        Platform::CiscoIos,
        "hostname café-core-01\ninterface GigabitEthernet1/0/1\n  description 東京Uplink\n",
    )
    .expect("cisco config parses");
    let view = hier_config_core::config_view(&cisco_tree).expect("view available");
    assert_eq!(view.hostname().as_deref(), Some("café-core-01"));
    let ifaces = view.interface_views();
    assert_eq!(ifaces.len(), 1);
    assert_eq!(ifaces[0].description(), "東京Uplink");
}
