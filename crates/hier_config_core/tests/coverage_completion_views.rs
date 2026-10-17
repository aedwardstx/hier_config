//! Boundary behavior for drivers, range expansion, post-load fixups and views
//! that the broader suites do not reach.

use hier_config_core::post_load::{expand_range, hp_procurve_expand_range};
use hier_config_core::view::{
    ConfigOps, InterfaceDot1qMode, InterfaceDuplex, InterfaceOps, InterfaceView, NacHostMode, Vlan,
};
use hier_config_core::{ConfigView, Driver, MatchRule, Platform, Tree, view_ops_for_platform};
use serde_json::json;

fn driver_with_rules(value: serde_json::Value) -> Driver {
    Driver {
        rules: serde_json::from_value(value).unwrap(),
        ..Driver::default()
    }
}

#[test]
fn default_strategy_negation_rules_need_no_regex_validation() {
    let driver = driver_with_rules(json!({
        "negation": [{"strategy": "default", "match_rules": [{"startswith": "logging "}]}]
    }));
    assert_eq!(driver.rules.validate_regexes(), Ok(()));
    assert_eq!(
        driver.try_compute_negation("logging host 10.0.0.1", |_| true),
        Ok("default logging host 10.0.0.1".to_owned())
    );
}

#[test]
fn regex_key_uses_whole_match_when_prefix_candidate_is_unusable() {
    let driver = Driver::default();
    // Stripping `.*` from " .*" leaves a candidate matching only whitespace, and
    // from `a\.*` leaves the invalid pattern `a\`; both keep the whole match.
    let cases = [
        (" .*", "ip address 10.0.0.1", "re|address 10.0.0.1"),
        ("a\\.*", "a..x", "re|a.."),
    ];
    for (pattern, text, expected) in cases {
        assert_eq!(
            driver.try_idempotency_key(&[text], &[MatchRule::re_search(pattern)]),
            Ok(vec![expected.to_owned()]),
            "{pattern}"
        );
    }
}

#[test]
fn expand_range_caps_total_values_including_single_numbers() {
    assert_eq!(
        expand_range("1-1000000").map(|values| values.len()),
        Ok(1_000_000)
    );
    assert_eq!(expand_range("1-1000000,1"), Err("range too large"));
}

#[test]
fn hp_procurve_expand_range_caps_total_ports_including_single_ports() {
    assert_eq!(
        hp_procurve_expand_range("1-1000000").map(|ports| ports.len()),
        Ok(1_000_000)
    );
    assert_eq!(
        hp_procurve_expand_range("1-1000000,A1"),
        Err("port range too large")
    );
}

#[test]
fn aruba_aoscx_trunk_split_ignores_lines_with_extra_words() {
    let config = "\
interface 1/1/1
    vlan trunk allowed 10,20 extra
    vlan trunk allowed 30-31
";
    let tree = Tree::from_str(Platform::ArubaAoscx, config).unwrap();
    assert_eq!(
        tree.dump_simple(false),
        vec![
            "interface 1/1/1",
            "  vlan trunk allowed 10,20 extra",
            "  vlan trunk allowed 30",
            "  vlan trunk allowed 31",
        ]
    );
}

#[test]
fn hp_procurve_device_profile_keeps_single_and_unparseable_tagged_vlans() {
    let config = "\
device-profile name \"ap\"
   untagged-vlan 5
   tagged-vlan 10
   tagged-vlan 30-20
   tagged-vlan 40-41
";
    let tree = Tree::from_str(Platform::HpProcurve, config).unwrap();
    assert_eq!(
        tree.dump_simple(false),
        vec![
            "device-profile name \"ap\"",
            "  untagged-vlan 5",
            "  tagged-vlan 10",
            "  tagged-vlan 30-20",
            "  tagged-vlan 40",
            "  tagged-vlan 41",
        ]
    );
}

#[test]
fn view_enums_display_and_serialize_with_their_wire_values() {
    let cases: [(String, String, &str); 3] = [
        (
            NacHostMode::MultiAuth.to_string(),
            serde_json::to_string(&NacHostMode::MultiAuth).unwrap(),
            "multi-auth",
        ),
        (
            InterfaceDot1qMode::TaggedAll.to_string(),
            serde_json::to_string(&InterfaceDot1qMode::TaggedAll).unwrap(),
            "3",
        ),
        (
            InterfaceDuplex::Half.to_string(),
            serde_json::to_string(&InterfaceDuplex::Half).unwrap(),
            "half",
        ),
    ];
    for (display, serialized, expected) in cases {
        assert_eq!(display, expected);
        assert_eq!(serialized, format!("\"{expected}\""));
    }
}

#[test]
fn config_view_exposes_ops_debug_and_bundle_views() {
    let tree = Tree::from_str(
        Platform::Generic,
        "hostname edge\ninterface Port-channel1\ninterface GigabitEthernet1\n  channel-group 1 mode active",
    )
    .unwrap();
    let ops = view_ops_for_platform(Platform::CiscoIos).unwrap();
    let view = ConfigView::new(&tree, ops);

    assert!(std::ptr::addr_eq(view.ops(), ops));
    assert_eq!(
        format!("{view:?}"),
        "ConfigView { hostname: Some(\"edge\") }"
    );
    let bundles: Vec<&str> = view
        .bundle_interface_views()
        .iter()
        .map(InterfaceView::name)
        .collect();
    assert_eq!(bundles, vec!["Port-channel1"]);
}

#[derive(Debug)]
struct BareVlanOps;

impl ConfigOps for BareVlanOps {
    fn interface_ops(&self) -> &'static dyn InterfaceOps {
        view_ops_for_platform(Platform::CiscoIos)
            .unwrap()
            .interface_ops()
    }

    fn vlan_definition_pattern(&self) -> &'static str {
        "^vlan( [0-9]+)?$"
    }
}

static BARE_VLAN_OPS: BareVlanOps = BareVlanOps;

#[test]
fn custom_vlan_pattern_skips_definitions_without_an_id() {
    let tree = Tree::from_str(
        Platform::Generic,
        "vlan\n  name ORPHAN\nvlan 7\n  name USERS",
    )
    .unwrap();
    let view = ConfigView::new(&tree, &BARE_VLAN_OPS);
    assert_eq!(
        view.vlans(),
        vec![Vlan {
            id: 7,
            name: Some("USERS".to_owned()),
        }]
    );
}
