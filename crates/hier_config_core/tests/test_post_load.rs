use hier_config_core::models::Platform;
use hier_config_core::post_load::{expand_range, hp_procurve_expand_range};
use hier_config_core::tree::Tree;

#[test]
fn test_expand_range_basic() {
    let result = expand_range("1-3,5,7-9").unwrap();
    assert_eq!(result, vec![1, 2, 3, 5, 7, 8, 9]);

    let dedup = expand_range("1-3,2,3").unwrap();
    assert_eq!(dedup, vec![1, 2, 3]);

    let single = expand_range("42").unwrap();
    assert_eq!(single, vec![42]);

    assert!(expand_range("5-2").is_err());
    assert!(expand_range("abc").is_err());
}

#[test]
fn test_hp_procurve_expand_range_basic() {
    let trk = hp_procurve_expand_range("Trk1-Trk3").unwrap();
    assert_eq!(trk, vec!["Trk1", "Trk2", "Trk3"]);

    let slot = hp_procurve_expand_range("5/A1-5/A3").unwrap();
    assert_eq!(slot, vec!["5/A1", "5/A2", "5/A3"]);

    let stack = hp_procurve_expand_range("1/1-1/3").unwrap();
    assert_eq!(stack, vec!["1/1", "1/2", "1/3"]);

    let ports = hp_procurve_expand_range("1-3").unwrap();
    assert_eq!(ports, vec!["1", "2", "3"]);

    assert!(hp_procurve_expand_range("1/1,1/1").is_err());
}

#[test]
fn test_cisco_ios_acl_sequence_numbers() {
    let raw = "ip access-list extended TEST\n permit ip any any\n permit tcp any any";
    let tree = Tree::from_str(Platform::CiscoIos, raw).unwrap();
    let lines = tree.dump_simple(false);
    assert_eq!(
        lines,
        vec![
            "ip access-list extended TEST",
            "  10 permit ip any any",
            "  20 permit tcp any any",
        ]
    );
}

#[test]
fn test_cisco_ios_acl_remarks_strip() {
    let raw = "ip access-list extended TEST\n remark THIS IS A TEST\n permit ip any any";
    let tree = Tree::from_str(Platform::CiscoIos, raw).unwrap();
    let lines = tree.dump_simple(false);
    assert_eq!(
        lines,
        vec!["ip access-list extended TEST", "  10 permit ip any any",]
    );
}

#[test]
fn test_aruba_aoscx_vlan_trunk_split() {
    let raw = "interface 1/1/1\n vlan trunk allowed 1,2,3,5";
    let tree = Tree::from_str(Platform::ArubaAoscx, raw).unwrap();
    let lines = tree.dump_simple(false);
    assert_eq!(
        lines,
        vec![
            "interface 1/1/1",
            "  vlan trunk allowed 1",
            "  vlan trunk allowed 2",
            "  vlan trunk allowed 3",
            "  vlan trunk allowed 5",
        ]
    );
}

#[test]
fn test_cisco_xr_comments_fixup() {
    let raw = "!\n! interface comment\ninterface GigabitEthernet0/0/0/0\n shutdown";
    let tree = Tree::from_str(Platform::CiscoXr, raw).unwrap();
    let lines = tree.dump_simple(false);
    assert_eq!(
        lines,
        vec!["interface GigabitEthernet0/0/0/0", "  shutdown",]
    );
    let iface_id = tree
        .get_child_by_text(tree.root, "interface GigabitEthernet0/0/0/0")
        .unwrap();
    assert!(
        tree.arena[iface_id]
            .comments()
            .contains("interface comment")
    );
}

#[test]
fn trailing_top_level_exit_is_preserved() {
    // Invariant guard: the sectional-exit sweep must only touch descendants. Applied to
    // the root, it would delete a trailing top-level `exit` line, because the root
    // reports the platform default exit text once it has children.
    let raw = "interface Ethernet1\n description x\n exit\nvlan 10\nexit\n";
    let tree = Tree::from_str(Platform::CiscoIos, raw).unwrap();
    assert_eq!(
        tree.dump_simple(false),
        vec!["interface Ethernet1", "  description x", "vlan 10", "exit"]
    );
}

#[test]
fn trailing_top_level_quit_is_preserved_on_huawei_vrp() {
    // Same invariant with the Huawei VRP `quit` spelling of the exit command.
    let raw = "interface Ethernet1\n description x\n quit\nquit\n";
    let tree = Tree::from_str(Platform::HuaweiVrp, raw).unwrap();
    assert_eq!(
        tree.dump_simple(false),
        vec!["interface Ethernet1", "  description x", "quit"]
    );
}

#[test]
fn nested_sectional_exits_are_removed_at_every_depth() {
    let raw = concat!(
        "router bgp 65000\n",
        " address-family ipv4\n",
        "  network 10.0.0.0\n",
        "  exit-address-family\n",
        " exit\n",
    );
    let tree = Tree::from_str(Platform::CiscoIos, raw).unwrap();
    assert_eq!(
        tree.dump_simple(false),
        vec![
            "router bgp 65000",
            "  address-family ipv4",
            "    network 10.0.0.0",
        ]
    );
}

#[test]
fn every_sibling_section_loses_its_trailing_exit() {
    // The sweep walks children by index while `delete_sectional_exit` removes a child
    // of the node it is given, so no sibling may be skipped over by the deletions.
    let raw = concat!(
        "interface Ethernet1\n description a\n exit\n",
        "interface Ethernet2\n description b\n exit\n",
        "interface Ethernet3\n description c\n exit\n",
    );
    let tree = Tree::from_str(Platform::CiscoIos, raw).unwrap();
    assert_eq!(
        tree.dump_simple(false),
        vec![
            "interface Ethernet1",
            "  description a",
            "interface Ethernet2",
            "  description b",
            "interface Ethernet3",
            "  description c",
        ]
    );
}

#[test]
fn interior_exit_lines_and_leaf_siblings_are_left_alone() {
    // Only a *trailing* exit is sectional; one followed by more configuration stays,
    // and childless siblings the sweep skips are untouched either way.
    let raw = concat!(
        "interface Ethernet1\n description a\n exit\n shutdown\n",
        "hostname router1\n",
        "exit\n",
    );
    let tree = Tree::from_str(Platform::CiscoIos, raw).unwrap();
    assert_eq!(
        tree.dump_simple(false),
        vec![
            "interface Ethernet1",
            "  description a",
            "  exit",
            "  shutdown",
            "hostname router1",
            "exit",
        ]
    );
}
