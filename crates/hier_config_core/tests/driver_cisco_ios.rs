use hier_config_core::models::Platform;
use hier_config_core::tree::Tree;

#[test]
fn test_rm_ipv6_acl_sequence_numbers() {
    let config_text = "ipv6 access-list TEST_IPV6_ACL\n sequence 10 permit tcp any any eq 443\n sequence 20 deny ipv6 any any\n";
    let tree = Tree::from_str(Platform::CiscoIos, config_text).unwrap();
    let acl_id = tree
        .get_child_by_text(tree.root, "ipv6 access-list TEST_IPV6_ACL")
        .expect("ACL not found");

    assert!(
        tree.get_child_by_text(acl_id, "permit tcp any any eq 443")
            .is_some()
    );
    assert!(
        tree.get_child_by_text(acl_id, "deny ipv6 any any")
            .is_some()
    );
    let children_texts: Vec<&str> = tree.arena[acl_id]
        .children
        .iter()
        .map(|id| tree.arena[id].text.as_ref())
        .collect();
    assert!(!children_texts.iter().any(|t| t.starts_with("sequence")));
}

#[test]
fn test_remove_ipv4_acl_remarks() {
    let config_text = "ip access-list extended TEST_ACL\n remark Allow HTTPS traffic\n permit tcp any any eq 443\n remark Block all other traffic\n deny ip any any\n";
    let tree = Tree::from_str(Platform::CiscoIos, config_text).unwrap();
    let acl_id = tree
        .get_child_by_text(tree.root, "ip access-list extended TEST_ACL")
        .expect("ACL not found");

    assert!(
        tree.get_child_by_text(acl_id, "10 permit tcp any any eq 443")
            .is_some()
    );
    assert!(
        tree.get_child_by_text(acl_id, "20 deny ip any any")
            .is_some()
    );
    let children_texts: Vec<&str> = tree.arena[acl_id]
        .children
        .iter()
        .map(|id| tree.arena[id].text.as_ref())
        .collect();
    assert!(!children_texts.iter().any(|t| t.starts_with("remark")));
}

#[test]
fn test_add_acl_sequence_numbers() {
    let config_text = "ip access-list extended TEST_ACL\n permit tcp any any eq 443\n permit tcp any any eq 80\n deny ip any any\n";
    let tree = Tree::from_str(Platform::CiscoIos, config_text).unwrap();
    let acl_id = tree
        .get_child_by_text(tree.root, "ip access-list extended TEST_ACL")
        .expect("ACL not found");

    assert!(
        tree.get_child_by_text(acl_id, "10 permit tcp any any eq 443")
            .is_some()
    );
    assert!(
        tree.get_child_by_text(acl_id, "20 permit tcp any any eq 80")
            .is_some()
    );
    assert!(
        tree.get_child_by_text(acl_id, "30 deny ip any any")
            .is_some()
    );
}

#[test]
fn test_vlan_id_list_split_on_load() {
    let config_text = "vlan 69,381\n";
    let tree = Tree::from_str(Platform::CiscoIos, config_text).unwrap();

    assert!(tree.get_child_by_text(tree.root, "vlan 69").is_some());
    assert!(tree.get_child_by_text(tree.root, "vlan 381").is_some());
    assert!(tree.get_child_by_text(tree.root, "vlan 69,381").is_none());
}

#[test]
fn test_vlan_id_range_split_on_load() {
    let config_text = "vlan 10-12\n";
    let tree = Tree::from_str(Platform::CiscoIos, config_text).unwrap();

    let children: Vec<&str> = tree.arena[tree.root]
        .children
        .iter()
        .map(|id| tree.arena[id].text.as_ref())
        .collect();
    assert_eq!(children, vec!["vlan 10", "vlan 11", "vlan 12"]);
}

#[test]
fn test_single_vlan_not_split_on_load() {
    let config_text = "vlan 44\n name servers\n";
    let tree = Tree::from_str(Platform::CiscoIos, config_text).unwrap();

    let vlan_id = tree
        .get_child_by_text(tree.root, "vlan 44")
        .expect("vlan 44 not found");
    assert!(tree.get_child_by_text(vlan_id, "name servers").is_some());
}

#[test]
fn test_vlan_list_lookalikes_not_split_on_load() {
    let lines = [
        "vlans 10,20",
        "vlan-group 1,2",
        "no vlan 10,20",
        "vlan 10,20 name x",
        "vlan a,b",
    ];
    let tree = Tree::from_str(Platform::CiscoIos, &lines.join("\n")).unwrap();
    let texts: Vec<&str> = tree.arena[tree.root]
        .children
        .iter()
        .map(|id| tree.arena[id].text.as_ref())
        .collect();
    assert_eq!(
        texts,
        [
            "vlans 10,20",
            "vlan-group 1,2",
            "no vlan 10,20",
            "vlan 10,20 name x",
            "vlan a,b",
        ]
    );
}

#[test]
fn test_non_vlan_id_line_not_split_on_load() {
    let config_text = "vlan internal allocation policy ascending\n";
    let tree = Tree::from_str(Platform::CiscoIos, config_text).unwrap();

    assert!(
        tree.get_child_by_text(tree.root, "vlan internal allocation policy ascending")
            .is_some()
    );
}

#[test]
fn test_malformed_vlan_range_left_untouched() {
    let config_text = "vlan 1-2-3\n";
    let tree = Tree::from_str(Platform::CiscoIos, config_text).unwrap();

    assert!(tree.get_child_by_text(tree.root, "vlan 1-2-3").is_some());
    assert!(tree.get_child_by_text(tree.root, "vlan 1").is_none());
}

#[test]
fn test_reversed_vlan_range_left_untouched() {
    let config_text = "vlan 5-3,7\n";
    let tree = Tree::from_str(Platform::CiscoIos, config_text).unwrap();

    assert!(tree.get_child_by_text(tree.root, "vlan 5-3,7").is_some());
    assert!(tree.get_child_by_text(tree.root, "vlan 7").is_none());
}

#[test]
fn test_cisco_ios_trunk_allowed_vlan_not_split() {
    let config_text = "interface GigabitEthernet0/1\n switchport trunk allowed vlan 150-166\n";
    let tree = Tree::from_str(Platform::CiscoIos, config_text).unwrap();

    let intf_id = tree
        .get_child_by_text(tree.root, "interface GigabitEthernet0/1")
        .expect("interface not found");
    let children: Vec<&str> = tree.arena[intf_id]
        .children
        .iter()
        .map(|id| tree.arena[id].text.as_ref())
        .collect();
    assert_eq!(children, vec!["switchport trunk allowed vlan 150-166"]);
}

fn ios_tree(config_text: &str, enabled: Option<&[&str]>) -> Tree {
    let mut driver = hier_config_core::Driver::for_platform(Platform::CiscoIos);
    driver.rules.enabled_post_load =
        enabled.map(|names| names.iter().map(ToString::to_string).collect());
    let mut tree = Tree::new(driver);
    hier_config_core::parser::load_from_str(&mut tree, config_text).unwrap();
    tree
}

fn lineage_texts(tree: &Tree) -> Vec<(usize, String)> {
    fn walk(
        tree: &Tree,
        id: hier_config_core::NodeId,
        depth: usize,
        out: &mut Vec<(usize, String)>,
    ) {
        for child in tree.arena[id].children.iter() {
            out.push((depth, tree.arena[child].text.to_string()));
            walk(tree, child, depth + 1, out);
        }
    }
    let mut out = Vec::new();
    walk(tree, tree.root, 0, &mut out);
    out
}

#[test]
fn test_post_load_matches_sequential_callbacks() {
    use hier_config_core::platforms::cisco_ios::{
        add_acl_sequence_numbers, remove_ipv4_acl_remarks, rm_ipv6_acl_sequence_numbers,
        split_vlan_id_lists,
    };
    let config_text = "\
hostname r1
vlan 10-12
 name ignored
vlan 20,22
ip access-list extended A
 remark first
 permit tcp any any eq 443
 remark
 deny ip any any
 permit
ipv6 access-list B
 sequence 10 permit tcp any any eq 443
 sequence 20 deny ipv6 any any
 remark keep
vlan 30
ip access-listX
 permit ip any any
vlan 40-41
interface Gi0/1
 description vlan 50,51
ip access-list standard C
 remark only
";
    let names = [
        "remove_ipv6_acl_sequence_numbers",
        "remove_ipv4_acl_remarks",
        "add_acl_sequence_numbers",
        "split_vlan_id_lists",
    ];
    let callbacks: [fn(&mut Tree); 4] = [
        rm_ipv6_acl_sequence_numbers,
        remove_ipv4_acl_remarks,
        add_acl_sequence_numbers,
        split_vlan_id_lists,
    ];
    for mask in 0_u8..16 {
        let enabled: Vec<&str> = (0..4)
            .filter(|bit| mask & (1 << bit) != 0)
            .map(|bit| names[bit])
            .collect();
        let mut expected = ios_tree(config_text, Some(&[]));
        for (bit, callback) in callbacks.iter().enumerate() {
            if mask & (1 << bit) != 0 {
                callback(&mut expected);
            }
        }
        let actual = ios_tree(config_text, Some(&enabled));
        assert_eq!(
            lineage_texts(&actual),
            lineage_texts(&expected),
            "mask {mask}"
        );
    }
    let mut expected = ios_tree(config_text, Some(&[]));
    for callback in callbacks {
        callback(&mut expected);
    }
    assert_eq!(
        lineage_texts(&ios_tree(config_text, None)),
        lineage_texts(&expected)
    );
}
