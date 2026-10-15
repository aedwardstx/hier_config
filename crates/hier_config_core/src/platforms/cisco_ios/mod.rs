use crate::arena::NodeId;
use crate::platforms::PlatformOps;
use crate::platforms::functions::expand_range;
use crate::platforms::post_load_enabled;
use crate::tree::Tree;
use crate::view::config::ConfigOps;

pub const RULES_JSON: &str = include_str!("rules.json");

#[derive(Debug, Clone, Copy)]
pub struct CiscoIos;

impl PlatformOps for CiscoIos {
    fn rules_json(&self) -> &'static str {
        RULES_JSON
    }

    fn run_post_load(&self, tree: &mut Tree) {
        run_post_load(tree);
    }

    fn view_ops(&self) -> Option<&'static dyn ConfigOps> {
        Some(&crate::view::platforms::cisco_ios::CONFIG_OPS)
    }
}

pub static OPS: CiscoIos = CiscoIos;

pub fn run_post_load(tree: &mut Tree) {
    let ipv6_sequences = post_load_enabled(tree, "remove_ipv6_acl_sequence_numbers");
    let ipv4_remarks = post_load_enabled(tree, "remove_ipv4_acl_remarks");
    let acl_sequences = post_load_enabled(tree, "add_acl_sequence_numbers");
    let vlan_lists = post_load_enabled(tree, "split_vlan_id_lists");
    if !(ipv6_sequences || ipv4_remarks || acl_sequences || vlan_lists) {
        return;
    }
    // Each callback only rewrites one root child's subtree (VLAN splitting
    // appends new root children, which the snapshot excludes), so a single
    // root walk applying them in their documented order is equivalent to
    // running them one after another.
    let root_children = tree.arena[tree.root].children.as_slice().to_vec();
    for child_id in root_children {
        let text = &tree.arena[child_id].text;
        let is_ipv6_acl = ipv6_sequences && text.starts_with("ipv6 access-list ");
        let is_ipv4_acl = text.starts_with("ip access-list");
        let strip_remarks = ipv4_remarks && text.starts_with("ip access-list ");
        let is_vlan = vlan_lists && text.starts_with("vlan ");
        if is_ipv6_acl {
            rm_ipv6_acl_entry_sequence_numbers(tree, child_id);
        }
        if strip_remarks {
            remove_ipv4_acl_entry_remarks(tree, child_id);
        }
        if is_ipv4_acl && acl_sequences {
            add_acl_entry_sequence_numbers(tree, child_id);
        }
        if is_vlan {
            split_vlan_id_list(tree, child_id);
        }
    }
}

pub fn rm_ipv6_acl_sequence_numbers(tree: &mut Tree) {
    let root_children = tree.arena[tree.root].children.as_slice().to_vec();
    for acl_id in root_children {
        if tree.arena[acl_id].text.starts_with("ipv6 access-list ") {
            rm_ipv6_acl_entry_sequence_numbers(tree, acl_id);
        }
    }
}

fn rm_ipv6_acl_entry_sequence_numbers(tree: &mut Tree, acl_id: NodeId) {
    let entries = tree.arena[acl_id].children.as_slice().to_vec();
    for entry_id in entries {
        let text = &tree.arena[entry_id].text;
        if text.starts_with("sequence ") {
            let words: Vec<&str> = text.split_whitespace().collect();
            if words.len() >= 3 {
                let new_text = words[2..].join(" ");
                tree.set_text(entry_id, &new_text);
            }
        }
    }
}

pub fn remove_ipv4_acl_remarks(tree: &mut Tree) {
    let root_children = tree.arena[tree.root].children.as_slice().to_vec();
    for acl_id in root_children {
        if tree.arena[acl_id].text.starts_with("ip access-list ") {
            remove_ipv4_acl_entry_remarks(tree, acl_id);
        }
    }
}

fn remove_ipv4_acl_entry_remarks(tree: &mut Tree, acl_id: NodeId) {
    let entries = tree.arena[acl_id].children.as_slice().to_vec();
    for entry_id in entries {
        if tree.arena[entry_id].text.starts_with("remark ")
            || tree.arena[entry_id].text.as_ref() == "remark"
        {
            tree.delete_child(entry_id);
        }
    }
}

pub fn add_acl_sequence_numbers(tree: &mut Tree) {
    let root_children = tree.arena[tree.root].children.as_slice().to_vec();
    for child_id in root_children {
        if tree.arena[child_id].text.starts_with("ip access-list") {
            add_acl_entry_sequence_numbers(tree, child_id);
        }
    }
}

fn add_acl_entry_sequence_numbers(tree: &mut Tree, acl_id: NodeId) {
    let mut sequence_number = 10;
    let entries = tree.arena[acl_id].children.as_slice().to_vec();
    for sub_id in entries {
        let text = &tree.arena[sub_id].text;
        if text.starts_with("permit ")
            || text.starts_with("deny ")
            || &**text == "permit"
            || &**text == "deny"
        {
            let new_text = format!("{sequence_number} {text}");
            tree.set_text(sub_id, &new_text);
            sequence_number += 10;
        }
    }
}

/// Splits comma-separated or hyphenated VLAN lists under `vlan <list>` nodes into individual nodes.
///
/// # Panics
///
/// Panics if the internal static regular expression fails to compile.
pub fn split_vlan_id_lists(tree: &mut Tree) {
    let root_children = tree.arena[tree.root].children.as_slice().to_vec();
    for vlan_id in root_children {
        // The literal prefix rejects nearly every root line before the regex runs.
        if tree.arena[vlan_id].text.starts_with("vlan ") {
            split_vlan_id_list(tree, vlan_id);
        }
    }
}

fn split_vlan_id_list(tree: &mut Tree, vlan_id: NodeId) {
    let vlan_re = crate::regex_cache::regex(r"^vlan \d[\d,\-]*$").expect("static pattern is valid");
    let text = &tree.arena[vlan_id].text;
    if vlan_re.is_match(text)
        && tree.arena[vlan_id].children.is_empty()
        && let Some((_, spec)) = text.split_once(' ')
        && (spec.contains(',') || spec.contains('-'))
        && let Ok(vlans) = expand_range(spec)
        && !vlans.is_empty()
    {
        for v in vlans {
            let line = format!("vlan {v}");
            let _ = tree.add_child(tree.root, &line, true, true);
        }
        tree.delete_child(vlan_id);
    }
}
