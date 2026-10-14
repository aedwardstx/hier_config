//! Pins the single-pass renderers (`lines`, `dump`) to a reference built from
//! the per-node primitives across the shared corpus and every platform.

use hier_config_core::arena::NodeId;
use hier_config_core::models::{DumpLine, TextStyle};
use hier_config_core::{Platform, Tree};
use std::fs;
use std::path::Path;

fn reference_lines(tree: &Tree, node_id: NodeId, sectional_exiting: bool, out: &mut Vec<String>) {
    if node_id != tree.root {
        out.push(tree.cisco_style_text(node_id, TextStyle::WithoutComments, None));
    }
    for child_id in tree.sorted_children(node_id) {
        reference_lines(tree, child_id, sectional_exiting, out);
    }
    if node_id != tree.root
        && sectional_exiting
        && let Some(exit_text) = tree.sectional_exit(node_id)
    {
        let depth = if tree.sectional_exit_text_parent_level(node_id) {
            tree.depth(node_id).saturating_sub(1)
        } else {
            tree.depth(node_id)
        };
        let indent = " ".repeat(tree.driver.rules.indentation * depth);
        out.push(format!("{indent}{exit_text}"));
    }
}

fn reference_dump(tree: &Tree) -> Vec<DumpLine> {
    tree.all_children_sorted(tree.root)
        .into_iter()
        .map(|id| {
            let node = &tree.arena[id];
            DumpLine {
                depth: tree.depth(id),
                text: node.text.to_string(),
                tags: tree.tags(id),
                comments: node.comments().clone(),
                new_in_config: node.new_in_config,
            }
        })
        .collect()
}

fn assert_renders_match_reference(tree: &Tree, label: &str) {
    for sectional_exiting in [false, true] {
        let mut expected = Vec::new();
        reference_lines(tree, tree.root, sectional_exiting, &mut expected);
        assert_eq!(
            tree.lines(tree.root, sectional_exiting),
            expected,
            "{label}"
        );
        for id in tree.all_children(tree.root) {
            let mut subtree = Vec::new();
            reference_lines(tree, id, sectional_exiting, &mut subtree);
            assert_eq!(tree.lines(id, sectional_exiting), subtree, "{label}");
        }
    }
    assert_eq!(tree.dump().lines, reference_dump(tree), "{label}");
}

fn platform_for(name: &str) -> Platform {
    name.to_uppercase().parse().unwrap()
}

#[test]
fn corpus_renders_match_per_node_reference() {
    let cases = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/cases");
    let mut checked = 0;
    for platform_dir in fs::read_dir(cases).unwrap() {
        let platform_dir = platform_dir.unwrap().path();
        let platform = platform_for(platform_dir.file_name().unwrap().to_str().unwrap());
        for case in fs::read_dir(&platform_dir).unwrap() {
            let case = case.unwrap().path();
            for file in ["running.conf", "intended.conf"] {
                let Ok(text) = fs::read_to_string(case.join(file)) else {
                    continue;
                };
                let Ok(tree) = Tree::from_str(platform, &text) else {
                    continue;
                };
                assert_renders_match_reference(&tree, &format!("{}", case.display()));
                if let Ok(intended) = fs::read_to_string(case.join("intended.conf"))
                    && let Ok(target) = Tree::from_str(platform, &intended)
                    && let Ok(delta) = tree.config_to_get_to(&target)
                {
                    assert_renders_match_reference(&delta, &format!("{} delta", case.display()));
                }
                checked += 1;
            }
        }
    }
    assert!(checked > 100, "only {checked} corpus trees checked");
}

#[test]
fn renders_respect_order_weight_parent_level_exits_and_leaf_tags() {
    let mut tree = Tree::from_str(
        Platform::CiscoXr,
        "route-policy RP\n  if destination in PS then\n    pass\n  endif\nprefix-set PS\n  10.0.0.0/8\ninterface Gi0\n  description x\n  shutdown\nrouter bgp 1\n  neighbor 1.1.1.1\n    remote-as 2",
    )
    .unwrap();
    let interface = tree.arena[tree.root].children.get("interface Gi0").unwrap();
    let shutdown = tree.arena[interface].children.get("shutdown").unwrap();
    let bgp = tree.arena[tree.root].children.get("router bgp 1").unwrap();
    tree.arena[shutdown].order_weight = -5;
    tree.arena[bgp].order_weight = -1;
    tree.tags_add(interface, &["a", "b"]);
    tree.tags_add(shutdown, &["c"]);
    assert_renders_match_reference(&tree, "xr");
    let lines = tree.lines(tree.root, true);
    assert_eq!(lines[0], "router bgp 1");
    assert!(lines.contains(&"end-policy".to_string()));
    assert!(lines.iter().any(|line| line == "  shutdown"));
    let dump = tree.dump();
    let interface_line = dump
        .lines
        .iter()
        .find(|l| l.text == "interface Gi0")
        .unwrap();
    assert_eq!(
        interface_line
            .tags
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["a", "b", "c"]
    );
}
