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

fn reference_unified_diff(source: &Tree, s: NodeId, target: &Tree, t: NodeId) -> Vec<String> {
    let mut lines = Vec::new();
    for child in source.arena[s].children.iter() {
        let text = &source.arena[child].text;
        if let Some(other) = target.arena[t].children.get(text) {
            let nested = reference_unified_diff(source, child, target, other);
            if !nested.is_empty() {
                lines.push(format!("{}{}", source.indentation(child), text));
                lines.extend(nested);
            }
        } else {
            lines.push(format!("{}- {}", source.indentation(child), text));
            for id in source.descendants_sorted(child) {
                lines.push(format!(
                    "{}- {}",
                    source.indentation(id),
                    source.arena[id].text
                ));
            }
        }
    }
    for child in target.arena[t].children.iter() {
        let text = &target.arena[child].text;
        if !source.arena[s].children.contains(text) {
            lines.push(format!("{}+ {}", target.indentation(child), text));
            for id in target.descendants_sorted(child) {
                lines.push(format!(
                    "{}+ {}",
                    target.indentation(id),
                    target.arena[id].text
                ));
            }
        }
    }
    lines
}

fn assert_unified_diff_matches_reference(source: &Tree, target: &Tree, label: &str) {
    for (a, b) in [(source, target), (target, source)] {
        assert_eq!(
            a.unified_diff(b),
            reference_unified_diff(a, a.root, b, b.root),
            "{label}"
        );
    }
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
    for platform_dir in fs::read_dir(&cases).unwrap() {
        let platform_dir = platform_dir.unwrap().path();
        let platform = platform_for(platform_dir.file_name().unwrap().to_str().unwrap());
        for case in fs::read_dir(&platform_dir).unwrap() {
            let case = case.unwrap().path();
            // Every case must have both files; a missing or unparsable one fails here
            // rather than being skipped.
            let parse = |file: &str| {
                let path = case.join(file);
                let text = fs::read_to_string(&path)
                    .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
                Tree::from_str(platform, &text)
                    .unwrap_or_else(|error| panic!("{}: {error}", path.display()))
            };
            let running = parse("running.conf");
            let intended = parse("intended.conf");
            let label = case.display().to_string();
            assert_renders_match_reference(&running, &format!("{label} running"));
            assert_renders_match_reference(&intended, &format!("{label} intended"));
            let delta = running
                .config_to_get_to(&intended)
                .unwrap_or_else(|error| panic!("{label} delta: {error}"));
            assert_renders_match_reference(&delta, &format!("{label} delta"));
            assert_unified_diff_matches_reference(&running, &intended, &label);
            checked += 1;
        }
    }
    assert!(checked > 0, "no corpus cases under {}", cases.display());
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

#[test]
fn unified_diff_handles_duplicates_reordering_and_order_weight() {
    let mut source = Tree::from_str(
        Platform::Generic,
        "a\n  x\n  y\nb\n  y\nc\nd\n  keep\n    deep",
    )
    .unwrap();
    let mut target = Tree::from_str(
        Platform::Generic,
        "b\n  y\n  z\na\n  x\nd\n  keep\n    deeper\ne\n  f\n    g",
    )
    .unwrap();
    for tree in [&mut source, &mut target] {
        let root = tree.root;
        for text in ["a", "b"] {
            let first = tree.arena[root].children.get(text).unwrap();
            let duplicate = tree.create_child_unattached(root, text);
            tree.add_child(duplicate, "dup only", true, false).unwrap();
            let shared = std::sync::Arc::clone(&tree.arena[duplicate].text);
            tree.arena[root].children.append(&shared, duplicate, false);
            assert_eq!(tree.arena[root].children.get(text), Some(first));
        }
    }
    let e = target.arena[target.root].children.get("e").unwrap();
    let f = target.arena[e].children.get("f").unwrap();
    let late = target.add_child(e, "early", true, false).unwrap();
    target.arena[late].order_weight = -1;
    target.arena[f].order_weight = 3;
    assert_unified_diff_matches_reference(&source, &target, "duplicates");
    // Duplicates compare against the first indexed sibling, so a self-diff of
    // this tree is not empty; it must still match the reference.
    assert_unified_diff_matches_reference(&target, &target, "self");
    let lines = source.unified_diff(&target);
    assert!(lines.contains(&"  + early".to_string()), "{lines:?}");
}

#[test]
fn get_at_falls_back_when_texts_repeat_or_positions_shift() {
    let mut tree = Tree::from_str(Platform::Generic, "a\nb\nc").unwrap();
    let root = tree.root;
    let a = tree.arena[root].children.get("a").unwrap();
    let c = tree.arena[root].children.get("c").unwrap();
    let children = &tree.arena[root].children;
    assert_eq!(children.get_at(0, "a", &tree.arena), Some(a));
    assert_eq!(children.get_at(0, "c", &tree.arena), Some(c));
    assert_eq!(children.get_at(9, "c", &tree.arena), Some(c));
    assert_eq!(children.get_at(1, "missing", &tree.arena), None);
    let duplicate = tree.create_child_unattached(root, "a");
    let shared = std::sync::Arc::clone(&tree.arena[duplicate].text);
    tree.arena[root].children.append(&shared, duplicate, false);
    assert_eq!(
        tree.arena[root].children.get_at(3, "a", &tree.arena),
        Some(a)
    );
}
