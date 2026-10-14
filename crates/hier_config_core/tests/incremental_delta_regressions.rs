//! Regression tests for the incremental child-index updates and lazily created
//! delta sections used by remediation and `difference`.

use hier_config_core::arena::NodeId;
use hier_config_core::tree::Children;
use hier_config_core::{Platform, Tree};
use std::sync::Arc;

fn generic(text: &str) -> Tree {
    Tree::from_str(Platform::Generic, text).unwrap()
}

fn append_duplicate(tree: &mut Tree, parent: NodeId, text: &str) -> NodeId {
    let child = tree.create_child_unattached(parent, text);
    let shared = Arc::clone(&tree.arena[child].text);
    tree.arena[parent].children.append(&shared, child, false);
    child
}

fn rebuilt(tree: &Tree, parent: NodeId) -> Children {
    let mut children = tree.arena[parent].children.clone();
    children.rebuild_mapping(&tree.arena);
    children
}

fn assert_index_matches_rebuild(tree: &Tree, parent: NodeId) {
    let children = &tree.arena[parent].children;
    assert_eq!(*children, rebuilt(tree, parent));
    for id in children.iter() {
        let text = &tree.arena[id].text;
        let first = children
            .iter()
            .find(|&other| tree.arena[other].text == *text)
            .unwrap();
        assert_eq!(children.get(text), Some(first), "{text}");
    }
}

fn last_child(tree: &Tree, parent: NodeId) -> NodeId {
    let children = &tree.arena[parent].children;
    children.get_index(children.len() - 1).unwrap()
}

#[test]
fn set_text_keeps_index_equal_to_rebuild_for_every_position() {
    for size in [3_usize, 12] {
        let lines: Vec<String> = (0..size).map(|i| format!("line {i}")).collect();
        let base = generic(&lines.join("\n"));
        let root = base.root;
        let ids: Vec<NodeId> = base.arena[root].children.iter().collect();
        let renames = ["renamed", "line 0", "line 1", "line 2"];
        for (position, &id) in ids.iter().enumerate() {
            for rename in renames.iter().copied().chain([lines[position].as_str()]) {
                let mut tree = base.clone();
                tree.set_text(id, rename);
                assert_eq!(tree.arena[id].text.as_ref(), rename);
                assert_index_matches_rebuild(&tree, root);
            }
        }
    }
}

#[test]
fn set_text_on_last_duplicate_keeps_first_occurrence_indexed() {
    for size in [2_usize, 10] {
        let lines: Vec<String> = (0..size).map(|i| format!("line {i}")).collect();
        let mut tree = generic(&lines.join("\n"));
        let root = tree.root;
        let first = tree.arena[root].children.get("line 0").unwrap();
        let duplicate = append_duplicate(&mut tree, root, "line 0");

        tree.set_text(duplicate, "no line 0");
        assert_eq!(tree.arena[root].children.get("line 0"), Some(first));
        assert_eq!(tree.arena[root].children.get("no line 0"), Some(duplicate));
        assert_index_matches_rebuild(&tree, root);

        let last = last_child(&tree, root);
        assert_eq!(last, duplicate);
        tree.set_text(last, "line 1");
        assert_ne!(tree.arena[root].children.get("line 1"), Some(last));
        assert!(!tree.arena[root].children.contains("no line 0"));
        assert_index_matches_rebuild(&tree, root);
    }
}

#[test]
fn set_text_on_first_of_duplicates_promotes_the_later_duplicate() {
    let mut tree = generic("alpha\nbeta");
    let root = tree.root;
    let first = tree.arena[root].children.get("alpha").unwrap();
    let duplicate = append_duplicate(&mut tree, root, "alpha");
    tree.set_text(first, "gamma");
    assert_eq!(tree.arena[root].children.get("alpha"), Some(duplicate));
    assert_index_matches_rebuild(&tree, root);
}

#[test]
fn remediation_negating_many_disjoint_siblings_indexes_every_negation() {
    let running: Vec<String> = (0..40)
        .map(|i| format!("interface Ethernet{i}\n  description old {i}"))
        .collect();
    let intended: Vec<String> = (0..40).map(|i| format!("vlan {i}")).collect();
    let source = Tree::from_str(Platform::CiscoIos, &running.join("\n")).unwrap();
    let target = Tree::from_str(Platform::CiscoIos, &intended.join("\n")).unwrap();
    let delta = source.config_to_get_to(&target).unwrap();
    let root = delta.root;
    for i in 0..40 {
        let negation = delta.arena[root]
            .children
            .get(&format!("no interface Ethernet{i}"))
            .unwrap();
        assert!(delta.arena[negation].comments().contains("removes 2 lines"));
        assert!(
            !delta.arena[root]
                .children
                .contains(&format!("interface Ethernet{i}"))
        );
        assert!(delta.arena[root].children.contains(&format!("vlan {i}")));
    }
    assert_index_matches_rebuild(&delta, root);
    let lines = delta.dump_simple(false);
    assert_eq!(lines.len(), 80);
    assert_eq!(lines[0], "no interface Ethernet0");
    assert_eq!(lines[39], "no interface Ethernet39");
    assert_eq!(lines[40], "vlan 0");
}

#[test]
fn remediation_creates_only_sections_on_the_path_to_a_change() {
    let running = "a\n  b\n    c\n      keep\n  d\n    keep\ne\n  keep\nf\n  g\n    old";
    let intended = "a\n  b\n    c\n      keep\n  d\n    keep\ne\n  keep\nf\n  g\n    new\n  h";
    let source = generic(running);
    let target = generic(intended);
    let delta = source.config_to_get_to(&target).unwrap();
    assert_eq!(
        delta.dump_simple(false),
        ["f", "  g", "    no old", "    new", "  h"]
    );
    assert_eq!(delta.arena[delta.root].children.len(), 1);
    assert_eq!(delta.all_children(delta.root).len(), 5);
    let rollback = target.config_to_get_to(&source).unwrap();
    assert_eq!(
        rollback.dump_simple(false),
        ["f", "  no h", "  g", "    no new", "    old"]
    );
    assert!(
        source
            .config_to_get_to(&source)
            .unwrap()
            .dump_simple(false)
            .is_empty()
    );
}

#[test]
fn remediation_subtree_sharing_text_with_negation_keeps_first_in_index() {
    let source = generic("x\n  one\nno x\n  two");
    let target = generic("no x\n  three");
    let delta = source.config_to_get_to(&target).unwrap();
    let root = delta.root;
    let lines = delta.dump_simple(false);
    assert_eq!(lines, ["no x", "no x", "  no two", "  three"]);
    let first = delta.arena[root].children.get_index(0).unwrap();
    assert_eq!(delta.arena[root].children.get("no x"), Some(first));
    assert!(delta.arena[first].children.is_empty());
}

#[test]
fn difference_creates_only_sections_on_the_path_to_a_difference() {
    let source = generic("a\n  b\n    keep\n  c\n    extra\nd\n  keep\ne");
    let target = generic("a\n  b\n    keep\n  c\nd\n  keep");
    let diff = source.difference(&target).unwrap();
    assert_eq!(diff.dump_simple(false), ["a", "  c", "    extra", "e"]);
    assert_eq!(diff.all_children(diff.root).len(), 4);
    assert!(
        target
            .difference(&target)
            .unwrap()
            .dump_simple(false)
            .is_empty()
    );
}
