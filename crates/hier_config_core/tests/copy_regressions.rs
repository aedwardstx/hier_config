//! Regression tests for cross-tree copies: shared text, and merge instances
//! whose tags are built bottom-up during deep copies.

use hier_config_core::arena::NodeId;
use hier_config_core::tree::MAX_TREE_DEPTH;
use hier_config_core::{Platform, Tree, TreeError};
use std::collections::BTreeSet;
use std::sync::Arc;

fn tagged_source() -> Tree {
    let mut tree = Tree::from_str(
        Platform::CiscoIos,
        "interface Gi0/1\n description uplink\n ip address 10.0.0.1 255.255.255.0\n\
         router bgp 65000\n neighbor 10.0.0.2 remote-as 65001\n address-family ipv4\n  \
         neighbor 10.0.0.2 activate\n  network 10.0.0.0\nhostname r1\nrouter ospf 1",
    )
    .unwrap();
    let root = tree.root;
    let leaves: Vec<NodeId> = tree
        .descendants(root)
        .filter(|&id| tree.arena[id].is_leaf())
        .collect();
    for (index, id) in leaves.into_iter().enumerate() {
        let tags: BTreeSet<String> = match index % 3 {
            0 => BTreeSet::new(),
            1 => BTreeSet::from([format!("t{index}")]),
            _ => BTreeSet::from(["shared".to_string(), format!("t{index}")]),
        };
        tree.set_tags(id, tags);
        tree.arena[id].comments_mut().insert(format!("c{index}"));
    }
    tree
}

fn assert_instances_match_source(
    target: &Tree,
    source: &Tree,
    copies: &[(NodeId, NodeId)],
    deep: bool,
) {
    for &(new_id, source_id) in copies {
        let instance = target.arena[new_id]
            .instances()
            .iter()
            .rev()
            .find(|instance| instance.id == u64::from(source_id.index))
            .unwrap();
        assert_eq!(
            instance.tags,
            source.tags(source_id),
            "{}",
            source.arena[source_id].text
        );
        assert_eq!(&instance.comments, source.arena[source_id].comments());
        if deep {
            assert_eq!(target.tags(new_id), source.tags(source_id));
        }
    }
}

#[test]
fn merged_deep_copy_records_recursive_tag_unions() {
    let source = tagged_source();
    let mut target = Tree::from_str(Platform::CiscoIos, "router bgp 65000\n bgp log").unwrap();
    let mut copies = Vec::new();
    for child in source.arena[source.root].children.iter() {
        target
            .add_deep_copy_of_with(target.root, &source, child, true, &mut |new, old| {
                copies.push((new, old));
            })
            .unwrap();
    }
    assert_eq!(copies.len(), source.descendants(source.root).count());
    assert_instances_match_source(&target, &source, &copies, true);

    let mut merged = Tree::from_str(Platform::CiscoIos, "").unwrap();
    merged.merge(&source).unwrap();
    merged.merge(&source).unwrap();
    let bgp = merged.arena[merged.root]
        .children
        .get("router bgp 65000")
        .unwrap();
    assert_eq!(merged.arena[bgp].instances().len(), 2);
    for instance in merged.arena[bgp].instances() {
        let bgp_source = source.arena[source.root]
            .children
            .get("router bgp 65000")
            .unwrap();
        assert_eq!(instance.tags, source.tags(bgp_source));
    }
}

#[test]
fn shallow_copies_match_deep_copy_instances_and_share_text() {
    let source = tagged_source();
    let mut target = Tree::from_str(Platform::CiscoIos, "").unwrap();
    let bgp = source.arena[source.root]
        .children
        .get("router bgp 65000")
        .unwrap();
    let copy = target
        .add_shallow_copy_of(target.root, &source, bgp, true)
        .unwrap();
    assert_instances_match_source(&target, &source, &[(copy, bgp)], false);
    assert!(Arc::ptr_eq(
        &target.arena[copy].text,
        &source.arena[bgp].text
    ));
    assert!(target.arena[copy].is_leaf());
    assert!(target.arena[copy].tags().is_empty());

    let mut padded = Tree::from_str(Platform::CiscoIos, "hostname r1").unwrap();
    let leaf = padded.arena[padded.root]
        .children
        .get("hostname r1")
        .unwrap();
    padded.arena[leaf].text = Arc::from("  hostname r1 ");
    let trimmed = target
        .add_shallow_copy_of(target.root, &padded, leaf, false)
        .unwrap();
    assert_eq!(&*target.arena[trimmed].text, "hostname r1");
    assert_eq!(
        target.arena[target.root].children.get("hostname r1"),
        Some(trimmed)
    );
}

#[test]
fn copying_a_root_still_rejects_its_empty_text() {
    let mut source = Tree::from_str(Platform::Generic, "").unwrap();
    let root = source.root;
    source.arena[root]
        .tags_mut()
        .insert("root-only".to_string());
    let mut target = Tree::from_str(Platform::Generic, "").unwrap();
    let copy = target.add_shallow_copy_of(target.root, &source, root, true);
    // The root's empty text cannot become a child, as before.
    assert!(matches!(copy, Err(TreeError::EmptyText)));
}

#[test]
fn merged_deep_copy_failing_on_depth_keeps_completed_instances() {
    let mut source = Tree::from_str(Platform::Generic, "").unwrap();
    let mut parent = source.root;
    for level in 0..4 {
        parent = source
            .add_child(parent, &format!("level {level}"), true, false)
            .unwrap();
        let leaf = source
            .add_child(parent, &format!("leaf {level}"), true, false)
            .unwrap();
        source.set_tags(leaf, BTreeSet::from([format!("tag {level}")]));
    }
    let mut target = Tree::from_str(Platform::Generic, "").unwrap();
    let mut deep = target.root;
    for level in 0..MAX_TREE_DEPTH - 3 {
        deep = target
            .add_child(deep, &format!("d{level}"), true, false)
            .unwrap();
    }
    let top = source.arena[source.root].children.get("level 0").unwrap();
    let mut copies = Vec::new();
    let result = target.add_deep_copy_of_with(deep, &source, top, true, &mut |new, old| {
        copies.push((new, old));
    });
    assert!(matches!(result, Err(TreeError::MaxDepthExceeded(_))));
    assert!(!copies.is_empty());
    for &(new_id, source_id) in &copies {
        let instance = target.arena[new_id].instances().last().unwrap();
        assert_eq!(instance.tags, source.tags(source_id));
    }
}
