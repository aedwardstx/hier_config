//! Edge-case coverage for the tree, parser, remediation and constructor modules:
//! error propagation, edge-case inputs, and serialized dumps.

use hier_config_core::parser::{from_dump, parse_tree};
use hier_config_core::remediation::future;
use hier_config_core::{
    ConstructorError, Driver, Dump, DumpLine, IndentAdjustRule, MatchRule, PerLineSubRule,
    Platform, ReferenceLocation, StructuredFormat, Tree, TreeError, UnusedObjectRule,
    config_from_text,
};
use std::collections::BTreeSet;

/// A tree whose root carries `text` twice, bypassing the duplicate check.
fn with_duplicated_child(platform: Platform, parent_text: Option<&str>, text: &str) -> Tree {
    let mut tree = Tree::for_platform(platform);
    let parent = parent_text.map_or(tree.root, |parent_text| {
        tree.add_child(tree.root, parent_text, true, false).unwrap()
    });
    tree.add_child(parent, text, false, false).unwrap();
    tree.add_child(parent, text, false, false).unwrap();
    tree
}

fn assert_duplicate(result: Result<Tree, TreeError>, expected: &[&str]) {
    let Err(TreeError::DuplicateChild(path)) = result else {
        panic!("expected a duplicate-child error, got {result:?}");
    };
    assert_eq!(path, expected);
}

#[test]
fn future_reports_duplicate_sectional_overwrite_copies() {
    let source = Tree::for_platform(Platform::CiscoXr);
    let config = with_duplicated_child(Platform::CiscoXr, None, "template t1");
    assert_duplicate(future(&source, &config, false), &["template t1"]);
}

#[test]
fn future_reports_duplicate_idempotent_copies() {
    let source = Tree::from_str(Platform::CiscoXr, "router bgp 1\n bgp router-id 1.1.1.1").unwrap();
    let config = with_duplicated_child(
        Platform::CiscoXr,
        Some("router bgp 1"),
        "bgp router-id 2.2.2.2",
    );
    assert_duplicate(
        future(&source, &config, false),
        &["router bgp 1", "bgp router-id 2.2.2.2"],
    );
}

#[test]
fn future_reports_duplicate_shared_sections() {
    let source = Tree::from_str(Platform::Generic, "interface x").unwrap();
    let config = with_duplicated_child(Platform::Generic, None, "interface x");
    assert_duplicate(future(&source, &config, false), &["interface x"]);
}

#[test]
fn future_reports_duplicate_unresolved_negations() {
    let source = Tree::for_platform(Platform::Generic);
    let config = with_duplicated_child(Platform::Generic, None, "no logging host");
    assert_duplicate(future(&source, &config, false), &["no logging host"]);
}

#[test]
fn future_reports_duplicate_new_lines() {
    let source = Tree::for_platform(Platform::Generic);
    let config = with_duplicated_child(Platform::Generic, None, "logging host");
    assert_duplicate(future(&source, &config, false), &["logging host"]);
}

#[test]
fn structured_format_and_constructor_errors_render() {
    assert_eq!(StructuredFormat::Json.as_str(), "JSON");
    assert_eq!(StructuredFormat::Xml.as_str(), "XML");
    assert_eq!(StructuredFormat::Xml.to_string(), "XML");

    let converted = ConstructorError::from(TreeError::EmptyText);
    assert_eq!(converted, ConstructorError::Tree(TreeError::EmptyText));
    assert_eq!(converted.to_string(), "text was empty");

    let error = config_from_text(Platform::Generic, "logging host\nlogging host").unwrap_err();
    assert_eq!(
        error,
        ConstructorError::Tree(TreeError::DuplicateChild(vec!["logging host".to_owned()]))
    );
    assert_eq!(
        error.to_string(),
        r#"Found a duplicate section: ["logging host"]"#
    );
}

#[test]
fn max_depth_error_message_names_the_limit() {
    assert_eq!(
        TreeError::MaxDepthExceeded(7).to_string(),
        "Maximum configuration depth of 7 exceeded; the configuration is nested too \
         deeply to process"
    );
}

#[test]
fn match_rule_treats_exhausted_backtracking_as_no_match() {
    let rule = MatchRule::re_search(r"(a|a)*(?=b)|a+$");
    assert!(rule.is_match("aaa"));
    // The same text, long enough to exhaust the backtracking budget on the first
    // alternative, is reported as a non-match instead of hanging.
    assert!(!rule.is_match(&"a".repeat(40)));
}

#[test]
fn indent_adjust_surfaces_backtracking_failures() {
    let mut driver = Driver::for_platform(Platform::Generic);
    driver.rules.indent_adjust.push(IndentAdjustRule {
        start_expression: r"^(a|a)*(?=b)".to_owned(),
        end_expression: "^exit".to_owned(),
    });
    let Err(TreeError::InvalidRegex(message)) = parse_tree(driver, &"a".repeat(40)) else {
        panic!("expected the backtracking failure to surface");
    };
    assert!(message.contains("backtracking"), "{message}");
}

/// Unanchored substitutions that compile alone but not as one `RegexSet`.
fn oversized_subs(count: usize, width: usize) -> Vec<PerLineSubRule> {
    (0..count)
        .map(|index| PerLineSubRule {
            search: format!(r"r{index}-\w{{{width}}}"),
            replace: format!("sub{index}"),
        })
        .collect()
}

#[test]
fn per_line_subs_apply_when_the_unguarded_set_cannot_be_built() {
    let mut driver = Driver::for_platform(Platform::Generic);
    driver.rules.per_line_sub = oversized_subs(2, 200);
    let config = format!("r0-{}\nr1-{}\nkeep", "x".repeat(200), "y".repeat(200));
    let tree = parse_tree(driver, &config).unwrap();
    assert_eq!(tree.lines(tree.root, false), ["sub0", "sub1", "keep"]);
}

#[test]
fn per_line_subs_apply_when_the_prefilter_cannot_be_built() {
    // More rules than the dispatch table holds, too large for a combined set.
    let mut driver = Driver::for_platform(Platform::Generic);
    driver.rules.per_line_sub = (0..63)
        .map(|index| PerLineSubRule {
            search: format!("^tiny{index}$"),
            replace: "small".to_owned(),
        })
        .chain(oversized_subs(2, 200))
        .collect();
    let config = format!(
        "tiny7\nr0-{}\nr1-{}\nkeep",
        "x".repeat(200),
        "y".repeat(200)
    );
    let tree = parse_tree(driver, &config).unwrap();
    assert_eq!(
        tree.lines(tree.root, false),
        ["small", "sub0", "sub1", "keep"]
    );
}

fn dump_line(depth: usize, text: &str) -> DumpLine {
    DumpLine {
        depth,
        text: text.to_owned(),
        tags: BTreeSet::new(),
        comments: BTreeSet::new(),
        new_in_config: false,
    }
}

#[test]
fn from_dump_restores_siblings_ascents_skips_and_metadata() {
    let mut first = dump_line(1, "a");
    first.tags = BTreeSet::from(["edge".to_owned()]);
    first.comments = BTreeSet::from(["note".to_owned()]);
    first.new_in_config = true;
    let dump = Dump {
        lines: vec![
            first,
            dump_line(2, "b"),
            dump_line(2, "c"),
            dump_line(3, "d"),
            dump_line(2, "e"),
            // Two levels below its predecessor: no ancestor fits, so it lands at
            // the root.
            dump_line(4, "f"),
        ],
    };
    let tree = from_dump(Driver::for_platform(Platform::Generic), &dump).unwrap();
    assert_eq!(
        tree.lines(tree.root, false),
        ["a", "  b", "  c", "    d", "  e", "f"]
    );
    let a = tree.arena[tree.root].children.get("a").unwrap();
    assert_eq!(tree.arena[a].tags(), &BTreeSet::from(["edge".to_owned()]));
    assert_eq!(
        tree.arena[a].comments(),
        &BTreeSet::from(["note".to_owned()])
    );
    assert!(tree.arena[a].new_in_config);
    let f = tree.arena[tree.root].children.get("f").unwrap();
    assert_eq!(tree.arena[f].real_indent_level, 3);
}

#[test]
fn unused_objects_skip_definitions_without_a_name() {
    let mut driver = Driver::for_platform(Platform::Generic);
    driver.rules.unused_objects = vec![UnusedObjectRule {
        match_rules: vec![MatchRule::startswith("object-group")],
        name_re: r"^object-group(?: (?P<name>\S+))?$".to_owned(),
        reference_locations: vec![ReferenceLocation {
            match_rules: vec![MatchRule::startswith("ip access-list")],
            reference_re: r"\b{name}\b".to_owned(),
        }],
    }];
    let mut tree = Tree::new(driver);
    let root = tree.root;
    tree.add_child(root, "object-group", true, false).unwrap();
    let unused = tree
        .add_child(root, "object-group spare", true, false)
        .unwrap();
    tree.add_child(root, "object-group used", true, false)
        .unwrap();
    let acl = tree
        .add_child(root, "ip access-list acl", true, false)
        .unwrap();
    tree.add_child(acl, "permit used", true, false).unwrap();
    assert_eq!(tree.try_unused_objects().unwrap(), [unused]);
}

#[test]
fn fortios_idempotency_ignores_single_word_declarations() {
    let mut driver = Driver::for_platform(Platform::FortinetFortios);
    driver.declaration_prefix = "set".to_owned();
    let mut tree = Tree::new(driver.clone());
    let word = tree.add_child(tree.root, "settings", true, false).unwrap();
    let pair = tree
        .add_child(tree.root, "set mtu 1500", true, false)
        .unwrap();
    let mut other = Tree::new(driver);
    let other_word = other
        .add_child(other.root, "settings", true, false)
        .unwrap();
    let other_pair = other
        .add_child(other.root, "set mtu 9000", true, false)
        .unwrap();
    let candidates = [other_word, other_pair];
    assert_eq!(tree.idempotent_for(word, &other, &candidates), None);
    assert_eq!(
        tree.idempotent_for(pair, &other, &candidates),
        Some(other_pair)
    );
}

#[test]
fn deleted_node_ids_render_as_one_empty_line() {
    let mut tree =
        Tree::from_str(Platform::Generic, "interface x\n description d\nhostname h").unwrap();
    let interface = tree.arena[tree.root].children.get("interface x").unwrap();
    tree.delete_child(interface);
    assert_eq!(tree.lines(interface, false), [String::new()]);
    assert_eq!(tree.lines(tree.root, false), ["hostname h"]);
}
