use hier_config_core::formats::{FormatError, to_gnmi_json, to_netconf_xml, to_xml};
use hier_config_core::regex_cache::{fancy, python_replacement, regex};
use hier_config_core::{Platform, TextMatch, Tree, TreeError};

#[test]
fn repeated_xml_entries_with_the_same_identity_are_duplicate_children() {
    let error = Tree::from_xml(
        Platform::CiscoIos,
        "<c><i><name>a</name></i><i><name>a</name></i></c>",
        None,
    )
    .expect_err("duplicate identity");
    assert!(
        matches!(error, FormatError::Tree(TreeError::DuplicateChild(_))),
        "{error:?}"
    );
}

#[test]
fn unbalanced_xml_end_tags_are_rejected() {
    for source in ["</a>", "<a></a></b>"] {
        let error = Tree::from_xml(Platform::Generic, source, None).expect_err("unbalanced");
        let message = error.to_string();
        assert!(
            message.starts_with("The config is not valid XML"),
            "{message}"
        );
    }
}

#[test]
fn repeated_attribute_nodes_render_the_last_value() {
    let tree = Tree::from_str(Platform::Generic, "c\n  @x \"1\"\n  @x \"2\"").unwrap();
    assert_eq!(to_xml(&tree).unwrap(), "<c x=\"2\" />");
}

#[test]
fn netconf_renders_attributes_and_valueless_deletes() {
    let remediation = Tree::from_str(Platform::CiscoIos, "c\n  @x \"1\"\n  no shutdown").unwrap();
    assert_eq!(
        to_netconf_xml(&remediation, None, None).unwrap(),
        "<c x=\"1\" xmlns:nc=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n  \
<shutdown nc:operation=\"delete\" />\n</c>"
    );
}

#[test]
fn gnmi_renders_valueless_leaves_as_empty_objects() {
    let remediation = Tree::from_str(Platform::Generic, "c\n  shutdown").unwrap();
    let result = to_gnmi_json(&remediation, None, None).unwrap();
    assert_eq!(
        serde_json::Value::Object(result.update),
        serde_json::json!({"c": {"shutdown": {}}})
    );
    assert!(result.delete.is_empty());
}

#[test]
fn json_strings_use_python_short_escapes() {
    let tree = Tree::from_json(
        Platform::Generic,
        r#"{"a": "back\\slash", "b": "bell\bform\f"}"#,
        None,
    )
    .unwrap();
    assert_eq!(
        tree.dump_simple(false),
        [r#"a "back\\slash""#, r#"b "bell\bform\f""#]
    );
}

#[test]
fn contains_or_endswith_matches_either_predicate() {
    assert!(TextMatch::contains_or_endswith("interface Gi0/1", "Gi0"));
    assert!(TextMatch::contains_or_endswith("interface Gi0/1", "0/1"));
    assert!(!TextMatch::contains_or_endswith("interface Gi0/1", "Te0"));
}

#[test]
fn python_null_escapes_stop_at_non_octal_digits() {
    let re = regex("x").unwrap();
    assert_eq!(python_replacement(&re, r"a\0").unwrap(), "a\u{0}");
    assert_eq!(python_replacement(&re, r"\01x").unwrap(), "\u{1}x");
}

#[test]
fn backtracking_limit_failures_are_reported_as_errors() {
    let re = fancy(r"^(a|a)*\1b").expect("valid pattern");
    let error = re
        .is_match(&"a".repeat(40))
        .expect_err("catastrophic backtracking");
    assert!(
        error.starts_with(r#"regex evaluation failed for "^(a|a)*\\1b": "#),
        "{error}"
    );
}

#[test]
fn numeric_replacement_groups_that_overflow_are_rejected() {
    let re = regex("(x)").unwrap();
    let error = python_replacement(&re, r"\g<99999999999999999999999>").expect_err("overflow");
    assert_eq!(error, "number too large to fit in target type");
}

#[test]
fn re_search_reports_invalid_patterns() {
    let error = TextMatch::re_search("x", "(unclosed").expect_err("invalid pattern");
    assert_eq!(error.to_string(), "invalid pattern: (unclosed");
}
