use crate::arena::NodeId;
use crate::tree::{Tree, TreeError};
use rustc_hash::{FxHashMap as HashMap, FxHashSet as HashSet};
use std::sync::Arc;

/// Computes the delta configuration needed to transition from `source` to `target`.
///
/// # Errors
///
/// Returns [`TreeError`] if the delta tree cannot be built, for example when a
/// remediation line cannot be inserted under its parent.
pub fn config_to_get_to(source: &Tree, target: &Tree) -> Result<Tree, TreeError> {
    let mut delta = Tree::new(source.driver.clone());
    config_to_get_to_into(source, target, &mut delta)?;
    Ok(delta)
}

/// Computes the delta configuration needed to transition from `source` to `target`, populating `delta`.
///
/// # Errors
///
/// Returns [`TreeError`] if a remediation line cannot be inserted into `delta`.
pub fn config_to_get_to_into(
    source: &Tree,
    target: &Tree,
    delta: &mut Tree,
) -> Result<(), TreeError> {
    source
        .driver
        .rules
        .validate_regexes()
        .map_err(TreeError::InvalidRegex)?;
    target
        .driver
        .rules
        .validate_regexes()
        .map_err(TreeError::InvalidRegex)?;
    RemediationContext::new(source, target, delta).compute()
}

/// Delta sections entered while walking two trees, created only once a change
/// is emitted beneath them.
///
/// `base` is an existing delta node. Each pending section is appended (and
/// indexed) under its parent the first time [`Self::node`] is called inside it.
/// Nothing else is added to a parent while a child section is open, so sibling
/// order matches creating every section eagerly and dropping the empty ones.
#[derive(Debug)]
struct LazyDelta {
    base: NodeId,
    sections: Vec<(Arc<str>, Option<NodeId>)>,
}

impl LazyDelta {
    const fn new(base: NodeId) -> Self {
        Self {
            base,
            sections: Vec::new(),
        }
    }

    fn enter(&mut self, text: &Arc<str>) {
        self.sections.push((Arc::clone(text), None));
    }

    fn leave(&mut self) {
        self.sections.pop();
    }

    /// The current delta node if it already exists.
    fn existing(&self) -> Option<NodeId> {
        self.sections.last().map_or(Some(self.base), |&(_, id)| id)
    }

    /// The current delta node, creating any pending sections on the way.
    fn node(&mut self, delta: &mut Tree) -> Result<NodeId, TreeError> {
        if let Some(id) = self.existing() {
            return Ok(id);
        }
        let created = self.sections.iter().rposition(|&(_, id)| id.is_some());
        let mut parent = created
            .and_then(|index| self.sections[index].1)
            .unwrap_or(self.base);
        let first_pending = created.map_or(0, |index| index + 1);
        for (text, id) in &mut self.sections[first_pending..] {
            parent = delta.append_shared_child(parent, text)?;
            *id = Some(parent);
        }
        Ok(parent)
    }
}

/// Context managing the computation of remediation changes between a source and target tree into a delta tree.
#[derive(Debug)]
pub struct RemediationContext<'a> {
    pub source: &'a Tree,
    pub target: &'a Tree,
    pub delta: &'a mut Tree,
    lazy: LazyDelta,
}

impl<'a> RemediationContext<'a> {
    /// Creates a new remediation context.
    pub const fn new(source: &'a Tree, target: &'a Tree, delta: &'a mut Tree) -> Self {
        let lazy = LazyDelta::new(delta.root);
        Self {
            source,
            target,
            delta,
            lazy,
        }
    }

    /// Computes the delta from source root to target root into the delta root.
    ///
    /// # Errors
    ///
    /// Returns [`TreeError`] if constructing the remediation tree fails.
    pub fn compute(&mut self) -> Result<(), TreeError> {
        self.lazy = LazyDelta::new(self.delta.root);
        self.compute_node(self.source.root, self.target.root)
    }

    fn compute_node(&mut self, source_node: NodeId, target_node: NodeId) -> Result<(), TreeError> {
        self.compute_left(source_node, target_node)?;
        self.compute_right(source_node, target_node)?;
        Ok(())
    }

    fn compute_left(&mut self, source_node: NodeId, target_node: NodeId) -> Result<(), TreeError> {
        let target_children = self.target.arena[target_node].children.as_slice();

        for self_child_id in self.source.arena[source_node].children.iter() {
            let self_text = &self.source.arena[self_child_id].text;

            if self.target.arena[target_node].children.contains(self_text) {
                continue;
            }

            if self
                .source
                .is_idempotent_command(self_child_id, self.target, target_children)
            {
                continue;
            }

            // v3 adds the child under its *original* text and negates it in
            // place, so the duplicate check keys on the pre-negation text.
            let self_text = String::from(&**self_text);
            let negated_text = self.source.try_compute_negation(self_child_id)?;
            let delta_node = self.lazy.node(self.delta)?;
            let negated_id = self.delta.add_child(delta_node, &self_text, true, false)?;
            self.delta.set_text(negated_id, &negated_text);

            let child_count = self.source.arena[self_child_id].children.len();
            if child_count > 0 {
                self.delta.arena[negated_id]
                    .comments_mut()
                    .insert(format!("removes {} lines", child_count + 1));
            }
        }

        Ok(())
    }

    fn compute_right(&mut self, source_node: NodeId, target_node: NodeId) -> Result<(), TreeError> {
        let target = self.target;
        for target_child_id in target.arena[target_node].children.iter() {
            let target_text = &target.arena[target_child_id].text;

            if let Some(self_child_id) = self.source.arena[source_node].children.get(target_text) {
                if self.source.use_sectional_overwrite(self_child_id) {
                    self.overwrite_lazy(self_child_id, target_child_id, true)?;
                    continue;
                }

                if self
                    .source
                    .use_sectional_overwrite_without_negation(self_child_id)
                {
                    self.overwrite_lazy(self_child_id, target_child_id, false)?;
                    continue;
                }

                // The subtree section is only created once a change lands in it,
                // so unchanged sections cost no allocation. v3 uses
                // `instantiate_child` + `children.append` here, which performs no
                // duplicate check: the subtree may share its text with a negation
                // already emitted by `compute_left`.
                self.lazy.enter(target_text);
                let result = self.compute_node(self_child_id, target_child_id);
                self.lazy.leave();
                result?;
            } else {
                // Target child is absent from source
                if self
                    .lazy
                    .existing()
                    .is_some_and(|id| self.delta.arena[id].children.contains(target_text))
                {
                    continue;
                }

                let delta_node = self.lazy.node(self.delta)?;
                let new_item_id =
                    self.delta
                        .add_deep_copy_of(delta_node, self.target, target_child_id, false)?;
                self.delta.arena[new_item_id].new_in_config = true;
                for desc_id in self.delta.all_children(new_item_id) {
                    self.delta.arena[desc_id].new_in_config = true;
                }
                if !self.delta.arena[new_item_id].children.is_empty() {
                    self.delta.arena[new_item_id]
                        .comments_mut()
                        .insert("new section".to_string());
                }
            }
        }

        Ok(())
    }

    /// Replaces the children of `target_child_id` with those of `source_child_id`.
    ///
    /// # Errors
    ///
    /// Returns [`TreeError`] if modifying the delta tree fails.
    pub fn overwrite_with(
        &mut self,
        source_child_id: NodeId,
        target_child_id: NodeId,
        delta_node: NodeId,
        negate: bool,
    ) -> Result<(), TreeError> {
        let outer = std::mem::replace(&mut self.lazy, LazyDelta::new(delta_node));
        let result = self.overwrite_lazy(source_child_id, target_child_id, negate);
        self.lazy = outer;
        result
    }

    fn overwrite_lazy(
        &mut self,
        source_child_id: NodeId,
        target_child_id: NodeId,
        negate: bool,
    ) -> Result<(), TreeError> {
        if !children_equal(self.source, source_child_id, self.target, target_child_id) {
            let delta_node = self.lazy.node(self.delta)?;
            let self_text = &self.source.arena[source_child_id].text;
            // An empty source section carries nothing to drop, so skip the
            // negation and only re-create it. Negating here would emit a
            // spurious `no <section>` for a section that holds no lines.
            let negate = negate && !self.source.arena[source_child_id].children.is_empty();

            if negate {
                let new_neg_text = self.source.try_compute_negation(source_child_id)?;
                let neg_id = if let Some(existing_id) =
                    self.delta.arena[delta_node].children.get(self_text)
                {
                    self.delta.set_text(existing_id, &new_neg_text);
                    existing_id
                } else {
                    self.delta
                        .add_child(delta_node, &new_neg_text, false, false)?
                };
                self.delta.arena[neg_id]
                    .comments_mut()
                    .insert("dropping section".to_string());
            } else if let Some(existing_id) = self.delta.arena[delta_node].children.get(self_text) {
                self.delta.delete_child(existing_id);
            }

            let new_item_id =
                self.delta
                    .add_deep_copy_of(delta_node, self.target, target_child_id, false)?;
            self.delta.arena[new_item_id]
                .comments_mut()
                .insert("re-create section".to_string());
        }
        Ok(())
    }
}

/// Replaces the children of `target_child_id` with those of `source_child_id`.
///
/// # Errors
///
/// Returns [`TreeError`] if either node id is not present in its tree, or if a
/// copied child cannot be inserted.
pub fn overwrite_with(
    source: &Tree,
    source_child_id: NodeId,
    target: &Tree,
    target_child_id: NodeId,
    delta: &mut Tree,
    delta_node: NodeId,
    negate: bool,
) -> Result<(), TreeError> {
    RemediationContext::new(source, target, delta).overwrite_with(
        source_child_id,
        target_child_id,
        delta_node,
        negate,
    )
}

/// Recursively compares whether the child hierarchies of two nodes are equivalent.
pub fn children_equal(tree_a: &Tree, a: NodeId, tree_b: &Tree, b: NodeId) -> bool {
    let sorted_a = tree_a.sorted_children(a);
    let sorted_b = tree_b.sorted_children(b);

    if sorted_a.len() != sorted_b.len() {
        return false;
    }

    for (child_a, child_b) in sorted_a.into_iter().zip(sorted_b) {
        let node_a = &tree_a.arena[child_a];
        let node_b = &tree_b.arena[child_b];

        if node_a.text != node_b.text || node_a.tags() != node_b.tags() {
            return false;
        }

        if !children_equal(tree_a, child_a, tree_b, child_b) {
            return false;
        }
    }

    true
}

/// Predicts the future configuration resulting from applying `config` to `source`.
///
/// # Errors
///
/// Returns [`TreeError`] if the predicted tree cannot be assembled.
pub fn future(source: &Tree, config: &Tree, prune_empty_branches: bool) -> Result<Tree, TreeError> {
    let (future_config, _) = future_with_report(source, config, prune_empty_branches)?;
    Ok(future_config)
}

/// How `future()` resolved the change's negations (#285).
///
/// The node ids reference the returned future config tree, so callers can
/// resolve them back to nodes for surrounding context.
#[derive(Debug, Default, Clone)]
pub struct FutureReport {
    /// Kept negation lines whose positive form matched nothing in the source
    /// config -- the change did not apply cleanly.
    pub unresolved_negations: Vec<NodeId>,
    /// Negation lines that persisted by replacing an idempotency-tracked
    /// counterpart (e.g. IOS `no logging console`).
    pub idempotency_replacements: Vec<NodeId>,
}

/// Like [`future`], but also reports how negations resolved.
///
/// # Errors
///
/// Returns [`TreeError`] if the projected tree cannot be built.
pub fn future_with_report(
    source: &Tree,
    config: &Tree,
    prune_empty_branches: bool,
) -> Result<(Tree, FutureReport), TreeError> {
    source
        .driver
        .rules
        .validate_regexes()
        .map_err(TreeError::InvalidRegex)?;
    config
        .driver
        .rules
        .validate_regexes()
        .map_err(TreeError::InvalidRegex)?;
    let mut future_config = Tree::new(source.driver.clone());
    let mut report = FutureReport::default();
    {
        let mut ctx = FutureContext::new(source, config, &mut future_config, &mut report);
        ctx.compute()?;
        if prune_empty_branches {
            let future_root = ctx.future_config.root;
            ctx.prune_emptied_branches(source.root, future_root);
        }
    }
    Ok((future_config, report))
}

fn future_pre(
    source: &Tree,
    source_node: NodeId,
    config: &Tree,
    config_node: NodeId,
) -> (HashSet<Arc<str>>, HashSet<Arc<str>>) {
    let mut negated_or_recursed = HashSet::default();
    let mut config_children_ignore = HashSet::default();

    if !source.driver.rules.has_negate_with() {
        return (negated_or_recursed, config_children_ignore);
    }

    for self_child_id in source.arena[source_node].children.iter() {
        let self_text = &source.arena[self_child_id].text;
        if let Some(negation_text) = source.negate_with(self_child_id)
            && let Some(config_child_id) = config.arena[config_node].children.get(&negation_text)
        {
            negated_or_recursed.insert(Arc::clone(self_text));
            config_children_ignore.insert(Arc::clone(&config.arena[config_child_id].text));
        }
    }

    (negated_or_recursed, config_children_ignore)
}

/// Context managing the projection of configuration changes onto a source tree and tracking negation resolution.
#[derive(Debug)]
pub struct FutureContext<'a> {
    pub source: &'a Tree,
    pub config: &'a Tree,
    pub future_config: &'a mut Tree,
    pub report: &'a mut FutureReport,
}

impl<'a> FutureContext<'a> {
    /// Creates a new future projection context.
    pub const fn new(
        source: &'a Tree,
        config: &'a Tree,
        future_config: &'a mut Tree,
        report: &'a mut FutureReport,
    ) -> Self {
        Self {
            source,
            config,
            future_config,
            report,
        }
    }

    /// Projects the configuration changes from `config` onto `source`.
    ///
    /// # Errors
    ///
    /// Returns [`TreeError`] if modifying the projected tree fails.
    pub fn compute(&mut self) -> Result<(), TreeError> {
        let future_root = self.future_config.root;
        self.compute_node(self.source.root, self.config.root, future_root)
    }

    fn find_negated_counterpart(
        source: &Tree,
        source_node: NodeId,
        text: &str,
        lookup: &mut String,
    ) -> Option<NodeId> {
        lookup.clear();
        lookup.push_str(&source.driver.negation_prefix);
        lookup.push_str(text);
        source.arena[source_node].children.get(lookup)
    }

    fn compute_node(
        &mut self,
        source_node: NodeId,
        config_node: NodeId,
        future_node_id: NodeId,
    ) -> Result<(), TreeError> {
        let (mut negated_or_recursed, config_children_ignore) =
            future_pre(self.source, source_node, self.config, config_node);

        let source_children = self.source.arena[source_node].children.as_slice();
        let mut negated_text = String::new();

        for config_child_id in self.config.arena[config_node].children.iter() {
            let config_text = &self.config.arena[config_child_id].text;

            if config_children_ignore.contains(&**config_text) {
                continue;
            }

            let is_negation = config_text.starts_with(&self.source.driver.negation_prefix);
            let text_without_neg = self.source.driver.text_without_negation(config_text);

            if self.config.use_sectional_overwrite(config_child_id)
                || self
                    .config
                    .use_sectional_overwrite_without_negation(config_child_id)
            {
                self.future_config.add_deep_copy_of(
                    future_node_id,
                    self.config,
                    config_child_id,
                    false,
                )?;
            } else if is_negation
                && self.source.arena[source_node]
                    .children
                    .contains(text_without_neg)
            {
                negated_or_recursed.insert(Arc::from(text_without_neg));
            } else if let Some(self_child_id) =
                self.config
                    .idempotent_for(config_child_id, self.source, source_children)
            {
                let added = self.future_config.add_deep_copy_of(
                    future_node_id,
                    self.config,
                    config_child_id,
                    false,
                )?;
                if is_negation {
                    self.report.idempotency_replacements.push(added);
                }
                negated_or_recursed.insert(Arc::clone(&self.source.arena[self_child_id].text));
            } else if is_negation
                && Self::match_prefix_negations(
                    self.source,
                    source_node,
                    text_without_neg,
                    &mut negated_or_recursed,
                )
            {
                // Prefix negations inserted by helper
            } else if let Some(self_child_id) =
                self.source.arena[source_node].children.get(config_text)
            {
                let future_child = self.future_config.add_shallow_copy_of(
                    future_node_id,
                    self.source,
                    self_child_id,
                    false,
                )?;
                self.compute_node(self_child_id, config_child_id, future_child)?;
                negated_or_recursed.insert(Arc::clone(config_text));
            } else if is_negation {
                let added = self.future_config.add_shallow_copy_of(
                    future_node_id,
                    self.config,
                    config_child_id,
                    false,
                )?;
                self.report.unresolved_negations.push(added);
            } else if let Some(self_child_id) = Self::find_negated_counterpart(
                self.source,
                source_node,
                config_text,
                &mut negated_text,
            ) {
                negated_or_recursed.insert(Arc::clone(&self.source.arena[self_child_id].text));
            } else {
                self.future_config.add_deep_copy_of(
                    future_node_id,
                    self.config,
                    config_child_id,
                    false,
                )?;
            }
        }

        for self_child_id in self.source.arena[source_node].children.iter() {
            let self_text = &self.source.arena[self_child_id].text;
            if negated_or_recursed.contains(&**self_text) {
                continue;
            }
            self.future_config.add_deep_copy_of(
                future_node_id,
                self.source,
                self_child_id,
                false,
            )?;
        }

        Ok(())
    }

    /// Recursively prunes emptied branches where children in source were negated.
    pub fn prune_emptied_branches(&mut self, source_node: NodeId, future_node_id: NodeId) {
        let children: Vec<NodeId> = self.future_config.arena[future_node_id]
            .children
            .iter()
            .collect();

        for child_id in children {
            let child_text = &self.future_config.arena[child_id].text;
            if let Some(src_child_id) = self.source.arena[source_node].children.get(child_text) {
                self.prune_emptied_branches(src_child_id, child_id);
                if self.future_config.arena[child_id].children.is_empty()
                    && !self.source.arena[src_child_id].children.is_empty()
                {
                    self.future_config.delete_child(child_id);
                }
            }
        }
    }

    fn match_prefix_negations(
        source: &Tree,
        source_node: NodeId,
        stem: &str,
        negated_or_recursed: &mut HashSet<Arc<str>>,
    ) -> bool {
        let mut matched = false;
        for id in source.arena[source_node].children.iter() {
            let text = &source.arena[id].text;
            if text
                .strip_prefix(stem)
                .is_some_and(|rest| rest.starts_with(' '))
            {
                negated_or_recursed.insert(Arc::clone(text));
                matched = true;
            }
        }
        matched
    }
}

/// Strips leading sequence number from ACL entry line text.
#[must_use]
pub fn strip_acl_sequence_number(text: &str) -> String {
    let words: Vec<&str> = text.split_whitespace().collect();
    if let Some((first, rest)) = words.split_first()
        && first.chars().all(|c| c.is_ascii_digit())
    {
        return rest.join(" ");
    }
    words.join(" ")
}

/// Computes the difference configuration of `source` not present in `target`.
///
/// # Errors
///
/// Returns [`TreeError`] if the difference tree cannot be assembled.
pub fn difference(source: &Tree, target: &Tree) -> Result<Tree, TreeError> {
    let mut delta = Tree::new(source.driver.clone());
    let mut trees = DiffTrees {
        source,
        target,
        lazy: LazyDelta::new(delta.root),
        delta: &mut delta,
    };
    trees.compute()?;
    Ok(delta)
}

struct DiffTrees<'a> {
    source: &'a Tree,
    target: &'a Tree,
    delta: &'a mut Tree,
    lazy: LazyDelta,
}

impl DiffTrees<'_> {
    fn compute(&mut self) -> Result<(), TreeError> {
        self.compute_node(self.source.root, self.target.root, None, false)
    }

    fn compute_node(
        &mut self,
        source_node: NodeId,
        target_node: NodeId,
        target_acl_children: Option<&HashMap<String, NodeId>>,
        in_acl: bool,
    ) -> Result<(), TreeError> {
        let acl_prefixes = ["ip access-list ", "ipv4 access-list ", "ipv6 access-list "];

        for self_child_id in self.source.arena[source_node].children.iter() {
            let self_text = &self.source.arena[self_child_id].text;

            if self_text.starts_with(&self.source.driver.negation_prefix)
                || self_text.starts_with("default ")
            {
                continue;
            }

            let target_child = if in_acl {
                let stripped = strip_acl_sequence_number(self_text);
                target_acl_children.and_then(|map| map.get(&stripped).copied())
            } else {
                self.target.arena[target_node].children.get(self_text)
            };

            if let Some(target_child_id) = target_child {
                self.lazy.enter(self_text);

                let result = if acl_prefixes
                    .iter()
                    .any(|prefix| self_text.starts_with(prefix))
                {
                    let mut acl_map = HashMap::default();
                    for c_id in self.target.arena[target_child_id].children.iter() {
                        let stripped = strip_acl_sequence_number(&self.target.arena[c_id].text);
                        acl_map.insert(stripped, c_id);
                    }

                    self.compute_node(self_child_id, target_child_id, Some(&acl_map), true)
                } else {
                    self.compute_node(self_child_id, target_child_id, None, false)
                };
                self.lazy.leave();
                result?;
            } else {
                let delta_node = self.lazy.node(self.delta)?;
                self.delta
                    .add_deep_copy_of(delta_node, self.source, self_child_id, false)?;
            }
        }

        Ok(())
    }
}

/// Computes unified diff comparison lines between `source` and `target`.
pub fn unified_diff(source: &Tree, target: &Tree) -> Vec<String> {
    let mut lines = Vec::new();
    UnifiedDiff { source, target }.node(source.root, target.root, 1, &mut lines);
    lines
}

struct UnifiedDiff<'a> {
    source: &'a Tree,
    target: &'a Tree,
}

impl UnifiedDiff<'_> {
    /// Appends the diff of the children of `source_node` and `target_node`, which
    /// sit at `depth`, to `lines`.
    fn node(
        &self,
        source_node: NodeId,
        target_node: NodeId,
        depth: usize,
        lines: &mut Vec<String>,
    ) {
        let (source, target) = (self.source, self.target);
        let source_children = &source.arena[source_node].children;
        let target_children = &target.arena[target_node].children;
        let source_indent = source.driver.rules.indentation * (depth - 1);
        let target_indent = target.driver.rules.indentation * (depth - 1);

        // Elements in source
        for (position, self_child) in source_children.iter().enumerate() {
            let self_text = &source.arena[self_child].text;
            if let Some(target_child) = target_children.get_at(position, self_text, &target.arena) {
                let start = lines.len();
                self.node(self_child, target_child, depth + 1, lines);
                if lines.len() > start {
                    lines.insert(start, diff_line(source_indent, "", self_text));
                }
            } else {
                lines.push(diff_line(source_indent, "- ", self_text));
                push_subtree(source, self_child, depth + 1, "- ", lines);
            }
        }

        // Elements in target missing from source
        for (position, target_child) in target_children.iter().enumerate() {
            let target_text = &target.arena[target_child].text;
            if source_children
                .get_at(position, target_text, &source.arena)
                .is_none()
            {
                lines.push(diff_line(target_indent, "+ ", target_text));
                push_subtree(target, target_child, depth + 1, "+ ", lines);
            }
        }
    }
}

/// Appends every descendant of `node_id`, whose children sit at `depth`, in
/// sorted pre-order with `marker`.
fn push_subtree(tree: &Tree, node_id: NodeId, depth: usize, marker: &str, lines: &mut Vec<String>) {
    let indentation = tree.driver.rules.indentation;
    let children = tree.arena[node_id].children.as_slice();
    let sorted;
    let ordered = if tree.children_already_ordered(children) {
        children
    } else {
        sorted = tree.sorted_children(node_id);
        &sorted
    };
    for &child_id in ordered {
        lines.push(diff_line(
            indentation * (depth - 1),
            marker,
            &tree.arena[child_id].text,
        ));
        push_subtree(tree, child_id, depth + 1, marker, lines);
    }
}

fn diff_line(width: usize, marker: &str, text: &str) -> String {
    let mut line = String::with_capacity(width + marker.len() + text.len());
    line.extend(std::iter::repeat_n(' ', width));
    line.push_str(marker);
    line.push_str(text);
    line
}
