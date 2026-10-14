use crate::arena::{Arena, NodeId};
use crate::tree::node::Node;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::sync::Arc;

/// Text-keyed index from a child's text to the *first* child that carries it.
///
/// This deliberately uses `std::collections::HashMap` and its randomly seeded
/// `RandomState` rather than the faster `FxHashMap` used elsewhere in the crate:
/// the keys here are raw configuration lines, which are attacker-controlled. Fx's
/// hasher is fixed and unseeded, so a crafted configuration could force every line
/// into one bucket and degrade insertion to O(n^2). Maps keyed by internal
/// integers/`NodeId`s are not reachable this way and keep using `FxHashMap`.
type Mapping = HashMap<Arc<str>, NodeId>;

/// Largest index kept as a linear list before it is promoted to a [`Mapping`].
///
/// Most parents in a real configuration have a handful of children. Comparing a
/// few keys directly is cheaper than hashing the line with `SipHash`, and bounding
/// the list keeps each scan constant-time, so hash-flooding protection holds.
const LINEAR_INDEX_MAX: usize = 8;

/// Text index behind [`Children`], sized to the number of indexed children.
#[derive(Debug, Clone)]
enum Index {
    Linear(Vec<(Arc<str>, NodeId)>),
    Hashed(Mapping),
}

impl Index {
    /// An empty index, sized so it never regrows before promotion.
    fn new() -> Self {
        Self::Linear(Vec::with_capacity(LINEAR_INDEX_MAX))
    }

    fn get(&self, text: &str) -> Option<NodeId> {
        match self {
            Self::Linear(entries) => entries
                .iter()
                .find(|(key, _)| key.as_ref() == text)
                .map(|&(_, id)| id),
            Self::Hashed(mapping) => mapping.get(text).copied(),
        }
    }

    /// Records `id` for `text` unless an earlier child already claimed it, in
    /// which case that child's id is returned instead.
    fn insert_first(&mut self, text: &Arc<str>, id: NodeId) -> Option<NodeId> {
        match self {
            Self::Linear(entries) => {
                if let Some(&(_, existing)) = entries.iter().find(|(key, _)| key == text) {
                    return Some(existing);
                }
                if entries.len() < LINEAR_INDEX_MAX {
                    entries.push((Arc::clone(text), id));
                    return None;
                }
                let mut mapping: Mapping = entries.drain(..).collect();
                mapping.insert(Arc::clone(text), id);
                *self = Self::Hashed(mapping);
                None
            }
            Self::Hashed(mapping) => match mapping.entry(Arc::clone(text)) {
                Entry::Occupied(entry) => Some(*entry.get()),
                Entry::Vacant(entry) => {
                    entry.insert(id);
                    None
                }
            },
        }
    }

    /// Drops the entry for `text` if it maps to `id`.
    fn remove_if(&mut self, text: &str, id: NodeId) {
        match self {
            Self::Linear(entries) => {
                if let Some(position) = entries
                    .iter()
                    .position(|(key, existing)| *existing == id && key.as_ref() == text)
                {
                    entries.remove(position);
                }
            }
            Self::Hashed(mapping) => {
                if mapping.get(text) == Some(&id) {
                    mapping.remove(text);
                }
            }
        }
    }

    fn keys(&self) -> Box<dyn Iterator<Item = &str> + '_> {
        match self {
            Self::Linear(entries) => Box::new(entries.iter().map(|(key, _)| key.as_ref())),
            Self::Hashed(mapping) => Box::new(mapping.keys().map(Arc::as_ref)),
        }
    }

    fn from_mapping(mapping: Mapping) -> Self {
        if mapping.len() <= LINEAR_INDEX_MAX {
            let mut entries = Vec::with_capacity(LINEAR_INDEX_MAX);
            entries.extend(mapping);
            Self::Linear(entries)
        } else {
            Self::Hashed(mapping)
        }
    }

    fn len(&self) -> usize {
        match self {
            Self::Linear(entries) => entries.len(),
            Self::Hashed(mapping) => mapping.len(),
        }
    }

    fn entries(&self) -> Box<dyn Iterator<Item = (&Arc<str>, NodeId)> + '_> {
        match self {
            Self::Linear(entries) => Box::new(entries.iter().map(|(key, id)| (key, *id))),
            Self::Hashed(mapping) => Box::new(mapping.iter().map(|(key, id)| (key, *id))),
        }
    }
}

impl PartialEq for Index {
    /// Compares as maps: the representation and the scan order of a linear index
    /// depend on mutation history, not on what it indexes.
    fn eq(&self, other: &Self) -> bool {
        self.len() == other.len() && self.entries().all(|(key, id)| other.get(key) == Some(id))
    }
}

impl Eq for Index {}

/// Serialises as a plain text-to-id map whatever the representation, so the
/// wire form matches the earlier all-`HashMap` index.
impl Serialize for Index {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_map(self.entries())
    }
}

impl<'de> Deserialize<'de> for Index {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Mapping::deserialize(deserializer).map(Self::from_mapping)
    }
}

/// Ordered collection of child `NodeId`s with fast text-keyed lookup.
///
/// Preserves insertion order in a `Vec<NodeId>` while mapping `child.text` to the
/// *first* occurrence of a child with that text.
///
/// Three details keep this cheap on large configurations. The index is boxed and
/// only allocated once a child is appended with mapping enabled, so the leaf nodes
/// that make up most of a parsed tree carry a single null pointer rather than an
/// empty hash table. Small indexes are a linear list rather than a hash table (see
/// [`LINEAR_INDEX_MAX`]). Its keys are `Arc<str>` shared with the node itself, so
/// indexing a child is a reference-count bump instead of a second copy of every
/// configuration line.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Children {
    data: Vec<NodeId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mapping: Option<Box<Index>>,
}

impl Children {
    /// Creates an empty Children container.
    pub const fn new() -> Self {
        Self {
            data: Vec::new(),
            mapping: None,
        }
    }

    /// Number of children in the collection.
    pub const fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns true if there are no children.
    pub const fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Looks up a child by exact text match (returns the first matching child).
    pub fn get(&self, text: &str) -> Option<NodeId> {
        self.mapping.as_ref()?.get(text)
    }

    /// Looks up a child by text like [`Self::get`], first checking the child at
    /// `position`.
    ///
    /// Walks over two aligned configurations meet the same text at the same
    /// position on both sides. When every child text here is distinct (the index
    /// holds one entry per child), a positional match is necessarily the first
    /// child with that text, so the hash lookup is skipped.
    pub fn get_at(&self, position: usize, text: &str, arena: &Arena<Node>) -> Option<NodeId> {
        if let Some(&id) = self.data.get(position)
            && self
                .mapping
                .as_ref()
                .is_some_and(|index| index.len() == self.data.len())
            && arena.get(id).is_some_and(|node| node.text.as_ref() == text)
        {
            return Some(id);
        }
        self.get(text)
    }

    /// Checks if a child with `text` exists.
    pub fn contains(&self, text: &str) -> bool {
        self.get(text).is_some()
    }

    /// Retrieves a child by index.
    pub fn get_index(&self, index: usize) -> Option<NodeId> {
        self.data.get(index).copied()
    }

    /// Returns the index of a child in the ordered list.
    pub fn index_of(&self, id: NodeId) -> Option<usize> {
        self.data.iter().position(|&x| x == id)
    }

    /// Returns a slice of the child `NodeId`s in insertion order.
    pub fn as_slice(&self) -> &[NodeId] {
        &self.data
    }

    /// Iterates over all child `NodeId`s in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = NodeId> + '_ {
        self.data.iter().copied()
    }

    /// Appends a child to the collection.
    ///
    /// Only the first child with a given `text` is recorded in the mapping. Pass the
    /// child's own `Arc<str>` so the index shares that allocation.
    pub fn append(&mut self, text: &Arc<str>, child_id: NodeId, update_mapping: bool) {
        self.data.push(child_id);
        if update_mapping {
            self.mapping
                .get_or_insert_with(|| Box::new(Index::new()))
                .insert_first(text, child_id);
        }
    }

    /// Indexes `text` for the child that will be appended as `child_id`, in a
    /// single lookup.
    ///
    /// Returns the existing child's id, leaving the collection untouched, when a
    /// child with `text` is already indexed. Otherwise `child_id` is indexed and
    /// the caller must follow with [`Self::push_claimed`].
    pub(crate) fn claim(&mut self, text: &Arc<str>, child_id: NodeId) -> Option<NodeId> {
        self.mapping
            .get_or_insert_with(|| Box::new(Index::new()))
            .insert_first(text, child_id)
    }

    /// Appends a child whose text was indexed by [`Self::claim`].
    pub(crate) fn push_claimed(&mut self, child_id: NodeId) {
        // A parent that gains one child usually gains several; size for a few
        // at once rather than regrowing 0 -> 4 -> 8.
        if self.data.is_empty() {
            self.data.reserve_exact(LINEAR_INDEX_MAX);
        }
        self.data.push(child_id);
    }

    /// Replaces child at `index` and rebuilds the text mapping.
    pub fn set_index(
        &mut self,
        index: usize,
        new_id: NodeId,
        arena: &Arena<Node>,
    ) -> Option<NodeId> {
        if index < self.data.len() {
            let old_id = self.data[index];
            self.data[index] = new_id;
            self.rebuild_mapping(arena);
            Some(old_id)
        } else {
            None
        }
    }

    /// Clears all children.
    pub fn clear(&mut self) {
        self.data.clear();
        self.mapping = None;
    }

    /// Removes a specific child `NodeId` and rebuilds the text mapping.
    pub fn delete_by_id(&mut self, id: NodeId, arena: &Arena<Node>) {
        let old_len = self.data.len();
        self.data.retain(|&x| x != id);
        if self.data.len() != old_len {
            self.rebuild_mapping(arena);
        }
    }

    /// Removes all children with the given text and rebuilds the text mapping.
    pub fn delete_by_text(&mut self, text: &str, arena: &Arena<Node>) {
        if self.contains(text) {
            self.data.retain(|&id| {
                if let Some(node) = arena.get(id) {
                    node.text.as_ref() != text
                } else {
                    false
                }
            });
            self.rebuild_mapping(arena);
        }
    }

    /// Updates the mapping after the child `id` was renamed from `old_text` to
    /// `new_text`.
    ///
    /// Renaming the last child is the common case (remediation negates a line
    /// right after adding it) and is updated in place: no later sibling can
    /// inherit `old_text`, and any earlier holder of `new_text` stays first.
    /// Other positions fall back to [`Self::rebuild_mapping`].
    pub(crate) fn retext(
        &mut self,
        id: NodeId,
        old_text: &str,
        new_text: &Arc<str>,
        arena: &Arena<Node>,
    ) {
        match self.mapping.as_deref_mut() {
            Some(index) if self.data.last() == Some(&id) => {
                index.remove_if(old_text, id);
                index.insert_first(new_text, id);
            }
            _ => self.rebuild_mapping(arena),
        }
    }

    /// Rebuilds the text -> `NodeId` mapping from current `data`.
    pub fn rebuild_mapping(&mut self, arena: &Arena<Node>) {
        if self.data.is_empty() {
            self.mapping = None;
            return;
        }
        let mut index = Index::new();
        for &id in &self.data {
            if let Some(node) = arena.get(id) {
                index.insert_first(&node.text, id);
            }
        }
        self.mapping = Some(Box::new(index));
    }

    /// Returns an iterator over all keys in the mapping.
    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.mapping.iter().flat_map(|index| index.keys())
    }
}
