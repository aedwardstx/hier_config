use crate::arena::{Arena, NodeId};
use crate::tree::node::Node;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::sync::Arc;

/// Hash map behind the text index of a large section.
///
/// This deliberately uses `std::collections::HashMap` and its randomly seeded
/// `RandomState` rather than the faster `FxHashMap` used elsewhere in the crate:
/// the keys here are raw configuration lines, which are attacker-controlled. Fx's
/// hasher is fixed and unseeded, so a crafted configuration could force every line
/// into one bucket and degrade insertion to O(n^2). Maps keyed by internal
/// integers/`NodeId`s are not reachable this way and keep using `FxHashMap`.
type Mapping = HashMap<Arc<str>, NodeId>;

/// Most distinct texts an index holds before it switches to a hash map.
///
/// Typical sections (an interface, a neighbour) have a handful of children, so a
/// short linear scan of length-prefixed strings beats hashing every line with
/// `SipHash`. Lookups stay bounded by this constant; anything larger, including
/// attacker-sized sections, uses the seeded hash map.
const SMALL_INDEX_LIMIT: usize = 8;

/// Text-keyed index from a child's text to the *first* child that carries it.
#[derive(Debug, Clone)]
enum Index {
    Small(Vec<(Arc<str>, NodeId)>),
    Large(Mapping),
}

impl Index {
    const fn new() -> Self {
        Self::Small(Vec::new())
    }

    fn from_map(map: Mapping) -> Self {
        if map.len() <= SMALL_INDEX_LIMIT {
            Self::Small(map.into_iter().collect())
        } else {
            Self::Large(map)
        }
    }

    fn len(&self) -> usize {
        match self {
            Self::Small(entries) => entries.len(),
            Self::Large(map) => map.len(),
        }
    }

    fn get(&self, text: &str) -> Option<NodeId> {
        match self {
            Self::Small(entries) => entries
                .iter()
                .find(|(key, _)| key.as_ref() == text)
                .map(|&(_, id)| id),
            Self::Large(map) => map.get(text).copied(),
        }
    }

    /// Indexes `text` unless already present, creating its id only when it is new.
    fn insert_first(
        &mut self,
        text: &Arc<str>,
        insert: impl FnOnce() -> NodeId,
    ) -> Result<NodeId, NodeId> {
        match self {
            Self::Small(entries) => {
                if let Some(&(_, existing)) = entries
                    .iter()
                    .find(|(key, _)| key.as_ref() == text.as_ref())
                {
                    return Err(existing);
                }
                let id = insert();
                if entries.len() < SMALL_INDEX_LIMIT {
                    entries.push((Arc::clone(text), id));
                } else {
                    let mut map = Mapping::with_capacity(SMALL_INDEX_LIMIT * 2);
                    map.extend(entries.drain(..));
                    map.insert(Arc::clone(text), id);
                    *self = Self::Large(map);
                }
                Ok(id)
            }
            Self::Large(map) => match map.entry(Arc::clone(text)) {
                Entry::Occupied(existing) => Err(*existing.get()),
                Entry::Vacant(slot) => Ok(*slot.insert(insert())),
            },
        }
    }

    /// Drops `text` from the index if it currently resolves to `id`.
    fn remove_if(&mut self, text: &str, id: NodeId) {
        match self {
            Self::Small(entries) => {
                if let Some(position) = entries
                    .iter()
                    .position(|(key, value)| *value == id && key.as_ref() == text)
                {
                    entries.swap_remove(position);
                }
            }
            Self::Large(map) => {
                if map.get(text) == Some(&id) {
                    map.remove(text);
                }
            }
        }
    }

    fn entries(&self) -> impl Iterator<Item = (&Arc<str>, NodeId)> {
        let (small, large) = match self {
            Self::Small(entries) => (Some(entries), None),
            Self::Large(map) => (None, Some(map)),
        };
        small
            .into_iter()
            .flatten()
            .map(|(key, id)| (key, *id))
            .chain(large.into_iter().flatten().map(|(key, id)| (key, *id)))
    }
}

impl PartialEq for Index {
    /// Compares as maps: the representation and the scan order of a small index
    /// depend on mutation history, not on what it indexes.
    fn eq(&self, other: &Self) -> bool {
        self.len() == other.len() && self.entries().all(|(key, id)| other.get(key) == Some(id))
    }
}

impl Eq for Index {}

impl Serialize for Index {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_map(self.entries())
    }
}

impl<'de> Deserialize<'de> for Index {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Mapping::deserialize(deserializer).map(Self::from_map)
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
/// empty hash table. Its keys are `Arc<str>` shared with the node itself, so
/// indexing a child is a reference-count bump instead of a second copy of every
/// configuration line. And small sections are indexed by a short vector rather
/// than a hash map (see [`SMALL_INDEX_LIMIT`]).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Children {
    data: Vec<NodeId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mapping: Option<Box<Index>>,
}

impl Children {
    fn index_mut(&mut self) -> &mut Index {
        self.mapping.get_or_insert_with(|| Box::new(Index::new()))
    }

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
            let _ = self.index_mut().insert_first(text, || child_id);
        }
    }

    /// Appends a child unless one with `text` is already indexed, hashing `text` once.
    ///
    /// `insert` creates the child only when the text is new; otherwise the existing
    /// child's id is returned as the error and nothing is modified.
    pub(crate) fn append_unique(
        &mut self,
        text: &Arc<str>,
        insert: impl FnOnce() -> NodeId,
    ) -> Result<NodeId, NodeId> {
        let child_id = self.index_mut().insert_first(text, insert)?;
        self.data.push(child_id);
        Ok(child_id)
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

    /// Removes `id` in O(1) when it is the trailing child, returning whether it did.
    ///
    /// Unlike [`Self::delete_by_id`] this does not rebuild the mapping, so it only
    /// reproduces a rebuild when the mapping already indexes the first occurrence of
    /// every text (as `append` and the rebuilding mutators maintain). Under that
    /// invariant the trailing child is indexed only if no earlier sibling shares its
    /// text, so dropping its own entry is all a rebuild would change.
    pub(crate) fn pop_if_last(&mut self, id: NodeId, text: &str) -> bool {
        if self.data.last() != Some(&id) {
            return false;
        }
        self.data.pop();
        if self.data.is_empty() {
            self.mapping = None;
        } else if let Some(mapping) = self.mapping.as_mut() {
            mapping.remove_if(text, id);
        }
        true
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

    /// Rebuilds the text -> `NodeId` mapping from current `data`.
    pub fn rebuild_mapping(&mut self, arena: &Arena<Node>) {
        if self.data.is_empty() {
            self.mapping = None;
            return;
        }
        let mut index = Index::new();
        for &id in &self.data {
            if let Some(node) = arena.get(id) {
                let _ = index.insert_first(&node.text, || id);
            }
        }
        self.mapping = Some(Box::new(index));
    }

    /// Returns an iterator over all keys in the mapping.
    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.mapping
            .iter()
            .flat_map(|mapping| mapping.entries().map(|(key, _)| key.as_ref()))
    }
}
