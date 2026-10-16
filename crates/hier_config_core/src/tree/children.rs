use crate::arena::{Arena, NodeId};
use crate::tree::node::Node;
use serde::{Deserialize, Serialize};
use std::borrow::Borrow;
use std::collections::HashMap;
use std::collections::hash_map::{Entry, RandomState};
use std::hash::{BuildHasher, BuildHasherDefault, Hash, Hasher};
use std::sync::Arc;

/// Text-keyed index from a child's text to the *first* child that carries it.
///
/// This deliberately uses `std::collections::HashMap` and its randomly seeded
/// `RandomState` rather than the faster `FxHashMap` used elsewhere in the crate:
/// the keys here are raw configuration lines, which are attacker-controlled. Fx's
/// hasher is fixed and unseeded, so a crafted configuration could force every line
/// into one bucket and degrade insertion to O(n^2). Maps keyed by internal
/// integers/`NodeId`s are not reachable this way and keep using `FxHashMap`.
///
/// This is the serialised form; in memory a large index is a [`HashedIndex`].
type Mapping = HashMap<Arc<str>, NodeId>;

/// Largest index kept as a linear list before it is promoted to a [`Mapping`].
///
/// Most parents in a real configuration have a handful of children. Comparing a
/// few keys directly is cheaper than hashing the line with `SipHash`, and bounding
/// the list keeps each scan constant-time, so hash-flooding protection holds.
const LINEAR_INDEX_MAX: usize = 8;

/// An index key with its `SipHash`, computed once from the owning
/// [`HashedIndex`]'s randomly seeded state.
///
/// Growing a table rehashes every key; storing the hash means growth reuses it
/// instead of rereading each configuration line.
#[derive(Debug, Clone)]
struct HashedKey {
    hash: u64,
    text: Arc<str>,
}

/// A key as seen by lookups, so a `&str` probe can be hashed once and matched
/// against stored [`HashedKey`]s without allocating an `Arc`.
trait KeyView {
    fn hash_value(&self) -> u64;
    fn text(&self) -> &str;
}

struct Probe<'a> {
    hash: u64,
    text: &'a str,
}

impl KeyView for Probe<'_> {
    fn hash_value(&self) -> u64 {
        self.hash
    }
    fn text(&self) -> &str {
        self.text
    }
}

impl KeyView for HashedKey {
    fn hash_value(&self) -> u64 {
        self.hash
    }
    fn text(&self) -> &str {
        &self.text
    }
}

impl<'a> Borrow<dyn KeyView + 'a> for HashedKey {
    fn borrow(&self) -> &(dyn KeyView + 'a) {
        self
    }
}

impl Hash for dyn KeyView + '_ {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_u64(self.hash_value());
    }
}

impl PartialEq for dyn KeyView + '_ {
    fn eq(&self, other: &Self) -> bool {
        self.hash_value() == other.hash_value() && self.text() == other.text()
    }
}

impl Eq for dyn KeyView + '_ {}

impl Hash for HashedKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_u64(self.hash);
    }
}

impl PartialEq for HashedKey {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash && self.text == other.text
    }
}

impl Eq for HashedKey {}

/// Hands a [`HashedKey`]'s precomputed hash straight to the table.
#[derive(Default)]
struct StoredHash(u64);

impl Hasher for StoredHash {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        // Keys only ever write their stored `u64`; fold anything else in so the
        // hasher stays total.
        for &byte in bytes {
            self.0 = self.0.rotate_left(8) ^ u64::from(byte);
        }
    }

    fn write_u64(&mut self, hash: u64) {
        self.0 = hash;
    }
}

/// Hash table behind a large [`Index`], keyed by text with cached hashes.
#[derive(Debug, Clone)]
struct HashedIndex {
    state: RandomState,
    table: HashMap<HashedKey, NodeId, BuildHasherDefault<StoredHash>>,
}

impl HashedIndex {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            state: RandomState::new(),
            table: HashMap::with_capacity_and_hasher(capacity, BuildHasherDefault::default()),
        }
    }

    fn probe<'a>(&self, text: &'a str) -> Probe<'a> {
        Probe {
            hash: self.state.hash_one(text),
            text,
        }
    }

    fn get(&self, text: &str) -> Option<NodeId> {
        let probe = self.probe(text);
        let probe: &dyn KeyView = &probe;
        self.table.get(probe).copied()
    }

    fn insert_first(&mut self, text: &Arc<str>, id: NodeId) -> Option<NodeId> {
        // Indexes this large belong to the few sections holding most of a
        // configuration, which keep growing; quadrupling instead of doubling
        // halves the number of rehashes on the way there.
        if self.table.len() == self.table.capacity() {
            self.table.reserve(self.table.len() * 3);
        }
        let key = HashedKey {
            hash: self.state.hash_one(&**text),
            text: Arc::clone(text),
        };
        match self.table.entry(key) {
            Entry::Occupied(entry) => Some(*entry.get()),
            Entry::Vacant(entry) => {
                entry.insert(id);
                None
            }
        }
    }

    fn remove_if(&mut self, text: &str, id: NodeId) {
        let probe = self.probe(text);
        let probe: &dyn KeyView = &probe;
        if self.table.get(probe) == Some(&id) {
            self.table.remove(probe);
        }
    }

    fn entries(&self) -> impl Iterator<Item = (&Arc<str>, NodeId)> {
        self.table.iter().map(|(key, &id)| (&key.text, id))
    }
}

/// Up to [`LINEAR_INDEX_MAX`] index entries stored inline, filled from the front.
///
/// Held inline in the boxed [`Index`] rather than in a `Vec`, so a small parent's
/// index is one allocation instead of two. Most branches in a parsed tree have
/// such an index, and each extra allocation is also an extra free on drop.
#[derive(Debug, Clone)]
struct LinearIndex {
    entries: [Option<(Arc<str>, NodeId)>; LINEAR_INDEX_MAX],
    /// Number of filled slots; `Children::get_at` reads it on every lookup.
    len: usize,
}

impl LinearIndex {
    const fn new() -> Self {
        Self {
            entries: [const { None }; LINEAR_INDEX_MAX],
            len: 0,
        }
    }

    fn iter(&self) -> impl Iterator<Item = &(Arc<str>, NodeId)> {
        self.entries[..self.len].iter().filter_map(Option::as_ref)
    }

    const fn len(&self) -> usize {
        self.len
    }

    /// Stores `entry` in the first free slot, handing it back when full.
    fn push(&mut self, entry: (Arc<str>, NodeId)) -> Result<(), (Arc<str>, NodeId)> {
        match self.entries.get_mut(self.len) {
            Some(slot) => {
                *slot = Some(entry);
                self.len += 1;
                Ok(())
            }
            None => Err(entry),
        }
    }

    /// Removes the entry at `position`, keeping the rest packed and in order.
    fn remove(&mut self, position: usize) {
        self.entries[position] = None;
        self.entries[position..self.len].rotate_left(1);
        self.len -= 1;
    }

    /// Empties the index, yielding its entries in order.
    fn drain(&mut self) -> impl Iterator<Item = (Arc<str>, NodeId)> + '_ {
        let len = std::mem::take(&mut self.len);
        self.entries[..len].iter_mut().filter_map(Option::take)
    }
}

/// Text index behind [`Children`], sized to the number of indexed children.
#[derive(Debug, Clone)]
enum Index {
    Linear(LinearIndex),
    Hashed(HashedIndex),
}

impl Index {
    /// An empty index.
    const fn new() -> Self {
        Self::Linear(LinearIndex::new())
    }

    fn get(&self, text: &str) -> Option<NodeId> {
        match self {
            Self::Linear(entries) => entries
                .iter()
                .find(|(key, _)| key.as_ref() == text)
                .map(|&(_, id)| id),
            Self::Hashed(index) => index.get(text),
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
                let Err(_) = entries.push((Arc::clone(text), id)) else {
                    return None;
                };
                let mut index = HashedIndex::with_capacity(LINEAR_INDEX_MAX * 2);
                for (key, existing) in entries.drain() {
                    index.insert_first(&key, existing);
                }
                index.insert_first(text, id);
                *self = Self::Hashed(index);
                None
            }
            Self::Hashed(index) => index.insert_first(text, id),
        }
    }

    /// Drops the entry for `text` if it maps to `id`.
    fn remove_if(&mut self, text: &str, id: NodeId) {
        match self {
            Self::Linear(entries) => {
                let position = entries
                    .iter()
                    .position(|(key, existing)| *existing == id && key.as_ref() == text);
                if let Some(position) = position {
                    entries.remove(position);
                }
            }
            Self::Hashed(index) => index.remove_if(text, id),
        }
    }

    fn keys(&self) -> Box<dyn Iterator<Item = &str> + '_> {
        match self {
            Self::Linear(entries) => Box::new(entries.iter().map(|(key, _)| key.as_ref())),
            Self::Hashed(index) => Box::new(index.table.keys().map(|key| key.text.as_ref())),
        }
    }

    fn from_mapping(mapping: Mapping) -> Self {
        if mapping.len() <= LINEAR_INDEX_MAX {
            let mut entries = LinearIndex::new();
            for entry in mapping {
                let pushed = entries.push(entry);
                debug_assert!(pushed.is_ok(), "mapping fits the linear index");
            }
            Self::Linear(entries)
        } else {
            let mut index = HashedIndex::with_capacity(mapping.len());
            for (key, id) in &mapping {
                index.insert_first(key, *id);
            }
            Self::Hashed(index)
        }
    }

    fn len(&self) -> usize {
        match self {
            Self::Linear(entries) => entries.len(),
            Self::Hashed(index) => index.table.len(),
        }
    }

    fn entries(&self) -> Box<dyn Iterator<Item = (&Arc<str>, NodeId)> + '_> {
        match self {
            Self::Linear(entries) => Box::new(entries.iter().map(|(key, id)| (key, *id))),
            Self::Hashed(index) => Box::new(index.entries()),
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
/// `LINEAR_INDEX_MAX`). Its keys are `Arc<str>` shared with the node itself, so
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
    /// Other positions, or indexes not known to cover every child uniquely,
    /// fall back to [`Self::rebuild_mapping`].
    pub(crate) fn retext(
        &mut self,
        id: NodeId,
        old_text: &str,
        new_text: &Arc<str>,
        arena: &Arena<Node>,
    ) {
        match self.mapping.as_deref_mut() {
            Some(index) if self.data.last() == Some(&id) && index.len() == self.data.len() => {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn id(index: u32) -> NodeId {
        NodeId {
            index,
            generation: 1,
        }
    }

    #[test]
    fn linear_index_stays_packed_and_ordered_through_removals() {
        let texts: Vec<Arc<str>> = (0..LINEAR_INDEX_MAX)
            .map(|i| Arc::from(format!("line {i}")))
            .collect();
        let mut index = Index::new();
        for (i, text) in (0..).zip(&texts) {
            assert_eq!(index.insert_first(text, id(i)), None);
        }
        assert!(matches!(index, Index::Linear(_)));
        index.remove_if("line 3", id(99));
        assert_eq!(index.len(), LINEAR_INDEX_MAX);
        index.remove_if("line 3", id(3));
        index.remove_if("line 0", id(0));
        assert_eq!(
            index.keys().collect::<Vec<_>>(),
            ["line 1", "line 2", "line 4", "line 5", "line 6", "line 7"]
        );
        assert_eq!(index.insert_first(&texts[1], id(50)), Some(id(1)));
        assert_eq!(index.insert_first(&texts[0], id(60)), None);
        assert_eq!(index.get("line 0"), Some(id(60)));
        assert_eq!(index.get("line 7"), Some(id(7)));
        assert!(matches!(index, Index::Linear(_)));
    }

    #[test]
    fn linear_index_promotes_to_hashed_when_full() {
        let texts: Vec<Arc<str>> = (0..LINEAR_INDEX_MAX)
            .map(|i| Arc::from(format!("line {i}")))
            .collect();
        let mut index = Index::new();
        for (i, text) in (0..).zip(&texts) {
            assert_eq!(index.insert_first(text, id(i)), None);
        }
        index.remove_if("line 3", id(3));
        assert_eq!(index.insert_first(&texts[3], id(30)), None);
        let extra: Arc<str> = Arc::from("line 8");
        assert!(matches!(index, Index::Linear(_)));
        assert_eq!(index.insert_first(&extra, id(8)), None);
        assert!(matches!(index, Index::Hashed(_)));
        assert_eq!(index.len(), LINEAR_INDEX_MAX + 1);
        for (i, text) in (0..).zip(&texts) {
            let expected = if i == 3 { id(30) } else { id(i) };
            assert_eq!(index.get(text), Some(expected));
        }
    }

    #[test]
    fn hashed_index_keeps_first_entries_while_growing() {
        let texts: Vec<Arc<str>> = (0..300).map(|i| Arc::from(format!("line {i}"))).collect();
        let mut index = HashedIndex::with_capacity(1);
        for (i, text) in (0..).zip(&texts) {
            assert_eq!(index.insert_first(text, id(i)), None);
            assert_eq!(index.insert_first(text, id(i + 1000)), Some(id(i)));
        }
        assert_eq!(index.table.len(), texts.len());
        for (i, text) in (0..).zip(&texts) {
            assert_eq!(index.get(text), Some(id(i)));
        }
        assert_eq!(index.get("line 300"), None);
    }

    #[test]
    fn stored_hash_uses_the_written_hash_and_folds_other_bytes() {
        let mut hasher = StoredHash::default();
        hasher.write_u64(0x1234);
        assert_eq!(hasher.finish(), 0x1234);
        let mut bytes = StoredHash::default();
        bytes.write(&[1, 2]);
        assert_eq!(bytes.finish(), 0x0102);
    }

    #[test]
    fn hashed_keys_match_probes_by_hash_and_text() {
        let index = HashedIndex::with_capacity(1);
        let stored = HashedKey {
            hash: index.state.hash_one("a"),
            text: Arc::from("a"),
        };
        let probe = index.probe("a");
        let as_view: &dyn KeyView = &probe;
        let stored_view: &dyn KeyView = &stored;
        assert!(as_view == stored_view);
        let same_hash_other_text = Probe {
            hash: stored.hash,
            text: "b",
        };
        let other: &dyn KeyView = &same_hash_other_text;
        assert!(other != stored_view);
        assert_eq!(stored, stored.clone());
    }
}
