use crate::arena::NodeId;
use crate::driver::Driver;
use crate::models::{Dump, Platform};
use crate::regex_cache::{MatchRegex, python_replacement, rule_regex};
use crate::tree::{Tree, TreeError};
use regex::Regex;
use rustc_hash::FxHashSet as HashSet;
use std::borrow::Cow;
use std::sync::Arc;

/// The ASCII bytes allowed at one position of a [`PrefixGuard`], as a bitmask.
type ByteClass = u128;

/// Whether `byte` stands for itself in a pattern, inside `[...]` and out.
///
/// Deliberately narrow: anything with a meaning in either context simply ends
/// the guard.
const fn is_plain_literal(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b' ' | b'!'
                | b'"'
                | b'#'
                | b'%'
                | b'\''
                | b','
                | b'/'
                | b':'
                | b';'
                | b'<'
                | b'='
                | b'>'
                | b'@'
                | b'_'
                | b'`'
        )
}

/// Whether `byte` stands for itself outside a class; `-`, `&` and `~` only have a
/// meaning (ranges and set operators) inside one.
const fn is_plain_literal_outside_class(byte: u8) -> bool {
    is_plain_literal(byte) || matches!(byte, b'-' | b'&' | b'~')
}

/// The literal start that every match of an anchored rule pattern must have.
///
/// `per_line_sub` rules are almost always `^literal...` or `^\s*[chars]...`. For
/// such a pattern a line can only match if it begins with those bytes (after any
/// leading whitespace, for `\s*`), which a few byte comparisons decide. The guard
/// is a necessary condition only — a line it admits still runs the real regex —
/// so skipping a rule it rejects never changes the result.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PrefixGuard {
    /// The pattern starts `^\s*`, so the prefix follows any leading whitespace.
    skip_whitespace: bool,
    classes: Vec<ByteClass>,
    /// What follows the prefix when the guard spells out the entire pattern.
    tail: Option<GuardTail>,
}

/// The remainder of a pattern that a [`PrefixGuard`] fully describes.
///
/// With one of these the guard decides the match outright, not just a necessary
/// condition, so the substitution needs no regex at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GuardTail {
    /// Nothing: the match is the prefix itself.
    Open,
    /// `.*` or `.*$`: the match runs to the end of a single line.
    RestOfLine,
    /// `$`: the line must end right after the prefix.
    EndOfLine,
}

impl PrefixGuard {
    /// Derives the guard for `pattern`, or `None` when no literal start can be
    /// read off it with certainty.
    fn of(pattern: &str) -> Option<Self> {
        let rest = pattern.strip_prefix('^')?;
        // A top-level alternative need not be anchored at all.
        if pattern.contains('|') {
            return None;
        }
        let (skip_whitespace, rest) = rest
            .strip_prefix(r"\s*")
            .map_or((false, rest), |after| (true, after));
        let bytes = rest.as_bytes();
        let mut classes = Vec::new();
        let mut index = 0;
        let mut quantified = false;
        while let Some(&byte) = bytes.get(index) {
            let (class, next) = if byte == b'[' {
                let Some(class) = Self::class_at(bytes, index + 1) else {
                    break;
                };
                class
            } else if is_plain_literal_outside_class(byte) {
                (1 << byte, index + 1)
            } else {
                break;
            };
            match bytes.get(next) {
                // The element may be absent, so nothing from here on is certain.
                Some(b'*' | b'?' | b'{') => {
                    quantified = true;
                    break;
                }
                Some(b'+') => {
                    classes.push(class);
                    quantified = true;
                    break;
                }
                _ => classes.push(class),
            }
            index = next;
        }
        let tail = if quantified {
            None
        } else {
            match &rest[index..] {
                "" => Some(GuardTail::Open),
                ".*" | ".*$" => Some(GuardTail::RestOfLine),
                "$" => Some(GuardTail::EndOfLine),
                _ => None,
            }
        };
        // `\s*` would also consume a leading whitespace byte the guard demands.
        let whitespace: ByteClass = (1 << b' ') | (0x3e00); // space, \t..\r
        if skip_whitespace && classes.first().is_some_and(|class| class & whitespace != 0) {
            return None;
        }
        (!classes.is_empty()).then_some(Self {
            skip_whitespace,
            classes,
            tail,
        })
    }

    /// Parses a plain `[...]` class whose body starts at `start`, returning it
    /// and the index after the closing bracket.
    fn class_at(bytes: &[u8], start: usize) -> Option<(ByteClass, usize)> {
        let mut class: ByteClass = 0;
        for (offset, &byte) in bytes.get(start..)?.iter().enumerate() {
            if byte == b']' {
                return (class != 0).then_some((class, start + offset + 1));
            }
            if !is_plain_literal(byte) {
                return None;
            }
            class |= 1 << byte;
        }
        None
    }

    /// Bytes of `text` the guard's first class applies to.
    fn start<'a>(&self, text: &'a str) -> &'a [u8] {
        let bytes = text.as_bytes();
        if self.skip_whitespace {
            &bytes[leading_whitespace_len(text)..]
        } else {
            bytes
        }
    }

    /// Substitutes `replacement` for the rule's match in `text` without a regex,
    /// if the guard describes the whole pattern and `replacement` is literal.
    ///
    fn substitute(&self, text: &str, replacement: &str) -> Substitution {
        let Some(tail) = self.tail else {
            return Substitution::Undecided;
        };
        if !self.admits(text) {
            return Substitution::NoMatch;
        }
        if replacement.contains('$') || text.contains('\n') {
            return Substitution::Undecided;
        }
        let matched = text.len() - self.start(text).len() + self.classes.len();
        match tail {
            GuardTail::Open => Substitution::Replaced([replacement, &text[matched..]].concat()),
            GuardTail::RestOfLine => Substitution::Replaced(replacement.to_owned()),
            GuardTail::EndOfLine if matched == text.len() => {
                Substitution::Replaced(replacement.to_owned())
            }
            GuardTail::EndOfLine => Substitution::NoMatch,
        }
    }

    /// Returns false only when the rule cannot match `text`.
    fn admits(&self, text: &str) -> bool {
        let bytes = self.start(text);
        bytes.len() >= self.classes.len()
            && self
                .classes
                .iter()
                .zip(bytes)
                .all(|(class, &byte)| byte < 128 && class >> byte & 1 == 1)
    }
}

/// Outcome of [`PrefixGuard::substitute`].
#[derive(Debug, PartialEq, Eq)]
enum Substitution {
    /// The guard alone cannot decide; the regex must run.
    Undecided,
    /// The rule provably does not match.
    NoMatch,
    /// The rule matches and produces this text.
    Replaced(String),
}

/// Per-position byte tables for a group of guarded rules.
///
/// `allowed[k][byte]` holds the rules whose guard accepts `byte` at offset `k`,
/// including every rule whose guard is shorter than `k + 1` bytes; `ended[k]`
/// holds the rules whose guard is at most `k` bytes long, which are the only ones a
/// text ending at offset `k` can still satisfy. `AND`ing the entries for a line's
/// first bytes leaves exactly the rules whose first [`PrefixTables::DEPTH`] guard
/// bytes the line matches, so most lines are dismissed after two or three lookups.
struct PrefixTables {
    rules: u64,
    allowed: Box<[[u64; 256]; Self::DEPTH]>,
    ended: [u64; Self::DEPTH],
}

impl PrefixTables {
    /// Number of leading bytes tabulated.
    const DEPTH: usize = 8;

    fn new() -> Self {
        Self {
            rules: 0,
            allowed: Box::new([[0; 256]; Self::DEPTH]),
            ended: [0; Self::DEPTH],
        }
    }

    fn add(&mut self, rule: usize, guard: &PrefixGuard) {
        let bit = 1 << rule;
        self.rules |= bit;
        for (position, table) in self.allowed.iter_mut().enumerate() {
            let Some(&class) = guard.classes.get(position) else {
                self.ended[position] |= bit;
                for entry in table.iter_mut() {
                    *entry |= bit;
                }
                continue;
            };
            for (byte, entry) in table.iter_mut().enumerate().take(128) {
                if class >> byte & 1 == 1 {
                    *entry |= bit;
                }
            }
        }
    }

    /// The rules whose leading guard bytes `bytes` matches.
    fn candidates(&self, bytes: &[u8]) -> u64 {
        let mut mask = self.rules;
        for (position, table) in self.allowed.iter().enumerate() {
            let Some(&byte) = bytes.get(position) else {
                return mask & self.ended[position];
            };
            mask &= table[usize::from(byte)];
            if mask == 0 {
                break;
            }
        }
        mask
    }
}

/// Selects the rules that could match a line from its first bytes alone.
///
/// Guarded rules are filed in [`PrefixTables`] — one for plain `^` rules, one
/// read after the leading whitespace for `^\s*` rules — so a line pays a few
/// table lookups rather than a regex scan per rule. Unguarded rules fall back to a
/// `RegexSet` over just those patterns.
struct SubDispatch {
    guards: Vec<Option<PrefixGuard>>,
    anchored: PrefixTables,
    after_whitespace: PrefixTables,
    /// Rules with no guard, as a set over their patterns plus each set entry's rule.
    unguarded: Option<(Arc<regex::RegexSet>, Vec<usize>)>,
    /// Unguarded rules that are always candidates because no set could be built.
    always: u64,
}

impl SubDispatch {
    /// Widest rule list the `u64` candidate masks can describe.
    const MAX_RULES: usize = 64;

    fn new(rules: &[(Arc<Regex>, String)]) -> Option<Self> {
        if rules.len() > Self::MAX_RULES {
            return None;
        }
        let guards: Vec<_> = rules
            .iter()
            .map(|(re, _)| PrefixGuard::of(re.as_str()))
            .collect();
        let mut anchored = PrefixTables::new();
        let mut after_whitespace = PrefixTables::new();
        let mut unguarded_rules = Vec::new();
        for (rule, guard) in guards.iter().enumerate() {
            match guard {
                Some(guard) if guard.skip_whitespace => after_whitespace.add(rule, guard),
                Some(guard) => anchored.add(rule, guard),
                None => unguarded_rules.push(rule),
            }
        }
        let (unguarded, always) = if unguarded_rules.is_empty() {
            (None, 0)
        } else if let Some(set) = crate::regex_cache::regex_set(
            unguarded_rules.iter().map(|&rule| rules[rule].0.as_str()),
        ) {
            (Some((set, unguarded_rules)), 0)
        } else {
            (
                None,
                unguarded_rules
                    .iter()
                    .fold(0, |mask, rule| mask | 1 << rule),
            )
        };
        Some(Self {
            guards,
            anchored,
            after_whitespace,
            unguarded,
            always,
        })
    }

    /// Bitmask of the rules that might match `text`, whose leading whitespace is
    /// `indent` bytes long when the caller already knows it.
    fn candidates(&self, text: &str, indent: Option<usize>) -> u64 {
        let bytes = text.as_bytes();
        let mut mask = self.always | self.anchored.candidates(bytes);
        if self.after_whitespace.rules != 0 {
            let indent = indent.unwrap_or_else(|| leading_whitespace_len(text));
            mask |= self.after_whitespace.candidates(&bytes[indent..]);
        }
        if let Some((set, rules)) = &self.unguarded
            && set.is_match(text)
        {
            for entry in &set.matches(text) {
                mask |= 1 << rules[entry];
            }
        }
        mask
    }
}

/// The rewritten text, if a substitution produced one.
fn owned(text: Cow<'_, str>) -> Option<String> {
    match text {
        Cow::Owned(text) => Some(text),
        Cow::Borrowed(_) => None,
    }
}

/// Substitution rules resolved to compiled regexes once, ahead of the line loop.
///
/// Platforms define up to a few dozen `per_line_sub` rules, each of which would
/// otherwise be looked up in the regex cache — hashing the pattern and taking a
/// lock — for every line of the configuration.
struct PreparedSubs {
    /// Picks candidate rules per line; `None` only past [`SubDispatch::MAX_RULES`].
    dispatch: Option<SubDispatch>,
    /// Union of every rule pattern, used when there is no dispatch table.
    prefilter: Option<Arc<regex::RegexSet>>,
    rules: Vec<(Arc<Regex>, String)>,
}

impl PreparedSubs {
    fn new(rules: &[crate::models::PerLineSubRule]) -> Result<Self, TreeError> {
        let rules: Vec<(Arc<Regex>, String)> = rules
            .iter()
            .map(|rule| {
                let re = rule_regex(&rule.search)?;
                let replacement = python_replacement(&re, &rule.replace)?;
                Ok((re, replacement))
            })
            .collect::<Result<_, String>>()
            .map_err(TreeError::InvalidRegex)?;
        let dispatch = SubDispatch::new(&rules);
        let prefilter = if dispatch.is_some() {
            None
        } else {
            crate::regex_cache::regex_set(rules.iter().map(|(re, _)| re.as_str()))
        };
        Ok(Self {
            dispatch,
            prefilter,
            rules,
        })
    }

    /// Applies every rule in order, allocating only when a rule actually matches.
    ///
    /// Only the rules [`SubDispatch`] selects for the line run, each still checked
    /// against its full guard first; a rule it rules out provably leaves the text
    /// untouched. After a rule rewrites the text, the later rules are reselected
    /// for the result, which keeps the outcome identical to a plain sequential
    /// pass.
    #[cfg(test)]
    fn apply<'a>(&self, line: &'a str) -> Cow<'a, str> {
        self.apply_indented(line, None)
    }

    /// [`Self::apply`] for a line whose leading whitespace is `indent` bytes long,
    /// when the caller has already measured it.
    fn apply_indented<'a>(&self, line: &'a str, indent: Option<usize>) -> Cow<'a, str> {
        let Some(dispatch) = &self.dispatch else {
            return self.apply_with_set(line);
        };
        let mut text = Cow::Borrowed(line);
        let mut pending = dispatch.candidates(line, indent);
        while pending != 0 {
            let bit = pending.trailing_zeros();
            let rule = bit as usize;
            pending &= pending - 1;
            let (re, replace) = &self.rules[rule];
            let replaced = match &dispatch.guards[rule] {
                Some(guard) => match guard.substitute(&text, replace) {
                    Substitution::Replaced(replaced) => Some(replaced),
                    Substitution::Undecided if guard.admits(&text) => {
                        owned(re.replace_all(&text, replace.as_str()))
                    }
                    Substitution::NoMatch | Substitution::Undecided => None,
                },
                None => owned(re.replace_all(&text, replace.as_str())),
            };
            if let Some(replaced) = replaced {
                text = Cow::Owned(replaced);
                let later = u64::MAX.checked_shl(bit + 1).unwrap_or(0);
                pending = dispatch.candidates(&text, None) & later;
            }
        }
        text
    }

    /// [`Self::apply`] for rule lists too long for [`SubDispatch`].
    ///
    /// A combined `RegexSet` rejects most lines in a single pass and, for a line
    /// that does match, reports which rules match the current text; it is
    /// consulted again after each rewrite.
    fn apply_with_set<'a>(&self, line: &'a str) -> Cow<'a, str> {
        let mut text = Cow::Borrowed(line);
        let Some(prefilter) = &self.prefilter else {
            for (re, replace) in &self.rules {
                if let Cow::Owned(replaced) = re.replace_all(&text, replace.as_str()) {
                    text = Cow::Owned(replaced);
                }
            }
            return text;
        };
        if !prefilter.is_match(line) {
            return text;
        }

        let mut candidates = prefilter.matches(line);
        for (index, (re, replace)) in self.rules.iter().enumerate() {
            if !candidates.matched(index) {
                continue;
            }
            if let Cow::Owned(replaced) = re.replace_all(&text, replace.as_str()) {
                candidates = prefilter.matches(&replaced);
                text = Cow::Owned(replaced);
            }
        }
        text
    }
}

/// Converts a Juniper / `VyOS` / Nokia style config string into a list of set commands.
pub fn convert_to_set_commands(config_raw: &str) -> String {
    let mut path: Vec<&str> = Vec::new();
    let mut set_commands: Vec<String> = Vec::new();

    for line in config_raw.lines() {
        let stripped = line.trim();
        if stripped.is_empty() {
            continue;
        }

        let stripped = stripped.strip_suffix(';').unwrap_or(stripped);

        // Count indentation spaces to determine depth
        let leading_spaces = line.chars().take_while(|c| *c == ' ').count();
        let level = leading_spaces / 4;

        if level < path.len() {
            path.truncate(level);
        }

        if stripped.ends_with('{') || stripped.ends_with('}') {
            let section = stripped.trim_end_matches(['{', '}']).trim();
            if !section.is_empty() {
                path.push(section);
            }
        } else if stripped.starts_with("set ") || stripped.starts_with("delete ") {
            set_commands.push(stripped.to_string());
        } else {
            let cmd = if path.is_empty() {
                format!("set {stripped}")
            } else {
                format!("set {} {}", path.join(" "), stripped)
            };
            set_commands.push(cmd);
        }
    }

    set_commands.join("\n")
}

/// Applies platform-specific preprocessor if needed.
///
/// Only the set-command platforms rewrite the text; everything else borrows it, so a
/// large configuration is not copied just to be handed straight back.
pub fn config_preprocessor(platform: Platform, config_text: &str) -> Cow<'_, str> {
    crate::platforms::platform_ops(platform).config_preprocessor(config_text)
}

/// Tests if a line terminates a banner.
fn is_end_of_banner(
    config_line: &str,
    banner_end_lines: &HashSet<String>,
    banner_end_contains: &[String],
) -> bool {
    if config_line.starts_with('^') {
        return true;
    }
    if banner_end_lines.contains(config_line) {
        return true;
    }
    banner_end_contains.iter().any(|c| config_line.contains(c))
}

/// Cursor tracking the current insertion position in a [`Tree`].
#[derive(Debug, Clone, Copy)]
pub struct ParserCursor {
    pub current_section: NodeId,
    pub most_recent_item: NodeId,
}

impl ParserCursor {
    /// Creates a cursor positioned at `root`.
    #[must_use]
    pub const fn new(root: NodeId) -> Self {
        Self {
            current_section: root,
            most_recent_item: root,
        }
    }

    /// Inserts a new line into the tree at the appropriate hierarchy level given its indentation.
    ///
    /// # Errors
    ///
    /// Returns [`TreeError`] if the child cannot be attached, such as a duplicate child.
    pub fn record_line(
        &mut self,
        tree: &mut Tree,
        indent: i32,
        line: &str,
    ) -> Result<NodeId, TreeError> {
        self.record_trimmed_line(tree, indent, line.trim(), &mut SiblingTexts::new())
    }

    /// [`Self::record_line`] for a line the parser has already trimmed, sharing
    /// its text with an identical line seen at the same position in an earlier
    /// section.
    fn record_trimmed_line(
        &mut self,
        tree: &mut Tree,
        indent: i32,
        line: &str,
        texts: &mut SiblingTexts,
    ) -> Result<NodeId, TreeError> {
        // Walks back up the tree
        while indent <= tree.arena[self.current_section].real_indent_level
            && self.current_section != tree.root
        {
            if let Some(parent) = tree.arena[self.current_section].parent {
                self.current_section = parent;
            } else {
                break;
            }
        }

        // Walks down the tree by one step
        if indent > tree.arena[self.most_recent_item].real_indent_level {
            self.current_section = self.most_recent_item;
        }

        let parent = self.current_section;
        let at_root = parent == tree.root;
        let new_child = tree.add_parsed_child(parent, indent, |position| {
            if at_root {
                Arc::from(line)
            } else {
                texts.share(position, line)
            }
        })?;
        self.most_recent_item = new_child;

        Ok(new_child)
    }

    /// Resets the cursor to the tree root following a banner or section reset.
    pub const fn reset_to_root(&mut self, root: NodeId, most_recent_item: NodeId) {
        self.current_section = root;
        self.most_recent_item = most_recent_item;
    }
}

/// Recently parsed child texts, keyed by their position within the parent.
///
/// Configurations repeat the same lines in every instance of a section (each
/// interface's `no shutdown`, say). Comparing a line with the text last seen at
/// its position is a single byte comparison, and on a match the new node shares
/// that `Arc` instead of allocating, and later freeing, its own copy. Unlike a
/// hashed intern table this costs nothing for lines that never repeat.
struct SiblingTexts {
    slots: [Option<Arc<str>>; Self::POSITIONS],
}

impl SiblingTexts {
    /// Positions tracked; later children of large sections rarely repeat.
    const POSITIONS: usize = 16;

    const fn new() -> Self {
        Self {
            slots: [const { None }; Self::POSITIONS],
        }
    }

    /// Returns a shared text for `line` as the child at `position`.
    fn share(&mut self, position: usize, line: &str) -> Arc<str> {
        let Some(slot) = self.slots.get_mut(position) else {
            return Arc::from(line);
        };
        if let Some(previous) = slot.as_ref().filter(|previous| previous.as_ref() == line) {
            return Arc::clone(previous);
        }
        let text: Arc<str> = Arc::from(line);
        *slot = Some(Arc::clone(&text));
        text
    }
}

fn adjust_indent(
    prepared: &[(MatchRegex, MatchRegex)],
    line: &str,
    mut indent_adjust: i32,
    mut end_indent_adjust: Vec<MatchRegex>,
) -> Result<(i32, Vec<MatchRegex>), TreeError> {
    for (re, end_expression) in prepared {
        if re.is_match(line).map_err(TreeError::InvalidRegex)? {
            indent_adjust += 1;
            end_indent_adjust.push(end_expression.clone());
            return Ok((indent_adjust, end_indent_adjust));
        }
    }
    Ok((indent_adjust, end_indent_adjust))
}

/// Loads configuration lines into a `Tree`, then applies the post-load stages.
/// Loads configuration text into a `Tree`, running stock post-load callbacks
/// followed additively by the provided custom callbacks.
///
/// # Errors
///
/// Returns [`TreeError`] if a line cannot be attached to the tree, most commonly
/// [`TreeError::DuplicateChild`] when the configuration repeats a section that the
/// platform driver does not permit to be duplicated.
pub fn load_from_str_with_callbacks<F>(
    tree: &mut Tree,
    config_raw: &str,
    callbacks: impl IntoIterator<Item = F>,
) -> Result<(), TreeError>
where
    F: Fn(&mut Tree),
{
    parse_into_tree(tree, config_raw)?;
    crate::post_load::delete_sectional_exit_recursive(tree);
    crate::post_load::run_post_load_callbacks(tree);
    for cb in callbacks {
        cb(tree);
    }
    Ok(())
}

///
/// # Errors
///
/// Returns [`TreeError`] if a line cannot be attached to the tree, most commonly
/// [`TreeError::DuplicateChild`] when the configuration repeats a section that the
/// platform driver does not permit to be duplicated.
pub fn load_from_str(tree: &mut Tree, config_raw: &str) -> Result<(), TreeError> {
    load_from_str_with_callbacks::<fn(&mut Tree)>(tree, config_raw, [])
}

/// Parses configuration text into a `Tree` without running any post-load stage.
///
/// Callers that need to interleave their own post-load behaviour — such as the
/// Python bindings, which may have to defer to user-supplied callbacks — drive the
/// stages themselves rather than paying for the built-in ones twice.
/// Tests whether a line already satisfies the whitespace normalization the parser
/// would otherwise produce.
///
/// The overwhelming majority of real configuration lines are already normalized, so a
/// single non-allocating scan lets the parser borrow the input line instead of
/// rebuilding it word by word. Any non-ASCII byte takes the slow path, because
/// `split_whitespace` is Unicode-aware and this scan is not.
fn is_already_normalized(rest: &[u8]) -> bool {
    const SPACES: u64 = u64::from_le_bytes([b' '; 8]);
    const LOW: u64 = u64::from_le_bytes([0x7f; 8]);
    const HIGH: u64 = u64::from_le_bytes([0x80; 8]);
    const LAST: u64 = 0x80 << 56;

    // Eight bytes at a time: a word of printable ASCII and single spaces needs no
    // per-byte work. Any other byte hands the rest of the line to the exact scan.
    let (words, tail) = rest.as_chunks::<8>();
    let Some(last) = rest.last_chunk::<8>() else {
        return is_normalized_from(rest, false);
    };
    let mut prev_space = false;
    for (position, word) in words.iter().enumerate() {
        let word = u64::from_le_bytes(*word);
        if (word | word.wrapping_sub(SPACES) & !word) & HIGH != 0 {
            return is_normalized_from(&rest[position * 8..], prev_space);
        }
        let not_space = word ^ SPACES;
        let spaces = !((not_space & LOW).wrapping_add(LOW) | not_space | LOW);
        if spaces & (spaces >> 8 | u64::from(prev_space) << 7) != 0 {
            return false;
        }
        prev_space = spaces & LAST != 0;
    }
    if tail.is_empty() {
        return !prev_space;
    }
    // Re-read the tail as the line's last eight bytes. They overlap the final full
    // word, so every adjacent pair the tail adds lies inside this one word and the
    // byte-at-a-time loop is skipped.
    let word = u64::from_le_bytes(*last);
    if (word | word.wrapping_sub(SPACES) & !word) & HIGH != 0 {
        return is_normalized_from(tail, prev_space);
    }
    let not_space = word ^ SPACES;
    let spaces = !((not_space & LOW).wrapping_add(LOW) | not_space | LOW);
    spaces & (spaces >> 8 | LAST) == 0
}

/// Byte-at-a-time form of [`is_already_normalized`], resuming after a space when
/// `prev_space` is set.
fn is_normalized_from(rest: &[u8], mut prev_space: bool) -> bool {
    for &b in rest {
        if !b.is_ascii() {
            return false;
        }
        if b == b' ' {
            if prev_space {
                return false;
            }
            prev_space = true;
        } else {
            if b.is_ascii_whitespace() {
                return false;
            }
            prev_space = false;
        }
    }
    !prev_space
}

/// Byte length of the leading whitespace run in `line`.
///
/// Both loaders derive a line's indentation from this, so tab-, NBSP- or
/// U+2028-indented lines nest identically no matter which parser ran. Counting
/// bytes (not characters) keeps the result usable as a slice index and matches the
/// number of spaces `normalize_whitespace` re-emits.
pub(crate) fn leading_whitespace_len(line: &str) -> usize {
    // Indentation is almost always plain spaces followed by printable ASCII; only
    // anything else needs the Unicode-aware scan.
    let spaces = line.bytes().take_while(|&byte| byte == b' ').count();
    match line.as_bytes().get(spaces) {
        Some(byte) if byte.is_ascii_graphic() => spaces,
        _ => line.len() - line.trim_start().len(),
    }
}

/// `str::trim_end` with a shortcut for the usual line ending in printable ASCII.
fn trim_end(line: &str) -> &str {
    match line.as_bytes().last() {
        Some(byte) if byte.is_ascii_graphic() => line,
        _ => line.trim_end(),
    }
}

/// Finds the first line boundary Python's `str.splitlines()` recognises in
/// `bytes`, returning its byte offset and encoded length.
///
/// Every boundary begins with an ASCII control byte below `0x1f` or a non-ASCII
/// lead byte (NEL, LS and PS), so eight-byte words holding neither are skipped in
/// one step; ordinary configuration text is almost entirely such words. A word that
/// does hold one jumps straight to its first candidate byte.
///
/// Called once per line from [`SplitLines::next`]; lines average ~26 bytes, so
/// keeping it inlinable matters as much as the scan. Portable SIMD (`std::simd`,
/// `fearless_simd`) measured no faster than this once both were inlined, and a
/// movemask-style version was slower on NEON.
#[inline]
fn find_line_boundary(bytes: &[u8]) -> Option<(usize, usize)> {
    const LOW: u64 = u64::from_le_bytes([0x1f; 8]);
    const HIGH: u64 = u64::from_le_bytes([0x80; 8]);
    let mut index = 0;
    while let Some(word) = bytes.get(index..).and_then(<[u8]>::first_chunk::<8>) {
        let word = u64::from_le_bytes(*word);
        let candidates = (word.wrapping_sub(LOW) & !word | word) & HIGH;
        if candidates == 0 {
            index += 8;
            continue;
        }
        // A borrow can only flag bytes above a genuine candidate, so the lowest
        // flagged byte is always real.
        index += (candidates.trailing_zeros() / 8) as usize;
        if let Some(width) = line_boundary_width(bytes, index) {
            return Some((index, width));
        }
        index += 1;
    }
    while index < bytes.len() {
        if let Some(width) = line_boundary_width(bytes, index) {
            return Some((index, width));
        }
        index += 1;
    }
    None
}

/// Encoded length of the line boundary starting at `bytes[index]`, if any.
#[inline]
fn line_boundary_width(bytes: &[u8], index: usize) -> Option<usize> {
    match bytes[index] {
        b'\n' | b'\r' | 0x0b | 0x0c | 0x1c..=0x1e => Some(1),
        // U+0085 NEXT LINE.
        0xc2 if bytes.get(index + 1) == Some(&0x85) => Some(2),
        // U+2028 LINE SEPARATOR and U+2029 PARAGRAPH SEPARATOR.
        0xe2 if bytes.get(index + 1) == Some(&0x80)
            && matches!(bytes.get(index + 2), Some(0xa8 | 0xa9)) =>
        {
            Some(3)
        }
        _ => None,
    }
}

/// Iterator returned by [`splitlines`].
#[derive(Debug, Clone)]
pub struct SplitLines<'a> {
    rest: Option<&'a str>,
}

impl<'a> Iterator for SplitLines<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<&'a str> {
        let rest = self.rest?;
        let Some((index, width)) = find_line_boundary(rest.as_bytes()) else {
            self.rest = None;
            return (!rest.is_empty()).then_some(rest);
        };
        let line = &rest[..index];
        let mut next_start = index + width;
        if rest.as_bytes()[index] == b'\r' && rest.as_bytes().get(next_start) == Some(&b'\n') {
            next_start += 1;
        }
        self.rest = Some(&rest[next_start..]);
        Some(line)
    }
}

/// Splits `text` into lines the way Python's `str.splitlines()` does.
///
/// `str::lines()` only breaks on `\n` and `\r\n`; the v3 Python implementation also
/// breaks on a lone `\r`, the vertical tab/form feed family and the Unicode
/// NEL/LS/PS separators, so a config using any of them must not collapse into one
/// giant line here.
pub const fn splitlines(text: &str) -> SplitLines<'_> {
    SplitLines { rest: Some(text) }
}

/// Iterator returned by [`parse_lines`].
#[derive(Debug, Clone)]
struct ParseLines<'a> {
    rest: Option<&'a str>,
}

/// [`splitlines`] fused with the [`normalize_whitespace`] fast-path check.
///
/// Each item is a line plus, when the line is already normalized with plain-space
/// indentation, that indentation's length. Ordinary configuration lines are
/// therefore read once instead of being scanned for a line boundary and again for
/// whitespace; any other line yields `None` and is normalized as before.
const fn parse_lines(text: &str) -> ParseLines<'_> {
    ParseLines { rest: Some(text) }
}

impl<'a> Iterator for ParseLines<'a> {
    type Item = (&'a str, Option<usize>);

    fn next(&mut self) -> Option<Self::Item> {
        let rest = self.rest?;
        let bytes = rest.as_bytes();
        let (boundary, indent) = match scan_normalized_line(bytes) {
            Some((index, indent)) => (Some(index), indent),
            None => (find_line_boundary(bytes).map(|(index, _)| index), None),
        };
        let Some(index) = boundary else {
            self.rest = None;
            return (!rest.is_empty()).then_some((rest, None));
        };
        let width = line_boundary_width(bytes, index).unwrap_or(1);
        let mut next_start = index + width;
        if bytes[index] == b'\r' && bytes.get(next_start) == Some(&b'\n') {
            next_start += 1;
        }
        self.rest = Some(&rest[next_start..]);
        Some((&rest[..index], indent))
    }
}

/// Finds the line boundary ending an already-normalized, space-indented line in
/// one word-at-a-time pass, returning its offset and the indentation length.
///
/// Returns `None` whenever the line needs the general path: non-space indentation,
/// a control or non-ASCII byte before the boundary, doubled or trailing spaces, or
/// a final line with no boundary at all.
fn scan_normalized_line(bytes: &[u8]) -> Option<(usize, Option<usize>)> {
    const SPACES: u64 = u64::from_le_bytes([b' '; 8]);
    const LOW: u64 = u64::from_le_bytes([0x7f; 8]);
    const HIGH: u64 = u64::from_le_bytes([0x80; 8]);
    const LAST: u64 = 0x80 << 56;

    let indent = bytes.iter().take_while(|&&byte| byte == b' ').count();
    if !bytes.get(indent)?.is_ascii_graphic() {
        return None;
    }
    let mut index = indent;
    let mut prev_space = false;
    while let Some(word) = bytes.get(index..).and_then(<[u8]>::first_chunk::<8>) {
        let word = u64::from_le_bytes(*word);
        let not_space = word ^ SPACES;
        let mut spaces = !((not_space & LOW).wrapping_add(LOW) | not_space | LOW);
        // Bytes below 0x20 or above 0x7f: every line boundary, and everything else
        // the normalization check would reject.
        let special = (word | word.wrapping_sub(SPACES) & !word) & HIGH;
        let position = (special != 0).then(|| (special.trailing_zeros() / 8) as usize);
        if let Some(position) = position {
            spaces &= (1u64 << (position * 8)) - 1;
        }
        if spaces & (spaces >> 8 | u64::from(prev_space) << 7) != 0 {
            return None;
        }
        let Some(position) = position else {
            prev_space = spaces & LAST != 0;
            index += 8;
            continue;
        };
        if position > 0 {
            prev_space = spaces >> (position * 8 - 1) & 1 != 0;
        }
        let boundary = index + position;
        line_boundary_width(bytes, boundary)?;
        return Some((boundary, (!prev_space).then_some(indent)));
    }
    // Fewer than eight bytes remain only at the end of the text.
    for (offset, &byte) in bytes[index..].iter().enumerate() {
        if byte == b' ' {
            if prev_space {
                return None;
            }
            prev_space = true;
        } else if byte.is_ascii_graphic() {
            prev_space = false;
        } else {
            let boundary = index + offset;
            line_boundary_width(bytes, boundary)?;
            return Some((boundary, (!prev_space).then_some(indent)));
        }
    }
    None
}

fn normalize_whitespace<'a>(raw_line: &'a str, buffer: &'a mut String) -> (&'a str, usize) {
    let leading_spaces = leading_whitespace_len(raw_line);
    let normalized = if is_already_normalized(&raw_line.as_bytes()[leading_spaces..]) {
        raw_line
    } else {
        buffer.clear();
        for _ in 0..leading_spaces {
            buffer.push(' ');
        }
        let mut first = true;
        for word in raw_line.split_whitespace() {
            if !first {
                buffer.push(' ');
            }
            buffer.push_str(word);
            first = false;
        }
        buffer
    };
    // The rebuilt line re-emits one space per byte of the original indentation, so
    // either way the result's leading whitespace is `leading_spaces` bytes long.
    (normalized, leading_spaces)
}

fn apply_full_text_subs<'a>(
    driver: &Driver,
    mut config_text: Cow<'a, str>,
) -> Result<Cow<'a, str>, TreeError> {
    for rule in &driver.rules.full_text_sub {
        let re = rule_regex(&rule.search).map_err(TreeError::InvalidRegex)?;
        let replacement =
            python_replacement(&re, &rule.replace).map_err(TreeError::InvalidRegex)?;
        if let Cow::Owned(replaced) = re.replace_all(&config_text, replacement.as_str()) {
            config_text = Cow::Owned(replaced);
        }
    }
    Ok(config_text)
}

struct BannerState {
    in_banner: bool,
    temp_banner: Vec<String>,
    banner_end_lines: HashSet<String>,
    banner_end_contains: Vec<String>,
}

impl BannerState {
    fn new() -> Self {
        Self {
            in_banner: false,
            temp_banner: Vec::new(),
            banner_end_lines: ["EOF", "%", "!"].iter().map(|s| (*s).to_string()).collect(),
            banner_end_contains: Vec::new(),
        }
    }

    fn check_start(&mut self, raw_line: &str) -> bool {
        if raw_line.starts_with("banner ") && raw_line != "banner motd ##" {
            self.in_banner = true;
            self.temp_banner.push(raw_line.to_string());
            let words: Vec<&str> = raw_line.split_whitespace().collect();
            if words.len() >= 3 {
                let delim = words[2];
                self.banner_end_contains.push(delim.to_string());
                if delim.starts_with('"') {
                    self.banner_end_contains.push("\"".to_string());
                }
                if !delim.is_empty() {
                    self.banner_end_lines
                        .insert(delim.chars().take(1).collect::<String>());
                    self.banner_end_lines
                        .insert(delim.chars().take(2).collect::<String>());
                }
            }
            return true;
        }
        false
    }
}

/// Tracks dynamic indentation adjustments triggered by platform indent rules.
struct IndentTracker {
    adjust: i32,
    end_expressions: Vec<MatchRegex>,
}

impl IndentTracker {
    const fn new() -> Self {
        Self {
            adjust: 0,
            end_expressions: Vec::new(),
        }
    }

    fn update(
        &mut self,
        indent_rules: &[(MatchRegex, MatchRegex)],
        line_content: &str,
    ) -> Result<(), TreeError> {
        if !indent_rules.is_empty() {
            let (adj, ends) = adjust_indent(
                indent_rules,
                line_content,
                self.adjust,
                std::mem::take(&mut self.end_expressions),
            )?;
            self.adjust = adj;
            self.end_expressions = ends;
        }

        if let Some(re) = self.end_expressions.first()
            && re.is_match(line_content).map_err(TreeError::InvalidRegex)?
        {
            self.adjust -= 1;
            self.end_expressions.remove(0);
        }
        Ok(())
    }
}

/// Encapsulates mutable parsing state across configuration lines.
struct ParserState {
    cursor: ParserCursor,
    indent: IndentTracker,
    banner: BannerState,
    normalized: String,
    texts: SiblingTexts,
}

impl ParserState {
    fn new(root: NodeId) -> Self {
        Self {
            cursor: ParserCursor::new(root),
            indent: IndentTracker::new(),
            banner: BannerState::new(),
            normalized: String::with_capacity(256),
            texts: SiblingTexts::new(),
        }
    }

    fn handle_banner_continuation(
        &mut self,
        tree: &mut Tree,
        raw_line: &str,
    ) -> Result<(), TreeError> {
        if raw_line != "!" {
            self.banner.temp_banner.push(raw_line.to_string());
        }

        if is_end_of_banner(
            raw_line,
            &self.banner.banner_end_lines,
            &self.banner.banner_end_contains,
        ) {
            self.banner.in_banner = false;
            let banner_text = self.banner.temp_banner.join("\n");
            let child = tree.add_child(tree.root, &banner_text, true, false)?;
            tree.arena[child].real_indent_level = 0;
            self.cursor.reset_to_root(tree.root, child);
            self.banner.temp_banner.clear();
        }
        Ok(())
    }
}

/// Parses `config_raw` into `tree` without running the post-load stages.
///
/// # Errors
///
/// Returns [`TreeError`] if a parsed line cannot be inserted, most commonly
/// [`TreeError::DuplicateChild`].
pub fn parse_into_tree(tree: &mut Tree, config_raw: &str) -> Result<(), TreeError> {
    tree.driver
        .rules
        .validate_regexes()
        .map_err(TreeError::InvalidRegex)?;
    let config_text = apply_full_text_subs(&tree.driver, Cow::Borrowed(config_raw))?;
    let config_text = config_preprocessor(tree.driver.platform, &config_text);

    // Resolve every regex used inside the line loop up front.
    let per_line_subs = PreparedSubs::new(&tree.driver.rules.per_line_sub)?;
    let indent_rules: Vec<(MatchRegex, MatchRegex)> = tree
        .driver
        .rules
        .indent_adjust
        .iter()
        .map(|expression| {
            Ok((
                MatchRegex::cached(&expression.start_expression)?,
                MatchRegex::cached(&expression.end_expression)?,
            ))
        })
        .collect::<Result<_, String>>()
        .map_err(TreeError::InvalidRegex)?;

    let mut state = ParserState::new(tree.root);

    // Most lines become a node, so sizing the arena up front avoids repeatedly
    // reallocating and copying the node table while parsing a large configuration.
    // The estimate is bounded by the line count, so a long line or banner cannot
    // reserve node slots in proportion to its length.
    tree.arena.reserve(initial_text_capacity(&config_text));

    for (raw_line, normalized_indent) in parse_lines(&config_text) {
        if state.banner.in_banner {
            state.handle_banner_continuation(tree, raw_line)?;
            continue;
        }

        if state.banner.check_start(raw_line) {
            continue;
        }

        let (normalized_line, indent) = match normalized_indent {
            Some(indent) => (raw_line, indent),
            None => normalize_whitespace(raw_line, &mut state.normalized),
        };
        let line = per_line_subs.apply_indented(normalized_line, Some(indent));
        let line_trimmed_right = trim_end(&line);
        if line_trimmed_right.is_empty() {
            continue;
        }

        // A line no substitution rewrote keeps the indentation measured above.
        let actual_indent = match line {
            Cow::Borrowed(_) => indent,
            Cow::Owned(_) => leading_whitespace_len(line_trimmed_right),
        };
        let this_indent = i32::try_from(actual_indent).unwrap_or(i32::MAX) + state.indent.adjust;
        let line_content = &line_trimmed_right[actual_indent..];
        state
            .cursor
            .record_trimmed_line(tree, this_indent, line_content, &mut state.texts)?;

        state.indent.update(&indent_rules, line_content)?;
    }

    if state.banner.in_banner {
        return Err(TreeError::UnterminatedBanner(
            state
                .banner
                .temp_banner
                .first()
                .cloned()
                .unwrap_or_default(),
        ));
    }

    tree.arena.shrink_excess();
    Ok(())
}

/// Fast load parser for clean/pre-formatted configurations.
///
/// Unlike [`load_from_str`] this applies only `per_line_sub` rules and assumes the
/// input needs no preprocessing, so it skips banner and comment handling.
///
/// Pass `run_post_load = false` when the caller supplies its own post-load
/// callbacks, as the Python bindings do for drivers that override the stock set.
///
/// `lines` may be any iterable of string-like items, so callers holding borrowed
/// or reference-counted strings need not collect a `Vec<&str>` first. The arena is
/// sized from the iterator's lower size bound.
///
/// # Errors
///
/// Returns [`TreeError`] if a line cannot be inserted into the tree.
pub fn load_fast<I>(tree: &mut Tree, lines: I, run_post_load: bool) -> Result<(), TreeError>
where
    I: IntoIterator,
    I::Item: AsRef<str>,
{
    let lines = lines.into_iter();
    let mut loader = FastLoader::new(tree, lines.size_hint().0)?;
    for line in lines {
        loader.load_line(tree, line.as_ref(), None)?;
    }
    finish_fast_load(tree, run_post_load);
    Ok(())
}

/// [`load_fast`] for configuration text not yet split into lines.
///
/// The text is split on exactly the [`splitlines`] boundaries, so this is
/// equivalent to calling [`load_fast`] on the split lines, but walks the text
/// once instead of collecting the lines first and re-scanning each of them.
///
/// # Errors
///
/// Returns [`TreeError`] if a line cannot be inserted into the tree.
pub fn load_fast_text(tree: &mut Tree, text: &str, run_post_load: bool) -> Result<(), TreeError> {
    // Estimated from the byte length, as in [`parse_into_tree`].
    let mut loader = FastLoader::new(tree, initial_text_capacity(text))?;
    for (line, normalized_indent) in parse_lines(text) {
        loader.load_line(tree, line, normalized_indent)?;
    }
    finish_fast_load(tree, run_post_load);
    Ok(())
}

/// Initial node-arena reservation for parsing `text`.
///
/// Configuration lines average about 25 bytes, so the byte length gives a close
/// estimate without a separate line-counting pass (which measured 4–10% slower on
/// the parse benchmarks). Text made of a few very long lines overshoots; the
/// untouched reservation is returned by [`Arena::shrink_excess`] once loading ends.
///
/// [`Arena::shrink_excess`]: crate::arena::Arena::shrink_excess
const fn initial_text_capacity(text: &str) -> usize {
    text.len() / 24 + 1
}

fn finish_fast_load(tree: &mut Tree, run_post_load: bool) {
    tree.arena.shrink_excess();
    crate::post_load::delete_sectional_exit_recursive(tree);
    if run_post_load {
        crate::post_load::run_post_load_callbacks(tree);
    }
}

/// Per-parse state shared by [`load_fast`] and [`load_fast_text`].
struct FastLoader {
    cursor: ParserCursor,
    texts: SiblingTexts,
    per_line_subs: PreparedSubs,
    /// Reused across lines so the slow path allocates at most once for the whole parse.
    normalized: String,
}

impl FastLoader {
    fn new(tree: &mut Tree, expected_lines: usize) -> Result<Self, TreeError> {
        tree.driver
            .rules
            .validate_regexes()
            .map_err(TreeError::InvalidRegex)?;
        let per_line_subs = PreparedSubs::new(&tree.driver.rules.per_line_sub)?;
        // Nearly every line becomes a node, so sizing the arena up front avoids the
        // repeated grow-and-copy of a node table whose entries are hundreds of bytes.
        tree.arena.reserve(expected_lines);
        Ok(Self {
            cursor: ParserCursor::new(tree.root),
            texts: SiblingTexts::new(),
            per_line_subs,
            normalized: String::with_capacity(256),
        })
    }

    /// Loads one line. `normalized_indent` is the indentation length of a line
    /// already known to be space-indented and whitespace-normalized, as reported by
    /// [`parse_lines`]; such a line skips both scans below.
    fn load_line(
        &mut self,
        tree: &mut Tree,
        original_line: &str,
        normalized_indent: Option<usize>,
    ) -> Result<(), TreeError> {
        // One indentation scan per line: it doubles as the blank-line check, and is
        // reused unless a substitution actually rewrote the line.
        let original_indent =
            normalized_indent.unwrap_or_else(|| leading_whitespace_len(original_line));
        if original_indent == original_line.len() {
            return Ok(());
        }

        let processed_line = self
            .per_line_subs
            .apply_indented(original_line, Some(original_indent));
        let (indent_len, known_normalized) = match &processed_line {
            Cow::Borrowed(_) => (original_indent, normalized_indent.is_some()),
            Cow::Owned(rewritten) => (leading_whitespace_len(rewritten), false),
        };
        let processed_trimmed = &processed_line[indent_len..];
        if processed_trimmed.is_empty() {
            return Ok(());
        }

        let indent = i32::try_from(indent_len).unwrap_or(i32::MAX);

        // Mirrors the full parser: lines that already have single-space separators and
        // no trailing whitespace — nearly all of them — are borrowed as-is instead of
        // being rebuilt word by word.
        let normalized_line: &str =
            if known_normalized || is_already_normalized(processed_trimmed.as_bytes()) {
                processed_trimmed
            } else {
                self.normalized.clear();
                for word in processed_trimmed.split_whitespace() {
                    if !self.normalized.is_empty() {
                        self.normalized.push(' ');
                    }
                    self.normalized.push_str(word);
                }
                &self.normalized
            };

        self.cursor
            .record_trimmed_line(tree, indent, normalized_line, &mut self.texts)?;
        Ok(())
    }
}

/// Parses pre-formatted lines into a `Tree`, running stock post-load callbacks (if enabled)
/// followed additively by the provided custom callbacks.
///
/// # Errors
///
/// Returns [`TreeError`] if a line cannot be inserted into the tree.
pub fn load_fast_with_callbacks<F>(
    tree: &mut Tree,
    lines: &[&str],
    run_post_load: bool,
    callbacks: impl IntoIterator<Item = F>,
) -> Result<(), TreeError>
where
    F: Fn(&mut Tree),
{
    load_fast(tree, lines, run_post_load)?;
    for cb in callbacks {
        cb(tree);
    }
    Ok(())
}

/// Parses configuration text into a new [`Tree`], applying all post-load stages.
///
/// This provides a pure, transactional constructor: on failure no partially-populated
/// tree is left behind.
///
/// # Errors
///
/// Returns [`TreeError`] if a line cannot be parsed or attached to the tree.
pub fn parse_tree(driver: Driver, config_raw: &str) -> Result<Tree, TreeError> {
    let mut tree = Tree::new(driver);
    load_from_str(&mut tree, config_raw)?;
    Ok(tree)
}

/// Parses configuration text into a new [`Tree`], running stock post-load callbacks
/// followed additively by the provided custom callbacks.
///
/// # Errors
///
/// Returns [`TreeError`] if a line cannot be parsed or attached to the tree.
pub fn parse_tree_with_callbacks<F>(
    driver: Driver,
    config_raw: &str,
    callbacks: impl IntoIterator<Item = F>,
) -> Result<Tree, TreeError>
where
    F: Fn(&mut Tree),
{
    let mut tree = Tree::new(driver);
    load_from_str_with_callbacks(&mut tree, config_raw, callbacks)?;
    Ok(tree)
}

/// Parses pre-formatted lines into a new [`Tree`], running post-load stages as requested.
///
/// # Errors
///
/// Returns [`TreeError`] if a line cannot be parsed or attached to the tree.
pub fn parse_fast(driver: Driver, lines: &[&str], run_post_load: bool) -> Result<Tree, TreeError> {
    let mut tree = Tree::new(driver);
    load_fast(&mut tree, lines, run_post_load)?;
    Ok(tree)
}

/// Parses pre-formatted lines into a new [`Tree`], running stock post-load callbacks (if enabled)
/// followed additively by the provided custom callbacks.
///
/// # Errors
///
/// Returns [`TreeError`] if a line cannot be parsed or attached to the tree.
pub fn parse_fast_with_callbacks<F>(
    driver: Driver,
    lines: &[&str],
    run_post_load: bool,
    callbacks: impl IntoIterator<Item = F>,
) -> Result<Tree, TreeError>
where
    F: Fn(&mut Tree),
{
    let mut tree = Tree::new(driver);
    load_fast_with_callbacks(&mut tree, lines, run_post_load, callbacks)?;
    Ok(tree)
}

/// Loads a `Tree` from a serialized `Dump`.
///
/// # Errors
///
/// Returns [`TreeError`] if the dump describes a structure that cannot be
/// reconstructed, such as a child whose recorded depth has no matching parent.
pub fn from_dump(driver: Driver, dump: &Dump) -> Result<Tree, TreeError> {
    let mut tree = Tree::new(driver);
    let mut last_item = tree.root;

    for item in &dump.lines {
        let parent = if item.depth == 1 {
            tree.root
        } else if tree.depth(last_item) == item.depth {
            tree.arena[last_item].parent.unwrap_or(tree.root)
        } else if tree.depth(last_item) + 1 == item.depth {
            last_item
        } else {
            let lineage = tree.lineage(last_item);
            if item.depth >= 2 && item.depth - 2 < lineage.len() {
                lineage[item.depth - 2]
            } else {
                tree.root
            }
        };

        let new_id = tree.add_child(parent, &item.text, false, false)?;
        let node = &mut tree.arena[new_id];
        // Only touch the extras block when the dump actually carries something,
        // so the common unadorned line never allocates one.
        if !item.tags.is_empty() {
            node.tags_mut().extend(item.tags.iter().cloned());
        }
        if !item.comments.is_empty() {
            node.comments_mut().extend(item.comments.iter().cloned());
        }
        node.new_in_config = item.new_in_config;
        node.real_indent_level = i32::try_from(item.depth).unwrap_or(i32::MAX) - 1;
        last_item = new_id;
    }

    Ok(tree)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Applies `rules` one after another with no prefiltering at all.
    fn sequential_subs(rules: &[crate::models::PerLineSubRule], line: &str) -> String {
        let mut text = line.to_owned();
        for rule in rules {
            let re = rule_regex(&rule.search).unwrap();
            let replacement = python_replacement(&re, &rule.replace).unwrap();
            text = re.replace_all(&text, replacement.as_str()).into_owned();
        }
        text
    }

    fn sub(search: &str, replace: &str) -> crate::models::PerLineSubRule {
        crate::models::PerLineSubRule {
            search: search.to_owned(),
            replace: replace.to_owned(),
        }
    }

    const SUB_PROBES: &[&str] = &[
        "",
        " ",
        "!",
        "! comment",
        "   ! indented comment",
        "\u{3000}! ideographic-space comment",
        "\u{a0}# nbsp comment",
        "#",
        "end",
        "end ",
        "endx",
        "end-policy",
        "end-set",
        "next",
        "version 15.2",
        "Building configuration...",
        "Current configuration : 1234 bytes",
        "! Last configuration change at 10:00",
        "ntp clock-period 17179",
        " logging event link-status",
        " logging event link-statusx",
        "  ipv6 unreachables disable",
        " no ip address",
        " no ip address 10.0.0.1",
        " exit-address-family",
        "interface GigabitEthernet0/1",
        " description Link to device — 设备",
        " speed 1000",
        " duplex full",
        "snmp-server location  two spaces",
        "boot system flash:image.bin",
        "router(config)# show run",
        "; procurve comment",
        "Running configuration:",
        "ver 08.0.30",
        "crypto key generate rsa general-keys modulus 2048",
        "exit",
        "  exit",
    ];

    #[test]
    fn per_line_subs_match_a_sequential_pass_for_every_platform() {
        for platform in Platform::ALL {
            let rules = Driver::for_platform(platform).rules.per_line_sub;
            let prepared = PreparedSubs::new(&rules).unwrap();
            for line in SUB_PROBES {
                assert_eq!(
                    prepared.apply(line),
                    sequential_subs(&rules, line),
                    "{platform:?}: {line:?}"
                );
            }
        }
    }

    #[test]
    fn per_line_subs_rerun_later_rules_on_rewritten_text() {
        let rules = [
            sub("^a", "!b"),
            sub(r"^\s*[#!]x", "unreachable"),
            sub("^!b", "  #c"),
            sub(r"^\s*#c$", "done"),
            sub("c", "C"),
            sub(r"^\s+done", "late"),
            sub("^(?i)DONE", "flagged"),
        ];
        let prepared = PreparedSubs::new(&rules).unwrap();
        for line in ["a", "ab", "!b", "  #c", "x", "done", "DONE", "#x"] {
            assert_eq!(
                prepared.apply(line),
                sequential_subs(&rules, line),
                "{line:?}"
            );
        }
    }

    #[test]
    fn per_line_subs_beyond_the_dispatch_width_still_apply_in_order() {
        let mut rules: Vec<_> = (0..70).map(|i| sub(&format!("^r{i}$"), "")).collect();
        rules.push(sub("^r69$", "r70"));
        rules.push(sub("^z", "r1"));
        let prepared = PreparedSubs::new(&rules).unwrap();
        for line in ["r0", "r1", "r69", "r70", "zz", "q"] {
            assert_eq!(
                prepared.apply(line),
                sequential_subs(&rules, line),
                "{line:?}"
            );
        }
    }

    #[test]
    fn prefix_guards_only_describe_text_every_match_starts_with() {
        let cases: [(&str, Option<(bool, usize)>); 20] = [
            ("^end$", Some((false, 3))),
            (r"^\s*[#!].*", Some((true, 1))),
            ("^ntp clock-period .*", Some((false, 17))),
            // A quantified element is optional, so the guard stops before it.
            ("^ab*c", Some((false, 1))),
            ("^ab?", Some((false, 1))),
            ("^ab{0,2}", Some((false, 1))),
            ("^ab+c", Some((false, 2))),
            (r"^ver \S+", Some((false, 4))),
            // Unanchored, alternated, flagged or otherwise opaque patterns are unguarded.
            (".*speed.*", None),
            ("!.*", None),
            ("^a|b", None),
            ("^(?i)end", None),
            (r"^\S+#.*", None),
            ("^[^!]", None),
            ("^[a-z]", None),
            ("^[]", None),
            ("^.x", None),
            // `\s*` could also consume a leading space the guard would demand.
            (r"^\s* x", None),
            (r"^\s*[ x]", None),
            (r"^\s*$", None),
        ];
        for (pattern, expected) in cases {
            let guard =
                PrefixGuard::of(pattern).map(|guard| (guard.skip_whitespace, guard.classes.len()));
            assert_eq!(guard, expected, "{pattern}");
        }
    }

    #[test]
    fn prefix_guards_record_when_they_describe_the_whole_pattern() {
        let tail = |pattern: &str| PrefixGuard::of(pattern).and_then(|guard| guard.tail);
        assert_eq!(tail(r"^\s*[#!].*"), Some(GuardTail::RestOfLine));
        assert_eq!(tail("^version.*$"), Some(GuardTail::RestOfLine));
        assert_eq!(tail("^end$"), Some(GuardTail::EndOfLine));
        assert_eq!(tail("^ no ip address"), Some(GuardTail::Open));
        assert_eq!(tail("^ab+"), None);
        assert_eq!(tail("^ab*"), None);
        assert_eq!(tail(r"^ver \S+"), None);
        assert_eq!(tail("^end.+"), None);
        assert_eq!(tail("^end.*x"), None);
    }

    #[test]
    fn exact_prefix_guards_substitute_like_the_regex() {
        let rules = [
            sub(r"^\s*[#!].*", ""),
            sub("^end$", "fin"),
            sub(r"^\s*no ip", "ip"),
            sub("^ab.*", r"\g<0>-copy"),
            sub("^cost$", "$5"),
            sub("^tail", "$x"),
            sub("^line.*", "L"),
        ];
        let prepared = PreparedSubs::new(&rules).unwrap();
        for line in [
            "!",
            "  # note",
            "\u{3000}!x",
            "end",
            "end ",
            "ending",
            " no ip address",
            "\u{a0}no ipx",
            "no i",
            "abc",
            "cost",
            "costs",
            "tail end",
            "line\nnext",
            "line\rx",
            "",
        ] {
            assert_eq!(
                prepared.apply(line),
                sequential_subs(&rules, line),
                "{line:?}"
            );
        }
    }

    #[test]
    fn prefix_guards_skip_unicode_whitespace_like_the_regex() {
        let guard = PrefixGuard::of(r"^\s*[#!]").unwrap();
        assert!(guard.admits("\u{3000}\u{a0}\t!"));
        assert!(guard.admits("#"));
        assert!(!guard.admits("x!"));
        assert!(!guard.admits("   "));
        let literal = PrefixGuard::of("^end").unwrap();
        assert!(literal.admits("endx"));
        assert!(!literal.admits("en"));
        assert!(!literal.admits(" end"));
        assert!(!literal.admits("énd"));
    }

    #[test]
    fn parsed_lines_are_trimmed_of_whitespace_substitutions_introduce() {
        let mut driver = Driver::default();
        driver.rules.per_line_sub = vec![
            crate::models::PerLineSubRule {
                search: "^tail$".to_owned(),
                replace: "end\u{a0}\u{2003}".to_owned(),
            },
            crate::models::PerLineSubRule {
                search: "^lead ".to_owned(),
                replace: "\u{3000}".to_owned(),
            },
        ];
        let mut tree = Tree::new(driver);
        parse_into_tree(
            &mut tree,
            "parent x\u{2003}\nlead child\u{a0}\ntail \nplain\t",
        )
        .unwrap();
        let texts: Vec<_> = tree
            .all_children_sorted(tree.root)
            .into_iter()
            .map(|id| {
                (
                    tree.arena[id].text.to_string(),
                    tree.arena[id].real_indent_level,
                )
            })
            .collect();
        assert_eq!(
            texts,
            [
                ("parent x".to_owned(), 0),
                ("child".to_owned(), 3),
                ("end".to_owned(), 0),
                ("plain".to_owned(), 0)
            ]
        );
    }

    #[test]
    fn load_fast_skips_blank_lines_and_indents_after_per_line_subs() {
        let mut driver = Driver::default();
        driver.rules.per_line_sub = vec![
            crate::models::PerLineSubRule {
                search: "^drop.*".to_owned(),
                replace: "   ".to_owned(),
            },
            crate::models::PerLineSubRule {
                search: "^NEST ".to_owned(),
                replace: "  ".to_owned(),
            },
        ];
        let lines = [
            "interface a",
            "",
            "   ",
            "\t\u{a0}\u{2028}",
            "drop me",
            "NEST description  two   spaces ",
            "\u{a0}shutdown",
            "\u{3000}mtu 9000",
            "interface b",
            "\tdescription tabbed",
        ];
        let mut tree = Tree::new(driver);
        load_fast(&mut tree, &lines, false).unwrap();
        assert_eq!(
            tree.dump_simple(false),
            [
                "interface a",
                "  description two spaces",
                "  shutdown",
                "    mtu 9000",
                "interface b",
                "  description tabbed",
            ]
        );
        let root = &tree.arena[tree.root];
        let first = root.children.iter().next().unwrap();
        let indents: Vec<i32> = tree.arena[first]
            .children
            .iter()
            .map(|child| tree.arena[child].real_indent_level)
            .collect();
        assert_eq!(indents, [2, 2]);
    }

    #[test]
    fn normalized_indent_matches_the_rebuilt_line() {
        for raw in [
            "  ip address  1.1.1.1",
            "\t interface x",
            "  \u{a0}description  café",
            " \u{2028}a\u{a0} b",
            "   ",
            "plain",
            "  normal line",
        ] {
            let mut buffer = String::new();
            let (line, indent) = normalize_whitespace(raw, &mut buffer);
            assert_eq!(indent, leading_whitespace_len(line), "{raw:?}");
        }
    }

    #[test]
    fn fused_line_scan_matches_splitlines_and_normalization() {
        const ALPHABET: [&str; 16] = [
            "a", "b", "c", "d", "e", "f", " ", " ", " ", "\n", "\r", "\t", "\u{e9}", "\u{2028}",
            "\u{85}", "\x1f",
        ];
        let mut state: u32 = 0x2545_f491;
        for _ in 0..20_000 {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            let len = state as usize % 120;
            let mut next = state;
            let text: String = (0..len)
                .map(|_| {
                    next ^= next << 13;
                    next ^= next >> 17;
                    next ^= next << 5;
                    ALPHABET[(next % 16) as usize]
                })
                .collect();
            let fused: Vec<(&str, Option<usize>)> = parse_lines(&text).collect();
            let expected: Vec<&str> = splitlines(&text).collect();
            assert_eq!(
                fused.iter().map(|(line, _)| *line).collect::<Vec<_>>(),
                expected,
                "{text:?}"
            );
            for (line, indent) in fused {
                if let Some(indent) = indent {
                    let mut buffer = String::new();
                    assert_eq!(
                        normalize_whitespace(line, &mut buffer),
                        (line, indent),
                        "{line:?}"
                    );
                }
            }
        }
        let clean: Vec<_> =
            parse_lines(" interface Gi0/1\r\n  ip address 1.1.1.1 255.0.0.0\n").collect();
        assert_eq!(
            clean,
            [
                (" interface Gi0/1", Some(1)),
                ("  ip address 1.1.1.1 255.0.0.0", Some(2))
            ]
        );
    }

    #[test]
    fn word_at_a_time_normalization_check_matches_the_byte_scan() {
        const ALPHABET: [u8; 6] = [b'a', b' ', b' ', b'\t', 0x01, 0xc3];
        let mut state: u32 = 0x9e37_79b9;
        for _ in 0..50_000 {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            let len = state as usize % 30;
            let bytes: Vec<u8> = (0u32..)
                .take(len)
                .map(|offset| ALPHABET[(state.rotate_left(offset * 3) % 6) as usize])
                .collect();
            assert_eq!(
                is_already_normalized(&bytes),
                is_normalized_from(&bytes, false),
                "{bytes:?}"
            );
        }
        // Double spaces straddling, and a trailing space ending, an eight-byte word.
        assert!(!is_already_normalized(b"abcdefg  hijklmnop"));
        assert!(!is_already_normalized(b"abcdefgh "));
        assert!(is_already_normalized(b"abcdefg hijklmno p"));
        // The tail is re-read as an overlapping word: its pairs, its last byte and
        // bytes the overlap shares with the previous word must all be judged once.
        assert!(!is_already_normalized(b"abcdefghij  k"));
        assert!(!is_already_normalized(b"abcdefgh ijk "));
        assert!(!is_already_normalized(b"abcdefgh ijk\t"));
        assert!(!is_already_normalized(b"abcdefgh ij\xc3\xa9"));
        assert!(is_already_normalized(b"abcdefg hij k"));
        assert!(is_already_normalized(b"abcdefgh i j k l"));
    }

    fn byte_scan_line_boundary(bytes: &[u8]) -> Option<(usize, usize)> {
        (0..bytes.len()).find_map(|index| {
            let rest = &bytes[index..];
            let width = match rest {
                [b'\n' | b'\r' | 0x0b | 0x0c | 0x1c..=0x1e, ..] => 1,
                [0xc2, 0x85, ..] => 2,
                [0xe2, 0x80, 0xa8 | 0xa9, ..] => 3,
                _ => return None,
            };
            Some((index, width))
        })
    }

    #[test]
    fn word_at_a_time_line_boundary_matches_the_byte_scan() {
        // Boundaries, near-miss control and lead bytes, and filler.
        const ALPHABET: [u8; 13] = [
            b'a', b'z', b' ', b'\t', b'\n', b'\r', 0x1c, 0x1f, 0x01, 0xc2, 0x85, 0xe2, 0x80,
        ];
        let mut state: u32 = 0x9e37_79b9;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as usize
        };
        for _ in 0..50_000 {
            let len = next() % 40;
            let mut bytes: Vec<u8> = (0..len)
                .map(|_| ALPHABET[next() % ALPHABET.len()])
                .collect();
            if len > 3 && next() % 4 == 0 {
                let at = next() % (len - 2);
                bytes[at..at + 3].copy_from_slice(&[0xe2, 0x80, 0xa8]);
            }
            assert_eq!(
                find_line_boundary(&bytes),
                byte_scan_line_boundary(&bytes),
                "{bytes:?}"
            );
        }
        // A lone candidate byte at every offset around the eight-byte word edges,
        // including a non-boundary control byte followed by a real one in the same word.
        for offset in 0..24 {
            for candidate in [
                &b"\n"[..],
                b"\x01\n",
                b"\xc2\x85",
                b"\xe2\x80\xa9",
                b"\xc3\xa9\r",
            ] {
                let mut bytes = vec![b'x'; offset];
                bytes.extend_from_slice(candidate);
                bytes.extend_from_slice(b"yyyyyyyyyyyy");
                assert_eq!(
                    find_line_boundary(&bytes),
                    byte_scan_line_boundary(&bytes),
                    "offset {offset} {candidate:?}"
                );
            }
        }
    }

    #[test]
    fn test_is_end_of_banner() {
        let end_lines: HashSet<String> =
            ["EOF", "%", "!"].iter().map(|s| (*s).to_string()).collect();
        let contains = vec!["^C".to_string()];
        let no_end_lines: HashSet<String> = HashSet::default();

        // A caret-prefixed line always terminates a banner.
        assert!(is_end_of_banner("^C", &end_lines, &contains));
        // Exact matches against the configured end lines terminate it.
        assert!(is_end_of_banner("%", &end_lines, &[]));
        assert!(is_end_of_banner("!", &end_lines, &[]));
        // So does a trailing delimiter on a content line.
        assert!(is_end_of_banner(
            "This is banner text^C",
            &no_end_lines,
            &contains
        ));
        // Ordinary banner content does not.
        assert!(!is_end_of_banner(
            "This is just regular text",
            &no_end_lines,
            &[]
        ));
    }

    #[test]
    fn test_adjust_indent() {
        let prepared = vec![(
            MatchRegex::cached("^policy-map").unwrap(),
            MatchRegex::cached("^ *class").unwrap(),
        )];

        // A matching line opens a new virtual indent level.
        let (indent, ends) = adjust_indent(&prepared, "policy-map test", 0, Vec::new()).unwrap();
        assert_eq!(indent, 1);
        assert_eq!(ends.len(), 1);
        assert!(ends[0].is_match("class foo").unwrap());

        // A non-matching line leaves both accumulators untouched.
        let (plain_indent, plain_ends) =
            adjust_indent(&prepared, "hostname Router1", 0, Vec::new()).unwrap();
        assert_eq!(plain_indent, 0);
        assert!(plain_ends.is_empty());

        // With no rules configured there is nothing to adjust.
        let (unruled_indent, unruled_ends) =
            adjust_indent(&[], "policy-map test", 0, Vec::new()).unwrap();
        assert_eq!(unruled_indent, 0);
        assert!(unruled_ends.is_empty());
    }

    #[test]
    fn test_parse_simple_cisco_config() {
        let config = "
hostname Router1
!
interface GigabitEthernet0/1
 description Uplink
 ip address 10.0.0.1 255.255.255.0
!
router bgp 65000
 neighbor 10.0.0.2 remote-as 65001
";
        let mut tree = Tree::for_platform(Platform::CiscoIos);
        load_from_str(&mut tree, config).unwrap();

        assert_eq!(tree.arena[tree.root].children.len(), 3);
        let iface = tree.arena[tree.root]
            .children
            .get("interface GigabitEthernet0/1")
            .unwrap();
        assert_eq!(tree.arena[iface].children.len(), 2);
        assert!(
            tree.arena[iface]
                .children
                .get("description Uplink")
                .is_some()
        );
        assert!(
            tree.arena[iface]
                .children
                .get("ip address 10.0.0.1 255.255.255.0")
                .is_some()
        );
    }

    #[test]
    fn test_parse_banner() {
        let config = "
hostname Router1
banner motd ^
WARNING: Authorized Access Only!
Disconnect immediately if unauthorized.
^
interface Loopback0
";
        let mut tree = Tree::for_platform(Platform::CiscoIos);
        load_from_str(&mut tree, config).unwrap();

        assert_eq!(tree.arena[tree.root].children.len(), 3);
        let banner_node = tree.arena[tree.root].children.as_slice()[1];
        assert!(tree.arena[banner_node].text.starts_with("banner motd ^"));
        assert!(
            tree.arena[banner_node]
                .text
                .contains("Authorized Access Only!")
        );
    }

    #[test]
    fn test_dump_roundtrip() {
        let config = "
interface GigabitEthernet0/1
 description Link
";
        let mut tree = Tree::for_platform(Platform::Generic);
        load_from_str(&mut tree, config).unwrap();

        let dump = tree.dump();
        assert_eq!(dump.lines.len(), 2);
        assert_eq!(dump.lines[0].text, "interface GigabitEthernet0/1");
        assert_eq!(dump.lines[1].text, "description Link");

        let reloaded = from_dump(Driver::for_platform(Platform::Generic), &dump).unwrap();
        assert_eq!(reloaded.dump().lines.len(), 2);
    }

    #[test]
    fn test_unterminated_banner_reports_the_offending_line() {
        // Regression: reaching EOF inside a banner used to surface as
        // `InvalidParent(NodeId { .. })`, which told the user nothing about
        // what went wrong. v3 raised "we are still in a banner", so the error
        // must name the banner it failed to close.
        let mut tree = Tree::default();
        let err = load_from_str(&mut tree, "banner motd \"Hello\"\nvlan 10\n")
            .expect_err("an unterminated banner must be rejected");

        assert!(matches!(err, TreeError::UnterminatedBanner(_)), "{err:?}");
        let message = err.to_string();
        assert!(message.contains("Unterminated banner"), "{message}");
        assert!(message.contains("banner motd"), "{message}");
    }

    #[test]
    fn test_parse_banner_with_multibyte_delimiter_does_not_panic() {
        // Regression: the banner delimiter used to be byte-sliced (`delim[..1]`,
        // `delim[..2]`), which panics when the delimiter starts with a multibyte
        // character such as the euro sign. Parsing must not panic on arbitrary input.
        let config = "hostname Router1\nbanner motd \u{20ac}\nAuthorized only\n\u{20ac}\ninterface Loopback0\n";
        let mut tree = Tree::for_platform(Platform::CiscoIos);
        load_from_str(&mut tree, config).unwrap();
        assert!(
            tree.arena[tree.root]
                .children
                .iter()
                .any(|id| tree.arena[id].text.starts_with("banner motd"))
        );
    }

    #[test]
    fn test_pure_parse_tree_and_parse_fast() {
        use std::cell::Cell;

        let config = "hostname Router1\ninterface GigabitEthernet0/1\n description Link\n";
        let tree = parse_tree(Driver::for_platform(Platform::CiscoIos), config).unwrap();
        assert_eq!(tree.len(), 3);

        let custom_run = Cell::new(false);
        let tree_with_cb = parse_tree_with_callbacks(
            Driver::for_platform(Platform::CiscoIos),
            config,
            [&|_t: &mut Tree| {
                custom_run.set(true);
            }],
        )
        .unwrap();
        assert!(custom_run.get());
        assert_eq!(tree_with_cb.len(), 3);

        let lines = ["hostname FastRouter", "interface Fast0/0"];
        let fast_tree = parse_fast(Driver::for_platform(Platform::CiscoIos), &lines, true).unwrap();
        assert_eq!(fast_tree.len(), 2);

        let fast_cb_run = Cell::new(false);
        let fast_tree_cb = parse_fast_with_callbacks(
            Driver::for_platform(Platform::CiscoIos),
            &lines,
            true,
            [&|_t: &mut Tree| {
                fast_cb_run.set(true);
            }],
        )
        .unwrap();
        assert!(fast_cb_run.get());
        assert_eq!(fast_tree_cb.len(), 2);
    }

    #[test]
    fn load_fast_text_matches_load_fast_over_splitlines() {
        let configs = [
            "",
            "hostname r1",
            "interface a\n description  two   spaces \n\n   \n\tshutdown\r\n mtu 9000\r\
             interface b\x0b ip address 10.0.0.1 255.0.0.0\x0c\u{85}\u{2028} vlan 10\u{2029}end",
            "interface Vlan1\n ip address 1.1.1.1 255.0.0.0\n!\nrouter bgp 1\n  neighbor x\n \
             exit\n\u{a0}tail line with trailing space \nlast",
            "interface Ethernet1/1\n switchport trunk allowed vlan 1-20\n description caf\u{e9}",
        ];
        for platform in [Platform::Generic, Platform::CiscoIos, Platform::CiscoXr] {
            for config in configs {
                for run_post_load in [false, true] {
                    let lines: Vec<&str> = splitlines(config).collect();
                    let mut expected = Tree::for_platform(platform);
                    load_fast(&mut expected, &lines, run_post_load).unwrap();
                    let mut actual = Tree::for_platform(platform);
                    load_fast_text(&mut actual, config, run_post_load).unwrap();
                    assert_eq!(
                        actual.dump_simple(false),
                        expected.dump_simple(false),
                        "{platform:?} {config:?}"
                    );
                    assert_eq!(actual.dump(), expected.dump(), "{platform:?} {config:?}");
                }
            }
        }
    }

    #[test]
    fn load_fast_text_matches_load_fast_after_per_line_subs() {
        let mut driver = Driver::default();
        driver.rules.per_line_sub = [
            ("^drop.*", "   "),
            ("^NEST ", "  "),
            ("^ mtu", "   mtu  "),
            ("shutdown$", "shutdown   "),
        ]
        .into_iter()
        .map(|(search, replace)| crate::models::PerLineSubRule {
            search: search.to_owned(),
            replace: replace.to_owned(),
        })
        .collect();
        let config = "interface a\ndrop me\nNEST description x\n mtu 9000\n shutdown\n\
                      interface b\n\tdescription  tabbed\n shutdown";
        let lines: Vec<&str> = splitlines(config).collect();
        let mut expected = Tree::new(driver.clone());
        load_fast(&mut expected, &lines, false).unwrap();
        let mut actual = Tree::new(driver);
        load_fast_text(&mut actual, config, false).unwrap();
        assert_eq!(actual.dump(), expected.dump());
        assert_eq!(
            actual.dump_simple(false),
            [
                "interface a",
                "  description x",
                "    mtu 9000",
                "  shutdown",
                "interface b",
                "  description tabbed",
                "  shutdown",
            ]
        );
    }

    #[test]
    fn long_lines_keep_no_excess_arena_capacity_after_any_loader() {
        let long = "x".repeat(1_000_000);
        let text = format!("description {long}\nhostname {long}");
        let loaders: [fn(&mut Tree, &str); 3] = [
            |tree, config| parse_into_tree(tree, config).unwrap(),
            |tree, config| load_fast_text(tree, config, false).unwrap(),
            |tree, config| load_fast(tree, splitlines(config), false).unwrap(),
        ];
        for load in loaders {
            let mut tree = Tree::for_platform(Platform::Generic);
            load(&mut tree, &text);
            // The root plus one node per line.
            assert_eq!(tree.arena.len(), 3);
            assert!(
                tree.arena.capacity() <= 2 * tree.arena.len(),
                "two long lines kept {} node slots",
                tree.arena.capacity()
            );
        }
    }

    #[test]
    fn load_fast_text_reports_duplicate_children_like_load_fast() {
        let mut driver = Driver::for_platform(Platform::Generic);
        driver.rules.parent_allows_duplicate_child.clear();
        let config = "interface a\n mtu 1\n mtu 1";
        let lines: Vec<&str> = splitlines(config).collect();
        let mut expected = Tree::new(driver.clone());
        let mut actual = Tree::new(driver);
        assert_eq!(
            load_fast_text(&mut actual, config, false).is_err(),
            load_fast(&mut expected, &lines, false).is_err()
        );
    }

    #[test]
    fn repeated_section_lines_share_text_without_changing_the_tree() {
        let config = "interface a\n no shutdown\n mtu 9000\ninterface b\n no shutdown\n \
                      mtu 1500\ninterface c\n mtu 1500\n no shutdown\nno shutdown\nno shutdown 2";
        for fast in [false, true] {
            let mut tree = Tree::for_platform(Platform::Generic);
            if fast {
                let lines: Vec<&str> = config.lines().collect();
                load_fast(&mut tree, &lines, true).unwrap();
            } else {
                parse_into_tree(&mut tree, config).unwrap();
            }
            let text = |path: &[&str]| {
                let id = path.iter().fold(tree.root, |parent, part| {
                    tree.get_child_by_text(parent, part).unwrap()
                });
                Arc::clone(&tree.arena[id].text)
            };
            let a = text(&["interface a", "no shutdown"]);
            let b = text(&["interface b", "no shutdown"]);
            let c = text(&["interface c", "no shutdown"]);
            assert!(Arc::ptr_eq(&a, &b));
            assert!(!Arc::ptr_eq(&b, &c));
            assert!(!Arc::ptr_eq(
                &text(&["interface b", "mtu 1500"]),
                &text(&["interface c", "mtu 1500"])
            ));
            assert_eq!(&*c, "no shutdown");
            assert_eq!(&*text(&["no shutdown"]), "no shutdown");
            assert!(!Arc::ptr_eq(&text(&["no shutdown"]), &a));
            assert_eq!(
                tree.dump_simple(false),
                [
                    "interface a",
                    "  no shutdown",
                    "  mtu 9000",
                    "interface b",
                    "  no shutdown",
                    "  mtu 1500",
                    "interface c",
                    "  mtu 1500",
                    "  no shutdown",
                    "no shutdown",
                    "no shutdown 2",
                ]
            );
        }
    }

    #[test]
    fn sibling_texts_only_track_leading_positions() {
        let mut texts = SiblingTexts::new();
        let late = SiblingTexts::POSITIONS;
        let first = texts.share(late, "x");
        assert!(!Arc::ptr_eq(&first, &texts.share(late, "x")));
        let early = texts.share(0, "x");
        assert!(Arc::ptr_eq(&early, &texts.share(0, "x")));
        assert!(!Arc::ptr_eq(&early, &texts.share(1, "x")));
        assert_eq!(&*texts.share(0, "y"), "y");
        assert!(!Arc::ptr_eq(&early, &texts.share(0, "x")));
    }

    #[test]
    fn parser_rejects_lines_beyond_max_tree_depth() {
        let limit = crate::tree::MAX_TREE_DEPTH;
        let config = |depth: usize| -> String {
            (0..depth).fold(String::new(), |mut config, level| {
                config.push_str(&" ".repeat(level));
                config.push_str("level\n");
                config
            })
        };
        assert!(Tree::from_str(Platform::Generic, &config(limit)).is_ok());
        assert!(matches!(
            Tree::from_str(Platform::Generic, &config(limit + 1)),
            Err(TreeError::MaxDepthExceeded(_))
        ));
        let mut tree = Tree::new(Driver::default());
        let mut cursor = ParserCursor::new(tree.root);
        cursor.record_line(&mut tree, 0, "a").unwrap();
        cursor.record_line(&mut tree, 1, "b").unwrap();
        cursor.record_line(&mut tree, 0, "c").unwrap();
        cursor.record_line(&mut tree, 1, "d").unwrap();
        let d = cursor.record_line(&mut tree, 2, "e").unwrap();
        assert_eq!(tree.depth(d), 3);
    }

    #[test]
    fn test_parser_cursor_walks_hierarchy() {
        let mut tree = Tree::for_platform(Platform::Generic);
        let mut cursor = ParserCursor::new(tree.root);

        let top1 = cursor.record_line(&mut tree, 0, "parent1").unwrap();
        assert_eq!(cursor.current_section, tree.root);
        assert_eq!(cursor.most_recent_item, top1);

        let child1 = cursor.record_line(&mut tree, 1, "child1").unwrap();
        assert_eq!(cursor.current_section, top1);
        assert_eq!(cursor.most_recent_item, child1);

        let child2 = cursor.record_line(&mut tree, 1, "child2").unwrap();
        assert_eq!(cursor.current_section, top1);
        assert_eq!(cursor.most_recent_item, child2);

        let top2 = cursor.record_line(&mut tree, 0, "parent2").unwrap();
        assert_eq!(cursor.current_section, tree.root);
        assert_eq!(cursor.most_recent_item, top2);
    }
}
