use hier_config_core::parser::splitlines;
use proptest::prelude::*;

/// Straightforward model of Python's `str.splitlines()` used as the oracle.
fn reference(text: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    let mut start = 0;
    let mut chars = text.char_indices().peekable();
    while let Some((index, character)) = chars.next() {
        if matches!(
            character,
            '\n' | '\r'
                | '\u{0b}'
                | '\u{0c}'
                | '\u{1c}'
                | '\u{1d}'
                | '\u{1e}'
                | '\u{85}'
                | '\u{2028}'
                | '\u{2029}'
        ) {
            lines.push(&text[start..index]);
            start = index + character.len_utf8();
            if character == '\r' && chars.peek().is_some_and(|&(_, next)| next == '\n') {
                chars.next();
                start += 1;
            }
        }
    }
    if start < text.len() {
        lines.push(&text[start..]);
    }
    lines
}

/// Characters chosen to exercise every boundary, the multibyte lead bytes the
/// byte scan inspects (`0xC2`, `0xE2`), and non-boundary control characters.
const ALPHABET: &[char] = &[
    'a',
    ' ',
    '\t',
    '\n',
    '\r',
    '\u{0b}',
    '\u{0c}',
    '\u{1c}',
    '\u{1d}',
    '\u{1e}',
    '\u{1f}',
    '\u{85}',
    '\u{84}',
    '\u{a0}',
    '\u{2028}',
    '\u{2029}',
    '\u{2027}',
    '\u{202a}',
    '\u{2080}',
    'é',
    '设',
    '\u{1f600}',
    '\0',
];

proptest! {
    #[test]
    fn splitlines_matches_python_model(
        indices in proptest::collection::vec(0..ALPHABET.len(), 0..64)
    ) {
        let text: String = indices.into_iter().map(|i| ALPHABET[i]).collect();
        prop_assert_eq!(splitlines(&text).collect::<Vec<_>>(), reference(&text));
    }

    #[test]
    fn splitlines_matches_python_model_on_arbitrary_text(text in "\\PC*|[\\x00-\\x7f\u{85}\u{2028}\u{2029}]*") {
        prop_assert_eq!(splitlines(&text).collect::<Vec<_>>(), reference(&text));
    }
}

#[test]
fn splitlines_handles_boundaries_at_chunk_edges() {
    // Long runs push boundaries across 8-byte chunk boundaries of a word-at-a-time scan.
    for pad in 0..20 {
        let filler = "x".repeat(pad);
        for boundary in [
            "\n", "\r\n", "\r", "\u{85}", "\u{2028}", "\u{2029}", "\u{1e}",
        ] {
            let text = format!("{filler}{boundary}{filler}é{boundary}{boundary}tail");
            assert_eq!(
                splitlines(&text).collect::<Vec<_>>(),
                reference(&text),
                "{text:?}"
            );
        }
    }
}
