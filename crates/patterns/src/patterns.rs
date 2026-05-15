//! Pattern definitions and helpers.

use regex::Regex;

/// Check if a Solidity source contains a regex pattern.
pub fn source_matches(source: &str, pattern: &str) -> Option<Vec<usize>> {
    let re = Regex::new(pattern).ok()?;
    let lines: Vec<_> = source.lines().collect();
    let mut matches = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if re.is_match(line) {
            matches.push(i + 1);
        }
    }
    if matches.is_empty() {
        None
    } else {
        Some(matches)
    }
}
