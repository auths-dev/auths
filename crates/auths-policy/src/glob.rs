//! Hardened glob matcher for path/ref matching.
//!
//! Intentionally limited. Spec-documented. Exhaustively tested.
//!
//! # Supported Syntax
//!
//! | Pattern | Matches |
//! |---------|---------|
//! | `*` | Any single path segment (no `/`) |
//! | `**` | Zero or more path segments |
//! | `foo` | Literal segment `foo` |
//! | `release-*` | Segment starting with `release-` |
//! | `*-beta` | Segment ending with `-beta` |
//!
//! # Not Supported (by design)
//!
//! - Character classes `[abc]`
//! - Alternation `{a,b}`
//! - `?` single-character wildcard
//! - Regex
//!
//! # Normalization
//!
//! Both pattern and input are split on `/`. Empty segments (from
//! consecutive or trailing slashes) are filtered. This means
//! `foo//bar` matches `foo/bar`.

use crate::types::ValidatedGlob;

/// Match an input path against a validated glob pattern.
///
/// See module documentation for supported syntax.
pub fn glob_match(pattern: &ValidatedGlob, input: &str) -> bool {
    let pat_parts: Vec<&str> = pattern
        .as_str()
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();
    let inp_parts: Vec<&str> = input.split('/').filter(|s| !s.is_empty()).collect();
    match_parts(&pat_parts, &inp_parts)
}

fn match_parts(pattern: &[&str], input: &[&str]) -> bool {
    match (pattern, input) {
        // Both empty = match
        ([], []) => true,

        // Pattern is just "**" = match anything
        (["**"], _) => true,

        // Pattern has literal/wildcard segment, input has segment
        ([p, rest_pat @ ..], [i, rest_inp @ ..]) if *p != "**" => {
            segment_match(p, i) && match_parts(rest_pat, rest_inp)
        }

        // Pattern starts with "**"
        (["**", rest_pat @ ..], _) => {
            // "**" matches zero segments
            match_parts(rest_pat, input)
                // "**" matches one segment and continues
                || (!input.is_empty() && match_parts(pattern, &input[1..]))
        }

        // Pattern exhausted but input remains, or input exhausted but pattern remains
        _ => false,
    }
}

fn segment_match(pattern: &str, input: &str) -> bool {
    // Single star matches any segment
    if pattern == "*" {
        return true;
    }

    // Check for prefix star (e.g., "*-beta")
    if let Some(suffix) = pattern.strip_prefix('*') {
        // Must not contain another star for this simple case
        if !suffix.contains('*') {
            return input.ends_with(suffix);
        }
    }

    // Check for suffix star (e.g., "release-*")
    if let Some(prefix) = pattern.strip_suffix('*') {
        // Must not contain another star for this simple case
        if !prefix.contains('*') {
            return input.starts_with(prefix);
        }
    }

    // Check for both prefix and suffix star (e.g., "*feature*")
    if pattern.starts_with('*') && pattern.ends_with('*') && pattern.len() > 2 {
        let middle = &pattern[1..pattern.len() - 1];
        if !middle.contains('*') {
            return input.contains(middle);
        }
    }

    // Literal match
    pattern == input
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ValidatedGlob;

    fn g(s: &str) -> ValidatedGlob {
        ValidatedGlob::parse(s).unwrap()
    }

    #[test]
    fn exact_match() {
        assert!(glob_match(&g("foo/bar"), "foo/bar"));
        assert!(!glob_match(&g("foo/bar"), "foo/baz"));
    }

    #[test]
    fn exact_match_single_segment() {
        assert!(glob_match(&g("main"), "main"));
        assert!(!glob_match(&g("main"), "master"));
    }

    #[test]
    fn single_star() {
        assert!(glob_match(&g("foo/*/baz"), "foo/bar/baz"));
        assert!(glob_match(&g("foo/*/baz"), "foo/anything/baz"));
        assert!(!glob_match(&g("foo/*/baz"), "foo/bar/qux/baz"));
    }

    #[test]
    fn single_star_at_end() {
        assert!(glob_match(&g("foo/*"), "foo/bar"));
        assert!(glob_match(&g("foo/*"), "foo/anything"));
        assert!(!glob_match(&g("foo/*"), "foo/bar/baz"));
    }

    #[test]
    fn single_star_at_start() {
        assert!(glob_match(&g("*/bar"), "foo/bar"));
        assert!(glob_match(&g("*/bar"), "anything/bar"));
        assert!(!glob_match(&g("*/bar"), "foo/baz/bar"));
    }

    #[test]
    fn double_star_any_depth() {
        assert!(glob_match(&g("foo/**"), "foo/bar"));
        assert!(glob_match(&g("foo/**"), "foo/bar/baz/qux"));
        assert!(glob_match(&g("foo/**"), "foo"));
    }

    #[test]
    fn double_star_middle() {
        assert!(glob_match(&g("foo/**/baz"), "foo/baz"));
        assert!(glob_match(&g("foo/**/baz"), "foo/a/baz"));
        assert!(glob_match(&g("foo/**/baz"), "foo/a/b/c/baz"));
        assert!(!glob_match(&g("foo/**/baz"), "foo/a/b/c/qux"));
    }

    #[test]
    fn double_star_at_start() {
        assert!(glob_match(&g("**/baz"), "baz"));
        assert!(glob_match(&g("**/baz"), "foo/baz"));
        assert!(glob_match(&g("**/baz"), "foo/bar/baz"));
    }

    #[test]
    fn prefix_star() {
        assert!(glob_match(&g("release-*"), "release-v1"));
        assert!(glob_match(&g("release-*"), "release-v2.0.0"));
        assert!(glob_match(&g("release-*"), "release-"));
        assert!(!glob_match(&g("release-*"), "feature-v1"));
    }

    #[test]
    fn suffix_star() {
        assert!(glob_match(&g("*-beta"), "v1-beta"));
        assert!(glob_match(&g("*-beta"), "release-2.0-beta"));
        assert!(!glob_match(&g("*-beta"), "v1-alpha"));
    }

    #[test]
    fn contains_star() {
        assert!(glob_match(&g("*feature*"), "my-feature-branch"));
        assert!(glob_match(&g("*feature*"), "feature"));
        assert!(glob_match(&g("*feature*"), "feature-x"));
        assert!(glob_match(&g("*feature*"), "x-feature"));
        assert!(!glob_match(&g("*feature*"), "my-branch"));
    }

    #[test]
    fn normalise_slashes() {
        assert!(glob_match(&g("foo/bar"), "foo//bar"));
        assert!(glob_match(&g("foo/bar"), "foo/bar/"));
        assert!(glob_match(&g("foo/bar"), "/foo/bar"));
    }

    #[test]
    fn empty_input_matches_double_star() {
        assert!(glob_match(&g("**"), ""));
        assert!(glob_match(&g("**"), "a/b/c"));
    }

    #[test]
    fn double_star_alone_matches_everything() {
        assert!(glob_match(&g("**"), ""));
        assert!(glob_match(&g("**"), "a"));
        assert!(glob_match(&g("**"), "a/b/c"));
    }

    #[test]
    fn no_path_traversal() {
        // ValidatedGlob::parse rejects ".." at parse time
        assert!(ValidatedGlob::parse("foo/../bar").is_err());
        assert!(ValidatedGlob::parse("..").is_err());
        assert!(ValidatedGlob::parse("foo/..").is_err());
    }

    #[test]
    fn refs_pattern() {
        assert!(glob_match(&g("refs/heads/main"), "refs/heads/main"));
        assert!(glob_match(&g("refs/heads/*"), "refs/heads/feature-x"));
        assert!(glob_match(
            &g("refs/heads/release-*"),
            "refs/heads/release-v2"
        ));
        assert!(!glob_match(
            &g("refs/heads/release-*"),
            "refs/tags/release-v2"
        ));
    }

    #[test]
    fn refs_heads_all() {
        assert!(glob_match(&g("refs/heads/**"), "refs/heads/main"));
        assert!(glob_match(&g("refs/heads/**"), "refs/heads/feature/nested"));
        assert!(!glob_match(&g("refs/heads/**"), "refs/tags/v1"));
    }

    #[test]
    fn complex_patterns() {
        // Match any ref under refs/heads that starts with feature-
        assert!(glob_match(
            &g("refs/heads/feature-*"),
            "refs/heads/feature-123"
        ));
        assert!(!glob_match(
            &g("refs/heads/feature-*"),
            "refs/heads/bugfix-123"
        ));

        // Match any file under src/**/*.rs (but we only do path segments, not extensions)
        assert!(glob_match(&g("src/**"), "src/lib.rs"));
        assert!(glob_match(&g("src/**"), "src/policy/mod.rs"));
    }

    #[test]
    fn empty_pattern_after_normalization() {
        // Single slash normalizes to empty, which matches empty input
        // But ValidatedGlob rejects empty patterns, so this won't happen in practice
        // The pattern "/" normalizes to "" which would be rejected
    }

    #[test]
    fn pattern_longer_than_input() {
        assert!(!glob_match(&g("foo/bar/baz"), "foo/bar"));
    }

    #[test]
    fn input_longer_than_pattern() {
        assert!(!glob_match(&g("foo"), "foo/bar"));
    }

    #[test]
    fn multiple_double_stars() {
        assert!(glob_match(&g("**/**/foo"), "foo"));
        assert!(glob_match(&g("**/**/foo"), "a/foo"));
        assert!(glob_match(&g("**/**/foo"), "a/b/foo"));
    }
}
