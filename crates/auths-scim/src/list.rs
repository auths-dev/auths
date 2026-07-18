//! SCIM 2.0 ListResponse (RFC 7644 Section 3.4.2).

use serde::{Deserialize, Serialize};

use crate::constants::SCHEMA_LIST_RESPONSE;

/// Maximum number of resources a single SCIM list page may return. RFC 7644 §3.4.2.4 lets a
/// server impose its own maximum on the client's `count`; this bounds the page so a client
/// cannot force the whole tenant to be materialized into one response.
pub const MAX_LIST_COUNT: u64 = 200;

/// Resolve the effective page size from a client's requested `count`, bounded by
/// [`MAX_LIST_COUNT`]. An absent `count` defaults to the maximum; a larger request is clamped
/// down to it. The result is a `usize` ready to pass to `Iterator::take`.
///
/// Args:
/// * `requested`: the client's `count` query parameter, if any.
///
/// Usage:
/// ```
/// use auths_scim::list::clamp_list_count;
/// assert_eq!(clamp_list_count(Some(10_000)), 200);
/// assert_eq!(clamp_list_count(Some(50)), 50);
/// ```
pub fn clamp_list_count(requested: Option<u64>) -> usize {
    requested.unwrap_or(MAX_LIST_COUNT).min(MAX_LIST_COUNT) as usize
}

/// SCIM 2.0 ListResponse container (RFC 7644 Section 3.4.2).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ScimListResponse<T> {
    pub schemas: Vec<String>,
    pub total_results: u64,
    pub start_index: u64,
    pub items_per_page: u64,
    #[serde(rename = "Resources")]
    pub resources: Vec<T>,
}

impl<T> ScimListResponse<T> {
    /// Create a list response with the standard schema.
    pub fn new(resources: Vec<T>, total_results: u64, start_index: u64) -> Self {
        let items_per_page = resources.len() as u64;
        Self {
            schemas: vec![SCHEMA_LIST_RESPONSE.into()],
            total_results,
            start_index,
            items_per_page,
            resources,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn serde_roundtrip() {
        let response = ScimListResponse::new(vec!["a".to_string(), "b".to_string()], 10, 1);
        let json = serde_json::to_string(&response).unwrap();
        let parsed: ScimListResponse<String> = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, response);
    }

    #[test]
    fn items_per_page_matches_resources() {
        let response = ScimListResponse::new(vec![1, 2, 3], 100, 1);
        assert_eq!(response.items_per_page, 3);
    }

    #[test]
    fn uppercase_resources_key() {
        let response: ScimListResponse<String> = ScimListResponse::new(vec![], 0, 1);
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"Resources\""));
    }

    #[test]
    fn count_is_bounded_by_the_server_maximum() {
        // An unbounded or oversized `count` is clamped to the server maximum so a single list
        // request cannot materialize the whole tenant.
        assert_eq!(clamp_list_count(Some(u64::MAX)), MAX_LIST_COUNT as usize);
        assert_eq!(clamp_list_count(Some(10_000)), MAX_LIST_COUNT as usize);
        assert_eq!(clamp_list_count(None), MAX_LIST_COUNT as usize);
    }

    #[test]
    fn count_below_the_maximum_is_honored() {
        assert_eq!(clamp_list_count(Some(50)), 50);
        assert_eq!(clamp_list_count(Some(0)), 0);
    }
}
