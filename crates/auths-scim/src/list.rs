//! SCIM 2.0 ListResponse (RFC 7644 Section 3.4.2).

use serde::{Deserialize, Serialize};

use crate::constants::SCHEMA_LIST_RESPONSE;

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
}
