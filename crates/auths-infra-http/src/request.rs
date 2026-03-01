use auths_core::ports::network::NetworkError;

use crate::error::{map_reqwest_error, map_status_error};

pub(crate) fn build_get_request(client: &reqwest::Client, url: &str) -> reqwest::RequestBuilder {
    client.get(url)
}

pub(crate) fn build_post_request(
    client: &reqwest::Client,
    url: &str,
    body: Vec<u8>,
) -> reqwest::RequestBuilder {
    client
        .post(url)
        .header("Content-Type", "application/octet-stream")
        .body(body)
}

pub(crate) async fn execute_request(
    request: reqwest::RequestBuilder,
    endpoint: &str,
) -> Result<reqwest::Response, NetworkError> {
    request
        .send()
        .await
        .map_err(|e| map_reqwest_error(e, endpoint))
}

pub(crate) async fn parse_response_bytes(
    response: reqwest::Response,
    resource: &str,
) -> Result<Vec<u8>, NetworkError> {
    let status = response.status().as_u16();
    if !response.status().is_success() {
        return Err(map_status_error(status, resource));
    }
    response
        .bytes()
        .await
        .map(|b| b.to_vec())
        .map_err(|e| NetworkError::InvalidResponse {
            detail: e.to_string(),
        })
}

pub(crate) async fn parse_response_json<T: serde::de::DeserializeOwned>(
    response: reqwest::Response,
    resource: &str,
) -> Result<T, NetworkError> {
    let status = response.status().as_u16();
    if !response.status().is_success() {
        return Err(map_status_error(status, resource));
    }
    let bytes = response
        .bytes()
        .await
        .map_err(|e| NetworkError::InvalidResponse {
            detail: e.to_string(),
        })?;
    serde_json::from_slice(&bytes).map_err(|e| NetworkError::InvalidResponse {
        detail: e.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_get_creates_get_request() {
        let client = reqwest::Client::new();
        let req = build_get_request(&client, "https://example.com/test");
        let built = req.build().unwrap();
        assert_eq!(built.method(), reqwest::Method::GET);
        assert_eq!(built.url().as_str(), "https://example.com/test");
    }

    #[test]
    fn build_post_creates_post_with_body() {
        let client = reqwest::Client::new();
        let req = build_post_request(&client, "https://example.com/submit", b"data".to_vec());
        let built = req.build().unwrap();
        assert_eq!(built.method(), reqwest::Method::POST);
        assert_eq!(
            built.headers().get("Content-Type").unwrap(),
            "application/octet-stream"
        );
    }
}
