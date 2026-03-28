/// GitHub Actions OIDC token acquisition.
///
/// # Usage
///
/// ```ignore
/// let token = github_actions_oidc_token().await?;
/// ```
#[allow(clippy::disallowed_methods)] // CI platform boundary: GitHub Actions env vars
pub async fn github_actions_oidc_token() -> Result<String, String> {
    let actions_id_token_url = std::env::var("ACTIONS_ID_TOKEN_REQUEST_URL").map_err(|_| {
        "ACTIONS_ID_TOKEN_REQUEST_URL not set (not running in GitHub Actions)".to_string()
    })?;

    let actions_id_token_request_token =
        std::env::var("ACTIONS_ID_TOKEN_REQUEST_TOKEN").map_err(|_| {
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN not set (not running in GitHub Actions)".to_string()
        })?;

    let client = crate::default_http_client();

    let response = client
        .get(&actions_id_token_url)
        .bearer_auth(&actions_id_token_request_token)
        .send()
        .await
        .map_err(|e| format!("failed to acquire GitHub Actions OIDC token: {}", e))?;

    let json: serde_json::Value = response
        .json()
        .await
        .map_err(|e| format!("failed to parse GitHub Actions token response: {}", e))?;

    json.get("token")
        .and_then(|t| t.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| "GitHub Actions token response missing 'token' field".to_string())
}

/// GitLab CI OIDC token acquisition.
///
/// # Usage
///
/// ```ignore
/// let token = gitlab_ci_oidc_token().await?;
/// ```
#[allow(clippy::disallowed_methods)] // CI platform boundary: GitLab env vars
pub async fn gitlab_ci_oidc_token() -> Result<String, String> {
    let ci_job_jwt_v2 = std::env::var("CI_JOB_JWT_V2")
        .map_err(|_| "CI_JOB_JWT_V2 not set (not running in GitLab CI)".to_string())?;

    Ok(ci_job_jwt_v2)
}

/// CircleCI OIDC token acquisition.
///
/// # Usage
///
/// ```ignore
/// let token = circleci_oidc_token().await?;
/// ```
#[allow(clippy::disallowed_methods)] // CI platform boundary: CircleCI env vars
pub async fn circleci_oidc_token() -> Result<String, String> {
    let circle_oidc_token = std::env::var("CIRCLE_OIDC_TOKEN")
        .map_err(|_| "CIRCLE_OIDC_TOKEN not set (not running in CircleCI)".to_string())?;

    Ok(circle_oidc_token)
}

/// Normalize platform-specific OIDC claims to a standard WorkloadIdentity format.
///
/// Maps GitHub Actions, GitLab CI, and CircleCI claims to common fields:
/// - repository/project name
/// - actor/user identifier
/// - workflow/pipeline identifier
/// - job identifier
pub fn normalize_workload_claims(
    platform: &str,
    claims: serde_json::Value,
) -> Result<serde_json::Map<String, serde_json::Value>, String> {
    let mut normalized = serde_json::Map::new();

    match platform {
        "github" => {
            // GitHub Actions standard claims
            if let Some(repo) = claims.get("repository").and_then(|v| v.as_str()) {
                normalized.insert(
                    "repository".to_string(),
                    serde_json::Value::String(repo.to_string()),
                );
            }
            if let Some(actor) = claims.get("actor").and_then(|v| v.as_str()) {
                normalized.insert(
                    "actor".to_string(),
                    serde_json::Value::String(actor.to_string()),
                );
            }
            if let Some(workflow) = claims.get("workflow").and_then(|v| v.as_str()) {
                normalized.insert(
                    "workflow".to_string(),
                    serde_json::Value::String(workflow.to_string()),
                );
            }
            if let Some(job_workflow_ref) = claims.get("job_workflow_ref").and_then(|v| v.as_str())
            {
                normalized.insert(
                    "job_workflow_ref".to_string(),
                    serde_json::Value::String(job_workflow_ref.to_string()),
                );
            }
            if let Some(run_id) = claims.get("run_id").and_then(|v| v.as_str()) {
                normalized.insert(
                    "run_id".to_string(),
                    serde_json::Value::String(run_id.to_string()),
                );
            }
            if let Some(run_number) = claims.get("run_number").and_then(|v| v.as_str()) {
                normalized.insert(
                    "run_number".to_string(),
                    serde_json::Value::String(run_number.to_string()),
                );
            }
            Ok(normalized)
        }
        "gitlab" => {
            // GitLab CI ID token claims
            if let Some(project_id) = claims.get("project_id").and_then(|v| v.as_i64()) {
                normalized.insert(
                    "project_id".to_string(),
                    serde_json::Value::Number(project_id.into()),
                );
            }
            if let Some(project_path) = claims.get("project_path").and_then(|v| v.as_str()) {
                normalized.insert(
                    "project_path".to_string(),
                    serde_json::Value::String(project_path.to_string()),
                );
            }
            if let Some(user_id) = claims.get("user_id").and_then(|v| v.as_i64()) {
                normalized.insert(
                    "user_id".to_string(),
                    serde_json::Value::Number(user_id.into()),
                );
            }
            if let Some(user_login) = claims.get("user_login").and_then(|v| v.as_str()) {
                normalized.insert(
                    "user_login".to_string(),
                    serde_json::Value::String(user_login.to_string()),
                );
            }
            if let Some(pipeline_id) = claims.get("pipeline_id").and_then(|v| v.as_i64()) {
                normalized.insert(
                    "pipeline_id".to_string(),
                    serde_json::Value::Number(pipeline_id.into()),
                );
            }
            if let Some(job_id) = claims.get("job_id").and_then(|v| v.as_i64()) {
                normalized.insert(
                    "job_id".to_string(),
                    serde_json::Value::Number(job_id.into()),
                );
            }
            Ok(normalized)
        }
        "circleci" => {
            // CircleCI OIDC token claims
            if let Some(project_id) = claims.get("project_id").and_then(|v| v.as_str()) {
                normalized.insert(
                    "project_id".to_string(),
                    serde_json::Value::String(project_id.to_string()),
                );
            }
            if let Some(project_name) = claims.get("project_name").and_then(|v| v.as_str()) {
                normalized.insert(
                    "project_name".to_string(),
                    serde_json::Value::String(project_name.to_string()),
                );
            }
            if let Some(workflow_id) = claims.get("workflow_id").and_then(|v| v.as_str()) {
                normalized.insert(
                    "workflow_id".to_string(),
                    serde_json::Value::String(workflow_id.to_string()),
                );
            }
            if let Some(job_number) = claims.get("job_number").and_then(|v| v.as_str()) {
                normalized.insert(
                    "job_number".to_string(),
                    serde_json::Value::String(job_number.to_string()),
                );
            }
            if let Some(org_id) = claims.get("org_id").and_then(|v| v.as_str()) {
                normalized.insert(
                    "org_id".to_string(),
                    serde_json::Value::String(org_id.to_string()),
                );
            }
            Ok(normalized)
        }
        _ => Err(format!("unknown OIDC platform: {}", platform)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_github_claims() {
        let claims = serde_json::json!({
            "repository": "owner/repo",
            "actor": "github-user",
            "workflow": "test.yml",
            "job_workflow_ref": "owner/repo/.github/workflows/test.yml@main",
            "run_id": "12345",
            "run_number": "1"
        });

        let result = normalize_workload_claims("github", claims);
        assert!(result.is_ok());
        let normalized = result.unwrap();
        assert_eq!(
            normalized.get("repository").and_then(|v| v.as_str()),
            Some("owner/repo")
        );
        assert_eq!(
            normalized.get("actor").and_then(|v| v.as_str()),
            Some("github-user")
        );
    }

    #[test]
    fn test_normalize_gitlab_claims() {
        let claims = serde_json::json!({
            "project_id": 123,
            "project_path": "group/project",
            "user_id": 456,
            "user_login": "gitlab-user",
            "pipeline_id": 789,
            "job_id": 999
        });

        let result = normalize_workload_claims("gitlab", claims);
        assert!(result.is_ok());
        let normalized = result.unwrap();
        assert_eq!(
            normalized.get("project_path").and_then(|v| v.as_str()),
            Some("group/project")
        );
    }

    #[test]
    fn test_normalize_circleci_claims() {
        let claims = serde_json::json!({
            "project_id": "abc123",
            "project_name": "my-project",
            "workflow_id": "def456",
            "job_number": "1",
            "org_id": "ghi789"
        });

        let result = normalize_workload_claims("circleci", claims);
        assert!(result.is_ok());
        let normalized = result.unwrap();
        assert_eq!(
            normalized.get("project_name").and_then(|v| v.as_str()),
            Some("my-project")
        );
    }

    #[test]
    fn test_unknown_platform() {
        let claims = serde_json::json!({});
        let result = normalize_workload_claims("unknown", claims);
        assert!(result.is_err());
    }
}
