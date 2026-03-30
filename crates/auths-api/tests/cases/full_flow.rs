//! Full flow integration test: provision → authorize → revoke

use super::helpers::start_test_server;
use auths_sdk::domains::agents::{AuthorizeRequest, ProvisionRequest};
use auths_verifier::IdentityDID;
use chrono::Utc;

#[tokio::test]
async fn test_full_flow_provision_authorize_revoke() {
    let (base_url, client) = start_test_server().await;

    // ============================================================================
    // Step 1: Provision a root agent
    // ============================================================================
    #[allow(clippy::disallowed_methods)] // Test code calls Utc::now()
    let now = Utc::now();

    let provision_req = ProvisionRequest {
        delegator_did: None, // None = root agent
        agent_name: "test-agent".to_string(),
        capabilities: vec![], // Capabilities will be assigned by the handler
        ttl_seconds: 3600,
        max_delegation_depth: Some(2),
        signature: "test-sig-root".to_string(),
        timestamp: now,
    };

    let provision_resp = client
        .post(format!("{}/v1/agents", base_url))
        .json(&provision_req)
        .send()
        .await
        .expect("Provision request failed");

    assert_eq!(
        provision_resp.status(),
        201,
        "Provision should return 201 Created"
    );

    let provision_body: serde_json::Value = provision_resp
        .json()
        .await
        .expect("Failed to parse provision response");

    let agent_did_str = provision_body["agent_did"]
        .as_str()
        .expect("agent_did not in response")
        .to_string();

    let agent_did =
        IdentityDID::parse(&agent_did_str).expect("Failed to parse agent DID from response");

    // Note: bearer_token is None for now (TODO: generate JWT)
    let _bearer_token = provision_body["bearer_token"]
        .as_str()
        .or_else(|| provision_body["bearer_token"].as_null().map(|_| ""));

    // ============================================================================
    // Step 2: Authorize an operation with the agent
    // ============================================================================
    let auth_req = AuthorizeRequest {
        agent_did: agent_did.clone(),
        capability: "sign_commit".to_string(),
        signature: "test-sig-auth".to_string(),
        timestamp: now,
    };

    let auth_resp = client
        .post(format!("{}/v1/authorize", base_url))
        .json(&auth_req)
        .send()
        .await
        .expect("Authorize request failed");

    assert_eq!(auth_resp.status(), 200, "Authorize should return 200 OK");

    let auth_body: serde_json::Value = auth_resp
        .json()
        .await
        .expect("Failed to parse auth response");

    assert_eq!(
        auth_body["authorized"].as_bool(),
        Some(true),
        "Authorization should succeed for 'sign_commit' capability"
    );
    assert!(
        auth_body["matched_capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c.as_str() == Some("sign_commit")),
        "Should match 'sign_commit' capability"
    );

    // ============================================================================
    // Step 3: Try to authorize a capability the agent doesn't have (should fail)
    // ============================================================================
    let auth_req2 = AuthorizeRequest {
        agent_did: agent_did.clone(),
        capability: "sign_release".to_string(),
        signature: "test-sig-auth2".to_string(),
        timestamp: now,
    };

    let auth_resp2 = client
        .post(format!("{}/v1/authorize", base_url))
        .json(&auth_req2)
        .send()
        .await
        .expect("Authorize sign_release request failed");

    assert_eq!(
        auth_resp2.status(),
        403,
        "Should reject unauthorized capability"
    );

    // ============================================================================
    // Step 5: List agents (should show our agent)
    // ============================================================================
    let list_resp = client
        .get(format!("{}/v1/agents", base_url))
        .send()
        .await
        .expect("List request failed");

    assert_eq!(list_resp.status(), 200);
    let list_body: serde_json::Value = list_resp
        .json()
        .await
        .expect("Failed to parse list response");

    let agents = list_body["agents"].as_array().expect("agents not an array");
    assert!(
        agents
            .iter()
            .any(|a| a["agent_did"].as_str() == Some(agent_did.as_str())),
        "Agent should be in list"
    );
    assert_eq!(
        list_body["total"].as_i64(),
        Some(1),
        "Should have 1 agent in registry"
    );

    // ============================================================================
    // Step 6: Get specific agent details
    // ============================================================================
    let get_resp = client
        .get(format!("{}/v1/agents/{}", base_url, agent_did.as_str()))
        .send()
        .await
        .expect("Get agent request failed");

    assert_eq!(get_resp.status(), 200);
    let agent_details: serde_json::Value = get_resp
        .json()
        .await
        .expect("Failed to parse agent details");

    assert_eq!(
        agent_details["agent_did"].as_str(),
        Some(agent_did_str.as_str())
    );
    assert_eq!(agent_details["agent_name"].as_str(), Some("test-agent"));
    assert_eq!(agent_details["status"].as_str(), Some("Active"));

    // ============================================================================
    // Step 7: Revoke the agent
    // ============================================================================
    let revoke_resp = client
        .delete(format!("{}/v1/agents/{}", base_url, agent_did.as_str()))
        .send()
        .await
        .expect("Revoke request failed");

    assert_eq!(
        revoke_resp.status(),
        204,
        "Revoke should return 204 No Content"
    );

    // ============================================================================
    // Step 8: Verify agent is revoked (authorization should fail)
    // ============================================================================
    let auth_after_revoke = AuthorizeRequest {
        agent_did: agent_did.clone(),
        capability: "sign_commit".to_string(),
        signature: "test-sig-after-revoke".to_string(),
        timestamp: now,
    };

    let auth_revoked_resp = client
        .post(format!("{}/v1/authorize", base_url))
        .json(&auth_after_revoke)
        .send()
        .await
        .expect("Authorize after revoke request failed");

    assert_eq!(
        auth_revoked_resp.status(),
        401,
        "Should reject revoked agent"
    );

    // ============================================================================
    // Step 9: Verify agent is gone from list
    // ============================================================================
    let list_after_revoke = client
        .get(format!("{}/v1/agents", base_url))
        .send()
        .await
        .expect("List after revoke request failed");

    assert_eq!(list_after_revoke.status(), 200);
    let list_body_after: serde_json::Value = list_after_revoke
        .json()
        .await
        .expect("Failed to parse list response");

    let agents_after = list_body_after["agents"]
        .as_array()
        .expect("agents not an array");
    assert!(
        !agents_after
            .iter()
            .any(|a| a["agent_did"].as_str() == Some(agent_did_str.as_str())),
        "Revoked agent should not be in list"
    );
    assert_eq!(
        list_body_after["total"].as_i64(),
        Some(0),
        "Should have 0 agents after revoke"
    );
}
