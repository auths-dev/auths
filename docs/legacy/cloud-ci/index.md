# Cloud & CI

Connect Auths identities to cloud IAM and CI/CD pipelines.

## The Problem

Cloud providers (AWS, GCP, Azure) use OIDC for workload identity federation. KERI uses Ed25519 attestation chains. These two systems don't speak the same language.

The **OIDC Bridge** solves this by translating KERI attestation chains into RS256 JWTs that cloud providers accept. This lets your CI pipelines and services authenticate to cloud resources using their Auths identity -- no long-lived access keys needed.

## Sections

- **[OIDC Bridge API](oidc-bridge-api.md)** -- Endpoints, request/response schemas, and configuration for the `auths-oidc-bridge`.

- **[AWS Integration](aws-integration.md)** -- Set up IAM OIDC providers, trust policies, and roles. Includes Terraform and CloudFormation templates.

- **[GitHub Actions OIDC](github-actions-oidc.md)** -- Use GitHub Actions workload identity with the OIDC Bridge for two-factor proof (KERI + GitHub).

- **[CI Verification](ci-verification.md)** -- Verify commit signatures in CI pipelines using the Python, JavaScript, or CLI SDKs.

- **[Enterprise Security](enterprise-security.md)** -- STRIDE threat model, key rotation procedures, deployment topology, and incident response for the OIDC Bridge.

- **[Dynamic Client Registration](dynamic-client-registration.md)** -- RFC 7591 endpoint for microservices to self-register as OIDC clients using KERI capability receipts.
