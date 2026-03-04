# OIDC Bridge Integration Tests

## Quick Start (unit tests)

```bash
cargo nextest run -p auths-oidc-bridge
```

All non-`#[ignore]` tests run against the in-process bridge and require no external services.

## Cloud Provider E2E Tests

The `#[ignore]` tests validate token exchange against real cloud providers. Run them with:

```bash
cargo nextest run -p auths-oidc-bridge -- --ignored
```

Each provider requires specific environment variables and cloud-side configuration.

---

### AWS STS

**Environment variables:**

| Variable | Description |
|---|---|
| `AWS_ROLE_ARN` | IAM role ARN to assume |
| `AUTHS_BRIDGE_URL` | Deployed bridge base URL (HTTPS) |
| `AWS_ACCESS_KEY_ID` | AWS credentials (or use default chain) |
| `AWS_SECRET_ACCESS_KEY` | AWS credentials |

**Cloud setup:**

1. Deploy the OIDC bridge with a stable HTTPS URL
2. Create an IAM OIDC Identity Provider pointing to the bridge's issuer URL
3. Create an IAM role with a trust policy:
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [{
       "Effect": "Allow",
       "Principal": { "Federated": "arn:aws:iam::ACCOUNT:oidc-provider/YOUR_BRIDGE_HOST" },
       "Action": "sts:AssumeRoleWithWebIdentity",
       "Condition": {
         "StringEquals": {
           "YOUR_BRIDGE_HOST:aud": "sts.amazonaws.com"
         }
       }
     }]
   }
   ```

**LocalStack (offline):**

```bash
LOCALSTACK_URL=http://localhost:4566 cargo nextest run -p auths-oidc-bridge -- test_aws_sts_localstack --ignored
```

LocalStack does not validate JWT signatures. This test only verifies STS request/response parsing.

---

### GCP Workload Identity Federation

**Environment variables:**

| Variable | Description |
|---|---|
| `GCP_PROJECT_NUMBER` | Numeric GCP project number |
| `GCP_POOL_ID` | Workload Identity Pool ID |
| `GCP_PROVIDER_ID` | Workload Identity Pool Provider ID |
| `AUTHS_BRIDGE_URL` | Deployed bridge base URL (HTTPS) |

**Cloud setup:**

1. Deploy the OIDC bridge with a stable HTTPS URL
2. Create a Workload Identity Pool:
   ```bash
   gcloud iam workload-identity-pools create auths-pool \
     --location=global \
     --display-name="Auths Bridge Pool"
   ```
3. Create a Provider in the pool:
   ```bash
   gcloud iam workload-identity-pools providers create-oidc auths-provider \
     --location=global \
     --workload-identity-pool=auths-pool \
     --issuer-uri="https://YOUR_BRIDGE_HOST" \
     --allowed-audiences="https://iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/auths-pool/providers/auths-provider" \
     --attribute-mapping="google.subject=assertion.sub"
   ```
4. Grant the workload identity access to GCP resources via IAM bindings

---

### Azure AD Workload Identity

**Environment variables:**

| Variable | Description |
|---|---|
| `AZURE_TENANT_ID` | Azure AD tenant ID |
| `AZURE_CLIENT_ID` | App registration client ID |
| `AUTHS_BRIDGE_URL` | Deployed bridge base URL (HTTPS) |

**Cloud setup:**

1. Deploy the OIDC bridge with a stable HTTPS URL
2. Create an Azure AD app registration
3. Add a federated credential:
   - Issuer: `https://YOUR_BRIDGE_HOST`
   - Subject: The KERI DID that will be the JWT `sub` claim
   - Audience: The app registration's client ID (or `api://CLIENT_ID`)
4. The bridge's JWKS endpoint (`/.well-known/jwks.json`) must be reachable from Azure AD

---

## Test Architecture

```
tests/
├── cases/
│   ├── mod.rs          # Module declarations
│   ├── helpers.rs      # Shared test utilities (app builders, attestation signing)
│   ├── oidc.rs         # Unit/integration tests (run without external services)
│   ├── aws.rs          # AWS STS e2e tests (#[ignore])
│   ├── gcp.rs          # GCP Workload Identity e2e tests (#[ignore])
│   └── azure.rs        # Azure AD e2e tests (#[ignore])
└── README.md           # This file
```

The `mint_jwt_from_bridge()` helper in `helpers.rs` supports both modes:
- **In-process**: Uses `test_app()` when `AUTHS_BRIDGE_URL` is not set
- **Deployed**: Sends real HTTP requests when `AUTHS_BRIDGE_URL` is set
