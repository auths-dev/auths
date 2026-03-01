# Server Verification

Verify attestation chains in a backend service.

## Rust

```rust
use auths_verifier::{Attestation, verify_with_keys, verify_chain};

// Load attestation from request body
let att: Attestation = Attestation::from_json(request_body)?;

// Verify against known issuer key
let issuer_pk = hex::decode(&config.trusted_issuer_pk)?;
verify_with_keys(&att, &issuer_pk)?;

// Or verify a chain
let attestations: Vec<Attestation> = load_chain_from_request()?;
let report = verify_chain(&attestations)?;

match report.status {
    VerificationStatus::Valid => {
        // Proceed with authenticated request
    }
    _ => {
        return Err(AuthError::InvalidAttestation);
    }
}
```

## Python (Flask)

```python
from flask import Flask, request, jsonify
from auths_verifier import verify_attestation

app = Flask(__name__)
TRUSTED_PK = "aabbccdd..."  # Your trusted root public key

@app.route("/api/protected", methods=["POST"])
def protected():
    att_json = request.headers.get("X-Auths-Attestation")
    if not att_json:
        return jsonify({"error": "Missing attestation"}), 401

    result = verify_attestation(att_json, TRUSTED_PK)
    if not result.valid:
        return jsonify({"error": f"Invalid: {result.error}"}), 403

    return jsonify({"message": "Authenticated"})
```

## Go (HTTP middleware)

```go
func authsMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        attJSON := r.Header.Get("X-Auths-Attestation")
        if attJSON == "" {
            http.Error(w, "Missing attestation", http.StatusUnauthorized)
            return
        }

        result := verifier.VerifyAttestationHex(attJSON, trustedPKHex)
        if !result.Valid {
            http.Error(w, "Invalid attestation", http.StatusForbidden)
            return
        }

        next.ServeHTTP(w, r)
    })
}
```

## Key management for servers

The server needs to know the **trusted root public key**. Options:

1. **Environment variable**: `AUTHS_TRUSTED_PK=aabbccdd...`
2. **Config file**: Store in your application's config
3. **Allowed-signers file**: For multiple trusted identities

The server never needs a private key -- it only verifies.
