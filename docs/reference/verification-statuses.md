# Verification Statuses

All verification functions return one of these status types.

## Status types

| Status | Description | Additional data |
|--------|-------------|-----------------|
| `Valid` | All checks passed | None |
| `Expired` | Attestation past `expires_at` | `at`: expiration timestamp |
| `Revoked` | Attestation has `revoked: true` | `at`: revocation timestamp (if available) |
| `InvalidSignature` | Signature verification failed | `step`: index in chain where failure occurred |
| `BrokenChain` | Chain has a gap | `missing_link`: DID of the missing link |

## By language

=== "Rust"

    ```rust
    match report.status {
        VerificationStatus::Valid => { /* ok */ }
        VerificationStatus::Expired { at } => { /* expired */ }
        VerificationStatus::Revoked { at } => { /* revoked */ }
        VerificationStatus::InvalidSignature { step } => { /* bad sig */ }
        VerificationStatus::BrokenChain { missing_link } => { /* gap */ }
    }
    ```

=== "Python"

    ```python
    if report.status.status_type == "Valid":
        pass
    elif report.status.status_type == "Expired":
        print(report.status.at)
    elif report.status.status_type == "InvalidSignature":
        print(report.status.step)
    ```

=== "TypeScript"

    ```typescript
    switch (report.status.type) {
      case "Valid": break;
      case "Expired": console.log(report.status.at); break;
      case "InvalidSignature": console.log(report.status.step); break;
      case "BrokenChain": console.log(report.status.missing_link); break;
    }
    ```

=== "Go"

    ```go
    switch report.Status {
    case verifier.StatusValid:
    case verifier.StatusExpired:
        fmt.Println(report.ExpiredAt)
    case verifier.StatusInvalidSignature:
        fmt.Println(report.FailedStep)
    case verifier.StatusBrokenChain:
        fmt.Println(report.MissingLink)
    }
    ```

=== "Swift"

    ```swift
    switch report.status {
    case .valid: break
    case .expired(let at): print(at)
    case .revoked(let at): print(at ?? "unknown")
    case .invalidSignature(let step): print(step)
    case .brokenChain(let link): print(link)
    }
    ```

## Verification report

A `VerificationReport` contains:

| Field | Type | Description |
|-------|------|-------------|
| `status` | `VerificationStatus` | Overall result |
| `chain` | `ChainLink[]` | Per-link verification details |
| `warnings` | `string[]` | Non-fatal warnings |

Each `ChainLink` contains:

| Field | Type | Description |
|-------|------|-------------|
| `issuer` | `string` | Issuer DID |
| `subject` | `string` | Subject DID |
| `valid` | `bool` | Whether this link passed |
| `error` | `string?` | Error message if failed |
