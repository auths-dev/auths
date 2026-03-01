// Package verifier provides Go bindings for the Auths attestation verification library.
//
// This package wraps the Rust auths-verifier library via CGo, providing a type-safe
// Go API for verifying attestations.
//
// # Basic Usage
//
//	result := verifier.VerifyAttestation(attestationJSON, issuerPublicKeyBytes)
//	if result.Valid {
//		fmt.Println("Attestation verified!")
//	}
//
// # Building
//
// Before using this package, you need to build the native library:
//
//	cd packages/auths-verifier-go
//	./build.sh
//
// Then set CGO_LDFLAGS to point to the library:
//
//	export CGO_LDFLAGS="-L/path/to/auths/target/release -lauths_verifier"
package verifier

/*
#cgo LDFLAGS: -lauths_verifier
#include <stdint.h>
#include <stdlib.h>

// C FFI declarations - must match ffi.rs
#define VERIFY_SUCCESS 0
#define ERR_VERIFY_NULL_ARGUMENT -1
#define ERR_VERIFY_JSON_PARSE -2
#define ERR_VERIFY_INVALID_PK_LEN -3
#define ERR_VERIFY_ISSUER_SIG_FAIL -4
#define ERR_VERIFY_DEVICE_SIG_FAIL -5
#define ERR_VERIFY_EXPIRED -6
#define ERR_VERIFY_REVOKED -7
#define ERR_VERIFY_SERIALIZATION -8
#define ERR_VERIFY_OTHER -99

extern int ffi_verify_attestation_json(
    const uint8_t* attestation_json_ptr,
    size_t attestation_json_len,
    const uint8_t* issuer_pk_ptr,
    size_t issuer_pk_len
);
*/
import "C"
import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
	"unsafe"
)

// Error codes returned by the FFI layer
const (
	VerifySuccess        = 0
	ErrNullArgument      = -1
	ErrJSONParse         = -2
	ErrInvalidPKLen      = -3
	ErrIssuerSigFail     = -4
	ErrDeviceSigFail     = -5
	ErrExpired           = -6
	ErrRevoked           = -7
	ErrSerialization     = -8
	ErrOther             = -99
)

// JSON input size limits (must match Rust constants in core.rs)
const (
	MaxAttestationJSONSize = 64 * 1024       // 64 KiB per single attestation
	MaxJSONBatchSize       = 1024 * 1024     // 1 MiB for arrays of attestations
)

// Common errors
var (
	ErrNullPointer        = errors.New("null pointer argument")
	ErrInvalidJSON        = errors.New("invalid attestation JSON")
	ErrInvalidPublicKey   = errors.New("invalid public key length (expected 32 bytes)")
	ErrIssuerSignature    = errors.New("issuer signature verification failed")
	ErrDeviceSignature    = errors.New("device signature verification failed")
	ErrAttestationExpired = errors.New("attestation has expired")
	ErrAttestationRevoked = errors.New("attestation has been revoked")
	ErrSerializationFailed = errors.New("serialization error")
	ErrVerificationFailed = errors.New("verification failed")
	ErrInputTooLarge      = errors.New("JSON input too large")
)

// VerificationResult contains the result of an attestation verification.
type VerificationResult struct {
	Valid bool
	Error error
}

// VerificationStatus represents the status of a verification operation.
type VerificationStatus int

const (
	StatusValid VerificationStatus = iota
	StatusExpired
	StatusRevoked
	StatusInvalidSignature
	StatusBrokenChain
)

func (s VerificationStatus) String() string {
	switch s {
	case StatusValid:
		return "Valid"
	case StatusExpired:
		return "Expired"
	case StatusRevoked:
		return "Revoked"
	case StatusInvalidSignature:
		return "InvalidSignature"
	case StatusBrokenChain:
		return "BrokenChain"
	default:
		return "Unknown"
	}
}

// ChainLink represents a single link in an attestation chain.
type ChainLink struct {
	Issuer  string
	Subject string
	Valid   bool
	Error   string
}

// VerificationReport contains detailed verification results.
type VerificationReport struct {
	Status   VerificationStatus
	Chain    []ChainLink
	Warnings []string

	// Additional details for specific statuses
	ExpiredAt  *time.Time // Set when Status == StatusExpired
	RevokedAt  *time.Time // Set when Status == StatusRevoked
	FailedStep int        // Set when Status == StatusInvalidSignature
	MissingLink string    // Set when Status == StatusBrokenChain
}

// IsValid returns true if the verification succeeded.
func (r *VerificationReport) IsValid() bool {
	return r.Status == StatusValid
}

// VerifyAttestation verifies a single attestation against an issuer's public key.
//
// Parameters:
//   - attestationJSON: The attestation as a JSON byte slice
//   - issuerPK: The issuer's Ed25519 public key (32 bytes)
//
// Returns:
//   - VerificationResult with Valid=true on success, or Error set on failure
//
// Example:
//
//	result := verifier.VerifyAttestation([]byte(attestationJSON), issuerPKBytes)
//	if result.Valid {
//		fmt.Println("Attestation is valid!")
//	} else {
//		fmt.Printf("Verification failed: %v\n", result.Error)
//	}
func VerifyAttestation(attestationJSON []byte, issuerPK []byte) VerificationResult {
	if len(attestationJSON) == 0 {
		return VerificationResult{Valid: false, Error: ErrInvalidJSON}
	}
	if len(attestationJSON) > MaxAttestationJSONSize {
		return VerificationResult{Valid: false, Error: fmt.Errorf("%w: %d bytes, max %d", ErrInputTooLarge, len(attestationJSON), MaxAttestationJSONSize)}
	}
	if len(issuerPK) != 32 {
		return VerificationResult{Valid: false, Error: ErrInvalidPublicKey}
	}

	// Get pointers to the data
	jsonPtr := (*C.uint8_t)(unsafe.Pointer(&attestationJSON[0]))
	jsonLen := C.size_t(len(attestationJSON))
	pkPtr := (*C.uint8_t)(unsafe.Pointer(&issuerPK[0]))
	pkLen := C.size_t(len(issuerPK))

	// Call the FFI function
	result := C.ffi_verify_attestation_json(jsonPtr, jsonLen, pkPtr, pkLen)

	// Convert result to Go error
	switch result {
	case VerifySuccess:
		return VerificationResult{Valid: true, Error: nil}
	case ErrNullArgument:
		return VerificationResult{Valid: false, Error: ErrNullPointer}
	case ErrJSONParse:
		return VerificationResult{Valid: false, Error: ErrInvalidJSON}
	case ErrInvalidPKLen:
		return VerificationResult{Valid: false, Error: ErrInvalidPublicKey}
	case ErrIssuerSigFail:
		return VerificationResult{Valid: false, Error: ErrIssuerSignature}
	case ErrDeviceSigFail:
		return VerificationResult{Valid: false, Error: ErrDeviceSignature}
	case ErrExpired:
		return VerificationResult{Valid: false, Error: ErrAttestationExpired}
	case ErrRevoked:
		return VerificationResult{Valid: false, Error: ErrAttestationRevoked}
	case ErrSerialization:
		return VerificationResult{Valid: false, Error: ErrSerializationFailed}
	default:
		return VerificationResult{Valid: false, Error: fmt.Errorf("%w (code: %d)", ErrVerificationFailed, result)}
	}
}

// VerifyAttestationHex verifies a single attestation using hex-encoded public key.
//
// This is a convenience wrapper around VerifyAttestation that accepts a hex string
// for the public key instead of raw bytes.
//
// Parameters:
//   - attestationJSON: The attestation as a JSON string
//   - issuerPKHex: The issuer's Ed25519 public key as a hex string (64 chars)
//
// Example:
//
//	result := verifier.VerifyAttestationHex(attestationJSON, "abcd1234...")
func VerifyAttestationHex(attestationJSON string, issuerPKHex string) VerificationResult {
	pkBytes, err := hex.DecodeString(issuerPKHex)
	if err != nil {
		return VerificationResult{Valid: false, Error: fmt.Errorf("invalid hex public key: %w", err)}
	}
	return VerifyAttestation([]byte(attestationJSON), pkBytes)
}

// Attestation represents an Auths attestation for Go-side chain verification.
// This mirrors the Rust Attestation struct for local verification logic.
type Attestation struct {
	Version           int        `json:"version"`
	RID               string     `json:"rid"`
	Issuer            string     `json:"issuer"`
	Subject           string     `json:"subject"`
	DevicePublicKey   []byte     `json:"device_public_key"`
	IdentitySignature []byte     `json:"identity_signature"`
	DeviceSignature   []byte     `json:"device_signature"`
	RevokedAt         *time.Time `json:"revoked_at,omitempty"`
	ExpiresAt         *time.Time `json:"expires_at,omitempty"`
	Timestamp         *time.Time `json:"timestamp,omitempty"`
	Note              *string    `json:"note,omitempty"`
	Payload           any        `json:"payload,omitempty"`
}

// VerifyChain verifies a chain of attestations from root to leaf.
//
// Parameters:
//   - attestationsJSON: List of attestation JSON byte slices
//   - rootPK: The root identity's Ed25519 public key (32 bytes)
//
// Returns a VerificationReport with per-link details.
//
// Example:
//
//	report := verifier.VerifyChain([][]byte{att1JSON, att2JSON}, rootPKBytes)
//	if report.IsValid() {
//		fmt.Println("Chain verified!")
//	}
func VerifyChain(attestationsJSON [][]byte, rootPK []byte) VerificationReport {
	total := 0
	for _, b := range attestationsJSON {
		total += len(b)
	}
	if total > MaxJSONBatchSize {
		return VerificationReport{
			Status:      StatusBrokenChain,
			Warnings:    []string{fmt.Sprintf("Total JSON too large: %d bytes, max %d", total, MaxJSONBatchSize)},
			MissingLink: "input too large",
		}
	}

	if len(rootPK) != 32 {
		return VerificationReport{
			Status:   StatusInvalidSignature,
			Chain:    nil,
			Warnings: []string{"Invalid root public key length"},
		}
	}

	// Handle empty chain
	if len(attestationsJSON) == 0 {
		return VerificationReport{
			Status:      StatusBrokenChain,
			Chain:       nil,
			MissingLink: "empty chain",
		}
	}

	chain := make([]ChainLink, 0, len(attestationsJSON))
	currentPK := rootPK

	for i, attJSON := range attestationsJSON {
		// Parse the attestation
		var att Attestation
		if err := json.Unmarshal(attJSON, &att); err != nil {
			return VerificationReport{
				Status: StatusBrokenChain,
				Chain:  chain,
				Warnings: []string{fmt.Sprintf("Failed to parse attestation %d: %v", i, err)},
				MissingLink: fmt.Sprintf("parse error at step %d", i),
			}
		}

		link := ChainLink{
			Issuer:  att.Issuer,
			Subject: att.Subject,
		}

		// Check chain linkage (except for first attestation)
		if i > 0 {
			prevJSON := attestationsJSON[i-1]
			var prevAtt Attestation
			if err := json.Unmarshal(prevJSON, &prevAtt); err == nil {
				if att.Issuer != prevAtt.Subject {
					link.Valid = false
					link.Error = fmt.Sprintf("Chain broken: expected issuer '%s', got '%s'", prevAtt.Subject, att.Issuer)
					chain = append(chain, link)
					return VerificationReport{
						Status:      StatusBrokenChain,
						Chain:       chain,
						MissingLink: fmt.Sprintf("Issuer mismatch at step %d", i),
					}
				}
			}
		}

		// Check revocation
		if att.RevokedAt != nil {
			link.Valid = false
			link.Error = "Attestation revoked"
			chain = append(chain, link)
			return VerificationReport{
				Status: StatusRevoked,
				Chain:  chain,
			}
		}

		// Check expiration
		if att.ExpiresAt != nil && time.Now().After(*att.ExpiresAt) {
			link.Valid = false
			link.Error = fmt.Sprintf("Attestation expired on %s", att.ExpiresAt.Format(time.RFC3339))
			chain = append(chain, link)
			expiredAt := *att.ExpiresAt
			return VerificationReport{
				Status:    StatusExpired,
				Chain:     chain,
				ExpiredAt: &expiredAt,
			}
		}

		// Verify the signature using FFI
		result := VerifyAttestation(attJSON, currentPK)
		if !result.Valid {
			link.Valid = false
			link.Error = result.Error.Error()
			chain = append(chain, link)
			return VerificationReport{
				Status:     StatusInvalidSignature,
				Chain:      chain,
				FailedStep: i,
			}
		}

		link.Valid = true
		chain = append(chain, link)

		// The next attestation's issuer key is this attestation's device public key
		currentPK = att.DevicePublicKey
	}

	return VerificationReport{
		Status: StatusValid,
		Chain:  chain,
	}
}

// VerifyChainHex is a convenience wrapper around VerifyChain that accepts
// hex-encoded public key.
func VerifyChainHex(attestationsJSON []string, rootPKHex string) VerificationReport {
	pkBytes, err := hex.DecodeString(rootPKHex)
	if err != nil {
		return VerificationReport{
			Status:   StatusInvalidSignature,
			Warnings: []string{fmt.Sprintf("Invalid hex public key: %v", err)},
		}
	}

	jsonBytes := make([][]byte, len(attestationsJSON))
	for i, s := range attestationsJSON {
		jsonBytes[i] = []byte(s)
	}

	return VerifyChain(jsonBytes, pkBytes)
}

// IsDeviceListed checks if a device appears in the attestation list.
//
// This function checks membership only. It does NOT verify cryptographic signatures.
// For security-critical authorization checks, use VerifyDeviceAuthorization().
//
// Parameters:
//   - identityDID: The identity DID (e.g., "did:key:z...")
//   - deviceDID: The device DID to check
//   - attestationsJSON: List of attestation JSON byte slices
//
// Returns true if the device is listed and not expired/revoked.
func IsDeviceListed(identityDID, deviceDID string, attestationsJSON [][]byte) bool {
	now := time.Now()

	for _, attJSON := range attestationsJSON {
		if len(attJSON) > MaxAttestationJSONSize {
			continue
		}
		var att Attestation
		if err := json.Unmarshal(attJSON, &att); err != nil {
			continue
		}

		// Check issuer matches identity
		if att.Issuer != identityDID {
			continue
		}

		// Check subject matches device
		if att.Subject != deviceDID {
			continue
		}

		// Check not revoked
		if att.RevokedAt != nil {
			continue
		}

		// Check not expired
		if att.ExpiresAt != nil && now.After(*att.ExpiresAt) {
			continue
		}

		// Found a valid attestation
		return true
	}

	return false
}

// VerifyDeviceAuthorization cryptographically verifies that a device is authorized.
//
// Unlike IsDeviceListed, this function verifies cryptographic signatures
// to ensure attestations have not been forged or tampered with.
//
// Parameters:
//   - identityDID: The identity DID (e.g., "did:key:z...")
//   - deviceDID: The device DID to check
//   - attestationsJSON: List of attestation JSON byte slices
//   - identityPK: The identity's Ed25519 public key (32 bytes)
//
// Returns a VerificationReport with verification details.
func VerifyDeviceAuthorization(identityDID, deviceDID string, attestationsJSON [][]byte, identityPK []byte) VerificationReport {
	total := 0
	for _, b := range attestationsJSON {
		total += len(b)
	}
	if total > MaxJSONBatchSize {
		return VerificationReport{
			Status:      StatusBrokenChain,
			Warnings:    []string{fmt.Sprintf("Total JSON too large: %d bytes, max %d", total, MaxJSONBatchSize)},
			MissingLink: "input too large",
		}
	}

	if len(identityPK) != 32 {
		return VerificationReport{
			Status:   StatusInvalidSignature,
			Warnings: []string{"Invalid identity public key length"},
		}
	}

	// Find matching attestations
	var matchingIdx int = -1
	for i, attJSON := range attestationsJSON {
		var att Attestation
		if err := json.Unmarshal(attJSON, &att); err != nil {
			continue
		}

		if att.Issuer == identityDID && att.Subject == deviceDID {
			matchingIdx = i
			break
		}
	}

	if matchingIdx == -1 {
		return VerificationReport{
			Status:      StatusBrokenChain,
			MissingLink: fmt.Sprintf("No attestation found for device %s under %s", deviceDID, identityDID),
		}
	}

	attJSON := attestationsJSON[matchingIdx]
	var att Attestation
	if err := json.Unmarshal(attJSON, &att); err != nil {
		return VerificationReport{
			Status:      StatusBrokenChain,
			MissingLink: fmt.Sprintf("Failed to parse attestation: %v", err),
		}
	}

	link := ChainLink{
		Issuer:  att.Issuer,
		Subject: att.Subject,
	}

	// Check revocation
	if att.RevokedAt != nil {
		link.Valid = false
		link.Error = "Attestation revoked"
		return VerificationReport{
			Status: StatusRevoked,
			Chain:  []ChainLink{link},
		}
	}

	// Check expiration
	if att.ExpiresAt != nil && time.Now().After(*att.ExpiresAt) {
		link.Valid = false
		link.Error = fmt.Sprintf("Attestation expired on %s", att.ExpiresAt.Format(time.RFC3339))
		expiredAt := *att.ExpiresAt
		return VerificationReport{
			Status:    StatusExpired,
			Chain:     []ChainLink{link},
			ExpiredAt: &expiredAt,
		}
	}

	// Verify signature using FFI
	result := VerifyAttestation(attJSON, identityPK)
	if !result.Valid {
		link.Valid = false
		link.Error = result.Error.Error()
		return VerificationReport{
			Status:     StatusInvalidSignature,
			Chain:      []ChainLink{link},
			FailedStep: 0,
		}
	}

	link.Valid = true
	return VerificationReport{
		Status: StatusValid,
		Chain:  []ChainLink{link},
	}
}
