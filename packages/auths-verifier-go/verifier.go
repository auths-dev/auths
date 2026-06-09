// Package verifier provides Go bindings for the Auths attestation + credential
// verification library.
//
// This package wraps the Rust auths-verifier cdylib via CGo. Every verification path —
// attestations, attestation chains, device authorization, and the KERI credential /
// presentation verdicts — is computed by the SAME Rust core the CLI and other language
// bindings use, so Go can never diverge from the canonical verdict. There is NO pure-Go
// re-implementation of chain logic.
//
// # Building (CGO_ENABLED=1 required)
//
// This package CANNOT be used with CGO_ENABLED=0 (a static-Go / distroless build): it links
// the native cdylib and needs a C toolchain. Build the native library first:
//
//	cd packages/auths-verifier-go
//	./build.sh   # cargo build --release -p auths_verifier --features ffi
//
// Then point the linker/loader at it (the build script prints the exact exports):
//
//	export CGO_LDFLAGS="-L/path/to/auths/target/release -lauths_verifier"
//	export DYLD_LIBRARY_PATH="/path/to/auths/target/release"  # macOS
//	export LD_LIBRARY_PATH="/path/to/auths/target/release"    # Linux
package verifier

/*
#cgo LDFLAGS: -lauths_verifier
#include <stdint.h>
#include <stdlib.h>

// C FFI declarations — must match crates/auths-verifier/src/ffi.rs.
#define VERIFY_SUCCESS 0
#define ERR_VERIFY_NULL_ARGUMENT -1
#define ERR_VERIFY_JSON_PARSE -2
#define ERR_VERIFY_INVALID_PK_LEN -3
#define ERR_VERIFY_ISSUER_SIG_FAIL -4
#define ERR_VERIFY_DEVICE_SIG_FAIL -5
#define ERR_VERIFY_EXPIRED -6
#define ERR_VERIFY_REVOKED -7
#define ERR_VERIFY_SERIALIZATION -8
#define ERR_VERIFY_INSUFFICIENT_WITNESSES -9
#define ERR_VERIFY_WITNESS_PARSE -10
#define ERR_VERIFY_INPUT_TOO_LARGE -11
#define ERR_VERIFY_FUTURE_TIMESTAMP -12
#define ERR_VERIFY_BUFFER_TOO_SMALL -13
#define ERR_VERIFY_INVALID_UTF8 -14
#define ERR_VERIFY_OTHER -99
#define ERR_VERIFY_PANIC -127

extern int ffi_verify_attestation_json(
    const uint8_t* attestation_json_ptr,
    size_t attestation_json_len,
    const uint8_t* issuer_pk_ptr,
    size_t issuer_pk_len
);

extern int ffi_verify_chain_json(
    const uint8_t* chain_json_ptr,
    size_t chain_json_len,
    const uint8_t* root_pk_ptr,
    size_t root_pk_len,
    uint8_t* result_ptr,
    size_t* result_len
);

extern int ffi_verify_device_authorization_json(
    const uint8_t* identity_did_ptr,
    size_t identity_did_len,
    const uint8_t* device_did_ptr,
    size_t device_did_len,
    const uint8_t* chain_json_ptr,
    size_t chain_json_len,
    const uint8_t* identity_pk_ptr,
    size_t identity_pk_len,
    uint8_t* result_ptr,
    size_t* result_len
);

extern int auths_verify_presentation_json(
    const uint8_t* request_ptr,
    size_t request_len,
    uint8_t* result_ptr,
    size_t* result_len
);

extern int auths_verify_credential_json(
    const uint8_t* request_ptr,
    size_t request_len,
    uint8_t* result_ptr,
    size_t* result_len
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

// FFI status codes (must match ffi.rs). The exported subset is the historical attestation
// surface; the rest are internal transport codes for the buffer-returning entrypoints.
const (
	VerifySuccess    = 0
	ErrNullArgument  = -1
	ErrJSONParse     = -2
	ErrInvalidPKLen  = -3
	ErrIssuerSigFail = -4
	ErrDeviceSigFail = -5
	ErrExpired       = -6
	ErrRevoked       = -7
	ErrSerialization = -8
	ErrOther         = -99

	codeInsufficientWitnesses = -9
	codeInputTooLarge         = -11
	codeFutureTimestamp       = -12
	codeBufferTooSmall        = -13
	codeInvalidUTF8           = -14
	codePanic                 = -127
)

// JSON input size limits (must match the Rust constants in core.rs / contract.rs).
const (
	MaxAttestationJSONSize = 64 * 1024   // 64 KiB per single attestation
	MaxJSONBatchSize       = 1024 * 1024 // 1 MiB for arrays / bundled verify requests
)

// initialReportBuffer is the first buffer size tried for the report/verdict entrypoints; it
// grows on overflow (the verdict path reports its required size, the report path doubles).
const initialReportBuffer = 8 * 1024

// maxReportBuffer caps the report-buffer growth (a guard against a pathological serialization).
const maxReportBuffer = 4 * 1024 * 1024

// Common errors.
var (
	ErrNullPointer         = errors.New("null pointer argument")
	ErrInvalidJSON         = errors.New("invalid JSON")
	ErrInvalidPublicKey    = errors.New("invalid public key length (expected 32 / 33 / 65 bytes)")
	ErrIssuerSignature     = errors.New("issuer signature verification failed")
	ErrDeviceSignature     = errors.New("device signature verification failed")
	ErrAttestationExpired  = errors.New("attestation has expired")
	ErrAttestationRevoked  = errors.New("attestation has been revoked")
	ErrSerializationFailed = errors.New("serialization error")
	ErrVerificationFailed  = errors.New("verification failed")
	ErrInputTooLarge       = errors.New("JSON input too large")
	ErrInvalidUTF8         = errors.New("request was not valid UTF-8")
	ErrVerifierPanic       = errors.New("verifier panicked (caught at the FFI boundary)")
)

// validPKLen reports whether n is a curve-tagged public-key length the FFI accepts
// (32 = Ed25519, 33 = P-256 compressed, 65 = P-256 uncompressed).
func validPKLen(n int) bool {
	return n == 32 || n == 33 || n == 65
}

// ============================================================================
// Single attestation
// ============================================================================

// VerificationResult contains the result of a single attestation verification.
type VerificationResult struct {
	Valid bool
	Error error
}

// VerifyAttestation verifies a single attestation against an issuer's public key.
//
// Parameters:
//   - attestationJSON: the attestation as a JSON byte slice
//   - issuerPK: the issuer's public key (32 Ed25519, or 33/65 P-256 bytes)
func VerifyAttestation(attestationJSON []byte, issuerPK []byte) VerificationResult {
	if len(attestationJSON) == 0 {
		return VerificationResult{Valid: false, Error: ErrInvalidJSON}
	}
	if len(attestationJSON) > MaxAttestationJSONSize {
		return VerificationResult{Valid: false, Error: fmt.Errorf("%w: %d bytes, max %d", ErrInputTooLarge, len(attestationJSON), MaxAttestationJSONSize)}
	}
	if !validPKLen(len(issuerPK)) {
		return VerificationResult{Valid: false, Error: ErrInvalidPublicKey}
	}

	jsonPtr := (*C.uint8_t)(unsafe.Pointer(&attestationJSON[0]))
	jsonLen := C.size_t(len(attestationJSON))
	pkPtr := (*C.uint8_t)(unsafe.Pointer(&issuerPK[0]))
	pkLen := C.size_t(len(issuerPK))

	result := C.ffi_verify_attestation_json(jsonPtr, jsonLen, pkPtr, pkLen)

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

// VerifyAttestationHex verifies a single attestation using a hex-encoded public key.
func VerifyAttestationHex(attestationJSON string, issuerPKHex string) VerificationResult {
	pkBytes, err := hex.DecodeString(issuerPKHex)
	if err != nil {
		return VerificationResult{Valid: false, Error: fmt.Errorf("invalid hex public key: %w", err)}
	}
	return VerifyAttestation([]byte(attestationJSON), pkBytes)
}

// ============================================================================
// KERI credential / presentation verdicts (the fn-153.3 cross-boundary contract)
// ============================================================================

// VerdictKind is the discriminant of a credential / presentation verdict (the `kind` field).
type VerdictKind string

// Presentation + credential verdict kinds. These mirror the Rust discriminated union exactly
// (camelCase tags); a handler switches on the typed constant, never a magic int.
const (
	KindValid                    VerdictKind = "valid"
	KindHolderNotCurrentKey      VerdictKind = "holderNotCurrentKey"
	KindWrongAudience            VerdictKind = "wrongAudience"
	KindNonceMismatchOrConsumed  VerdictKind = "nonceMismatchOrConsumed"
	KindExpired                  VerdictKind = "expired"
	KindSubjectKelInvalid        VerdictKind = "subjectKelInvalid"
	KindCredentialNotValid       VerdictKind = "credentialNotValid"
	KindSaidMismatch             VerdictKind = "saidMismatch"
	KindSchemaInvalid            VerdictKind = "schemaInvalid"
	KindIssuerSignatureInvalid   VerdictKind = "issuerSignatureInvalid"
	KindRegistryNotEstablished   VerdictKind = "registryNotEstablished"
	KindCredentialRevoked        VerdictKind = "credentialRevoked"
	KindWitnessQuorumNotMet      VerdictKind = "witnessQuorumNotMet"
	KindIssuerKelDuplicitous     VerdictKind = "issuerKelDuplicitous"
	KindMalformedRequest         VerdictKind = "malformedRequest"
	KindInputTooLarge            VerdictKind = "inputTooLarge"
	KindUnsupportedSchemaVersion VerdictKind = "unsupportedSchemaVersion"
)

// CredentialVerdict is the typed credential verify outcome (a tagged union flattened into one
// struct; only the fields for the active Kind are populated).
type CredentialVerdict struct {
	SchemaVersion int         `json:"schemaVersion"`
	Kind          VerdictKind `json:"kind"`

	// valid
	Issuer  string   `json:"issuer,omitempty"`
	Subject string   `json:"subject,omitempty"`
	Caps    []string `json:"caps,omitempty"`
	AsOf    uint64   `json:"asOf,omitempty"`

	// credentialRevoked
	RevokedAt uint64 `json:"revokedAt,omitempty"`

	// expired
	ExpiredAt string `json:"expiredAt,omitempty"`
	Now       string `json:"now,omitempty"`

	// witnessQuorumNotMet
	Event     string `json:"event,omitempty"`
	Collected int    `json:"collected,omitempty"`
	Required  int    `json:"required,omitempty"`

	// request-layer errors
	Message  string `json:"message,omitempty"`
	Field    string `json:"field,omitempty"`
	Count    int    `json:"count,omitempty"`
	Limit    int    `json:"limit,omitempty"`
	Got      int    `json:"got,omitempty"`
	Expected int    `json:"expected,omitempty"`
}

// IsValid reports whether the credential verified.
func (v CredentialVerdict) IsValid() bool { return v.Kind == KindValid }

// PresentationVerdict is the typed presentation verify outcome (a tagged union flattened into
// one struct; only the fields for the active Kind are populated).
type PresentationVerdict struct {
	SchemaVersion int         `json:"schemaVersion"`
	Kind          VerdictKind `json:"kind"`

	// valid
	Issuer    string   `json:"issuer,omitempty"`
	Subject   string   `json:"subject,omitempty"`
	Caps      []string `json:"caps,omitempty"`
	Role      *string  `json:"role,omitempty"`
	ExpiresAt *string  `json:"expiresAt,omitempty"`

	// credentialNotValid (nests the credential verdict)
	Credential *CredentialVerdict `json:"credential,omitempty"`

	// request-layer errors
	Message  string `json:"message,omitempty"`
	Field    string `json:"field,omitempty"`
	Count    int    `json:"count,omitempty"`
	Limit    int    `json:"limit,omitempty"`
	Got      int    `json:"got,omitempty"`
	Expected int    `json:"expected,omitempty"`
}

// IsValid reports whether the presentation verified and was honored.
func (v PresentationVerdict) IsValid() bool { return v.Kind == KindValid }

// verdictFn is one of the buffer-returning verdict entrypoints (caller-owned output buffer,
// BUFFER_TOO_SMALL retry convention from fn-153.4).
type verdictFn func(reqPtr *C.uint8_t, reqLen C.size_t, outPtr *C.uint8_t, outLen *C.size_t) C.int

// callVerdictJSON drives a bundled verify-JSON request through `fn` and returns the verdict
// JSON bytes. The verdict (valid / revoked / malformedRequest / …) is encoded IN that JSON;
// a non-nil error here is a transport failure only (null arg, oversize, panic), never a
// verification "no". The output buffer is Go-owned end to end — no Rust pointer crosses the
// boundary, so there is nothing to free.
func callVerdictJSON(requestJSON []byte, fn verdictFn) ([]byte, error) {
	if len(requestJSON) == 0 {
		return nil, ErrInvalidJSON
	}
	if len(requestJSON) > MaxJSONBatchSize {
		return nil, ErrInputTooLarge
	}
	reqPtr := (*C.uint8_t)(unsafe.Pointer(&requestJSON[0]))
	reqLen := C.size_t(len(requestJSON))

	buf := make([]byte, initialReportBuffer)
	for attempt := 0; attempt < 2; attempt++ {
		outLen := C.size_t(len(buf))
		rc := fn(reqPtr, reqLen, (*C.uint8_t)(unsafe.Pointer(&buf[0])), &outLen)
		switch rc {
		case VerifySuccess:
			return append([]byte(nil), buf[:int(outLen)]...), nil
		case codeBufferTooSmall:
			// The required length was written back to outLen; resize exactly and retry once.
			buf = make([]byte, int(outLen))
		default:
			return nil, transportError(rc)
		}
	}
	return nil, ErrVerificationFailed
}

// transportError maps an FFI transport status to a Go error (verification verdicts never use
// this path — they are carried in the returned JSON).
func transportError(rc C.int) error {
	switch rc {
	case ErrNullArgument:
		return ErrNullPointer
	case codeInputTooLarge:
		return ErrInputTooLarge
	case codeInvalidUTF8:
		return ErrInvalidUTF8
	case ErrSerialization:
		return ErrSerializationFailed
	case codePanic:
		return ErrVerifierPanic
	default:
		return fmt.Errorf("%w (code: %d)", ErrVerificationFailed, int(rc))
	}
}

// VerifyPresentation verifies a credential presentation from a bundled JSON request (the
// fn-153.3 contract) and returns a typed PresentationVerdict. A malformed request yields a
// `malformedRequest` verdict (Kind), not a Go error — only transport failures error.
func VerifyPresentation(requestJSON []byte) (PresentationVerdict, error) {
	out, err := callVerdictJSON(requestJSON, func(rp *C.uint8_t, rl C.size_t, op *C.uint8_t, ol *C.size_t) C.int {
		return C.auths_verify_presentation_json(rp, rl, op, ol)
	})
	if err != nil {
		return PresentationVerdict{}, err
	}
	var v PresentationVerdict
	if err := json.Unmarshal(out, &v); err != nil {
		return PresentationVerdict{}, fmt.Errorf("failed to parse presentation verdict: %w", err)
	}
	return v, nil
}

// VerifyCredential verifies an issued credential from a bundled JSON request (the fn-153.3
// contract) and returns a typed CredentialVerdict. Same error contract as VerifyPresentation.
func VerifyCredential(requestJSON []byte) (CredentialVerdict, error) {
	out, err := callVerdictJSON(requestJSON, func(rp *C.uint8_t, rl C.size_t, op *C.uint8_t, ol *C.size_t) C.int {
		return C.auths_verify_credential_json(rp, rl, op, ol)
	})
	if err != nil {
		return CredentialVerdict{}, err
	}
	var v CredentialVerdict
	if err := json.Unmarshal(out, &v); err != nil {
		return CredentialVerdict{}, fmt.Errorf("failed to parse credential verdict: %w", err)
	}
	return v, nil
}

// ============================================================================
// Attestation chain + device authorization (routed through the Rust core)
// ============================================================================

// VerificationStatus represents the status of a verification operation.
type VerificationStatus int

const (
	StatusValid VerificationStatus = iota
	StatusExpired
	StatusRevoked
	StatusInvalidSignature
	StatusBrokenChain
	StatusInsufficientWitnesses
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
	case StatusInsufficientWitnesses:
		return "InsufficientWitnesses"
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

	ExpiredAt   *time.Time // set when Status == StatusExpired
	RevokedAt   *time.Time // set when Status == StatusRevoked
	FailedStep  int        // set when Status == StatusInvalidSignature
	MissingLink string     // set when Status == StatusBrokenChain
}

// IsValid returns true if the verification succeeded.
func (r *VerificationReport) IsValid() bool {
	return r.Status == StatusValid
}

// Attestation mirrors the Rust attestation for membership checks (IsDeviceListed only).
// It is NOT used for chain verification — that is delegated to the Rust core.
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

// rustStatus mirrors the internally-tagged Rust VerificationStatus (`{"type":…}`).
type rustStatus struct {
	Type        string     `json:"type"`
	At          *time.Time `json:"at"`
	Step        *int       `json:"step"`
	MissingLink string     `json:"missing_link"`
	Required    int        `json:"required"`
	Verified    int        `json:"verified"`
}

// rustChainLink mirrors the Rust ChainLink JSON.
type rustChainLink struct {
	Issuer  string  `json:"issuer"`
	Subject string  `json:"subject"`
	Valid   bool    `json:"valid"`
	Error   *string `json:"error"`
}

// rustReport mirrors the serialized Rust VerificationReport.
type rustReport struct {
	Status   rustStatus      `json:"status"`
	Chain    []rustChainLink `json:"chain"`
	Warnings []string        `json:"warnings"`
}

// reportInvoke runs one of the report-returning FFI entrypoints into a caller-owned buffer.
type reportInvoke func(outPtr *C.uint8_t, outLen *C.size_t) C.int

// callReportFFI drives a report-returning entrypoint, growing the buffer on a serialization
// (too-small) status. These entrypoints do not report a required length, so the buffer is
// doubled up to a cap. Returns the report JSON, or a non-success status code.
func callReportFFI(invoke reportInvoke) ([]byte, C.int) {
	size := initialReportBuffer
	for {
		buf := make([]byte, size)
		outLen := C.size_t(size)
		rc := invoke((*C.uint8_t)(unsafe.Pointer(&buf[0])), &outLen)
		if rc == ErrSerialization && size < maxReportBuffer {
			size *= 2
			continue
		}
		if rc != VerifySuccess {
			return nil, rc
		}
		return append([]byte(nil), buf[:int(outLen)]...), VerifySuccess
	}
}

// parseRustReport maps the serialized Rust report into the Go VerificationReport.
func parseRustReport(reportJSON []byte) VerificationReport {
	var raw rustReport
	if err := json.Unmarshal(reportJSON, &raw); err != nil {
		return VerificationReport{
			Status:      StatusBrokenChain,
			MissingLink: fmt.Sprintf("failed to parse Rust report: %v", err),
		}
	}

	chain := make([]ChainLink, 0, len(raw.Chain))
	for _, l := range raw.Chain {
		link := ChainLink{Issuer: l.Issuer, Subject: l.Subject, Valid: l.Valid}
		if l.Error != nil {
			link.Error = *l.Error
		}
		chain = append(chain, link)
	}

	report := VerificationReport{Chain: chain, Warnings: raw.Warnings}
	switch raw.Status.Type {
	case "Valid":
		report.Status = StatusValid
	case "Expired":
		report.Status = StatusExpired
		report.ExpiredAt = raw.Status.At
	case "Revoked":
		report.Status = StatusRevoked
		report.RevokedAt = raw.Status.At
	case "InvalidSignature":
		report.Status = StatusInvalidSignature
		if raw.Status.Step != nil {
			report.FailedStep = *raw.Status.Step
		}
	case "BrokenChain":
		report.Status = StatusBrokenChain
		report.MissingLink = raw.Status.MissingLink
	case "InsufficientWitnesses":
		report.Status = StatusInsufficientWitnesses
	default:
		report.Status = StatusBrokenChain
		report.MissingLink = fmt.Sprintf("unknown status %q", raw.Status.Type)
	}
	return report
}

// reportFromErrCode maps an FFI error status (the `Err` path of a report entrypoint) to a Go
// report, so callers see a typed status instead of a bare code.
func reportFromErrCode(rc C.int) VerificationReport {
	switch rc {
	case ErrExpired:
		return VerificationReport{Status: StatusExpired}
	case ErrRevoked:
		return VerificationReport{Status: StatusRevoked}
	case ErrIssuerSigFail, ErrDeviceSigFail, ErrInvalidPKLen:
		return VerificationReport{Status: StatusInvalidSignature}
	case codeInsufficientWitnesses:
		return VerificationReport{Status: StatusInsufficientWitnesses}
	case ErrJSONParse:
		return VerificationReport{Status: StatusBrokenChain, MissingLink: "attestation JSON parse error"}
	case codeInputTooLarge:
		return VerificationReport{Status: StatusBrokenChain, MissingLink: "input too large"}
	default:
		return VerificationReport{Status: StatusBrokenChain, MissingLink: fmt.Sprintf("verifier error (code: %d)", int(rc))}
	}
}

// chainBytes marshals the per-attestation JSON objects into one JSON array for the FFI.
func chainBytes(attestationsJSON [][]byte) ([]byte, error) {
	arr := make([]json.RawMessage, len(attestationsJSON))
	for i, b := range attestationsJSON {
		arr[i] = json.RawMessage(b)
	}
	return json.Marshal(arr)
}

// VerifyChain verifies a chain of attestations from root to leaf via the Rust core.
//
// The per-link signature + linkage verification is performed entirely in Rust (no pure-Go
// re-implementation), so Go cannot diverge from the canonical verdict. Lightweight input
// guards (size, key length, empty chain) short-circuit before the FFI call.
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
	if !validPKLen(len(rootPK)) {
		return VerificationReport{Status: StatusInvalidSignature, Warnings: []string{"Invalid root public key length"}}
	}
	if len(attestationsJSON) == 0 {
		return VerificationReport{Status: StatusBrokenChain, MissingLink: "empty chain"}
	}

	chainJSON, err := chainBytes(attestationsJSON)
	if err != nil {
		return VerificationReport{Status: StatusBrokenChain, MissingLink: fmt.Sprintf("chain marshal error: %v", err)}
	}

	reportJSON, rc := callReportFFI(func(op *C.uint8_t, ol *C.size_t) C.int {
		return C.ffi_verify_chain_json(
			(*C.uint8_t)(unsafe.Pointer(&chainJSON[0])), C.size_t(len(chainJSON)),
			(*C.uint8_t)(unsafe.Pointer(&rootPK[0])), C.size_t(len(rootPK)),
			op, ol,
		)
	})
	if rc != VerifySuccess {
		return reportFromErrCode(rc)
	}
	return parseRustReport(reportJSON)
}

// VerifyChainHex is a convenience wrapper around VerifyChain accepting a hex root key.
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

// VerifyDeviceAuthorization cryptographically verifies that a device is authorized by an
// identity, via the Rust core (no pure-Go verification).
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
	if !validPKLen(len(identityPK)) {
		return VerificationReport{Status: StatusInvalidSignature, Warnings: []string{"Invalid identity public key length"}}
	}

	chainJSON, err := chainBytes(attestationsJSON)
	if err != nil {
		return VerificationReport{Status: StatusBrokenChain, MissingLink: fmt.Sprintf("chain marshal error: %v", err)}
	}

	// C.CString allocates NUL-terminated copies of the DID strings; we own and free them.
	idC := C.CString(identityDID)
	defer C.free(unsafe.Pointer(idC))
	devC := C.CString(deviceDID)
	defer C.free(unsafe.Pointer(devC))

	reportJSON, rc := callReportFFI(func(op *C.uint8_t, ol *C.size_t) C.int {
		return C.ffi_verify_device_authorization_json(
			(*C.uint8_t)(unsafe.Pointer(idC)), C.size_t(len(identityDID)),
			(*C.uint8_t)(unsafe.Pointer(devC)), C.size_t(len(deviceDID)),
			(*C.uint8_t)(unsafe.Pointer(&chainJSON[0])), C.size_t(len(chainJSON)),
			(*C.uint8_t)(unsafe.Pointer(&identityPK[0])), C.size_t(len(identityPK)),
			op, ol,
		)
	})
	if rc != VerifySuccess {
		return reportFromErrCode(rc)
	}
	return parseRustReport(reportJSON)
}

// IsDeviceListed checks whether a device appears in the attestation list (membership only).
//
// This is NOT a cryptographic check — it does not verify signatures. For authorization use
// VerifyDeviceAuthorization. Membership is a pure local scan, so it does not call the FFI.
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
		if att.Issuer != identityDID || att.Subject != deviceDID {
			continue
		}
		if att.RevokedAt != nil {
			continue
		}
		if att.ExpiresAt != nil && now.After(*att.ExpiresAt) {
			continue
		}
		return true
	}
	return false
}
