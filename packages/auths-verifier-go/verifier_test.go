package verifier

import (
	"testing"
	"time"
)

// TestVerificationStatusString tests the String() method of VerificationStatus
func TestVerificationStatusString(t *testing.T) {
	tests := []struct {
		status   VerificationStatus
		expected string
	}{
		{StatusValid, "Valid"},
		{StatusExpired, "Expired"},
		{StatusRevoked, "Revoked"},
		{StatusInvalidSignature, "InvalidSignature"},
		{StatusBrokenChain, "BrokenChain"},
		{VerificationStatus(999), "Unknown"},
	}

	for _, tt := range tests {
		if got := tt.status.String(); got != tt.expected {
			t.Errorf("VerificationStatus(%d).String() = %s, want %s", tt.status, got, tt.expected)
		}
	}
}

// TestVerifyAttestationInvalidInputs tests error handling for invalid inputs
func TestVerifyAttestationInvalidInputs(t *testing.T) {
	tests := []struct {
		name     string
		json     []byte
		pk       []byte
		expected error
	}{
		{
			name:     "empty JSON",
			json:     []byte{},
			pk:       make([]byte, 32),
			expected: ErrInvalidJSON,
		},
		{
			name:     "short public key",
			json:     []byte(`{}`),
			pk:       make([]byte, 16),
			expected: ErrInvalidPublicKey,
		},
		{
			name:     "long public key",
			json:     []byte(`{}`),
			pk:       make([]byte, 64),
			expected: ErrInvalidPublicKey,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := VerifyAttestation(tt.json, tt.pk)
			if result.Valid {
				t.Error("Expected verification to fail")
			}
			if result.Error != tt.expected {
				t.Errorf("Expected error %v, got %v", tt.expected, result.Error)
			}
		})
	}
}

// TestVerifyAttestationHexInvalidHex tests hex decoding error
func TestVerifyAttestationHexInvalidHex(t *testing.T) {
	result := VerifyAttestationHex("{}", "not-hex")
	if result.Valid {
		t.Error("Expected verification to fail for invalid hex")
	}
}

// TestVerifyChainEmpty tests empty chain handling
func TestVerifyChainEmpty(t *testing.T) {
	report := VerifyChain([][]byte{}, make([]byte, 32))
	if report.Status != StatusBrokenChain {
		t.Errorf("Expected StatusBrokenChain, got %v", report.Status)
	}
	if report.MissingLink != "empty chain" {
		t.Errorf("Expected 'empty chain', got '%s'", report.MissingLink)
	}
}

// TestVerifyChainInvalidRootPK tests invalid root public key handling
func TestVerifyChainInvalidRootPK(t *testing.T) {
	report := VerifyChain([][]byte{[]byte(`{}`)}, make([]byte, 16))
	if report.Status != StatusInvalidSignature {
		t.Errorf("Expected StatusInvalidSignature, got %v", report.Status)
	}
}

// TestVerificationReportIsValid tests the IsValid method
func TestVerificationReportIsValid(t *testing.T) {
	tests := []struct {
		status   VerificationStatus
		expected bool
	}{
		{StatusValid, true},
		{StatusExpired, false},
		{StatusRevoked, false},
		{StatusInvalidSignature, false},
		{StatusBrokenChain, false},
	}

	for _, tt := range tests {
		report := VerificationReport{Status: tt.status}
		if got := report.IsValid(); got != tt.expected {
			t.Errorf("VerificationReport{Status: %v}.IsValid() = %v, want %v",
				tt.status, got, tt.expected)
		}
	}
}

// TestIsDeviceListedNoAttestations tests with empty attestations
func TestIsDeviceListedNoAttestations(t *testing.T) {
	if IsDeviceListed("did:key:z123", "did:key:z456", [][]byte{}) {
		t.Error("Expected false for empty attestations")
	}
}

// TestIsDeviceListedInvalidJSON tests with invalid JSON
func TestIsDeviceListedInvalidJSON(t *testing.T) {
	if IsDeviceListed("did:key:z123", "did:key:z456", [][]byte{[]byte("not-json")}) {
		t.Error("Expected false for invalid JSON")
	}
}

// TestIsDeviceListedRevoked tests with revoked attestation
func TestIsDeviceListedRevoked(t *testing.T) {
	attJSON := []byte(`{"issuer": "did:key:z123", "subject": "did:key:z456", "revoked_at": "2025-01-01T00:00:00Z"}`)
	if IsDeviceListed("did:key:z123", "did:key:z456", [][]byte{attJSON}) {
		t.Error("Expected false for revoked attestation")
	}
}

// TestIsDeviceListedExpired tests with expired attestation
func TestIsDeviceListedExpired(t *testing.T) {
	expired := time.Now().Add(-24 * time.Hour).Format(time.RFC3339)
	attJSON := []byte(`{"issuer": "did:key:z123", "subject": "did:key:z456", "expires_at": "` + expired + `"}`)
	if IsDeviceListed("did:key:z123", "did:key:z456", [][]byte{attJSON}) {
		t.Error("Expected false for expired attestation")
	}
}

// TestIsDeviceListedWrongIssuer tests with mismatched issuer
func TestIsDeviceListedWrongIssuer(t *testing.T) {
	attJSON := []byte(`{"issuer": "did:key:wrong", "subject": "did:key:z456"}`)
	if IsDeviceListed("did:key:z123", "did:key:z456", [][]byte{attJSON}) {
		t.Error("Expected false for wrong issuer")
	}
}

// TestIsDeviceListedWrongDevice tests with mismatched device
func TestIsDeviceListedWrongDevice(t *testing.T) {
	attJSON := []byte(`{"issuer": "did:key:z123", "subject": "did:key:wrong"}`)
	if IsDeviceListed("did:key:z123", "did:key:z456", [][]byte{attJSON}) {
		t.Error("Expected false for wrong device")
	}
}

// TestIsDeviceListedValid tests with a valid attestation
func TestIsDeviceListedValid(t *testing.T) {
	future := time.Now().Add(24 * time.Hour).Format(time.RFC3339)
	attJSON := []byte(`{"issuer": "did:key:z123", "subject": "did:key:z456", "expires_at": "` + future + `"}`)
	if !IsDeviceListed("did:key:z123", "did:key:z456", [][]byte{attJSON}) {
		t.Error("Expected true for valid attestation")
	}
}
