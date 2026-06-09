package verifier

import (
	"os"
	"path/filepath"
	"testing"
)

// Cross-language fixture vectors emitted by the Rust builders (fn-153.3/.5), shared by the
// WASM/Node/Python/Go bindings. These assert the Go binding's verdicts match the canonical
// Rust verdicts for the valid / revoked / malformed cases — proving Go does not diverge.
//
// Requires the native cdylib (`./build.sh` first); skipped automatically if the fixtures are
// absent (e.g. the package vendored outside the monorepo).
const fixtureDir = "../../crates/auths-verifier/tests/fixtures"

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	path := filepath.Join(fixtureDir, name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("fixture %s not available (%v) — run from the monorepo with ./build.sh", name, err)
	}
	return data
}

func TestVerifyPresentationValidFixture(t *testing.T) {
	verdict, err := VerifyPresentation(readFixture(t, "presentation_valid.json"))
	if err != nil {
		t.Fatalf("transport error: %v", err)
	}
	if verdict.Kind != KindValid {
		t.Fatalf("expected kind %q, got %q", KindValid, verdict.Kind)
	}
	if got := verdict.Subject; len(got) < 9 || got[:9] != "did:keri:" {
		t.Errorf("expected a did:keri: subject, got %q", got)
	}
	if len(verdict.Caps) != 1 || verdict.Caps[0] != "sign" {
		t.Errorf("expected caps [sign], got %v", verdict.Caps)
	}
}

func TestVerifyCredentialValidFixture(t *testing.T) {
	verdict, err := VerifyCredential(readFixture(t, "credential_valid.json"))
	if err != nil {
		t.Fatalf("transport error: %v", err)
	}
	if verdict.Kind != KindValid {
		t.Fatalf("expected kind %q, got %q", KindValid, verdict.Kind)
	}
	if len(verdict.Caps) != 1 || verdict.Caps[0] != "sign" {
		t.Errorf("expected caps [sign], got %v", verdict.Caps)
	}
}

func TestVerifyCredentialRevokedFixture(t *testing.T) {
	verdict, err := VerifyCredential(readFixture(t, "credential_revoked.json"))
	if err != nil {
		t.Fatalf("transport error: %v", err)
	}
	if verdict.Kind != KindCredentialRevoked {
		t.Fatalf("expected kind %q, got %q", KindCredentialRevoked, verdict.Kind)
	}
	if verdict.IsValid() {
		t.Error("a revoked credential must not report valid")
	}
}

func TestVerifyPresentationMalformedIsTypedVerdict(t *testing.T) {
	// A malformed request is a typed verdict, NOT a transport error or a panic.
	verdict, err := VerifyPresentation([]byte("{not json"))
	if err != nil {
		t.Fatalf("malformed input must yield a verdict, not a transport error: %v", err)
	}
	if verdict.Kind != KindMalformedRequest {
		t.Fatalf("expected kind %q, got %q", KindMalformedRequest, verdict.Kind)
	}
	if verdict.Message == "" {
		t.Error("malformedRequest verdict must carry a message")
	}
}

// TestVerdictNoLeakUnderRepeatedCalls exercises the buffer path many times; a leak of
// Rust-owned memory (there is none — the buffer is Go-owned) or of the input C.CString would
// surface under the race detector / repeated allocation.
func TestVerdictNoLeakUnderRepeatedCalls(t *testing.T) {
	req := readFixture(t, "credential_valid.json")
	for i := 0; i < 200; i++ {
		if _, err := VerifyCredential(req); err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
	}
}
