"""Auths SDK quickstart — validates the README examples actually work."""

from auths import Auths, VerificationError

auths = Auths()
print(f"Auths client initialized: repo={auths.repo_path}")

# Demonstrate error handling
try:
    auths.verify(attestation_json="{}", issuer_key="bad")
except VerificationError as e:
    print(f"Expected error: code={e.code}, message={e.message}")

print("Quickstart complete!")
