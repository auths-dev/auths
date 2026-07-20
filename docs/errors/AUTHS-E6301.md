# AUTHS-E6301

**Crate:** `auths-cli`

**Type:** `SignerKelError::Unavailable`

## Message

signer's KEL for {did} is not available locally: {reason}

## Suggestion

Fetch the signer's KEL with `git fetch <remote> 'refs/auths/*:refs/auths/*'`, or verify against an evidence bundle with `--identity-bundle`.
