# wit-n4 trap — a forged build attestation that must stay RED

A probe that has never been seen RED is not yet evidence. This fixture feeds the
WIT-N4 probe a known-bad **forged** build attestation (via `TRAP_FIXTURE`) that
`auths witness status` MUST reject.

- `wrong-digest/forged.auths.json` — a genuinely-signed `auths artifact sign --ci`
  attestation whose signature is perfectly valid, but whose attested digest is the
  digest of a DIFFERENT artifact — NOT the binary the node runs.

The probe stands a node up with this attestation injected where the GREEN path
injects the genuine one, then runs `auths witness status`. It asserts a non-zero
exit with a distinct reason ("rejected … different binary … not running what it
attests"). A zero exit here means `status` accepted a node whose attestation is
for a binary it is not running — the node could be executing anything and still
claim a green build, and the "the node proves what binary it runs" guarantee
becomes cosmetic.

This is the WIT-N4 adversarial twin, frozen: "an attestation whose digest differs
from the running binary fails verification." The check that keeps it RED is the
two-leg verdict — signature valid AND attested digest == the node's own
self-measurement of `/proc/self/exe`. The forged attestation passes leg one and
dies on leg two. If this ever goes GREEN, an operator can vouch for the network
while running an unattested binary.
