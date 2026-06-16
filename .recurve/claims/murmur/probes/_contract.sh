#!/usr/bin/env bash
# The probe contract (frozen — see schema/gap.schema.json's engine):
#   exit 0  GREEN   the desired behavior is present
#   exit 1  RED     the desired behavior is absent (print ONE detail line a
#                   sculptor can treat as the spec: "ours=X expected=Y")
#   exit 2  BROKEN  could not measure (missing oracle/fixture/build)
#   anything else (crash, timeout) coerces to BROKEN — never to a verdict.
#
# Traps: when $TRAP_FIXTURE is set, the runner is feeding you a KNOWN-BAD
# counterexample from probes/<name>.trap/<fixture>/ — you MUST exit 1.
# A probe that has never been seen RED is not yet evidence.
#
# Probes are hermetic: build nothing, touch no sacred space, finish in
# seconds against already-built artifacts, no network unless the claim is
# about network. They drive the staged murmur-relay binary / the murmur-core
# seam (which fails closed "feature absent" in the skeleton) — never a model,
# never a live network. The simulator is a DEV check for the operator, never
# part of a gate probe.
green() { echo "${1:-behavior present}"; exit 0; }
red()   { echo "${1:?print the one RED line of truth}"; exit 1; }
broken(){ echo "${1:-could not measure}"; exit 2; }
