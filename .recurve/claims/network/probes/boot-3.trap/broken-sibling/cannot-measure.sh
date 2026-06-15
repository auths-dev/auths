#!/usr/bin/env bash
# A KNOWN-BAD sibling: a probe that cannot decide. It exits 2 (BROKEN) — the
# exact verdict BOOT-3 exists to forbid in a clean baseline. A probe missing its
# oracle/fixture/build looks exactly like this from the runner's side: it
# announces it could not measure and exits 2.
#
# BOOT-3, handed this fixture via TRAP_FIXTURE, must NOTICE the BROKEN exit and
# turn RED. If BOOT-3 ever went GREEN here, it would be certifying a baseline as
# clean while a sibling silently could-not-measure — the burndown would start on
# a lie. That green is the highest-order gate failure this trap guards against.
echo "could not measure: oracle/fixture/build prerequisite is absent (this is the BROKEN a clean baseline must not contain)"
exit 2
