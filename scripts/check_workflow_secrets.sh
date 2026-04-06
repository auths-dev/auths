#!/bin/bash
# Detect ${{ secrets.* }} inside body: blocks of GitHub workflows.
# This catches the exact bug that leaked AUTHS_CI_TOKEN to a public release page.
FOUND=0
for f in .github/workflows/*.yml; do
  if awk '/body:/,/^[^ ]/' "$f" | grep -q '\${{ secrets\.' ; then
    echo "BLOCKED: $f has \${{ secrets.* }} in a body: block — this WILL leak secrets"
    FOUND=1
  fi
done
exit $FOUND
