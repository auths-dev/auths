#!/usr/bin/env bash
set -euo pipefail

pip install --break-system-packages -r deploy/vercel/requirements.txt
python -m mkdocs build
