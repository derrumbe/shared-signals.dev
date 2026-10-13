#!/usr/bin/env bash
# Lists openid/sharedsignals commits newer than the one the site was last checked against
# (SPECS_SYNC in src/consts.ts), and which spec files they touched.
set -euo pipefail
since=$(grep -o "commit: '[0-9a-f]*'" "$(dirname "$0")/../src/consts.ts" | cut -d"'" -f2)
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
git clone -q https://github.com/openid/sharedsignals "$tmp"
cd "$tmp"
if [ -z "$(git log --oneline "$since"..HEAD)" ]; then echo "Up to date with $since."; exit 0; fi
git log --format='%h %cs %s' --stat "$since"..HEAD -- '*.md' '*.xml'
