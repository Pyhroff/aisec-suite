#!/usr/bin/env bash
# Scan the vulnerable server (expected to fail the gate), then the fixed one (expected to pass).
set -u
here="$(cd "$(dirname "$0")" && pwd)"
out="${OUT_DIR:-$here/out}"
mkdir -p "$out"

echo "== 1. vulnerable server =="
aisec scan "$here/vulnerable" --fail-on high --reach annotate --sarif "$out/vulnerable.sarif" --json "$out/vulnerable.json"
vuln_rc=$?

echo
echo "== 2. fixed server =="
aisec scan "$here/fixed" --fail-on high --reach annotate --sarif "$out/fixed.sarif" --json "$out/fixed.json"
fixed_rc=$?

echo
echo "vulnerable exit=$vuln_rc (expect 1)   fixed exit=$fixed_rc (expect 0)"
[ "$vuln_rc" -eq 1 ] && [ "$fixed_rc" -eq 0 ]
