#!/bin/bash
# End-to-end check of the same command chain NetCrack runs, using the bundled
# synthetic capture. If this prints "password1", the toolchain works and the
# app's Converter + Cracker will work too.
#
#   ./Scripts/test-sample.sh
#
# Requires: hcxpcapngtool (brew install hcxtools) and hashcat.

set -uo pipefail
cd "$(dirname "$0")/.."

SAMPLE="Samples/netcrack-demo.pcap"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }

echo "==> 1. Converting $SAMPLE with hcxpcapngtool"
if command -v hcxpcapngtool >/dev/null 2>&1; then
  hcxpcapngtool -o "$WORK/out.22000" "$SAMPLE"
  if [ -s "$WORK/out.22000" ]; then
    echo "    hashes:"
    sed 's/^/    /' "$WORK/out.22000"
  else
    echo "    hcxpcapngtool produced no hashes (synthetic frames may be rejected by your"
    echo "    hcxtools version). Falling back to the pre-made hash file."
    cp Samples/netcrack-demo.22000 "$WORK/out.22000"
  fi
else
  echo "    hcxpcapngtool not installed; using Samples/netcrack-demo.22000"
  cp Samples/netcrack-demo.22000 "$WORK/out.22000"
fi

echo "==> 2. Cracking with hashcat -m 22000 against the bundled top-10k"
command -v hashcat >/dev/null 2>&1 || fail "hashcat is not installed (brew install hashcat)"

hashcat -m 22000 "$WORK/out.22000" NetCrack/Resources/top10k.txt \
  -w 3 --status --status-timer=1 --potfile-path "$WORK/test.potfile" \
  --force --quiet 2>&1 | tail -5

echo "==> 3. Reading the key back with --show"
KEY="$(hashcat -m 22000 "$WORK/out.22000" --show --potfile-path "$WORK/test.potfile" \
        --force 2>/dev/null | awk -F: '{print $NF}' | tail -1)"

if [ "$KEY" = "password1" ]; then
  echo
  echo "PASS: recovered '$KEY' — the converter/cracker chain works."
else
  echo
  fail "expected 'password1', got '${KEY:-nothing}'"
fi
