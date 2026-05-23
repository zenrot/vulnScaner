#!/usr/bin/env sh
set -eu

FIXTURE="tests/fixtures/scan-response.json"
SCRIPT="scripts/format-mr-comment.sh"
PASS=0
FAIL=0

ok() {  printf '  \033[32m✓\033[0m %s\n' "$1"; PASS=$((PASS+1)); }
err() { printf '  \033[31m✗\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }

echo "=== format-mr-comment.sh ==="
OUTPUT=$(sh "$SCRIPT" "$FIXTURE")

check() {
  if printf '%s' "$OUTPUT" | grep -qF "$1"; then ok "$1"
  else err "missing: $1"; fi
}

check "<!-- sast-bot -->"
check "## 🔒 Отчёт SAST"
check "🔴 FAIL"
check "Проверено"
check "Command Injection"
check "true_positive"
check "needs_review"
check "Hardcoded Secret"
check "SQL Injection"

COUNT=$(printf '%s' "$OUTPUT" | grep -c "<!-- sast-bot -->" || true)
if [ "$COUNT" -eq 1 ]; then ok "sast-bot marker appears exactly once"
else err "sast-bot marker appears $COUNT times (expected 1)"; fi

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="

[ "$FAIL" -eq 0 ]
