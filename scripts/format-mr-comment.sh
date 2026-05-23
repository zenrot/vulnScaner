#!/usr/bin/env sh
set -eu

SCAN_FILE="${1:-scan-response.json}"

if ! command -v jq > /dev/null 2>&1; then
  echo "Error: jq is required" >&2
  exit 1
fi
if [ ! -f "$SCAN_FILE" ]; then
  echo "Error: $SCAN_FILE not found" >&2
  exit 1
fi

SHOULD_FAIL=$(jq -r '.should_fail // false' "$SCAN_FILE")
TOTAL=$(jq -r '.report.stats.total_findings // 0' "$SCAN_FILE")
TRIAGED=$(jq -r '.report.stats.ai_triaged_findings // 0' "$SCAN_FILE")
TP=$(jq -r '.report.stats.true_positive_count // 0' "$SCAN_FILE")
NR=$(jq -r '.report.stats.needs_review_count // 0' "$SCAN_FILE")
FP=$(jq -r '.report.stats.false_positive_count // 0' "$SCAN_FILE")
FILES=$(jq -r '.report.scan_metrics.files_scanned // 0' "$SCAN_FILE")

if [ "$SHOULD_FAIL" = "true" ]; then
  STATUS="🔴 FAIL"
else
  STATUS="🟢 PASS"
fi

cat <<HEADER
## 🔒 Отчёт SAST

<!-- sast-bot -->

| | |
|---|---|
| **Статус** | ${STATUS} |
| **Файлов просканировано** | ${FILES} |
| **Всего находок** | ${TOTAL} |
| **Проверено** | ${TRIAGED} |
| **Реальные** | ${TP} |
| **На проверку** | ${NR} |
| **Ложные** | ${FP} |

HEADER

COUNT=$(jq '[.report.findings[] | select(.verdict.label == "true_positive" or .verdict.label == "needs_review")] | length' "$SCAN_FILE")

if [ "$COUNT" -gt 0 ]; then
  echo "### Находки"
  echo ""

  jq -c '[.report.findings[] | select(.verdict.label == "true_positive" or .verdict.label == "needs_review")] | .[:20][]' "$SCAN_FILE" \
  | while IFS= read -r item; do
    RULE=$(printf '%s' "$item" | jq -r '.finding.rule_id // ""')
    TITLE=$(printf '%s' "$item" | jq -r '.finding.title // .finding.rule_id // ""')
    SEV=$(printf '%s' "$item" | jq -r '.finding.severity // ""')
    FILE=$(printf '%s' "$item" | jq -r '.finding.file // ""' | sed 's|.*/||')
    LINE=$(printf '%s' "$item" | jq -r '.finding.line // "?"')
    LABEL=$(printf '%s' "$item" | jq -r '.verdict.label // ""')
    EVIDENCE=$(printf '%s' "$item" | jq -r '.finding.evidence // ""')
    RATIONALE=$(printf '%s' "$item" | jq -r '.verdict.rationale // ""')
    FIX=$(printf '%s' "$item" | jq -r '.verdict.remediation // ""')
    SNIPPET=$(printf '%s' "$item" | jq -r '.snippet // ""')

    case "$SEV" in
      CRITICAL|HIGH) ICON="🔴" ;;
      MEDIUM) ICON="🟡" ;;
      *) ICON="🔵" ;;
    esac

    printf '<details>\n'
    printf '<summary>%s %s · %s · %s (%s:%s)</summary>\n\n' "$ICON" "$SEV" "$LABEL" "$TITLE" "$FILE" "$LINE"
    [ -n "$EVIDENCE" ] && printf '**Свидетельство:** `%s`\n\n' "$EVIDENCE"
    [ -n "$RATIONALE" ] && printf '**Вердикт:** %s\n\n' "$RATIONALE"
    [ -n "$FIX" ] && printf '**Исправление:** %s\n\n' "$FIX"
    if [ -n "$SNIPPET" ]; then
      printf '```go\n%s\n```\n\n' "$SNIPPET"
    fi
    printf '</details>\n'
  done

  if [ "$COUNT" -gt 20 ]; then
    EXTRA=$((COUNT - 20))
    printf '\n*…и ещё %d находок. Смотри артефакты сборки.*\n' "$EXTRA"
  fi
fi
