#!/bin/sh
set -e

# Parse inputs from action.yml args.
# POSIX sh only supports $1-$9 directly; use shift for args 10+.
PATH_ARG="${1:-.}"
MODE="${2:-full}"
FORMAT="${3:-sarif}"
OUTPUT_DIR="${4:-/tmp/oqs-results}"
FAIL_ON="${5:-}"
NO_CONFIG=$(echo "${6:-true}" | tr '[:upper:]' '[:lower:]')
UPLOAD_SARIF=$(echo "${7:-true}" | tr '[:upper:]' '[:lower:]')
PR_COMMENT=$(echo "${8:-false}" | tr '[:upper:]' '[:lower:]')
COMPLIANCE="${9:-}"
shift 9 2>/dev/null || true
CI_MODE="${1:-blocking}"
DATA_LIFETIME="${2:-0}"
WEBHOOK_URL="${3:-}"

# Select command based on mode
SCAN_CMD="scan"
DIFF_BASE_VAL=""
if [ "$MODE" = "diff" ]; then
  SCAN_CMD="diff"
  DIFF_BASE_VAL="${DIFF_BASE:-origin/main}"
fi

# Build --no-config flag if enabled (default: true for CI security)
NO_CONFIG_FLAG=""
if [ "$NO_CONFIG" = "true" ]; then
  NO_CONFIG_FLAG="--no-config"
fi

# Run the scanner with JSON output for metric extraction.
# All flag values are properly quoted to prevent word-splitting/glob injection.
SCAN_EXIT=0
oqs-scanner "$SCAN_CMD" --path "$PATH_ARG" --format json --output "${OUTPUT_DIR}.json" \
  --incremental --cache-path /tmp/oqs-ci-cache.json \
  ${NO_CONFIG_FLAG:+"$NO_CONFIG_FLAG"} \
  ${FAIL_ON:+--fail-on "$FAIL_ON"} \
  ${DIFF_BASE_VAL:+--base "$DIFF_BASE_VAL"} \
  ${COMPLIANCE:+--compliance "$COMPLIANCE"} \
  ${CI_MODE:+--ci-mode "$CI_MODE"} \
  ${DATA_LIFETIME:+--data-lifetime-years "$DATA_LIFETIME"} \
  ${WEBHOOK_URL:+--webhook-url "$WEBHOOK_URL"} \
  || SCAN_EXIT=$?

# Initialize metric variables with sane defaults (used by PR comment even if JSON fails)
QRS="0"; QRS_GRADE="N/A"; FINDINGS="0"; CRITICAL="0"; DEPRECATED="0"; QUANTUM_SAFE="0"

# Parse outputs from JSON result using correct field names
if [ -f "${OUTPUT_DIR}.json" ]; then
  QRS=$(python3 -c "import sys,json; d=json.load(sys.stdin); q=d.get('quantumReadinessScore'); print(q.get('score',0) if q else 0)" < "${OUTPUT_DIR}.json" 2>/dev/null || echo "0")
  QRS_GRADE=$(python3 -c "import sys,json; d=json.load(sys.stdin); q=d.get('quantumReadinessScore'); print(str(q.get('grade','N/A'))[:3] if q else 'N/A')" < "${OUTPUT_DIR}.json" 2>/dev/null || echo "N/A")
  FINDINGS=$(python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('summary',{}).get('totalFindings',0))" < "${OUTPUT_DIR}.json" 2>/dev/null || echo "0")
  CRITICAL=$(python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('summary',{}).get('quantumVulnerable',0))" < "${OUTPUT_DIR}.json" 2>/dev/null || echo "0")
  DEPRECATED=$(python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('summary',{}).get('deprecated',0))" < "${OUTPUT_DIR}.json" 2>/dev/null || echo "0")
  QUANTUM_SAFE=$(python3 -c "import sys,json; d=json.load(sys.stdin); s=d.get('summary',{}); print(int(s.get('quantumSafe',0))+int(s.get('quantumResistant',0)))" < "${OUTPUT_DIR}.json" 2>/dev/null || echo "0")

  # Write outputs for GitHub Actions
  if [ -n "$GITHUB_OUTPUT" ]; then
    echo "quantum-readiness-score=${QRS}" >> "$GITHUB_OUTPUT"
    echo "finding-count=${FINDINGS}" >> "$GITHUB_OUTPUT"
    echo "critical-count=${CRITICAL}" >> "$GITHUB_OUTPUT"
  fi
fi

# Generate requested format output if not JSON (reuse scan results, don't rescan)
if [ "$FORMAT" != "json" ]; then
  if ! oqs-scanner "$SCAN_CMD" --path "$PATH_ARG" --format "$FORMAT" --output "$OUTPUT_DIR" \
    --incremental --cache-path /tmp/oqs-ci-cache.json \
    ${NO_CONFIG_FLAG:+"$NO_CONFIG_FLAG"} \
    ${FAIL_ON:+--fail-on "$FAIL_ON"} \
    ${DIFF_BASE_VAL:+--base "$DIFF_BASE_VAL"} \
    ${COMPLIANCE:+--compliance "$COMPLIANCE"} \
    ${CI_MODE:+--ci-mode "$CI_MODE"} \
    ${DATA_LIFETIME:+--data-lifetime-years "$DATA_LIFETIME"} 2>&1; then
    echo "::warning::Secondary format ($FORMAT) generation failed"
  fi
fi

# Always generate SARIF for GitHub Code Scanning upload when upload-sarif=true
SARIF_PATH="${OUTPUT_DIR}.sarif"
if [ "$UPLOAD_SARIF" = "true" ] && [ "$FORMAT" != "sarif" ]; then
  # Generate SARIF for Code Scanning. Use incremental mode to avoid re-scanning.
  # Errors are logged but don't fail the overall action (SARIF upload is best-effort).
  if ! oqs-scanner "$SCAN_CMD" --path "$PATH_ARG" --format sarif --output "$SARIF_PATH" \
    --incremental --cache-path /tmp/oqs-ci-cache.json \
    ${NO_CONFIG_FLAG:+"$NO_CONFIG_FLAG"} \
    ${DIFF_BASE_VAL:+--base "$DIFF_BASE_VAL"} \
    ${COMPLIANCE:+--compliance "$COMPLIANCE"} 2>&1; then
    echo "::warning::SARIF generation failed — Code Scanning upload will be skipped"
  fi
elif [ "$FORMAT" = "sarif" ]; then
  # SARIF was already generated as the primary format — copy/rename to .sarif extension
  if [ -f "$OUTPUT_DIR" ]; then
    cp "$OUTPUT_DIR" "$SARIF_PATH"
  fi
fi

# Write CBOM output path if cbom format was requested
if [ "$FORMAT" = "cbom" ] && [ -n "$GITHUB_OUTPUT" ]; then
  echo "cbom-path=${OUTPUT_DIR}" >> "$GITHUB_OUTPUT"
fi

# Set SARIF path in output for downstream upload-sarif action
if [ -n "$GITHUB_OUTPUT" ] && [ -f "$SARIF_PATH" ]; then
  echo "sarif-path=${SARIF_PATH}" >> "$GITHUB_OUTPUT"
fi

# Write step summary if available
if [ -n "$GITHUB_STEP_SUMMARY" ] && [ -f "${OUTPUT_DIR}.json" ]; then
  python3 -c "
import sys, json
d = json.load(sys.stdin)
q = d.get('quantumReadinessScore')
s = d.get('summary', {})
score = int(q.get('score', 0)) if q else 'N/A'
grade = str(q.get('grade', 'N/A'))[:3] if q else 'N/A'
total = int(s.get('totalFindings', 0))
vuln = int(s.get('quantumVulnerable', 0))
safe = int(s.get('quantumSafe', 0)) + int(s.get('quantumResistant', 0))
print(f'## OQS Scanner Results')
print(f'| Metric | Value |')
print(f'|--------|-------|')
print(f'| Quantum Readiness Score | **{score}** ({grade}) |')
print(f'| Total Findings | {total} |')
print(f'| Quantum Vulnerable | {vuln} |')
print(f'| Quantum Safe/Resistant | {safe} |')
" < "${OUTPUT_DIR}.json" >> "$GITHUB_STEP_SUMMARY" 2>/dev/null || true
fi

# Post PR comment if requested and running on a pull_request event
if [ "$PR_COMMENT" = "true" ] && [ "$GITHUB_EVENT_NAME" = "pull_request" ]; then
  # Guard: token must be present
  if [ -z "$GITHUB_TOKEN" ]; then
    echo "::warning::pr-comment requires GITHUB_TOKEN with pull-requests: write permission"
  else
    PR_NUMBER=$(jq -r '.pull_request.number' "$GITHUB_EVENT_PATH" 2>/dev/null || echo "")
    IS_FORK=$(jq -r '.pull_request.head.repo.fork // false' "$GITHUB_EVENT_PATH" 2>/dev/null || echo "false")

    # Fork PRs have read-only GITHUB_TOKEN — comment will fail
    if [ "$IS_FORK" = "true" ]; then
      echo "::warning::PR comments not supported for fork PRs (GITHUB_TOKEN is read-only)"
    elif [ -n "$PR_NUMBER" ] && [ "$PR_NUMBER" != "null" ]; then
      # Sanitize VERSION to alphanumeric, dots, hyphens only
      VERSION=$(oqs-scanner version 2>/dev/null | head -1 | tr -cd '[:alnum:].-' || echo "unknown")

      COMMENT_BODY="<!-- oqs-scanner-comment -->
## OQS Scanner Results

**Quantum Readiness Score:** ${QRS}/100 (Grade: ${QRS_GRADE})

| Metric | Count |
|--------|-------|
| Total Findings | ${FINDINGS} |
| Quantum Vulnerable | ${CRITICAL} |
| Deprecated | ${DEPRECATED} |
| Quantum Safe/Resistant | ${QUANTUM_SAFE} |

<details>
<summary>What do these results mean?</summary>

- **Quantum Vulnerable**: Algorithms broken by quantum computers (RSA, ECDSA, ECDH, DH). Migrate to ML-KEM/ML-DSA.
- **Deprecated**: Classically broken algorithms (MD5, DES, RC4). Replace immediately.
- **Quantum Safe/Resistant**: Algorithms that resist quantum attacks (AES-256, SHA-256, ML-KEM).

</details>

---
*Scanned by [OQS Scanner](https://github.com/jimbo111/open-quantum-secure) v${VERSION}*"

      # Check for existing OQS comment (use hidden marker, per_page=100 for pagination)
      EXISTING_COMMENT_ID=$(curl -sf \
          -H "Authorization: token ${GITHUB_TOKEN}" \
          -H "Accept: application/vnd.github.v3+json" \
          "https://api.github.com/repos/${GITHUB_REPOSITORY}/issues/${PR_NUMBER}/comments?per_page=100&direction=desc" \
          | jq -r '.[] | select(.body | contains("oqs-scanner-comment")) | .id' 2>/dev/null | head -1 || echo "")

      COMMENT_JSON=$(jq -n --arg body "$COMMENT_BODY" '{body: $body}')

      if [ -n "$EXISTING_COMMENT_ID" ] && [ "$EXISTING_COMMENT_ID" != "null" ]; then
        # Update existing comment
        curl -sf -X PATCH \
            -H "Authorization: token ${GITHUB_TOKEN}" \
            -H "Accept: application/vnd.github.v3+json" \
            "https://api.github.com/repos/${GITHUB_REPOSITORY}/issues/comments/${EXISTING_COMMENT_ID}" \
            -d "$COMMENT_JSON" > /dev/null 2>&1 \
          && echo "Updated OQS Scanner comment on PR #${PR_NUMBER}" \
          || echo "::warning::Failed to update PR comment"
      else
        # Create new comment
        curl -sf -X POST \
            -H "Authorization: token ${GITHUB_TOKEN}" \
            -H "Accept: application/vnd.github.v3+json" \
            "https://api.github.com/repos/${GITHUB_REPOSITORY}/issues/${PR_NUMBER}/comments" \
            -d "$COMMENT_JSON" > /dev/null 2>&1 \
          && echo "Posted OQS Scanner results to PR #${PR_NUMBER}" \
          || echo "::warning::Failed to post PR comment"
      fi
    fi
  fi
fi

exit "$SCAN_EXIT"
