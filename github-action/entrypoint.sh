#!/bin/bash
set -euo pipefail

SCAN_PATH="${1:-.}"
SCAN_TYPE="${2:-auto}"
FAIL_ON="${3:-high}"
CONFIG_PATH="${4:-}"
FORMAT="${5:-text}"
ORCHESIS_VERSION="${6:-latest}"

# Install specific version if requested.
if [ "${ORCHESIS_VERSION}" != "latest" ]; then
    pip install --no-cache-dir "orchesis==${ORCHESIS_VERSION}" 2>/dev/null || true
fi

echo "Orchesis Security Scanner"
echo "================================"
echo "Scan path: ${SCAN_PATH}"
echo "Scan type: ${SCAN_TYPE}"
echo "Fail on: ${FAIL_ON}"
echo "Format: ${FORMAT}"
echo ""

# Build scan command.
CMD="orchesis scan"
REPORT_FILE="/tmp/orchesis-report"

case "${SCAN_TYPE}" in
    mcp)
        if [ -n "${CONFIG_PATH}" ]; then
            CMD="${CMD} --mcp-config ${CONFIG_PATH}"
        else
            CMD="${CMD} --mcp"
        fi
        ;;
    skill)
        CMD="${CMD} ${SCAN_PATH}"
        ;;
    policy)
        CMD="${CMD} ${SCAN_PATH} --type policy"
        ;;
    auto)
        if [ -n "${CONFIG_PATH}" ]; then
            CMD="${CMD} --mcp-config ${CONFIG_PATH}"
        elif [ -f "${SCAN_PATH}/mcp.json" ] || [ -f "${SCAN_PATH}/.cursor/mcp.json" ]; then
            CMD="${CMD} --mcp"
        elif [ -f "${SCAN_PATH}/policy.yaml" ]; then
            CMD="${CMD} ${SCAN_PATH}/policy.yaml --type policy"
        elif [ -f "${SCAN_PATH}/policy.yml" ]; then
            CMD="${CMD} ${SCAN_PATH}/policy.yml --type policy"
        else
            CMD="${CMD} ${SCAN_PATH}"
        fi
        ;;
esac

case "${FORMAT}" in
    json)
        CMD="${CMD} --format json"
        REPORT_FILE="${REPORT_FILE}.json"
        ;;
    sarif)
        CMD="${CMD} --format sarif"
        REPORT_FILE="${REPORT_FILE}.sarif"
        ;;
    *)
        CMD="${CMD} --format text"
        REPORT_FILE="${REPORT_FILE}.txt"
        ;;
esac

CMD="${CMD} --severity ${FAIL_ON}"

echo "Running: ${CMD}"
echo ""

SCAN_OUTPUT=""
SCAN_EXIT=0
SCAN_OUTPUT="$(bash -lc "${CMD}" 2>&1)" || SCAN_EXIT=$?

echo "${SCAN_OUTPUT}"
echo "${SCAN_OUTPUT}" > "${REPORT_FILE}"

# Parse results for GitHub outputs.
SCORE="$(printf '%s\n' "${SCAN_OUTPUT}" | awk 'match($0,/Score:[[:space:]]*[0-9]+/){print substr($0,RSTART,RLENGTH)}' | awk '{print $2}' | head -1)"
[ -z "${SCORE}" ] && SCORE="0"

FINDINGS="$(printf '%s\n' "${SCAN_OUTPUT}" | awk 'match($0,/[Ff]ound[[:space:]]+[0-9]+[[:space:]]+issue/){print substr($0,RSTART,RLENGTH)}' | awk '{print $2}' | head -1)"
[ -z "${FINDINGS}" ] && FINDINGS="0"

CRITICAL="$(printf '%s\n' "${SCAN_OUTPUT}" | awk 'BEGIN{IGNORECASE=1} /CRITICAL/{c++} END{print c+0}')"
HIGH="$(printf '%s\n' "${SCAN_OUTPUT}" | awk 'BEGIN{IGNORECASE=1} /HIGH/{if ($0 !~ /NON-HIGH/) c++} END{print c+0}')"

echo "score=${SCORE}" >> "${GITHUB_OUTPUT}"
echo "findings-count=${FINDINGS}" >> "${GITHUB_OUTPUT}"
echo "critical-count=${CRITICAL}" >> "${GITHUB_OUTPUT}"
echo "high-count=${HIGH}" >> "${GITHUB_OUTPUT}"
echo "exit-code=${SCAN_EXIT}" >> "${GITHUB_OUTPUT}"
echo "report-path=${REPORT_FILE}" >> "${GITHUB_OUTPUT}"

FAIL=0
case "${FAIL_ON}" in
    critical)
        [ "${CRITICAL}" -gt 0 ] && FAIL=1
        ;;
    high)
        if [ "${CRITICAL}" -gt 0 ] || [ "${HIGH}" -gt 0 ]; then
            FAIL=1
        fi
        ;;
    medium|low)
        [ "${SCAN_EXIT}" -gt 0 ] && FAIL=1
        ;;
    none)
        FAIL=0
        ;;
esac

echo ""
echo "================================"
if [ "${FAIL}" -eq 0 ]; then
    echo "Security check PASSED (score: ${SCORE}/100)"
else
    echo "Security check FAILED (score: ${SCORE}/100)"
    echo "Found issues at or above '${FAIL_ON}' severity."
    echo "Fix findings above or adjust 'fail-on' threshold."
fi

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    {
        echo "## Orchesis Security Scan"
        echo ""
        if [ "${FAIL}" -eq 0 ]; then
            echo "PASSED - Score: ${SCORE}/100"
        else
            echo "FAILED - Score: ${SCORE}/100"
        fi
        echo ""
        echo "| Severity | Count |"
        echo "|----------|-------|"
        echo "| Critical | ${CRITICAL} |"
        echo "| High | ${HIGH} |"
        echo "| Total findings | ${FINDINGS} |"
        echo ""
        echo "<details><summary>Full Report</summary>"
        echo ""
        echo '```'
        echo "${SCAN_OUTPUT}"
        echo '```'
        echo ""
        echo "</details>"
        echo ""
        echo "*Powered by [Orchesis](https://github.com/poushwell/orchesis)*"
    } >> "${GITHUB_STEP_SUMMARY}"
fi

exit "${FAIL}"
