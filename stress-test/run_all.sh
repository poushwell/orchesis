#!/bin/bash
set -euo pipefail

echo "=== Orchesis Stress Test ==="
echo "Running 4 frameworks × 3 attacks × 2 modes = 24 tests"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

for framework in openclaw crewai langgraph openai_agents; do
    echo ""
    echo "--- Framework: $framework ---"
    cd "$framework"
    echo "Running WITHOUT Orchesis..."
    python run_without_orchesis.py || true
    echo "Running WITH Orchesis..."
    python run_with_orchesis.py || true
    cd ..
done

echo ""
echo "=== Analyzing Results ==="
python analyze_results.py
echo "Done! See results/summary.md"
