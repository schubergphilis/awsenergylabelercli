#!/usr/bin/env bash
# File: lint.sh
# Modern replacement for ci/scripts/lint.py

set -euo pipefail

echo "🔍 Running code quality checks..."

# Run Ruff linting (exclude old CI directory)
echo "🚀 Running Ruff..."
if ! ruff check . --exclude ci/; then
    echo "❌ Ruff found issues"
    exit 1
fi
echo "✅ Ruff passed"

# Run Pylint
echo "🐍 Running Pylint..."
if ! pylint awsenergylabelercli/ aws_energy_labeler_cli.py; then
    echo "❌ Pylint found issues"
    exit 1
fi
echo "✅ Pylint passed"

echo "✅ All linting checks passed!"
