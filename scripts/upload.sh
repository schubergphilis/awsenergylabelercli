#!/usr/bin/env bash
# File: upload.sh
# Modern replacement for ci/scripts/upload.py

set -euo pipefail

echo "📤 Uploading package to PyPI..."

# Check if required environment variables are set
if [[ -z "${PYPI_API_TOKEN:-}" ]]; then
    echo "❌ PYPI_API_TOKEN environment variable is required"
    exit 1
fi

# First, build the package
echo "🏗️  Building package first..."
./scripts/build.sh

# Upload to PyPI
echo "🚀 Uploading to PyPI..."
python -m twine upload dist/* \
    --username __token__ \
    --password "$PYPI_API_TOKEN" \
    --skip-existing

echo "✅ Upload completed successfully!"
