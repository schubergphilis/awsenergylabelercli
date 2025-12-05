#!/usr/bin/env bash
# File: build.sh
# Modern replacement for ci/scripts/build.py

set -euo pipefail

echo "🏗️  Building package..."

# Clean up previous builds
echo "🧹 Cleaning up previous builds..."
rm -rf build/ dist/ *.egg-info/

# Copy required files to package directory
echo "📁 Copying required files..."
cp .VERSION awsenergylabelercli/
cp LICENSE awsenergylabelercli/
cp AUTHORS.rst awsenergylabelercli/
cp CONTRIBUTING.rst awsenergylabelercli/
cp HISTORY.rst awsenergylabelercli/
cp README.rst awsenergylabelercli/

# Build the package
echo "📦 Building distribution packages..."
python -m build

# Check the built package
echo "🔍 Checking built package..."
python -m twine check dist/*

# Clean up copied files
echo "🧹 Cleaning up copied files..."
rm -f awsenergylabelercli/.VERSION
rm -f awsenergylabelercli/LICENSE
rm -f awsenergylabelercli/AUTHORS.rst
rm -f awsenergylabelercli/CONTRIBUTING.rst
rm -f awsenergylabelercli/HISTORY.rst
rm -f awsenergylabelercli/README.rst

echo "✅ Build completed successfully!"
