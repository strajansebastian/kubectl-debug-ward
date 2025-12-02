#!/bin/bash
# Build script for kubectl-debug-ward Docker images
# Uses multi-stage build: Dockerfile.build -> Dockerfile

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "Building kubectl-debug-ward Docker images..."
echo ""

# Get version from git if available, otherwise use default
if git describe --tags --abbrev=0 >/dev/null 2>&1; then
    DEBUG_WARD_GIT_VERSION=$(git describe --tags --abbrev=0)
    echo "Using git version: $DEBUG_WARD_GIT_VERSION"
else
    DEBUG_WARD_GIT_VERSION=""
    DEBUG_WARD_VERSION="v0.0.0"
    echo "No git tags found, using default version: $DEBUG_WARD_VERSION"
fi

# Step 1: Build the builder image (contains Go and builds the binary)
echo ""
echo "Step 1: Building builder image..."
docker build \
    --build-arg DEBUG_WARD_GIT_VERSION="${DEBUG_WARD_GIT_VERSION}" \
    --build-arg DEBUG_WARD_VERSION="${DEBUG_WARD_VERSION:-v0.0.0}" \
    -f Dockerfile.build \
    -t kubectl-debug-ward-builder:latest \
    .

# Step 2: Build the runtime image (minimal, just kubectl + binary)
# This references the builder image from step 1
echo ""
echo "Step 2: Building runtime image..."
docker build \
    -t kubectl-debug-ward:latest \
    -t kubectl-debug-ward:${DEBUG_WARD_GIT_VERSION:-${DEBUG_WARD_VERSION:-v0.0.0}} \
    .

# Step 3: Build the dev image (for interactive development)
echo ""
echo "Step 3: Building development image..."
docker build \
    --build-arg DEBUG_WARD_GIT_VERSION="${DEBUG_WARD_GIT_VERSION}" \
    -f Dockerfile.dev \
    -t kubectl-debug-ward-dev:latest \
    .

echo ""
echo "=========================================="
echo "Build complete!"
echo "=========================================="
echo ""
echo "Images created:"
echo "  - kubectl-debug-ward:latest (runtime - minimal)"
echo "  - kubectl-debug-ward:${DEBUG_WARD_GIT_VERSION:-${DEBUG_WARD_VERSION:-v0.0.0}} (runtime - versioned)"
echo "  - kubectl-debug-ward-dev:latest (development - with build tools)"
echo "  - kubectl-debug-ward-builder:latest (builder - for building only)"
echo ""
echo "To run the container:"
echo "  ./docker-run.sh"
echo ""
echo "To run in development mode:"
echo "  ./docker-run.sh --dev"

