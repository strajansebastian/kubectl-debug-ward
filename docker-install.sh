#!/bin/bash
# Build and install kubectl-debug-ward binary locally from Docker

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Detect OS and architecture
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

# Map architecture
case $ARCH in
    x86_64)
        GOARCH="amd64"
        ;;
    arm64|aarch64)
        GOARCH="arm64"
        ;;
    *)
        GOARCH="amd64"
        echo "Warning: Unknown architecture $ARCH, defaulting to amd64"
        ;;
esac

# Map OS
case $OS in
    darwin)
        GOOS="darwin"
        ;;
    linux)
        GOOS="linux"
        ;;
    *)
        GOOS="linux"
        echo "Warning: Unknown OS $OS, defaulting to linux"
        ;;
esac

echo "Building for: $GOOS/$GOARCH"
echo ""

# Get version from git if available
if git describe --tags --abbrev=0 >/dev/null 2>&1; then
    DEBUG_WARD_GIT_VERSION=$(git describe --tags --abbrev=0)
    echo "Using git version: $DEBUG_WARD_GIT_VERSION"
else
    DEBUG_WARD_GIT_VERSION=""
    DEBUG_WARD_VERSION="v0.0.0"
    echo "No git tags found, using default version: $DEBUG_WARD_VERSION"
fi

echo "Building kubectl-debug-ward binary in Docker..."
echo ""

# Build the builder image with cross-compilation support
docker build \
    --build-arg DEBUG_WARD_GIT_VERSION="${DEBUG_WARD_GIT_VERSION}" \
    --build-arg DEBUG_WARD_VERSION="${DEBUG_WARD_VERSION:-v0.0.0}" \
    --build-arg GOOS="${GOOS}" \
    --build-arg GOARCH="${GOARCH}" \
    -f Dockerfile.build \
    -t kubectl-debug-ward-builder:latest \
    .

echo "Extracting binary from Docker container..."

# Create a temporary container and extract the binary
CONTAINER_ID=$(docker create kubectl-debug-ward-builder:latest)

# Find the binary path - it should be in /build/release/bin/kubectl-debug-ward-*/
BIN_PATH=$(docker run --rm kubectl-debug-ward-builder:latest sh -c 'find /build/release/bin -name kubectl-debug-ward -type f 2>/dev/null | head -1')

if [ -z "$BIN_PATH" ]; then
    echo "Error: Binary not found in container"
    echo "Checking container contents..."
    docker run --rm kubectl-debug-ward-builder:latest ls -la /build/release/bin/ 2>/dev/null || true
    docker rm $CONTAINER_ID > /dev/null 2>&1
    exit 1
fi

# Extract binary using docker run with volume mount (more reliable)
TEMP_BIN=$(mktemp)
docker run --rm \
    -v "$SCRIPT_DIR:/output" \
    kubectl-debug-ward-builder:latest \
    sh -c "cp $BIN_PATH /output/kubectl-debug-ward-temp && chmod +x /output/kubectl-debug-ward-temp"

if [ ! -f "$SCRIPT_DIR/kubectl-debug-ward-temp" ]; then
    echo "Error: Failed to extract binary from container"
    docker rm $CONTAINER_ID > /dev/null 2>&1
    exit 1
fi

TEMP_BIN="$SCRIPT_DIR/kubectl-debug-ward-temp"
docker rm $CONTAINER_ID > /dev/null 2>&1

# Determine install location
if [ -d "$HOME/.local/bin" ]; then
    INSTALL_DIR="$HOME/.local/bin"
elif [ -d "$HOME/bin" ]; then
    INSTALL_DIR="$HOME/bin"
else
    INSTALL_DIR="$HOME/.local/bin"
    mkdir -p "$INSTALL_DIR"
fi

INSTALL_PATH="$INSTALL_DIR/kubectl-debug-ward"

echo "Installing to: $INSTALL_PATH"
cp $TEMP_BIN $INSTALL_PATH
chmod +x $INSTALL_PATH
rm -f $TEMP_BIN

echo ""
echo "=========================================="
echo "Installation complete!"
echo "=========================================="
echo ""
echo "Binary installed to: $INSTALL_PATH"
echo ""
echo "Make sure $INSTALL_DIR is in your PATH:"
echo "  export PATH=\"$INSTALL_DIR:\$PATH\""
echo ""
echo "Then you can use it directly:"
echo "  kubectl debug-ward -n <namespace> <pod-name>"
echo ""
echo "Or add to your shell profile (~/.bashrc, ~/.zshrc, etc.):"
echo "  echo 'export PATH=\"$INSTALL_DIR:\$PATH\"' >> ~/.zshrc"
echo ""

