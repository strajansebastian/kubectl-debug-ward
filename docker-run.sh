#!/bin/bash
# Run script for kubectl-debug-ward Docker container

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Parse arguments
USE_DEV=false
ARGS=()

while [[ $# -gt 0 ]]; do
    case $1 in
        --dev)
            USE_DEV=true
            shift
            ;;
        *)
            ARGS+=("$1")
            shift
            ;;
    esac
done

# Determine which image to use
if [ "$USE_DEV" = true ]; then
    IMAGE="kubectl-debug-ward-dev:latest"
    echo "Using development image (with build tools)"
else
    IMAGE="kubectl-debug-ward:latest"
    echo "Using runtime image (minimal)"
fi

# Check if image exists
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "Docker image not found. Building it first..."
    ./docker-build.sh
fi

# Get version from git if available
if git describe --tags --abbrev=0 >/dev/null 2>&1; then
    DEBUG_WARD_GIT_VERSION=$(git describe --tags --abbrev=0)
else
    DEBUG_WARD_GIT_VERSION=""
fi

# Check if KUBECONFIG is set, otherwise use default
KUBECONFIG_PATH="${KUBECONFIG:-$HOME/.kube/config}"

if [ ! -f "$KUBECONFIG_PATH" ]; then
    echo "Error: Kubeconfig not found at $KUBECONFIG_PATH"
    echo "Please set KUBECONFIG environment variable or ensure ~/.kube/config exists"
    exit 1
fi

echo "Running kubectl-debug-ward container..."
echo "Image: $IMAGE"
echo "Kubeconfig: $KUBECONFIG_PATH"
echo ""

# Prepare volume mounts
VOLUMES=(
    -v "$(dirname $KUBECONFIG_PATH):/config"
)

# In dev mode, mount source code for live editing
if [ "$USE_DEV" = true ]; then
    VOLUMES+=(
        -v "$SCRIPT_DIR/cmd:/app/cmd"
        -v "$SCRIPT_DIR/pkg:/app/pkg"
        -v "$SCRIPT_DIR/release:/app/release"
        -v "$SCRIPT_DIR/test-resources:/app/test-resources"
    )
fi

# Run the container
if [ ${#ARGS[@]} -eq 0 ]; then
    # No arguments - run default command (bash for dev, help for runtime)
    if [ "$USE_DEV" = true ]; then
        docker run --rm -it \
            "${VOLUMES[@]}" \
            -e KUBECONFIG=/config/$(basename $KUBECONFIG_PATH) \
            -e DEBUG_WARD_LOG_LEVEL="${DEBUG_WARD_LOG_LEVEL:-info}" \
            -e DEBUG_WARD_GIT_VERSION="${DEBUG_WARD_GIT_VERSION}" \
            "$IMAGE" \
            /bin/bash
    else
        docker run --rm -it \
            "${VOLUMES[@]}" \
            -e KUBECONFIG=/config/$(basename $KUBECONFIG_PATH) \
            -e DEBUG_WARD_LOG_LEVEL="${DEBUG_WARD_LOG_LEVEL:-info}" \
            -e DEBUG_WARD_GIT_VERSION="${DEBUG_WARD_GIT_VERSION}" \
            "$IMAGE" \
            --help
    fi
else
    # Run with provided arguments
    docker run --rm -it \
        "${VOLUMES[@]}" \
        -e KUBECONFIG=/config/$(basename $KUBECONFIG_PATH) \
        -e DEBUG_WARD_LOG_LEVEL="${DEBUG_WARD_LOG_LEVEL:-info}" \
        -e DEBUG_WARD_GIT_VERSION="${DEBUG_WARD_GIT_VERSION}" \
        "$IMAGE" \
        "${ARGS[@]}"
fi

