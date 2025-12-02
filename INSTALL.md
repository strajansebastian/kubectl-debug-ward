# Installing debug-ward Locally

This guide shows how to build and install `kubectl-debug-ward` as a local binary that you can use directly without Docker.

## Quick Install

```bash
./docker-install.sh
```

This script:
1. Builds the binary in a Docker container (no local Go needed)
2. Extracts the binary from the container
3. Installs it to `~/.local/bin/` (or `~/bin/` if it exists)
4. Makes it executable

## After Installation

### Add to PATH

The script will tell you where the binary was installed. Add it to your PATH:

```bash
# For zsh
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc

# For bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

### Verify Installation

```bash
kubectl debug-ward --help
```

## Usage

Once installed, use it like any kubectl plugin:

```bash
# Basic usage
kubectl debug-ward -n <namespace> <pod-name>

# Example
kubectl debug-ward -n test-source-ns test-pod-with-security

# JSON output
kubectl debug-ward -n test-source-ns test-pod-with-security --output=json

# Direct creation
kubectl debug-ward -n test-source-ns test-pod-with-security --dry-run=false
```

## Installation Locations

The script tries these locations in order:
1. `~/.local/bin/` (creates if needed)
2. `~/bin/` (if it exists)

You can override by setting `INSTALL_DIR`:

```bash
INSTALL_DIR=/usr/local/bin ./docker-install.sh
```

## Manual Installation

If you prefer to install manually:

```bash
# Build in Docker
docker build -f Dockerfile.build -t kubectl-debug-ward-builder:latest .

# Create container
CONTAINER_ID=$(docker create kubectl-debug-ward-builder:latest)

# Find binary
BIN_PATH=$(docker exec $CONTAINER_ID find /build/release/bin -name kubectl-debug-ward -type f | head -1)

# Extract binary
docker cp $CONTAINER_ID:$BIN_PATH ./kubectl-debug-ward

# Clean up
docker rm $CONTAINER_ID

# Install
chmod +x ./kubectl-debug-ward
sudo mv ./kubectl-debug-ward /usr/local/bin/  # or ~/.local/bin/
```

## Requirements

- Docker (for building)
- kubectl (for using the plugin)
- Kubernetes cluster access

**No Go installation needed!** The binary is built entirely in Docker.

## Updating

To update to a new version:

```bash
./docker-install.sh
```

This will rebuild and reinstall the binary.

## Troubleshooting

### Binary not found after installation

Check if the install directory is in your PATH:

```bash
echo $PATH | grep -q "$HOME/.local/bin" && echo "In PATH" || echo "Not in PATH"
```

### Permission denied

Make sure the binary is executable:

```bash
chmod +x ~/.local/bin/kubectl-debug-ward
```

### kubectl plugin not recognized

kubectl plugins must be named `kubectl-<plugin-name>`. The binary is already named correctly as `kubectl-debug-ward`.

Verify:
```bash
which kubectl-debug-ward
kubectl debug-ward --help
```

## Comparison: Docker vs Local Install

| Feature | Docker (`docker-run.sh`) | Local Install |
|---------|-------------------------|---------------|
| Build | ✅ One-time build | ✅ One-time build |
| Run | `./docker-run.sh kubectl-debug-ward ...` | `kubectl debug-ward ...` |
| Speed | Slower (container startup) | ✅ Faster (direct binary) |
| Dependencies | Docker only | Docker (build), kubectl (run) |
| PATH setup | ❌ Not needed | ✅ Required once |

## See Also

- [SIMPLE_RUN.md](SIMPLE_RUN.md) - Simple usage examples
- [DOCKER_RUN.md](DOCKER_RUN.md) - Docker-based usage
- [README.md](README.md) - General documentation











