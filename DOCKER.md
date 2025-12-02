# Docker-based Development and Testing

This document describes how to build, run, and test `kubectl-debug-ward` entirely within Docker containers. This approach eliminates the need for local Go installation and ensures consistent builds across different environments.

## Prerequisites

- Docker installed and running
- Kubernetes cluster accessible (minikube, kind, or remote cluster)
- `kubectl` configured to access your cluster
- Kubeconfig file at `~/.kube/config` (or set `KUBECONFIG` environment variable)

## Quick Start

### 1. Build the Docker Images

```bash
./docker-build.sh
```

This script builds three separate images:
- **kubectl-debug-ward-builder:latest** - Build image with Go (used to compile the binary)
- **kubectl-debug-ward:latest** - Runtime image (minimal Alpine with kubectl + binary)
- **kubectl-debug-ward-dev:latest** - Development image (with build tools for interactive use)

The build process:
1. Builds the binary in the builder image
2. Creates a minimal runtime image with just kubectl and the compiled binary
3. Creates a dev image with Go tools for development

**No local Go installation required!**

### 2. Run the Tool

#### Runtime Mode (Minimal - Recommended)

```bash
# Run a command directly (uses minimal runtime image)
./docker-run.sh kubectl-debug-ward -n test-debug-ward test-pod-with-security
```

#### Development Mode (With Build Tools)

```bash
# Interactive shell with Go and build tools
./docker-run.sh --dev bash

# Or run commands in dev mode
./docker-run.sh --dev kubectl-debug-ward -n test-debug-ward test-pod-with-security
```

**Runtime mode** uses a minimal Alpine image (~50MB) with just kubectl and the binary.
**Dev mode** uses a larger image with Go tools, useful for rebuilding or debugging.

### 3. Test the Tool

After building, you can test the tool:

```bash
# Test with output mode (default)
./docker-run.sh kubectl-debug-ward -n test-source-ns test-pod-with-security

# Test with actual creation
./docker-run.sh kubectl-debug-ward -n test-source-ns test-pod-with-security --dry-run=false
```

## Detailed Usage

### Building the Images

The `docker-build.sh` script uses a multi-stage build approach:

1. **Dockerfile.build** - Builder image (golang:1.21-alpine)
   - Contains Go compiler
   - Builds the binary
   - Outputs to `/build/release/bin/`

2. **Dockerfile** - Runtime image (alpine:3.18)
   - Minimal Alpine Linux
   - kubectl installed
   - Binary copied from builder
   - ~50MB final image size

3. **Dockerfile.dev** - Development image (golang:1.21-alpine)
   - Go compiler + kubectl
   - Source code included
   - For interactive development

**Build with custom version:**

```bash
DEBUG_WARD_GIT_VERSION=v1.0.0 ./docker-build.sh
```

**Manual build (individual images):**

```bash
# Build builder
docker build -f Dockerfile.build -t kubectl-debug-ward-builder:latest .

# Build runtime (requires builder)
docker build -t kubectl-debug-ward:latest .

# Build dev
docker build -f Dockerfile.dev -t kubectl-debug-ward-dev:latest .
```

### Running Commands

The `docker-run.sh` script mounts:
- Source code directories (`cmd/`, `pkg/`, `release/`)
- Test resources (`test-resources/`)
- Kubeconfig directory
- Sets up environment variables

**Environment variables:**

- `KUBECONFIG`: Path to kubeconfig (default: `~/.kube/config`)
- `DEBUG_WARD_LOG_LEVEL`: Log level (default: `info`, options: `trace`, `debug`, `info`, `warn`, `error`)
- `DEBUG_WARD_GIT_VERSION`: Version tag (auto-detected from git)

**Examples:**

```bash
# Dry-run (default)
./docker-run.sh kubectl-debug-ward -n test-debug-ward test-pod-with-security

# Actual copy
./docker-run.sh kubectl-debug-ward -n test-debug-ward test-pod-with-security --dry-run=false

# With custom debug namespace
./docker-run.sh kubectl-debug-ward -n test-debug-ward test-pod-with-security --debug-warn-namespace=my-debug-ns

# With trace logging
DEBUG_WARD_LOG_LEVEL=trace ./docker-run.sh kubectl-debug-ward -n test-debug-ward test-pod-with-security
```

### Testing

You can test the tool manually:

1. **Setup test resources**:
   ```bash
   kubectl apply -f test-resources/source-namespace.yaml
   kubectl apply -f test-resources/test-configmap.yaml
   kubectl apply -f test-resources/test-secret.yaml
   kubectl apply -f test-resources/test-pod.yaml
   ```

2. **Test output mode**:
   ```bash
   ./docker-run.sh kubectl-debug-ward -n test-source-ns test-pod-with-security
   ```

3. **Test actual creation**:
   ```bash
   ./docker-run.sh kubectl-debug-ward -n test-source-ns test-pod-with-security --dry-run=false
   ```

**Cleanup after testing:**

```bash
kubectl delete namespace test-source-ns
kubectl delete namespace test-destination-ns
kubectl delete namespace debug-ward-tmp
```

## Development Workflow

### 1. Make Code Changes

Edit files in `cmd/` or `pkg/` directories.

### 2. Rebuild and Test

```bash
# Rebuild the image
./docker-build.sh

# Test the tool
./docker-run.sh kubectl-debug-ward -n test-source-ns test-pod-with-security
```

### 3. Interactive Development

```bash
# Get a shell in the container
./docker-run.sh bash

# Inside the container, you can:
# - Test: kubectl-debug-ward -n test-source-ns test-pod-with-security
# - Use kubectl: kubectl get pods -A
```

## Docker Image Structure

### Runtime Image (Dockerfile)
```
/alpine:3.18
├── /usr/local/bin/
│   ├── kubectl              # Kubernetes CLI
│   └── kubectl-debug-ward   # Compiled binary
└── /app/                    # Working directory
```

### Development Image (Dockerfile.dev)
```
/golang:1.21-alpine
├── /app/
│   ├── cmd/                 # Source code
│   ├── pkg/                 # Package code
│   └── release/              # Build output
├── /usr/local/bin/
│   ├── kubectl
│   └── kubectl-debug-ward
└── Go tools available for rebuilding
```

### Builder Image (Dockerfile.build)
```
/golang:1.21-alpine
└── /build/
    └── release/bin/
        └── kubectl-debug-ward-<version>/
            └── kubectl-debug-ward  # Binary output
```

## Troubleshooting

### Docker daemon not running

```bash
# macOS
open -a Docker

# Linux
sudo systemctl start docker
```

### Kubeconfig not found

```bash
# Check if kubeconfig exists
ls -la ~/.kube/config

# Or set KUBECONFIG explicitly
export KUBECONFIG=/path/to/your/kubeconfig
./docker-run.sh kubectl-debug-ward ...
```

### Permission denied

```bash
# Make scripts executable
chmod +x docker-build.sh docker-run.sh docker-test.sh
```

### Image pull errors in test pods

If test pods fail to pull images, ensure your cluster has internet access or use images available in your cluster:

```bash
# Edit test-resources/test-pod.yaml
# Change image: nginx:alpine to an image available in your cluster
```

## Advanced Usage

### Custom Build Arguments

```bash
docker build \
    --build-arg DEBUG_WARD_GIT_VERSION=v1.2.3 \
    -t kubectl-debug-ward:v1.2.3 \
    .
```

### Running with Different Kubeconfig

```bash
KUBECONFIG=/path/to/other/config ./docker-run.sh kubectl-debug-ward ...
```

### Debugging Inside Container

```bash
# Get shell access (runtime mode)
./docker-run.sh bash

# Get shell access (dev mode with Go tools)
./docker-run.sh --dev bash

# Inside container:
which kubectl-debug-ward
kubectl-debug-ward --help
kubectl get nodes
env | grep DEBUG_WARD
env | grep KUBECONFIG

# In dev mode, you can test and debug the tool
```

### Image Sizes

- **kubectl-debug-ward:latest** (runtime): ~50MB
- **kubectl-debug-ward-dev:latest** (dev): ~400MB
- **kubectl-debug-ward-builder:latest** (builder): ~400MB

The runtime image is kept minimal to reduce download time and storage.

## Integration with CI/CD

Example GitHub Actions workflow:

```yaml
name: Test
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Build Docker image
        run: ./docker-build.sh
      - name: Test tool
        run: ./docker-run.sh kubectl-debug-ward --help
        env:
          KUBECONFIG: ${{ secrets.KUBECONFIG }}
```

## See Also

- [README.md](README.md) - General project documentation
- [test-resources/README.md](test-resources/README.md) - Test resources documentation

