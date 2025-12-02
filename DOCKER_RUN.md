# Running debug-ward via Docker

## Quick Start

### 1. Build the Docker Image

```bash
./docker-build.sh
```

This creates three images:
- `kubectl-debug-ward:latest` - Runtime image (minimal, ~50MB)
- `kubectl-debug-ward-dev:latest` - Development image (with Go tools)
- `kubectl-debug-ward-builder:latest` - Builder image (for building only)

### 2. Run debug-ward

```bash
./docker-run.sh kubectl-debug-ward -n <namespace> <pod-name>
```

## Examples

### Basic Run (Output YAML)

```bash
./docker-run.sh kubectl-debug-ward -n test-source-ns test-pod-with-security
```

**Output:**
```yaml
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: test-app-config
  namespace: debug-ward-tmp
  labels:
    debug-ward: "true"
data:
  app.properties: |
    server.port=8080
---
apiVersion: v1
kind: Secret
metadata:
  name: test-app-secret
  namespace: debug-ward-tmp
  labels:
    debug-ward: "true"
type: Opaque
data:
  username: dGVzdHVzZXI=
---
apiVersion: v1
kind: Pod
metadata:
  name: test-pod-with-security
  namespace: debug-ward-tmp
  labels:
    debug-ward: "true"
spec:
  securityContext:
    runAsUser: 0
    runAsGroup: 0
    fsGroup: 0
  containers:
  - name: app-container
    image: nginx:alpine
    securityContext:
      privileged: true
      readOnlyRootFilesystem: false
      runAsUser: 0
      runAsGroup: 0
      runAsNonRoot: false
```

### JSON Output

```bash
./docker-run.sh kubectl-debug-ward -n test-source-ns test-pod-with-security --output=json
```

### Save to File

```bash
./docker-run.sh kubectl-debug-ward -n test-source-ns test-pod-with-security > debug-pod.yaml
```

### Direct Creation (No Output)

```bash
./docker-run.sh kubectl-debug-ward -n test-source-ns test-pod-with-security --dry-run=false
```

This creates resources directly in the cluster.

### Custom Debug Namespace

```bash
./docker-run.sh kubectl-debug-ward -n test-source-ns test-pod-with-security \
  --debug-warn-namespace=my-debug-ns
```

### With Trace Logging

```bash
DEBUG_WARD_LOG_LEVEL=trace ./docker-run.sh kubectl-debug-ward -n test-source-ns test-pod-with-security
```

## Development Mode

For interactive development with Go tools:

```bash
# Interactive shell
./docker-run.sh --dev bash

# Run command in dev mode
./docker-run.sh --dev kubectl-debug-ward -n test-source-ns test-pod-with-security
```

## Environment Variables

The `docker-run.sh` script supports:

- `KUBECONFIG` - Path to kubeconfig (default: `~/.kube/config`)
- `DEBUG_WARD_LOG_LEVEL` - Log level: `trace`, `debug`, `info`, `warn`, `error` (default: `info`)

Example:
```bash
DEBUG_WARD_LOG_LEVEL=debug KUBECONFIG=/path/to/config ./docker-run.sh kubectl-debug-ward -n test-source-ns test-pod-with-security
```

## What Gets Mounted

The Docker container automatically mounts:
- Your kubeconfig directory (`~/.kube/` or `$KUBECONFIG` directory)
- Source code directories (in dev mode): `cmd/`, `pkg/`, `release/`
- Test resources (in dev mode): `test-resources/`

## Troubleshooting

### Docker image not found

```bash
# Build it first
./docker-build.sh
```

### Kubeconfig not found

```bash
# Check if kubeconfig exists
ls -la ~/.kube/config

# Or set KUBECONFIG explicitly
export KUBECONFIG=/path/to/your/kubeconfig
./docker-run.sh kubectl-debug-ward -n test-source-ns test-pod-with-security
```

### Permission denied

```bash
# Make script executable
chmod +x docker-run.sh
```

## Comparison: Docker vs Local

| Feature | Docker | Local |
|---------|--------|-------|
| Go installation | ❌ Not needed | ✅ Required |
| kubectl installation | ❌ Not needed | ✅ Required |
| Consistent environment | ✅ Yes | ❌ Depends on system |
| Image size | ~50MB (runtime) | N/A |
| Build time | First build: ~5min | Depends on Go setup |

## See Also

- [DOCKER.md](DOCKER.md) - Detailed Docker documentation
- [SIMPLE_RUN.md](SIMPLE_RUN.md) - Simple run examples
- [README.md](README.md) - General usage











