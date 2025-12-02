# kubectl-debug-ward

Scope of the debug-ward project is to make debugging security policies inside kubernetes easier by allowing a copy of an existing pod without any security policies (or with a preselected list of security options in order to debug if the same behaviour is found in a namespace that is whitelisted from security policies enforced by Gatekeeper/Kyverno or other k8s security policy engines).

## Quick Start

### Option 1: Install Locally (Recommended)

Build and install the binary locally (no Docker needed for running):

```bash
# Build and install
./docker-install.sh

# Add to PATH (if not already)
export PATH="$HOME/.local/bin:$PATH"

# Use directly
kubectl debug-ward -n <namespace> <pod-name>
```

See [INSTALL.md](INSTALL.md) for installation details.

### Option 2: Run via Docker

Run the tool directly in Docker:

```bash
# Build the Docker image
./docker-build.sh

# Run the tool
./docker-run.sh kubectl-debug-ward -n <namespace> <pod-name>
```

See [DOCKER.md](DOCKER.md) for detailed Docker-based usage.

## Local Build (Requires Go)

### Build
```bash
bash release/build.sh
```

### Package the version and create the manifest
```bash
bash release/package.sh
```

## Usage

### Output Mode (default - prints YAML/JSON)

By default, `kubectl-debug-ward` runs in dry-run mode and outputs clean YAML that can be edited and applied:

```bash
# Print YAML (default)
kubectl debug-ward -n <namespace> <pod-name>

# Print JSON
kubectl debug-ward -n <namespace> <pod-name> --output=json

# Save to file for editing
kubectl debug-ward -n <namespace> <pod-name> --output=yaml > debug-pod.yaml
# Edit debug-pod.yaml, then: kubectl apply -f debug-pod.yaml
```

The output includes:
- ConfigMaps (referenced by the pod)
- Secrets (referenced by the pod)
- Pod (with security context overrides)

All runtime-only fields (UUID, status, owner references, etc.) are automatically removed.

### Direct Creation Mode

To create resources directly in the cluster:

```bash
kubectl debug-ward -n <namespace> <pod-name> --dry-run=false
```

### Custom Debug Namespace

```bash
kubectl debug-ward -n <namespace> <pod-name> --debug-warn-namespace=my-debug-ns
```

See [OUTPUT_MODE.md](OUTPUT_MODE.md) for detailed information about output formats and editing.

## What it does

1. **Reads the source pod** from the specified namespace
2. **Extracts dependencies**: ConfigMaps and Secrets referenced by the pod
3. **Cleans the pod spec**: Removes status, owner references, probes, resource limits, etc.
4. **Applies security overrides**: Sets privileged mode, removes security restrictions
5. **Creates resources**: In the debug namespace (default: `debug-ward-tmp`)

## Testing

Test resources are provided in `test-resources/` directory using **two separate namespaces**:
- **Source namespace**: `test-source-ns` (with security policies)
- **Destination namespace**: `test-destination-ns` (without security policies)

See [test-resources/README.md](test-resources/README.md) for details.

### Quick test:
```bash
# Set up test resources
kubectl apply -f test-resources/source-namespace.yaml
kubectl apply -f test-resources/test-configmap.yaml
kubectl apply -f test-resources/test-secret.yaml
kubectl apply -f test-resources/test-pod.yaml

# Test the tool
./docker-run.sh kubectl-debug-ward -n test-source-ns test-pod-with-security
```

## Security Settings

By default, `kubectl-debug-ward` overrides security contexts to allow debugging. To learn how to preserve or customize security settings, see [SECURITY_SETTINGS.md](SECURITY_SETTINGS.md).

## Documentation

- [INSTALL.md](INSTALL.md) - Local installation guide
- [SIMPLE_RUN.md](SIMPLE_RUN.md) - Simple usage examples
- [DOCKER.md](DOCKER.md) - Docker-based development and testing
- [DOCKER_RUN.md](DOCKER_RUN.md) - Running via Docker
- [OUTPUT_MODE.md](OUTPUT_MODE.md) - Output format (YAML/JSON) documentation
- [SECURITY_SETTINGS.md](SECURITY_SETTINGS.md) - Customizing security settings
- [test-resources/README.md](test-resources/README.md) - Test resources setup

## Legacy Docker Usage

For manual Docker usage:

```bash
# Build image
docker build -t kubectl-debug-ward:latest .

# Run interactive shell
docker run --rm -it \
    -v `pwd`/cmd:/app/cmd \
    -v `pwd`/pkg:/app/pkg \
    -v `pwd`/release:/app/release \
    -v  ~/.kube/:/config \
    -e KUBECONFIG=/config/config \
    -e DEBUG_WARD_LOG_LEVEL=trace \
    -e DEBUG_WARD_GIT_VERSION=`git describe --tags --abbrev=0` \
    kubectl-debug-ward:latest bash
```
