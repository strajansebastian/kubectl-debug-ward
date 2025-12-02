# Test Resources for kubectl-debug-ward

This directory contains test resources to verify the debug-ward functionality using **two separate namespaces**:
- **Source namespace** (`test-source-ns`): Contains the original pod with security policies
- **Destination namespace** (`test-destination-ns`): Where the pod will be copied without security restrictions

## Setup

1. Apply the test resources:
```bash
# Source namespace (with security policies)
kubectl apply -f source-namespace.yaml
kubectl apply -f test-configmap.yaml
kubectl apply -f test-secret.yaml
kubectl apply -f test-pod.yaml

# Destination namespace (without security policies)
kubectl apply -f destination-namespace.yaml
```

2. Wait for the pod to be created:
```bash
kubectl wait --for=condition=Ready pod/test-pod-with-security -n test-source-ns --timeout=60s
```

## Test the debug-ward

### Output Mode (default) - shows YAML/JSON that can be edited:
```bash
# Print YAML (default)
kubectl debug-ward -n test-source-ns test-pod-with-security --debug-warn-namespace=test-destination-ns

# Print JSON
kubectl debug-ward -n test-source-ns test-pod-with-security --debug-warn-namespace=test-destination-ns --output=json

# Save to file for editing
kubectl debug-ward -n test-source-ns test-pod-with-security --debug-warn-namespace=test-destination-ns --output=yaml > debug-pod.yaml
# Edit debug-pod.yaml, then apply: kubectl apply -f debug-pod.yaml
```

### Direct Creation Mode - creates resources immediately:
```bash
kubectl debug-ward -n test-source-ns test-pod-with-security \
  --debug-warn-namespace=test-destination-ns \
  --dry-run=false
```

See [OUTPUT_MODE.md](../OUTPUT_MODE.md) for details on output formats and editing.

### Using Docker (recommended):
```bash
# Run the demonstration script
./docker-demo.sh

# Or manually
./docker-run.sh kubectl-debug-ward \
  -n test-source-ns test-pod-with-security \
  --debug-warn-namespace=test-destination-ns
```

## Verify the Copy

### Compare security contexts:

**Source pod (with restrictions):**
```bash
kubectl get pod test-pod-with-security -n test-source-ns -o yaml | grep -A 10 securityContext
```

**Destination pod (without restrictions):**
```bash
kubectl get pod -n test-destination-ns -l debug-ward=true -o yaml | grep -A 10 securityContext
```

### Check created resources:
```bash
# In destination namespace
kubectl get all,configmaps,secrets -n test-destination-ns
```

## Namespace Structure

```
test-source-ns (source)
├── test-pod-with-security (original pod with security policies)
├── test-app-config (ConfigMap)
└── test-app-secret (Secret)

test-destination-ns (destination)
├── <pod-copy> (copied pod without security restrictions)
├── test-app-config (copied ConfigMap)
└── test-app-secret (copied Secret)
```

## Cleanup

```bash
kubectl delete namespace test-source-ns
kubectl delete namespace test-destination-ns
```

## Security Context Differences

The debug-ward tool will modify the security context as follows:

| Setting | Source (test-source-ns) | Destination (test-destination-ns) |
|---------|------------------------|-----------------------------------|
| `runAsUser` | 1000 | 0 (root) |
| `runAsGroup` | 1000 | 0 (root) |
| `runAsNonRoot` | true | false |
| `privileged` | false | true |
| `readOnlyRootFilesystem` | true | false |
| `allowPrivilegeEscalation` | false | (removed) |

See [SECURITY_SETTINGS.md](../SECURITY_SETTINGS.md) for details on preserving or customizing security settings.

