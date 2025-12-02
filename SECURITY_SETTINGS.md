# Security Settings Management

This document explains how `kubectl-debug-ward` handles security settings when copying pods between namespaces, and how you can preserve or override specific security configurations.

## Overview

When copying a pod from a source namespace (with security policies) to a destination namespace (without security policies), `kubectl-debug-ward` by default:

1. **Overrides** security contexts to allow debugging
2. **Removes** restrictive security policies
3. **Sets** privileged mode and root user access

However, you can customize which security settings to preserve or override.

## Default Behavior

By default, `kubectl-debug-ward` applies the following security overrides:

### Pod Security Context
- `runAsUser`: `0` (root)
- `runAsGroup`: `0` (root group)
- `fsGroup`: `0`
- `runAsNonRoot`: `false`
- `supplementalGroups`: `[]` (empty)
- `sysctls`: `[]` (empty)

### Container Security Context
- `privileged`: `true`
- `readOnlyRootFilesystem`: `false`
- `runAsUser`: `0` (root)
- `runAsGroup`: `0` (root group)
- `runAsNonRoot`: `false`
- `allowPrivilegeEscalation`: (removed/not set)

## Current Implementation

The current version of `kubectl-debug-ward` applies these security overrides by default. The following flags are planned but not yet fully implemented:

### Planned Pod Security Context Flags

```bash
--psc-runasuser=0              # Pod runAsUser
--psc-runasgroup=0             # Pod runAsGroup
--psc-fsgroup=0                # Pod FSGroup
--psc-fsgroupchangepolicy=Always  # Pod FSGroupChangePolicy
--psc-selinuxoptions="..."     # Pod SELinux options
--psc-seccompprofile="..."     # Pod Seccomp profile
--psc-supplementalgroups="1,2" # Pod supplemental groups
--psc-sysctls="net.ipv4.ip_forward=1"  # Pod sysctls
```

### Planned Container Security Context Flags

```bash
--pcsc-allowprivilegeescalation=true   # Allow privilege escalation
--pcsc-capabilities="NET_ADMIN,SYS_ADMIN"  # Capabilities
--pcsc-privileged=true                  # Privileged mode
--pcsc-procmount="..."                  # Proc mount type
--pcsc-readonlyfilesystem=false         # Read-only root filesystem
--pcsc-runasuser=0                      # Container runAsUser
--pcsc-runasgroup=0                      # Container runAsGroup
--pcsc-runasnonroot=false               # Run as non-root
--pcsc-selinuxoptions="..."              # Container SELinux options
--pcsc-seccompprofile="..."             # Container Seccomp profile
```

## Ways to Preserve Security Settings

### Method 1: Use Output Mode and Edit YAML

After creating the pod, modify it with `kubectl`:

```bash
# Copy the pod
kubectl debug-ward -n source-ns pod-name --dry-run=false

# Then patch it to restore specific security settings
kubectl patch pod <pod-name> -n debug-ward-tmp --type=json -p='[
  {
    "op": "replace",
    "path": "/spec/securityContext/runAsUser",
    "value": 1000
  },
  {
    "op": "replace",
    "path": "/spec/containers/0/securityContext/readOnlyRootFilesystem",
    "value": true
  }
]'
```

### Method 3: Use Output Mode and Edit

1. Generate the YAML with dry-run:
```bash
kubectl debug-ward -n source-ns pod-name > debug-pod.yaml
```

2. Edit the YAML to restore desired security settings:
```yaml
spec:
  securityContext:
    runAsUser: 1000  # Restore original
    runAsGroup: 1000
  containers:
  - name: app-container
    securityContext:
      readOnlyRootFilesystem: true  # Restore original
      privileged: false  # Remove privilege escalation
```

3. Apply the edited YAML:
```bash
kubectl apply -f debug-pod.yaml
```

### Method 4: Create a Wrapper Script

Create a script that calls debug-ward and then patches the result:

```bash
#!/bin/bash
# preserve-security.sh

SOURCE_NS=$1
POD_NAME=$2
DEST_NS=${3:-debug-ward-tmp}

# Copy the pod
kubectl debug-ward -n $SOURCE_NS $POD_NAME --debug-warn-namespace=$DEST_NS --dry-run=false

# Get the created pod name
POD_NAME_NEW=$(kubectl get pods -n $DEST_NS -l debug-ward=true -o jsonpath='{.items[0].metadata.name}')

# Restore specific security settings
kubectl patch pod $POD_NAME_NEW -n $DEST_NS --type=json -p='[
  {"op": "replace", "path": "/spec/securityContext/runAsUser", "value": 1000},
  {"op": "replace", "path": "/spec/securityContext/runAsGroup", "value": 1000},
  {"op": "replace", "path": "/spec/containers/0/securityContext/readOnlyRootFilesystem", "value": true},
  {"op": "replace", "path": "/spec/containers/0/securityContext/privileged", "value": false}
]'
```

## Selective Override Examples

### Example 1: Keep Original User IDs

If you want to keep the original user/group IDs but remove other restrictions:

```bash
# Generate output
kubectl debug-ward -n source-ns pod-name --output=yaml > debug-pod.yaml

# Edit to restore original user/group IDs
# Change in YAML:
# spec:
#   securityContext:
#     runAsUser: 1000  # Restore original value
#     runAsGroup: 1000  # Restore original value
#     fsGroup: 0        # Keep override

# Apply
kubectl apply -f debug-pod.yaml
```

### Example 2: Conditional Privilege Escalation

Only enable privileged mode for specific containers:

```bash
# Generate output
kubectl debug-ward -n source-ns pod-name --output=yaml > debug-pod.yaml

# Edit YAML to set privileged only for specific containers:
# containers:
# - name: app-container
#   securityContext:
#     privileged: true   # Keep for debugging
# - name: sidecar
#   securityContext:
#     privileged: false  # Disable for sidecar

# Apply
kubectl apply -f debug-pod.yaml
```

### Example 3: Preserve Volume Mount Permissions

Volume mounts are automatically preserved (except kube-api-access volumes which are removed):

```bash
# Generate output - volume mounts are already preserved
kubectl debug-ward -n source-ns pod-name --output=yaml > debug-pod.yaml

# Review volume mounts in the generated YAML
# They match the original pod (minus kube-api-access)

# Apply
kubectl apply -f debug-pod.yaml
```

## Best Practices

1. **Use Dry-Run First**: Always check what will be created with `--dry-run=true` (default)

2. **Review Security Contexts**: Compare source and destination security contexts:
   ```bash
   # Source
   kubectl get pod <pod-name> -n source-ns -o jsonpath='{.spec.securityContext}' | jq
   
   # Destination (after copy)
   kubectl get pod <pod-name> -n dest-ns -o jsonpath='{.spec.securityContext}' | jq
   ```

3. **Namespace Labels**: Use namespace labels to identify debug namespaces:
   ```yaml
   metadata:
     labels:
       debug-ward: "true"
       security-policy: "disabled"
   ```

4. **Gradual Override**: Start with minimal overrides and add more as needed for debugging

5. **Document Changes**: Keep track of which security settings you override and why

## Future Enhancements

The following features are planned for future releases:

- [ ] Command-line flags for all security context options
- [ ] Config file for security override presets
- [ ] Option to preserve specific security settings
- [ ] Security context diff view (before/after)
- [ ] Template-based security overrides

## Related Documentation

- [DOCKER.md](DOCKER.md) - Docker-based development
- [README.md](README.md) - General usage
- [test-resources/README.md](test-resources/README.md) - Test setup

