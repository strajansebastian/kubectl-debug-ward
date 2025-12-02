# Output Mode - YAML/JSON Generation

`kubectl-debug-ward` supports an output-only mode that generates clean YAML or JSON that can be edited and applied manually. This is useful when you want to:

- Review the changes before applying
- Customize security settings
- Apply to a different namespace or cluster
- Store the configuration for later use

## Default Behavior

By default, `kubectl-debug-ward` runs in **dry-run mode** (`--dry-run=true`), which means it only prints the output without creating resources.

## Output Formats

### YAML (Default)

```bash
kubectl debug-ward -n test-source-ns test-pod-with-security
```

Outputs clean YAML with:
- ConfigMaps (separated by `---`)
- Secrets (separated by `---`)
- Pod (separated by `---`)

### JSON

```bash
kubectl debug-ward -n test-source-ns test-pod-with-security --output=json
```

Outputs JSON format (one resource per line).

## Saving and Editing Output

### Save to File

```bash
# Save as YAML
kubectl debug-ward -n test-source-ns test-pod-with-security --output=yaml > debug-resources.yaml

# Save as JSON
kubectl debug-ward -n test-source-ns test-pod-with-security --output=json > debug-resources.json
```

### Edit the Output

The generated YAML/JSON is clean and ready to edit:

```yaml
# Example: debug-resources.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: test-app-config
  namespace: test-destination-ns
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
  namespace: test-destination-ns
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
  namespace: test-destination-ns
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

### Customize Before Applying

You can edit the file to:

1. **Change namespace**:
   ```yaml
   metadata:
     namespace: my-custom-debug-ns
   ```

2. **Restore security settings**:
   ```yaml
   spec:
     securityContext:
       runAsUser: 1000  # Restore original
       runAsNonRoot: true
   ```

3. **Modify container settings**:
   ```yaml
   containers:
   - name: app-container
     securityContext:
       privileged: false  # Disable privileged mode
       readOnlyRootFilesystem: true  # Re-enable read-only
   ```

4. **Add annotations or labels**:
   ```yaml
   metadata:
     annotations:
       debug-purpose: "troubleshooting"
     labels:
       debug-ward: "true"
       environment: "debug"
   ```

### Apply the Edited File

```bash
kubectl apply -f debug-resources.yaml
```

## What Gets Removed

The output mode automatically removes runtime-only fields that shouldn't be in the YAML/JSON:

### Removed from All Resources

- `creationTimestamp`
- `managedFields`
- `resourceVersion`
- `uid`
- `generation`
- `selfLink`
- `deletionTimestamp`
- `deletionGracePeriodSeconds`
- `finalizers`
- `ownerReferences`

### Removed from Pods

- `status` (entire status section)
- `generateName` (if present)
- System-generated labels (e.g., `pod-template-hash`, `controller-*`)

### Kept

- `name`
- `namespace` (set to debug namespace)
- `labels` (user labels + `debug-ward: true`)
- `annotations` (if present)
- All `spec` fields (cleaned but preserved)

## Use Cases

### 1. Review Before Applying

```bash
# Generate and review
kubectl debug-ward -n production app-pod --output=yaml | less

# If looks good, apply directly
kubectl debug-ward -n production app-pod --output=yaml | kubectl apply -f -
```

### 2. Customize Security Settings

```bash
# Generate
kubectl debug-ward -n production app-pod --output=yaml > debug-pod.yaml

# Edit to restore some security settings
vim debug-pod.yaml

# Apply
kubectl apply -f debug-pod.yaml
```

### 3. Apply to Different Cluster

```bash
# Generate on cluster A
kubectl debug-ward -n ns1 pod1 --output=yaml > pod1-debug.yaml

# Transfer and apply to cluster B
kubectl --context=cluster-b apply -f pod1-debug.yaml
```

### 4. Store for Later

```bash
# Generate and store
kubectl debug-ward -n production app-pod --output=yaml > \
  debug-configs/app-pod-$(date +%Y%m%d).yaml
```

### 5. Pipeline Integration

```bash
# Generate in CI/CD pipeline
kubectl debug-ward -n $NAMESPACE $POD_NAME --output=yaml > debug-resources.yaml

# Review in PR
# Apply after approval
kubectl apply -f debug-resources.yaml
```

## Examples

### Example 1: Basic Output

```bash
$ kubectl debug-ward -n test-source-ns test-pod-with-security

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
  # ... pod spec with security overrides
```

### Example 2: JSON Output

```bash
$ kubectl debug-ward -n test-source-ns test-pod-with-security --output=json

{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"test-app-config",...}}
{"apiVersion":"v1","kind":"Secret","metadata":{"name":"test-app-secret",...}}
{"apiVersion":"v1","kind":"Pod","metadata":{"name":"test-pod-with-security",...}}
```

### Example 3: Save and Edit

```bash
# Generate
kubectl debug-ward -n test-source-ns test-pod-with-security > my-debug-pod.yaml

# Edit to change namespace
sed -i '' 's/namespace: debug-ward-tmp/namespace: my-debug-ns/g' my-debug-pod.yaml

# Apply
kubectl apply -f my-debug-pod.yaml
```

## Comparison: Output Mode vs Direct Creation

| Feature | Output Mode (`--dry-run=true`) | Direct Creation (`--dry-run=false`) |
|---------|-------------------------------|-------------------------------------|
| Creates resources | ❌ No | ✅ Yes |
| Output format | YAML/JSON | Log messages |
| Editable | ✅ Yes | ❌ No |
| Reviewable | ✅ Yes | ❌ No |
| Customizable | ✅ Yes (edit file) | ❌ No |
| Use case | Review, edit, store | Quick copy |

## Tips

1. **Always review output** before applying, especially in production
2. **Use version control** for generated YAML files
3. **Add comments** in YAML files to document why changes were made
4. **Test in dev/staging** before using in production
5. **Use `--output=json`** for programmatic processing (jq, etc.)

## Related Documentation

- [SECURITY_SETTINGS.md](SECURITY_SETTINGS.md) - Customizing security settings
- [README.md](README.md) - General usage

