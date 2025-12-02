# Simple debug-ward Run

## Basic Command

```bash
kubectl debug-ward -n <source-namespace> <pod-name>
```

## Example

```bash
kubectl debug-ward -n test-source-ns test-pod-with-security
```

## Output (YAML format)

The tool outputs clean YAML with three resources separated by `---`:

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
    app.name=test-app
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

## Save to File

```bash
kubectl debug-ward -n test-source-ns test-pod-with-security > debug-pod.yaml
```

## Apply the Output

```bash
# Option 1: Pipe directly
kubectl debug-ward -n test-source-ns test-pod-with-security | kubectl apply -f -

# Option 2: Save, edit, then apply
kubectl debug-ward -n test-source-ns test-pod-with-security > debug-pod.yaml
# Edit debug-pod.yaml if needed
kubectl apply -f debug-pod.yaml
```

## JSON Output

```bash
kubectl debug-ward -n test-source-ns test-pod-with-security --output=json
```

Output:
```json
{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"test-app-config","namespace":"debug-ward-tmp","labels":{"debug-ward":"true"}},"data":{"app.properties":"server.port=8080\napp.name=test-app\n"}}
{"apiVersion":"v1","kind":"Secret","metadata":{"name":"test-app-secret","namespace":"debug-ward-tmp","labels":{"debug-ward":"true"}},"type":"Opaque","data":{"username":"dGVzdHVzZXI="}}
{"apiVersion":"v1","kind":"Pod","metadata":{"name":"test-pod-with-security","namespace":"debug-ward-tmp","labels":{"debug-ward":"true"}},"spec":{"securityContext":{"runAsUser":0,"runAsGroup":0,"fsGroup":0},"containers":[{"name":"app-container","image":"nginx:alpine","securityContext":{"privileged":true,"readOnlyRootFilesystem":false,"runAsUser":0,"runAsGroup":0,"runAsNonRoot":false}}]}}
```

## Direct Creation (Skip Output)

To create resources directly without output:

```bash
kubectl debug-ward -n test-source-ns test-pod-with-security --dry-run=false
```

This creates the resources in the `debug-ward-tmp` namespace (or the namespace specified with `--debug-warn-namespace`).

## Custom Namespace

```bash
kubectl debug-ward -n test-source-ns test-pod-with-security \
  --debug-warn-namespace=my-debug-ns
```

## What Happens

1. **Reads** the pod from source namespace (`test-source-ns`)
2. **Finds** all ConfigMaps and Secrets used by the pod
3. **Cleans** the pod (removes status, probes, resource limits, etc.)
4. **Overrides** security context (sets to root, privileged, etc.)
5. **Outputs** clean YAML/JSON ready to apply

## Using Docker

If using Docker-based workflow:

```bash
# Build first
./docker-build.sh

# Run
./docker-run.sh kubectl-debug-ward -n test-source-ns test-pod-with-security
```











