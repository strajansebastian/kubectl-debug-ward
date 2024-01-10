# kubectl-debug-ward

### build
```
bash release/build.sh
```

### package the version and create the manifest
```
bash release/package.sh
```


```
# initial build
docker build -t kubectl-debug-ward:latest .

# run local dev
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
