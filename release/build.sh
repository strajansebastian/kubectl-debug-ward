#!/bin/bash

if [ "${DEBUG_WARD_GIT_VERSION}" == "" ]; then
    export DEBUG_WARD_VERSION=v0.0.0
else
    export DEBUG_WARD_VERSION=$DEBUG_WARD_GIT_VERSION
fi

export DEBUG_WARD_BIN_PATH=release/bin/kubectl-debug-ward-${DEBUG_WARD_VERSION}

if [ ! -d "$DEBUG_WARD_BIN_PATH" ]; then
    mkdir -p $DEBUG_WARD_BIN_PATH
fi

GO111MODULE="on" go build -o $DEBUG_WARD_BIN_PATH/kubectl-debug-ward -ldflags "-X main.version=${DEBUG_WARD_VERSION}" cmd/kubectl-debug-ward.go
cp release/LICENSE $DEBUG_WARD_BIN_PATH/LICENSE

echo "### check results ###"
echo "ls -lah ${DEBUG_WARD_BIN_PATH}"
