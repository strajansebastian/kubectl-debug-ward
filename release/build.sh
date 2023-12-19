#!/bin/bash

export DEBUG_WARD_VERSION=$(git describe --tags --abbrev=0)
export DEBUG_WARD_BIN_PATH=release/bin/kubectl-debug-ward-${DEBUG_WARD_VERSION}

if [ ! -d "$DEBUG_WARD_BIN_PATH" ]; then
    mkdir -p $DEBUG_WARD_BIN_PATH
fi

GO111MODULE="on" go build -o $DEBUG_WARD_BIN_PATH/debug-ward -ldflags "-X main.version=${DEBUG_WARD_VERSION}" cmd/kubectl-debug-ward.go

echo "### check results ###"
echo "ls -lah ${DEBUG_WARD_BIN_PATH}"
