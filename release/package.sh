#!/bin/bash

if [ "${DEBUG_WARD_GIT_VERSION}" == "" ]; then
    export DEBUG_WARD_VERSION=v0.0.0
else
    export DEBUG_WARD_VERSION=$DEBUG_WARD_GIT_VERSION
fi

export DEBUG_WARD_BIN_PATH=release/bin/kubectl-debug-ward-${DEBUG_WARD_VERSION}
export DEBUG_WARD_ARCHIVE_PATH=release/package/kubectl-debug-ward-${DEBUG_WARD_VERSION}

if [ ! -d "$DEBUG_WARD_ARCHIVE_PATH" ]; then
    mkdir -p $DEBUG_WARD_ARCHIVE_PATH
fi

ARCH=$(uname -m)
OS=$(uname -s | tr '[:upper:]' '[:lower:]')

DEBUG_WARD_ARCHIVE_NAME="debug-ward-${DEBUG_WARD_VERSION}_${ARCH}_${OS}.tar.gz"
DEBUG_WARD_ARCHIVE_FULLPATH="${DEBUG_WARD_ARCHIVE_PATH}/${DEBUG_WARD_ARCHIVE_NAME}"
tar -czvf "$DEBUG_WARD_ARCHIVE_FULLPATH" -C "$(dirname $DEBUG_WARD_BIN_PATH)" "$(basename $DEBUG_WARD_BIN_PATH)"

DEBUG_WARD_ARCHIVE_MANIFEST_FULLPATH="$DEBUG_WARD_ARCHIVE_PATH/debug-ward-${DEBUG_WARD_VERSION}.yaml"
DEBUG_WARD_ARCHIVE_SHA256=`sha256sum ${DEBUG_WARD_ARCHIVE_FULLPATH} | cut -d' ' -f1 | xargs echo -n`
cat release/manifest.yaml | sed -r "s/DEBUG_WARD_MANIFEST_VERSION/$DEBUG_WARD_VERSION/g" | sed -r "s/DEBUG_WARD_MANIFEST_ARCHIVE_SHA256/${DEBUG_WARD_ARCHIVE_SHA256}/g" >$DEBUG_WARD_ARCHIVE_MANIFEST_FULLPATH

echo "### check results ###"
echo "ls -lah ${DEBUG_WARD_ARCHIVE_PATH}"

echo "### update krew"
echo "kubectl krew update"
kubectl krew update

echo "### uninstall debug-ward"
echo "kubectl krew uninstall debug-ward"
kubectl krew uninstall debug-ward

echo "### install plugin"
echo "kubectl krew install --manifest=$DEBUG_WARD_ARCHIVE_MANIFEST_FULLPATH --archive=$DEBUG_WARD_ARCHIVE_FULLPATH"
kubectl krew install --manifest=$DEBUG_WARD_ARCHIVE_MANIFEST_FULLPATH --archive=$DEBUG_WARD_ARCHIVE_FULLPATH
