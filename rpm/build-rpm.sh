#!/bin/bash
# Should be run from the root of the source tree

function buildPackages {
    PYTHON_BIN=$1
    BUILD_DIR=${BUILD_DIR:-`pwd`/rpmbuild}
    mkdir -p $BUILD_DIR/BUILD $BUILD_DIR/SOURCES $BUILD_DIR/SPECS $BUILD_DIR/RPMS $BUILD_DIR/SRPMS
    RELEASE=${RELEASE:-1}
    VERSION=`${PYTHON_BIN} setup.py --version`
    SPEC_FILE=apicapi.spec
    sed -e "s/@VERSION@/$VERSION/" -e "s/@RELEASE@/$RELEASE/" rpm/$SPEC_FILE.in > $BUILD_DIR/SPECS/$SPEC_FILE
    ${PYTHON_BIN} setup.py sdist --dist-dir $BUILD_DIR/SOURCES
    rpmbuild --clean -ba --define "_topdir $BUILD_DIR" $BUILD_DIR/SPECS/$SPEC_FILE
}

buildPackages python3
