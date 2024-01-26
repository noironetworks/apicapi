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

function savePackages {
    # Save the python2 packages
    cp rpmbuild/RPMS/noarch/*.rpm .
    cp rpmbuild/SRPMS/*.rpm .
    rm -rf rpmbuild
}

function python3Packaging {
    # Prepare build scripts for python3
    cp rpm/apicapi.spec.in .

    sed -i "s/python-/python3-/g" rpm/apicapi.spec.in
    sed -i "s/python2/python3/g" rpm/apicapi.spec.in
    sed -i "s/Name:           %{srcname}/Name:           python3-%{srcname}/g" rpm/apicapi.spec.in
}

function restorePackages {
    # restore the python2 packages
    mv *.src.rpm rpmbuild/SRPMS/
    mv *.noarch.rpm rpmbuild/RPMS/noarch/

    # Restore the spec file
    mv apicapi.spec.in rpm/apicapi.spec.in
}

buildPackages python2
savePackages
python3Packaging
buildPackages python3
restorePackages
