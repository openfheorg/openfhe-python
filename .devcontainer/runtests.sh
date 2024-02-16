#!/bin/bash
cd /home/vscode
source venv/bin/activate
mkdir -p build
cd build
FHEHOME=/workspaces/openfhe-python
cmake $FHEHOME
make install
# The NATIVEBIT variable is set in the Docker. It is the word size for an
# integer in OpenFHE.
cd $FHEHOME/tests && pytest --junitxml=$FHEHOME/test${NATIVEBIT}.xml --run-long
