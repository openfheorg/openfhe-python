#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
SCRIPT_NAME="$(basename -- "${BASH_SOURCE[0]}")"
SCRIPT_PATH="${SCRIPT_DIR}/${SCRIPT_NAME}"
echo "Running ${SCRIPT_PATH}"

# get to the root directory (should be ./openfhe-python)
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd -P)"
echo "cd ${PWD}"

# cleanup
rm -fr .venv-docs/ build/ docs/_build/ docs/html/ docs/doctrees/

# preconditions: you need the same basic tools RTD uses
sudo apt update
sudo apt install -y \
  python3-venv python3-pip \
  build-essential cmake git

# create and activate a clean venv
python3 -m venv .venv-docs
source .venv-docs/bin/activate
python3 -m pip install -U pip

# install doc dependencies
# installs only Sphinx + runtime deps (not openfhe yet)
python3 -m pip install -r docs/requirements.txt

# simulate RTD environment variables and build docs for the current branch
export READTHEDOCS=1
export READTHEDOCS_GIT_IDENTIFIER="$(git branch --show-current)"
export READTHEDOCS_GIT_COMMIT_HASH="$(git rev-parse HEAD)"

# build the wheel for docs
WHEEL_PATH="$(bash docs/scripts/build-wheel-for-docs.sh)"
# WHEEL_PATH="$(bash docs/scripts/build-wheel-for-docs.sh | tr -d '\r' | grep -E '\.whl$' | tail -n 1)"
# if [[ -z "$WHEEL_PATH" || ! -f "$WHEEL_PATH" ]]; then
#   echo "ERROR: wheel path not found or file missing: '$WHEEL_PATH'" >&2
#   exit 1
# fi
echo "--------------- Wheel built at: $WHEEL_PATH"

# Install the built wheel
python3 -m pip install "$WHEEL_PATH"
# Sanity check
python3 - <<'EOF'
import openfhe
print("openfhe import OK")
print("version:", getattr(openfhe, "__version__", "unknown"))
EOF

# Build the HTML docs
python3 -m sphinx -b html docs/ docs/_build/html
# # Or equivalently
# cd docs
# make html

# View the docs
firefox docs/_build/html/index.html
