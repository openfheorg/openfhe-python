#!/usr/bin/env bash
set -euo pipefail

exec 3>&1      # save original stdout in FD 3
exec 1>&2      # redirect all stdout to stderr from here on

# ---- prerequisites ----
if ! command -v cmake >/dev/null 2>&1; then
  echo "ERROR: cmake is required but not installed" >&2
  exit 1
fi

# the real branch name checked out by RTD
REAL_BRANCH_NAME="${READTHEDOCS_GIT_IDENTIFIER:-}"
if [[ -z "${REAL_BRANCH_NAME}" ]]; then
  echo "Error: READTHEDOCS_GIT_IDENTIFIER is empty" >&2
  exit 2
fi

echo "RTD REAL_BRANCH_NAME: ${REAL_BRANCH_NAME}" >&2

WHEEL_BUILD_DIR="${PWD}/build"
rm -rf "${WHEEL_BUILD_DIR}"
mkdir -p "${WHEEL_BUILD_DIR}"
cd "${WHEEL_BUILD_DIR}"

# get the packager
git clone https://github.com/openfheorg/openfhe-python-packager.git
cd "openfhe-python-packager"
git checkout main

# override OPENFHE_PYTHON_TAG in ci-vars.sh
sed -i "s|^OPENFHE_PYTHON_TAG=.*|OPENFHE_PYTHON_TAG=${REAL_BRANCH_NAME}|" ci-vars.sh

# run the packager
./build_openfhe_wheel.sh

# find the new wheel
WHEEL_DIR="build/dist"
if [[ ! -d "$WHEEL_DIR" ]]; then
  echo "Error: expected wheel directory '$WHEEL_DIR' not found" >&2
  exit 3
fi

mapfile -t matches < <(cd "$WHEEL_DIR" && ls -1 *.whl 2>/dev/null || true)
# cd build/dist/
# matches=( *.whl )
if (( ${#matches[@]} == 0 )); then
    echo "No .whl file generated" >&2
    exit 4
elif (( ${#matches[@]} > 1 )); then
    echo "Multiple .whl files generated:" >&2
    printf '  %s\n' "${matches[@]}" >&2
    exit 5
fi

# return the full path to the new wheel
printf '%s\n' "${WHEEL_BUILD_DIR}/openfhe-python-packager/${WHEEL_DIR}/${matches[0]}" >&3
