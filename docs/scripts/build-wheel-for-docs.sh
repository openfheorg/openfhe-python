#!/bin/sh

# the real branch name checked out by RTD
REAL_BRANCH_NAME="${READTHEDOCS_GIT_IDENTIFIER:-}"
if [[ -z "${REAL_BRANCH_NAME}" ]]; then
  echo "Error: READTHEDOCS_GIT_IDENTIFIER is empty" >&2
  exit 1
fi

echo "RTD REAL_BRANCH_NAME: ${REAL_BRANCH_NAME}" >&2

WHEEL_BUILD_DIR="${PWD}/build"
rm -rf "${WHEEL_BUILD_DIR}"
mkdir -p "${WORKDIR}"
cd "${WORKDIR}"

# get the packager
git clone https://github.com/openfheorg/openfhe-python-packager.git
cd "openfhe-python-packager"

# override OPENFHE_PYTHON_TAG in ci-vars.sh
sed -i "s|^OPENFHE_PYTHON_TAG=.*|OPENFHE_PYTHON_TAG=${BRANCH}|" ci-vars.sh

# run the packager
./build_openfhe_wheel.sh

# find the new wheel
cd build/dist/
matches=( *.whl )
if (( ${#matches[@]} == 0 )); then
    echo "No .whl file generated" >&2
    exit 1
elif (( ${#matches[@]} > 1 )); then
    echo "Multiple .whl files generated:" >&2
    printf '  %s\n' "${matches[@]}" >&2
    exit 1
fi

file="${matches[0]}"

# return the full path to the new wheel
printf '%s/%s\n' "$(pwd)" "$file"
