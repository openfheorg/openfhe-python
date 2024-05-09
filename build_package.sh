#!/bin/bash
# Exit on any error
set -e

# Find the venv directory
if [ -d ".venv" ]; then
    VENV_DIR=".venv"
elif [ -d "../.venv" ]; then
    VENV_DIR="../.venv"
else
    echo "The virtual environment does not exist. Please run 'python -m venv .venv' to create it." >&2
    exit 1
fi

# Activate the virtual environment
source $VENV_DIR/bin/activate

# Install pybind11-stubgen
if ! pip show pybind11-stubgen > /dev/null; then
    pip install pybind11-stubgen
fi

# Check if the virtual environment has the openfhe package installed
if ! pip show openfhe > /dev/null; then
    echo "The openfhe package is not installed in the virtual environment. Please run 'pip install -e .' to install it." >&2
    exit 1
fi

# Generate stub files using pybind11-stubgen
echo "Generating stub files..."
pybind11-stubgen openfhe

# Check if stub generation was successful
if [ $? -eq 0 ]; then
    echo "Stub files generated successfully."
else
    echo "Stub generation failed." >&2
    exit 1
fi

# Move the generated stub files to the openfhe package directory
echo "Moving the generated stub files to the openfhe package directory..."
mv stubs/openfhe/* openfhe/
rm -r -d stubs

# Build the source distribution and wheel distribution
echo "Building the sdist and bdist_wheel..."
python setup.py sdist bdist_wheel

# Indicate where the distributions were saved
echo "The distributions have been built and are located in the 'dist' directory. You can install the package using 'pip install dist/<distribution_file>'."
