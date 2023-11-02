# Official Python wrapper for OpenFHE

## Table of Contents

- [Building](#building)
  - [Prerequisites](#requirements)
  - [Linux Install](#linux)
    - [Installing directly on your system](#system-level-installation)
    - [Using Conda environments](#conda)
- [Running Examples](#code-examples)
- [OpenFHE Python Wrapper Documentation](#openfhe-python-wrapper-documentation)

## Building

### Requirements

Before building, make sure you have the following dependencies installed:

- [OpenFHE](https://github.com/openfheorg/openfhe-development) by following the instructions on [OpenFHE Documentation](https://openfhe-development.readthedocs.io/en/latest/sphinx_rsts/intro/installation/installation.html)
- [Python 3.6+](https://www.python.org/)
- [pybind11](https://pybind11.readthedocs.io/en/stable/installing.html)

We recommend following OpenFHE C++ installation instructions first (which covers Linux, Windows and MacOS) and then get back to this repo.

You can install pybind11 by runnning:
  
```bash
pip install "pybind11[global]" # or alternatively, if you use conda:
conda install -c conda-forge pybind11
```
For custom installation or any other issues, please refer to the official pybind11 documentation in the link above.

### Linux

#### System-level installation

To install OpenFHE-python directly to your system, ensure the dependencies are set up. Then clone the repository, open a terminal in the repo folder and run the following commands:

```bash
mkdir build
cd build
cmake ..  # Alternatively, cmake .. -DOpenFHE_DIR=/path/to/installed/openfhe if you installed OpenFHE elsewhere
make
make install  # You may have to run sudo make install
```

At this point the `.so` file has been built. Your exact installation process will depend on your virtual environment.
Cmake will automatically find the python installation path, if unwanted, you can specify the python path by adding `-DPYTHON_EXECUTABLE_PATH=/path/to/python` to the cmake command.

#### Conda

Alternatively you can install the library and handle the linking via Conda. Clone the repository, open a terminal in the repo folder and run the following commands:

```bash
conda create -n ${ENV_NAME} python=3.{X} anaconda
```

where `${ENV_NAME}` should be replaced with the name of your environment, and `{X}` should be replaced with your desired python version. For example you might have `
conda create -n openfhe_python python=3.9 anaconda`

It's recommended to specify the python path to avoid any issues with conda environments.
To do this, run the following commands:

```bash
mkdir build
cd build
cmake .. -DPYTHON_EXECUTABLE_PATH=$CONDA_PREFIX/bin/python # Add in -DOpenFHE_DIR=/path/to/installed/openfhe if you installed OpenFHE elsewhere
make
make install  # You may have to run sudo make install
```

The CONDA_PREFIX variable is set by conda, and points to the root of your active conda environment.

Then, you can develop the library:

```
mkdir lib
mv *.so lib
conda develop lib
```

which creates a lib folder, moves the built `.so` file into that lib folder, and tells conda where to look for external libraries.

**Note** You may wish to copy the `.so` file to any projects of your own, or add it to your system path to source from.

## Code Examples

To get familiar with the OpenFHE Python API, check out the examples:

- FHE for arithmetic over integers (BFV):
  - [Simple Code Example](examples/pke/simple-integers.py)
  <!-- - [Simple Code Example with Serialization](examples/pke/simple-integers-serial.py) -->
- FHE for arithmetic over integers (BGV):
  - [Simple Code Example](examples/pke/simple-integers-bgvrns.py)
  <!-- - [Simple Code Example with Serialization](examples/pke/simple-integers-serial-bgvrns.py) -->
- FHE for arithmetic over real numbers (CKKS):
  - [Simple Code Example](examples/pke/simple-real-numbers.py)
  - [Advanced Code Example](examples/pke/advanced-real-numbers.py)
  - [Advanced Code Example for High-Precision CKKS](examples/pke/advanced-real-numbers-128.py)
  - [Arbitrary Smooth Function Evaluation](examples/pke/function-evaluation.py)
  - [Simple CKKS Bootstrapping Example](examples/pke/simple-ckks-bootstrapping.py)
  - [Advanced CKKS Bootstrapping Example](examples/pke/advanced-ckks-bootstrapping.cpp)
  - [Double-Precision (Iterative) Bootstrapping Example](examples/pke/iterative-ckks-bootstrapping.py)
- FHE for Boolean circuits and larger plaintext spaces (FHEW/TFHE):
  - [Simple Code Example](examples/binfhe/boolean.py)
  - [Truth Table Example](examples/binfhe/boolean-truth-table.py)
  <!-- - [Code with JSON serialization](examples/binfhe/boolean-serial-json.py) -->
  <!-- - [Code with Binary Serialization](examples/binfhe/boolean-serial-binary.py) -->
  <!-- - [Large-Precision Comparison](examples/binfhe/eval-sign.py) -->
  <!-- - [Small-Precison Arbitrary Function Evaluation](examples/binfhe/eval-function.py) -->
  <!-- - Threshold FHE:  -->
  <!-- - [Code Example for BGV, BFV, and CKKS](examples/pke/threshold-fhe.py) -->
  <!-- - [Code Example for BFV with 5 parties](examples/pke/threshold-fhe-5p.py) -->

## OpenFHE Python Wrapper Documentation

[OpenFHE Python Wrapper API Reference](https://openfheorg.github.io/openfhe-python/html/index.html)
