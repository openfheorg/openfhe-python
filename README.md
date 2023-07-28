# Official Python wrapper for OpenFHE

## Table of Contents

- [Building](#building)
  - [Prerequisites](#requirements)
  - [Linux Install](#linux)
    - [Installing the .so: Conda](#conda)
    - [Installing the .so: System](#system-install)
- [Running Examples](#code-examples)
- [OpenFHE Python Wrapper Documentation](#openfhe-python-wrapper-documentation)

## Building

### Requirements

Before building, make sure you have the following dependencies installed:

- [OpenFHE](https://openfhe-development.readthedocs.io/en/latest/sphinx_rsts/intro/installation/installation.html)
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

With all the dependencies set up, clone the repository, open a terminal in the repo folder and run the following commands:

```bash
mkdir build
cd build
cmake ..  # Alternatively, cmake .. -DOpenFHE_DIR=/path/to/installed/openfhe
make
make install  # You may have to run sudo make install
```

At this point the `.so` file has been built. Your exact installation process will depend on your virtual environment.
Cmake will automatically find the python installation path, if unwanted, you can specify the python path by adding `-DPYTHON_EXECUTABLE_PATH=/path/to/python` to the cmake command.

#### Conda

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
cmake .. -DPYTHON_EXECUTABLE_PATH=$CONDA_PREFIX/bin/python
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
  - [Simple Code Example](src/pke/examples/simple-integers.py)
  <!-- - [Simple Code Example with Serialization](src/pke/examples/simple-integers-serial.py) -->
- FHE for arithmetic over integers (BGV):
  - [Simple Code Example](src/pke/examples/simple-integers-bgvrns.py)
  <!-- - [Simple Code Example with Serialization](src/pke/examples/simple-integers-serial-bgvrns.py) -->
- FHE for arithmetic over real numbers (CKKS):
  - [Simple Code Example](src/pke/examples/simple-real-numbers.py)
  - [Advanced Code Example](src/pke/examples/advanced-real-numbers.py)
  - [Advanced Code Example for High-Precision CKKS](src/pke/examples/advanced-real-numbers-128.py)
  - [Arbitrary Smooth Function Evaluation](src/pke/examples/function-evaluation.py)
  - [Simple CKKS Bootstrapping Example](src/pke/examples/simple-ckks-bootstrapping.py)
  - [Advanced CKKS Bootstrapping Example](src/pke/examples/advanced-ckks-bootstrapping.cpp)
  - [Double-Precision (Iterative) Bootstrapping Example](src/pke/examples/iterative-ckks-bootstrapping.py)
- FHE for Boolean circuits and larger plaintext spaces (FHEW/TFHE):
  - [Simple Code Example](src/binfhe/examples/boolean.py)
  - [Truth Table Example](src/binfhe/examples/boolean-truth-table.py)
  <!-- - [Code with JSON serialization](src/binfhe/examples/boolean-serial-json.py) -->
  <!-- - [Code with Binary Serialization](src/binfhe/examples/boolean-serial-binary.py) -->
  <!-- - [Large-Precision Comparison](src/binfhe/examples/eval-sign.py) -->
  <!-- - [Small-Precison Arbitrary Function Evaluation](src/binfhe/examples/eval-function.py) -->
  <!-- - Threshold FHE:  -->
  <!-- - [Code Example for BGV, BFV, and CKKS](src/pke/examples/threshold-fhe.py) -->
  <!-- - [Code Example for BFV with 5 parties](src/pke/examples/threshold-fhe-5p.py) -->

## OpenFHE Python Wrapper Documentation

[OpenFHE Python Wrapper API Reference](https://openfheorg.github.io/openfhe-python/html/index.html)
