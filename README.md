# OpenFHE-Python

[![License](https://img.shields.io/badge/License-BSD%202--Clause-blue.svg)](https://opensource.org/licenses/BSD-2-Clause)
[![Python Versions](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![OpenFHE Version](https://img.shields.io/badge/OpenFHE-1.6.1%2B-green)](https://github.com/openfheorg/openfhe-development)

Python wrapper for the main cryptographic capabilities of the OpenFHE C++ library. `OpenFHE-Python` provides a more user-friendly interface for Python developers, while keeping the efficiency of C++ FHE operations.

## Table of Contents

- [Breaking changes in v1.6](#breaking-changes-in-v16)
- [Installing using pip](#installing-using-pip)
- [Running from Docker](#running-from-docker)
- [Building from Source](#building-from-source)
  - [Prerequisites](#requirements)
  - [Linux Install](#linux)
    - [Installing directly on your system](#system-level-installation)
    - [Using Conda environments](#conda)
- [Running Examples](#code-examples)
- [OpenFHE Python Wrapper Documentation](#openfhe-python-wrapper-documentation)
- [Contributing Guide](#contributing-guide)

## Breaking changes in v1.6

- The `FHECKKSRNS` class is no longer exposed to Python. Its static depth helpers are now static methods of `CryptoContext`: replace `FHECKKSRNS.GetBootstrapDepth(...)` with `CryptoContext.GetBootstrapDepth(...)` (both overloads keep their signatures).
- The `BinFHEContext` attributes `SaveJSON`, `LoadJSON`, `SaveBinary`, `LoadBinary`, `SavePortableBinary`, `LoadPortableBinary`, `GetParams`, `GetLWEScheme`, `GetBinFHEScheme`, and `GetRefreshKey` were removed. They could never be called successfully in v1.5.1 (their argument or return types were not exposed to Python), but `hasattr` checks on them now return `False`. Use the module-level `SerializeToFile`/`Deserialize*` functions for serialization, and `GetN()`/`GetQ()` for the common parameter queries.

## Installing using pip (for Ubuntu)

On Ubuntu, openfhe-python can be installed using pip.  All available releases are listed at [Python Package Index OpenFHE Release History](https://pypi.org/project/openfhe/#history). Find the release for your version of Ubuntu and run

```
pip install openfhe==<openfhe_package_version>
```

Once installed, any python example at https://github.com/openfheorg/openfhe-python/tree/main/examples can be executed.

Note that Ubuntu LTS 22.04 and 24.04 are currently supported. `pip uninstall` can be used to uninstall the openfhe package.

## Building from Source

We recommend installing the wrapper from PyPI using `pip`, as this is the simplest method.
If you prefer to build from source, you can use the [openfhe-python-packager](https://github.com/openfheorg/openfhe-python-packager) on Linux or follow the build instructions below. The packager generates a wheel that can be installed with `pip`.

The legacy build instructions below are for other operating systems where [openfhe-python-packager](https://github.com/openfheorg/openfhe-python-packager) may not work.

### Requirements

Before building, make sure you have the following dependencies installed:

- [OpenFHE 1.6.1+](https://github.com/openfheorg/openfhe-development) by following the instructions in [OpenFHE Documentation](https://openfhe-development.readthedocs.io/en/latest/sphinx_rsts/intro/installation/installation.html)
- [Python 3.10+](https://www.python.org/)
- [pybind11](https://pybind11.readthedocs.io/en/stable/installing.html)
- [numpy](https://numpy.org/) (runtime): the module imports numpy at load time and uses it for the array fast paths — encoding CKKS plaintexts directly from 1-D numpy arrays and returning decoded values as numpy arrays (`Plaintext.GetRealPackedValueArray`/`GetCKKSPackedValueArray`). Runtime dependencies are listed in [requirements.txt](requirements.txt) (`pip install -r requirements.txt`); wheels built by the packager declare them automatically.

We recommend following OpenFHE C++ installation instructions first (which covers Linux, Windows and MacOS) and then getting back to this repo. See notes on installing `pybind11` below

### Linux

#### System-level installation

To install OpenFHE-python directly to your system, ensure the dependencies are set up. Then clone the repository, open a terminal in the repo folder and run the following commands:

```bash
pip install "pybind11[global]" 
pip install -r requirements.txt  # runtime dependencies of the module (numpy)
mkdir build
cd build
cmake ..  # Alternatively, cmake .. -DCMAKE_PREFIX_PATH=/path/to/installed/openfhe if you installed OpenFHE elsewhere
make
make install  # You may have to run sudo make install
```

With the default install prefix, `make install` copies the module directly into the site-packages directory of the Python interpreter cmake found (this also works inside virtual environments), so `import openfhe` works with no further setup.
Cmake will automatically find the python installation path, if unwanted, you can specify the python path by adding `-DPYTHON_EXECUTABLE_PATH=/path/to/python` to the cmake command.

If you install to a custom location instead (`cmake .. -DCMAKE_INSTALL_PREFIX=/your/path`), add that location to the `PYTHONPATH` environment variable so Python can find the module:

```
export PYTHONPATH=/your/path:$PYTHONPATH
```

Independently of where the Python module is installed, if you see an error saying that one of the OpenFHE .so libraries cannot be found when running a Python example, add the directory containing the OpenFHE C++ libraries to `LD_LIBRARY_PATH`. This is only needed when OpenFHE itself was installed somewhere the dynamic linker does not search by default.

#### Conda

Alternatively you can install the library and handle the linking via Conda. Clone the repository, open a terminal in the repo folder and run the following commands:

```bash
conda create -n ${ENV_NAME} python=3.{X} anaconda
```

where `${ENV_NAME}` should be replaced with the name of your environment, and `{X}` should be replaced with your desired python version. For example you might have `
conda create -n openfhe_python python=3.9 anaconda`. Now, you would install `pybind11` either via:

`pip install "pybind11[global]"` or via `conda install -c conda-forge pybind11`, but for now we recommend using the first method, with pip. Some users have reported issues when using the conda pybind11

Also install the module's runtime dependencies into the environment: `pip install -r requirements.txt` (or `conda install numpy`). The module imports them at load time, so `import openfhe` fails without them.

Now, you would clone the repository, and run the following commands to install :

```bash
mkdir build
cd build
cmake .. # Add in -DCMAKE_PREFIX_PATH=/path/to/installed/openfhe if you installed OpenFHE elsewhere
make
make install  # You may have to run sudo make install
```

Then, you can develop the library to link

```
cd ..
mkdir lib
mv *.so lib
conda develop lib
```

which creates a lib folder, moves the built `.so` file into that lib folder, and tells conda where to look for external libraries.

**Note** You may wish to copy the `.so` file to any projects of your own, or add it to your system path to source from.

## Running Tests

Run tests with [pytest](https://docs.pytest.org), which may be called `pytest-3` on your system. The tests import the module, so the runtime dependencies must be installed (`pip install -r requirements.txt`; already satisfied if you installed the wheel with pip). See the [testing readme](tests/README.md) for more information.

```bash
pytest [--run-long]
```

## Code Examples

To get familiar with the OpenFHE Python API, check out the examples:

- FHE for arithmetic over integers (BFV):
  - [Simple Code Example](examples/pke/simple-integers.py)
  - [Simple Code Example with Serialization](examples/pke/simple-integers-serial.py)
  - [Computation Circuit of Depth 3](examples/pke/depth-bfvrns.py)
  - [Computation Circuit of Depth 3 with the BEHZ Multiplication Technique](examples/pke/depth-bfvrns-behz.py)
- FHE for arithmetic over integers (BGV):
  - [Simple Code Example](examples/pke/simple-integers-bgvrns.py)
  - [Simple Code Example with Serialization](examples/pke/simple-integers-serial-bgvrns.py)
  - [Computation Circuit of Depth 3](examples/pke/depth-bgvrns.py)
- FHE for arithmetic over real numbers (CKKS):
  - [Simple Code Example](examples/pke/simple-real-numbers.py)
  - [Simple Code Example with Serialization](examples/pke/simple-real-numbers-serial.py)
  - [Simple Code Example for Complex Numbers](examples/pke/simple-complex-numbers.py)
  - [Advanced Code Example](examples/pke/advanced-real-numbers.py)
  - [Advanced Code Example for High-Precision CKKS](examples/pke/advanced-real-numbers-128.py)
  - [Arbitrary Smooth Function Evaluation](examples/pke/function-evaluation.py)
  - [Polynomial Evaluation](examples/pke/polynomial-evaluation.py)
  - [Linear Weighted Sum Evaluation](examples/pke/linearwsum-evaluation.py)
  - [Decryption with Noise Flooding](examples/pke/ckks-noise-flooding.py)
  - [Releasing Memory Used by Precomputations](examples/pke/ckks-release-memory.py)
- CKKS with Composite Scaling:
  - [Simple Code Example](examples/pke/simple-real-numbers-composite-scaling.py)
  - [Simple Code Example with Manual Rescaling](examples/pke/simple-composite-scaling-manual.py)
  - [High-Precision Polynomial Evaluation](examples/pke/polynomial-evaluation-high-precision-composite-scaling.py)
- CKKS Bootstrapping:
  - [Simple CKKS Bootstrapping Example](examples/pke/simple-ckks-bootstrapping.py)
  - [Advanced CKKS Bootstrapping Example](examples/pke/advanced-ckks-bootstrapping.py)
  - [Double-Precision (Iterative) Bootstrapping Example](examples/pke/iterative-ckks-bootstrapping.py)
  - [Simple Bootstrapping Example with Composite Scaling](examples/pke/simple-ckks-bootstrapping-composite-scaling.py)
  - [Double-Precision (Iterative) Bootstrapping Example with Composite Scaling](examples/pke/iterative-ckks-bootstrapping-composite-scaling.py)
  - [Serialization of Bootstrapping Keys](examples/pke/ckks-bootstrap-keys-serial.py)
  - [Functional Bootstrapping for RLWE Ciphertexts](examples/pke/functional-bootstrapping-ckks.py)
  - [Fourier-Extension (FE) Functional Bootstrapping](examples/pke/FE-functional-bootstrapping-ckks.py)
- Operations over Encrypted Vectors (BFV and CKKS):
  - [Vector Rotation Example](examples/pke/rotation.py)
  - [Inner Product Example](examples/pke/inner-product.py)
- Proxy Re-Encryption (PRE):
  - [Simple Code Example with Buffers (BFV)](examples/pke/pre-buffer.py)
  - [HRA-Secure PRE with 13 Hops (BGV)](examples/pke/pre-hra-secure.py)
- FHE for Boolean circuits and larger plaintext spaces (FHEW/TFHE):
  - [Simple Code Example with Symmetric Encryption](examples/binfhe/boolean.py)
  - [Simple Code Example with the AP Bootstrapping Method](examples/binfhe/boolean-ap.py)
  - [Simple Code Example with the LMKCDEY Bootstrapping Method](examples/binfhe/boolean-lmkcdey.py)
  - [Multi-Input Gates Example](examples/binfhe/boolean-multi-input.py)
  - [Truth Table Example](examples/binfhe/boolean-truth-tables.py)
  - [Code with JSON Serialization](examples/binfhe/boolean-serial-json.py)
  - [Code with Binary Serialization](examples/binfhe/boolean-serial-binary.py)
  - [Large-Precision Comparison](examples/binfhe/eval-sign.py)
  - [Small-Precision Arbitrary Function Evaluation](examples/binfhe/eval-function.py)
  - [Homomorphic Digit Decomposition](examples/binfhe/eval-decomp.py)
  - [Homomorphic Flooring](examples/binfhe/eval-flooring.py)
  - [JSON Serialization for Large-Precision Sign Evaluation with Dynamic Bootstrapping Keys](examples/binfhe/boolean-serial-json-dynamic-large-precision.py)
  - [Binary Serialization for Large-Precision Sign Evaluation with Dynamic Bootstrapping Keys](examples/binfhe/boolean-serial-binary-dynamic-large-precision.py)
- FHEW/TFHE with Public-Key Encryption:
  - [Simple Code Example](examples/binfhe/pke/boolean-pke.py)
  - [Simple Code Example with the AP Bootstrapping Method](examples/binfhe/pke/boolean-ap-pke.py)
  - [Truth Table Example](examples/binfhe/pke/boolean-truth-tables-pke.py)
  - [Code with JSON Serialization](examples/binfhe/pke/boolean-serial-json-pke.py)
  - [Code with Binary Serialization](examples/binfhe/pke/boolean-serial-binary-pke.py)
  - [Small-Precision Arbitrary Function Evaluation](examples/binfhe/pke/eval-function-pke.py)
  - [Homomorphic Flooring](examples/binfhe/pke/eval-flooring-pke.py)
- Scheme Switching:
  - [Examples with Scheme Switching between CKKS and FHEW/TFHE](examples/pke/scheme-switching.py)
  - [Scheme Switching with Serialization](examples/pke/scheme-switching-serial.py)
- Threshold FHE: 
  - [Code Example for BGV, BFV, and CKKS](examples/pke/threshold-fhe.py)
  - [Code Example for BFV with 5 parties](examples/pke/threshold-fhe-5p.py)
  - [2-party Interactive Bootstrapping Examples](examples/pke/interactive-bootstrapping.py)
  - [Simple n-party Interactive Bootstrapping Example](examples/pke/tckks-interactive-mp-bootstrapping.py)
  - [n-party Interactive Bootstrapping after Chebyshev Approximation](examples/pke/tckks-interactive-mp-bootstrapping-Chebyshev.py)

## OpenFHE Python Wrapper Documentation

[OpenFHE Python Wrapper API Reference](https://openfhe-python.readthedocs.io/en/latest/)

## Contributing Guide

[OpenFHE Development - Contributing Guide](https://openfhe-development.readthedocs.io/en/latest/sphinx_rsts/contributing/contributing_workflow.html)
