# [Work in Progress] Official Python wrapper for OpenFHE

## Table of Contents

- [Building](#building)
  - [Prerequisites](#requirements)
  - [Linux Install](#linux)
    - [Installing the .so: Conda](#conda)
    - [Installing the .so: System](#system-install)
- [Running Examples](#examples)

## Building

### Requirements

Before building, make sure you have the following dependencies installed:

- [CMake](https://cmake.org/)
- [Python 3.6+](https://www.python.org/)
- [pybind11](https://pybind11.readthedocs.io)
- [OpenFHE](https://github.com/openfheorg/openfhe-development)

### Linux

With all the dependencies set up, clone the repository, open a terminal in the repo folder and run the following commands:

```bash
mkdir build
cd build
cmake ..  // Alternatively, cmake .. -DOpenFHE_DIR=/path/to/installed/openfhe
make
```

At this point the `.so` file has been built. Your exact installation process will depend on your virtual environment.

#### Conda

```bash
conda create -n ${ENV_NAME} python=3.{X} anaconda
```

where `${ENV_NAME}` should be replaced with the name of your environment, and `{X}` should be replaced with your desired python version. For example you might have `
conda create -n openfhe_python python=3.9 anaconda`

then run 

```
mkdir lib
mv *.so lib
conda develop lib
```

which creates a lib folder, moves the built `.so` file into that lib folder, and tells conda where to look for external libraries.

**Note** You may wish to copy the `.so` file to any projects of your own, or add it to your system path to source from.

#### System install

```
make install  // You may have to run sudo make install
```

## Examples

After that, you can run the examples in the src/pke/examples folder:

```bash
python src/pke/examples/simple-integers.py
```

