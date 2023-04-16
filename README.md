# [Work in Progress] Official Python wrapper for OpenFHE

## Building

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
cmake ..
make
make install
```
Obs.: If the last command fails, try running it with sudo.

After that, you can run the examples in the src/pke/examples folder:

```bash
python src/pke/examples/simple-integers.py
```

