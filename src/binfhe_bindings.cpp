#include <pybind11/pybind11.h>
#include <iostream>
#include "openfhe.h"
#include "binfhe_bindings.h"
#include "binfhecontext.h"

using namespace lbcrypto;
namespace py = pybind11;

void bind_binfhe_enums(py::module &m) {
    //just print hello world
    std::cout << "Hello World!" << std::endl;
}

void bind_binfhe_context(py::module &m) {
    py::class_<BinFHEContext>(m,"BinFHEContext")
        .def(py::init<>());
}
