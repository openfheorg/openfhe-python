#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <openfhe/pke/openfhe.h>
#include <openfhe/pke/scheme/bfvrns/bfvrns-ser.h>
#include <openfhe/pke/cryptocontext-ser.h>
#include "bindings.h"
#include "serialization.h"

using namespace lbcrypto;
namespace py = pybind11;

void bind_serialization(pybind11::module &m) {
    m.def("SerializeToFile", static_cast<bool (*)(const std::string&, const CryptoContext<DCRTPoly>&, const SerType::SERJSON&)>(&Serial::SerializeToFile<DCRTPoly>), py::arg("filename"), py::arg("obj"), py::arg("sertype"));
    
}


