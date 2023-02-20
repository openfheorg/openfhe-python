#include <pybind11/pybind11.h>
#include <scheme/bfvrns/cryptocontextparams-bfvrns.h>
#include <scheme/cryptocontextparams-base.h>
#include <core/utils/inttypes.h>
#include "bindings.h"

using namespace lbcrypto;
namespace py = pybind11;


void bind_parameters(py::module &m){
    py::class_<Params>(m, "Params");
    py::class_<CCParams<CryptoContextBFVRNS>, Params>(m, "CCParamsBFVRNS")
            .def(py::init<>())
            // setters
            .def("SetPlaintextModulus", &CCParams<CryptoContextBFVRNS>::SetPlaintextModulus)
            .def("SetMultiplicativeDepth",&CCParams<CryptoContextBFVRNS>::SetMultiplicativeDepth)
            // getters
            .def("GetPlaintextModulus", &CCParams<CryptoContextBFVRNS>::GetPlaintextModulus)
            .def("GetMultiplicativeDepth", &CCParams<CryptoContextBFVRNS>::GetMultiplicativeDepth);
            //  .def_property("multiplicativeDepth",
            // &CCParams<CryptoContextBFVRNS>::GetMultiplicativeDepth,
            // &CCParams<CryptoContextBFVRNS>::SetMultiplicativeDepth)
            // .def_property("ptModulus",
            // &CCParams<CryptoContextBFVRNS>::GetPlaintextModulus,
            // &CCParams<CryptoContextBFVRNS>::SetPlaintextModulus);
}

PYBIND11_MODULE(openfhe, m) {
    m.doc() = "Open-Source Fully Homomorphic Encryption Library";
    bind_parameters(m);

}