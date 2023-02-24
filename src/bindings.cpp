#include <pybind11/pybind11.h>
#include <openfhe/pke/openfhe.h>
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

void bind_crypto_context(py::module &m){
    py::class_<CryptoContextImpl<DCRTPoly>,std::shared_ptr<CryptoContextImpl<DCRTPoly>>>(m,"CryptoContextDCRTPoly")
            .def("GetKeyGenLevel",&CryptoContextImpl<DCRTPoly>::GetKeyGenLevel)
            .def("SetKeyGenLevel",&CryptoContextImpl<DCRTPoly>::SetKeyGenLevel);

    m.def("GenCryptoContext", &GenCryptoContext<CryptoContextBFVRNS>);
    m.def("GenCryptoContext", &GenCryptoContext<CryptoContextBGVRNS>);
}

PYBIND11_MODULE(openfhe, m) {
    m.doc() = "Open-Source Fully Homomorphic Encryption Library";
    bind_parameters(m);
    bind_crypto_context(m);

}