#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include "openfhe.h"
#include "scheme/bfvrns/bfvrns-ser.h"
#include "scheme/bgvrns/bgvrns-ser.h"
#include "cryptocontext-ser.h"
#include "bindings.h"
#include "serialization.h"

using namespace lbcrypto;
namespace py = pybind11;

template <typename ST>
bool SerializeEvalMultKeyWrapper(const std::string& filename, const ST& sertype, std::string id)
{
    std::ofstream outfile(filename, std::ios::out | std::ios::binary);
    bool res;
    res = CryptoContextImpl<DCRTPoly>::SerializeEvalMultKey<ST>(outfile, sertype, id);
    outfile.close();
    return res;
}

void bind_serialization(pybind11::module &m) {
    // Json Serialization
    m.def("SerializeToFile", static_cast<bool (*)(const std::string&, const CryptoContext<DCRTPoly>&, const SerType::SERJSON&)>(&Serial::SerializeToFile<DCRTPoly>), py::arg("filename"), py::arg("obj"), py::arg("sertype"));
    m.def("DeserializeFromFile", static_cast<bool (*)(const std::string&, CryptoContext<DCRTPoly>& ,const SerType::SERJSON&)>(&Serial::DeserializeFromFile<DCRTPoly>), py::arg("filename"), py::arg("obj"), py::arg("sertype"));
    m.def("SerializeToFile", static_cast<bool (*)(const std::string&, const PublicKey<DCRTPoly>&, const SerType::SERJSON&)>(&Serial::SerializeToFile<PublicKey<DCRTPoly>>), py::arg("filename"), py::arg("obj"), py::arg("sertype"));
    m.def("DeserializeFromFile", static_cast<bool (*)(const std::string&, PublicKey<DCRTPoly>& ,const SerType::SERJSON&)>(&Serial::DeserializeFromFile<PublicKey<DCRTPoly>>), py::arg("filename"), py::arg("obj"), py::arg("sertype"));
    m.def("SerializeToFile", static_cast<bool (*)(const std::string&, const PrivateKey<DCRTPoly>&, const SerType::SERJSON&)>(&Serial::SerializeToFile<PrivateKey<DCRTPoly>>), py::arg("filename"), py::arg("obj"), py::arg("sertype"));
    m.def("DeserializeFromFile", static_cast<bool (*)(const std::string&, PrivateKey<DCRTPoly>& ,const SerType::SERJSON&)>(&Serial::DeserializeFromFile<PrivateKey<DCRTPoly>>), py::arg("filename"), py::arg("obj"), py::arg("sertype"));
    m.def("SerializeToFile", static_cast<bool (*)(const std::string&, const Ciphertext<DCRTPoly>&, const SerType::SERJSON&)>(&Serial::SerializeToFile<Ciphertext<DCRTPoly>>), py::arg("filename"), py::arg("obj"), py::arg("sertype"));
    m.def("DeserializeFromFile", static_cast<bool (*)(const std::string&, Ciphertext<DCRTPoly>& ,const SerType::SERJSON&)>(&Serial::DeserializeFromFile<Ciphertext<DCRTPoly>>), py::arg("filename"), py::arg("obj"), py::arg("sertype"));
    // Binary Serialization
    m.def("SerializeToFile", static_cast<bool (*)(const std::string&, const CryptoContext<DCRTPoly>&, const SerType::SERBINARY&)>(&Serial::SerializeToFile<DCRTPoly>), py::arg("filename"), py::arg("obj"), py::arg("sertype"));
    m.def("DeserializeFromFile", static_cast<bool (*)(const std::string&, CryptoContext<DCRTPoly>& ,const SerType::SERBINARY&)>(&Serial::DeserializeFromFile<DCRTPoly>), py::arg("filename"), py::arg("obj"), py::arg("sertype"));
    m.def("SerializeToFile", static_cast<bool (*)(const std::string&, const PublicKey<DCRTPoly>&, const SerType::SERBINARY&)>(&Serial::SerializeToFile<PublicKey<DCRTPoly>>), py::arg("filename"), py::arg("obj"), py::arg("sertype"));
    m.def("DeserializeFromFile", static_cast<bool (*)(const std::string&, PublicKey<DCRTPoly>& ,const SerType::SERBINARY&)>(&Serial::DeserializeFromFile<PublicKey<DCRTPoly>>), py::arg("filename"), py::arg("obj"), py::arg("sertype"));
    m.def("SerializeToFile", static_cast<bool (*)(const std::string&, const PrivateKey<DCRTPoly>&, const SerType::SERBINARY&)>(&Serial::SerializeToFile<PrivateKey<DCRTPoly>>), py::arg("filename"), py::arg("obj"), py::arg("sertype"));
    m.def("DeserializeFromFile", static_cast<bool (*)(const std::string&, PrivateKey<DCRTPoly>& ,const SerType::SERBINARY&)>(&Serial::DeserializeFromFile<PrivateKey<DCRTPoly>>), py::arg("filename"), py::arg("obj"), py::arg("sertype"));
    m.def("SerializeToFile", static_cast<bool (*)(const std::string&, const Ciphertext<DCRTPoly>&, const SerType::SERBINARY&)>(&Serial::SerializeToFile<Ciphertext<DCRTPoly>>), py::arg("filename"), py::arg("obj"), py::arg("sertype"));
    m.def("DeserializeFromFile", static_cast<bool (*)(const std::string&, Ciphertext<DCRTPoly>& ,const SerType::SERBINARY&)>(&Serial::DeserializeFromFile<Ciphertext<DCRTPoly>>), py::arg("filename"), py::arg("obj"), py::arg("sertype"));
    
    
}


