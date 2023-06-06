#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include "openfhe.h"
#include "bindings.h"
#include "utils/exception.h"
// header files needed for serialization
#include "serialization.h"
#include "metadata-ser.h"
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/bfvrns/bfvrns-ser.h"
#include "scheme/bgvrns/bgvrns-ser.h"

using namespace lbcrypto;
namespace py = pybind11;

template <typename ST>
bool SerializeEvalMultKeyWrapper(CryptoContext<DCRTPoly>& self,const std::string& filename, const ST& sertype, std::string id)
{
    std::ofstream outfile(filename, std::ios::out | std::ios::binary);
    bool res;
    res = self->SerializeEvalMultKey<ST>(outfile, sertype, id);
    outfile.close();
    return res;
}

template <typename ST>
bool SerializeEvalAutomorphismKeyWrapper(CryptoContext<DCRTPoly>& self,const std::string& filename, const ST& sertype, std::string id)
{
    std::ofstream outfile(filename, std::ios::out | std::ios::binary);
    bool res;
    res = self->SerializeEvalAutomorphismKey<ST>(outfile, sertype, id);
    outfile.close();
    return res;
}

template <typename ST>
bool DeserializeEvalMultKeyWrapper(CryptoContext<DCRTPoly>& self, const std::string& filename, const ST& sertype)
                    {
                        std::ifstream emkeys(filename, std::ios::in | std::ios::binary);
                         if (!emkeys.is_open()) {
                            std::cerr << "I cannot read serialization from " << filename << std::endl;
                         }
                        bool res;
                        res = self->DeserializeEvalMultKey<ST>(emkeys, sertype);
                        return res; }


CryptoContext<DCRTPoly> DeserializeFromFileWrapper(const std::string& filename, const SerType::SERJSON& sertype){
    CryptoContext<DCRTPoly> newob;
    bool res;
    res = lbcrypto::Serial::DeserializeFromFile(filename, newob, sertype);
    if (res) {
        return newob;
    } else {
        // throw an exception
        throw std::runtime_error("Cannot deserialize from file");
    }
}



void bind_serialization(pybind11::module &m) {
    // Json Serialization
    m.def("SerializeToFile", static_cast<bool (*)(const std::string&, const CryptoContext<DCRTPoly>&, const SerType::SERJSON&)>(&Serial::SerializeToFile<DCRTPoly>), py::arg("filename"), py::arg("obj"), py::arg("sertype"));
    m.def("DeserializeFromFile", static_cast<bool (*)(const std::string&, CryptoContext<DCRTPoly>& ,const SerType::SERJSON&)>(&Serial::DeserializeFromFile<DCRTPoly>), py::arg("filename"), py::arg("obj"), py::arg("sertype"));
    m.def("DeserializeFromFile2", static_cast<CryptoContext<DCRTPoly> (*)(const std::string& ,const SerType::SERJSON&)>(&DeserializeFromFileWrapper), py::arg("filename"), py::arg("sertype"));
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


