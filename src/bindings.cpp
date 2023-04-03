#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <pybind11/iostream.h>
#include <iostream>
#include <openfhe/pke/openfhe.h>
#include <openfhe/pke/key/key-ser.h>
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
    py::class_<CCParams<CryptoContextBGVRNS>, Params>(m, "CCParamsBGVRNS")
            .def(py::init<>())
            // setters
            .def("SetPlaintextModulus", &CCParams<CryptoContextBGVRNS>::SetPlaintextModulus)
            .def("SetMultiplicativeDepth",&CCParams<CryptoContextBGVRNS>::SetMultiplicativeDepth)
            // getters
            .def("GetPlaintextModulus", &CCParams<CryptoContextBGVRNS>::GetPlaintextModulus)
            .def("GetMultiplicativeDepth", &CCParams<CryptoContextBGVRNS>::GetMultiplicativeDepth);
           
}

void bind_crypto_context(py::module &m)
{
    py::class_<CryptoContextImpl<DCRTPoly>, std::shared_ptr<CryptoContextImpl<DCRTPoly>>>(m, "CryptoContext")
        .def(py::init<>())
        .def("GetKeyGenLevel", &CryptoContextImpl<DCRTPoly>::GetKeyGenLevel)
        .def("SetKeyGenLevel", &CryptoContextImpl<DCRTPoly>::SetKeyGenLevel)
        .def("Enable", static_cast<void (CryptoContextImpl<DCRTPoly>::*)(PKESchemeFeature)>(&CryptoContextImpl<DCRTPoly>::Enable), "Enable a feature for the CryptoContext")
        .def("KeyGen", &CryptoContextImpl<DCRTPoly>::KeyGen, "Generate a key pair with public and private keys")
        .def("EvalMultKeyGen", &CryptoContextImpl<DCRTPoly>::EvalMultKeyGen, "Generate the evaluation key for multiplication")
        .def("EvalRotateKeyGen", &CryptoContextImpl<DCRTPoly>::EvalRotateKeyGen, "Generate the evaluation key for rotation",
             py::arg("privateKey"), py::arg("indexList"), py::arg("publicKey") = nullptr)
        .def("MakePackedPlaintext", &CryptoContextImpl<DCRTPoly>::MakePackedPlaintext, "Make a plaintext from a vector of integers",
             py::arg("value"), py::arg("depth") = 1, py::arg("level") = 0)
        .def("EvalRotate", &CryptoContextImpl<DCRTPoly>::EvalRotate, "Rotate a ciphertext")
        .def("Encrypt", static_cast<Ciphertext<DCRTPoly> (CryptoContextImpl<DCRTPoly>::*)(const PublicKey<DCRTPoly>, Plaintext) const>(&CryptoContextImpl<DCRTPoly>::Encrypt),
             "Encrypt a plaintext using public key")
        .def("EvalAdd", static_cast<Ciphertext<DCRTPoly> (CryptoContextImpl<DCRTPoly>::*)(ConstCiphertext<DCRTPoly>, ConstCiphertext<DCRTPoly>) const>(&CryptoContextImpl<DCRTPoly>::EvalAdd), "Add two ciphertexts")
        .def("EvalMult", static_cast<Ciphertext<DCRTPoly> (CryptoContextImpl<DCRTPoly>::*)(ConstCiphertext<DCRTPoly>, ConstCiphertext<DCRTPoly>) const>(&CryptoContextImpl<DCRTPoly>::EvalMult), "Multiply two ciphertexts")
        .def_static(
            "ClearEvalMultKeys", []()
            { CryptoContextImpl<DCRTPoly>::ClearEvalMultKeys(); },
            "Clear the evaluation keys for multiplication")
        .def_static(
            "ClearEvalAutomorphismKeys", []()
            { CryptoContextImpl<DCRTPoly>::ClearEvalAutomorphismKeys(); },
            "Clear the evaluation keys for rotation")
        .def_static(
            "SerializeEvalMultKey", [](const std::string &filename, const SerType::SERBINARY &sertype, std::string id = "")
            {
                std::ofstream outfile(filename,std::ios::out | std::ios::binary);
                bool res;
                res = CryptoContextImpl<DCRTPoly>::SerializeEvalMultKey<SerType::SERBINARY>(outfile, sertype, id);
                outfile.close();
                return res; },
            py::arg("filename"), py::arg("sertype"), py::arg("id") = "",
            "Serialize an evaluation key for multiplication")
        .def_static(
            "SerializeEvalAutomorphismKey", [](const std::string &filename, const SerType::SERBINARY &sertype, std::string id = "")
            {
                std::ofstream outfile(filename,std::ios::out | std::ios::binary);
                bool res;
                res = CryptoContextImpl<DCRTPoly>::SerializeEvalAutomorphismKey<SerType::SERBINARY>(outfile, sertype, id);
                outfile.close();
                return res; },
            py::arg("filename"), py::arg("sertype"), py::arg("id") = "", "Serialize evaluation keys for rotation")
        .def_static("DeserializeEvalMultKey", [](std::shared_ptr<CryptoContextImpl<DCRTPoly>> &self,const std::string &filename, const SerType::SERBINARY &sertype)
                    {
                        std::ifstream emkeys(filename, std::ios::in | std::ios::binary);
                         if (!emkeys.is_open()) {
                            std::cerr << "I cannot read serialization from " << filename << std::endl;
                         }
                        bool res;
                        res = self->DeserializeEvalMultKey<SerType::SERBINARY>(emkeys, sertype);
                        return res; })
        .def_static("DeserializeEvalAutomorphismKey", [](std::shared_ptr<CryptoContextImpl<DCRTPoly>> &self,const std::string &filename, const SerType::SERBINARY &sertype)
                    {
                        std::ifstream erkeys(filename, std::ios::in | std::ios::binary);
                         if (!erkeys.is_open()) {
                            std::cerr << "I cannot read serialization from " << filename << std::endl;
                         }
                        bool res;
                        res = self->DeserializeEvalAutomorphismKey<SerType::SERBINARY>(erkeys, sertype);
                        return res; });

    // Generator Functions
    m.def("GenCryptoContext", &GenCryptoContext<CryptoContextBFVRNS>);
    m.def("GenCryptoContext", &GenCryptoContext<CryptoContextBGVRNS>);
    m.def("ReleaseAllContexts",&CryptoContextFactory<DCRTPoly>::ReleaseAllContexts);
}

void bind_enums_and_constants(py::module &m){
    // Scheme Types
    py::enum_<SCHEME>(m, "SCHEME")
            .value("INVALID_SCHEME", SCHEME::INVALID_SCHEME)
            .value("CKKSRNS_SCHEME", SCHEME::CKKSRNS_SCHEME)
            .value("BFVRNS_SCHEME", SCHEME::BFVRNS_SCHEME)
            .value("BGVRNS_SCHEME", SCHEME::BGVRNS_SCHEME);
    // PKE Features
    py::enum_<PKESchemeFeature>(m, "PKESchemeFeature")
            .value("PKE", PKESchemeFeature::PKE)
            .value("KEYSWITCH", PKESchemeFeature::KEYSWITCH)
            .value("PRE", PKESchemeFeature::PRE)
            .value("LEVELEDSHE", PKESchemeFeature::LEVELEDSHE)
            .value("ADVANCEDSHE", PKESchemeFeature::ADVANCEDSHE)
            .value("MULTIPARTY", PKESchemeFeature::MULTIPARTY)
            .value("FHE", PKESchemeFeature::FHE);
    // Serialization Types
    py::class_<SerType::SERJSON >(m, "SERJSON");
    py::class_<SerType::SERBINARY>(m, "SERBINARY");
    m.attr("JSON") = py::cast(SerType::JSON);
    m.attr("BINARY") = py::cast(SerType::BINARY);
}

void bind_keys(py::module &m){
    py::class_<PublicKeyImpl<DCRTPoly>,std::shared_ptr<PublicKeyImpl<DCRTPoly>>>(m,"PublicKey")
    .def(py::init<>());
    py::class_<PrivateKeyImpl<DCRTPoly>,std::shared_ptr<PrivateKeyImpl<DCRTPoly>>>(m,"PrivateKey");
    py::class_<KeyPair<DCRTPoly>>(m,"KeyPair")
            .def_readwrite("publicKey", &KeyPair<DCRTPoly>::publicKey)
            .def_readwrite("secretKey", &KeyPair<DCRTPoly>::secretKey);
}

void bind_encodings(py::module &m){
    py::class_<PlaintextImpl,std::shared_ptr<PlaintextImpl>>(m,"Plaintext")
    .def("GetScalingFactor", &PlaintextImpl::GetScalingFactor)
    .def("SetScalingFactor", &PlaintextImpl::SetScalingFactor)
    .def("GetLength", &PlaintextImpl::GetLength)
    .def("GetSchemeID", &PlaintextImpl::GetSchemeID)
    .def("SetLength", &PlaintextImpl::SetLength)
    .def("IsEncoded", &PlaintextImpl::IsEncoded)
    //.def("GetEncondingParams", &PlaintextImpl::GetEncondingParams)
    .def("Encode", &PlaintextImpl::Encode)
    .def("Decode", &PlaintextImpl::Decode)
    .def("__repr__", [] (const PlaintextImpl& p) {
        std::stringstream ss;
        ss << "<Plaintext Object: ";
        p.PrintValue(ss);
        ss << ">";
        return ss.str();
    })
    .def("__str__", [] (const PlaintextImpl& p) {
        std::stringstream ss;
        p.PrintValue(ss);
        return ss.str();
    });

}

void bind_ciphertext(py::module &m){
    py::class_<CiphertextImpl<DCRTPoly>,std::shared_ptr<CiphertextImpl<DCRTPoly>>>(m,"Ciphertext")
        .def(py::init<>());
        // .def("GetDepth", &CiphertextImpl<DCRTPoly>::GetDepth)
        // .def("SetDepth", &CiphertextImpl<DCRTPoly>::SetDepth)
        // .def("GetLevel", &CiphertextImpl<DCRTPoly>::GetLevel)
        // .def("SetLevel", &CiphertextImpl<DCRTPoly>::SetLevel)
        // .def("GetHopLevel", &CiphertextImpl<DCRTPoly>::GetHopLevel)
        // .def("SetHopLevel", &CiphertextImpl<DCRTPoly>::SetHopLevel)
        // .def("GetScalingFactor", &CiphertextImpl<DCRTPoly>::GetScalingFactor)
        // .def("SetScalingFactor", &CiphertextImpl<DCRTPoly>::SetScalingFactor)
        // .def("GetSlots", &CiphertextImpl<DCRTPoly>::GetSlots)
        // .def("SetSlots", &CiphertextImpl<DCRTPoly>::SetSlots);
}


PYBIND11_MODULE(openfhe, m) {
    m.doc() = "Open-Source Fully Homomorphic Encryption Library";
    bind_parameters(m);
    bind_crypto_context(m);
    bind_enums_and_constants(m);
    bind_keys(m);
    bind_encodings(m);
    bind_ciphertext(m);
    bind_decryption(m);
    bind_serialization(m);
}
