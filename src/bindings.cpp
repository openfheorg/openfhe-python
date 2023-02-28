#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
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
            .def("SetKeyGenLevel",&CryptoContextImpl<DCRTPoly>::SetKeyGenLevel)
            .def("Enable",static_cast<void (CryptoContextImpl<DCRTPoly>::*)(PKESchemeFeature)>(&CryptoContextImpl<DCRTPoly>::Enable), "Enable a feature for the CryptoContext")
            .def("KeyGen",&CryptoContextImpl<DCRTPoly>::KeyGen,"Generate a key pair with public and private keys") 
            .def("EvalMultKeyGen",&CryptoContextImpl<DCRTPoly>::EvalMultKeyGen,"Generate the evaluation key for multiplication")
            .def("EvalRotateKeyGen",&CryptoContextImpl<DCRTPoly>::EvalRotateKeyGen,"Generate the evaluation key for rotation",
            py::arg("privateKey"),py::arg("indexList"),py::arg("publicKey")=nullptr)
            .def("MakePackedPlaintext",&CryptoContextImpl<DCRTPoly>::MakePackedPlaintext,"Make a plaintext from a vector of integers",
            py::arg("value"),py::arg("depth")=1,py::arg("level")=0)
            .def("EvalRotate",&CryptoContextImpl<DCRTPoly>::EvalRotate,"Rotate a ciphertext");
            //.def("MakePackedPlaintext",static_cast<Plaintext (CryptoContextImpl<DCRTPoly>::*)(const std::vector<int64_t>&)>(&CryptoContextImpl<DCRTPoly>::MakePackedPlaintext), "Make a plaintext from a vector of integers")
    // Generator Functions    
    m.def("GenCryptoContext", &GenCryptoContext<CryptoContextBFVRNS>);
    m.def("GenCryptoContext", &GenCryptoContext<CryptoContextBGVRNS>);
    

}




void bind_enums(py::module &m){
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
}

void bind_keys(py::module &m){
    py::class_<PublicKeyImpl<DCRTPoly>,std::shared_ptr<PublicKeyImpl<DCRTPoly>>>(m,"PublicKey");
    py::class_<PrivateKeyImpl<DCRTPoly>,std::shared_ptr<PrivateKeyImpl<DCRTPoly>>>(m,"PrivateKey");
    py::class_<KeyPair<DCRTPoly>>(m,"KeyPair")
            .def_readwrite("publicKey", &KeyPair<DCRTPoly>::publicKey)
            .def_readwrite("secretKey", &KeyPair<DCRTPoly>::secretKey);
}

void bind_encodings(py::module &m){
    py::class_<PlaintextImpl,std::shared_ptr<PlaintextImpl>>(m,"Plaintext")
    .def("GetScalingFactor", &PlaintextImpl::GetScalingFactor)
    .def("SetScalingFactor", &PlaintextImpl::SetScalingFactor)
    .def("GetSchemeID", &PlaintextImpl::GetSchemeID)
    .def("IsEncoded", &PlaintextImpl::IsEncoded)
    //.def("GetEncondingParams", &PlaintextImpl::GetEncondingParams)
    .def("Encode", &PlaintextImpl::Encode)
    .def("Decode", &PlaintextImpl::Decode);

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
    bind_enums(m);
    bind_keys(m);
    bind_encodings(m);
    bind_ciphertext(m);

}