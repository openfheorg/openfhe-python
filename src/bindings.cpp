#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <pybind11/complex.h>
#include <pybind11/functional.h>
#include <pybind11/operators.h>
#include <pybind11/iostream.h>
#include <iostream>
#include "openfhe.h"
#include "key/key-ser.h"
#include "bindings.h"
#include "cryptocontext_wrapper.h"
#include "serialization.h"
#include "binfhe_bindings.h"

using namespace lbcrypto;
namespace py = pybind11;

void bind_parameters(py::module &m)
{
    py::class_<Params>(m, "Params");
    py::class_<CCParams<CryptoContextBFVRNS>, Params>(m, "CCParamsBFVRNS")
        .def(py::init<>())
        // setters
        .def("SetPlaintextModulus", &CCParams<CryptoContextBFVRNS>::SetPlaintextModulus)
        .def("SetMultiplicativeDepth", &CCParams<CryptoContextBFVRNS>::SetMultiplicativeDepth)
        // getters
        .def("GetPlaintextModulus", &CCParams<CryptoContextBFVRNS>::GetPlaintextModulus)
        .def("GetMultiplicativeDepth", &CCParams<CryptoContextBFVRNS>::GetMultiplicativeDepth);
    py::class_<CCParams<CryptoContextBGVRNS>, Params>(m, "CCParamsBGVRNS")
        .def(py::init<>())
        // setters
        .def("SetPlaintextModulus", &CCParams<CryptoContextBGVRNS>::SetPlaintextModulus)
        .def("SetMultiplicativeDepth", &CCParams<CryptoContextBGVRNS>::SetMultiplicativeDepth)
        // getters
        .def("GetPlaintextModulus", &CCParams<CryptoContextBGVRNS>::GetPlaintextModulus)
        .def("GetMultiplicativeDepth", &CCParams<CryptoContextBGVRNS>::GetMultiplicativeDepth);
    // bind ckks rns params
    py::class_<CCParams<CryptoContextCKKSRNS>, Params>(m, "CCParamsCKKSRNS")
        .def(py::init<>())
        // setters
        .def("SetPlaintextModulus", &CCParams<CryptoContextCKKSRNS>::SetPlaintextModulus)
        .def("SetMultiplicativeDepth", &CCParams<CryptoContextCKKSRNS>::SetMultiplicativeDepth)
        .def("SetScalingModSize", &CCParams<CryptoContextCKKSRNS>::SetScalingModSize)
        .def("SetBatchSize", &CCParams<CryptoContextCKKSRNS>::SetBatchSize)
        .def("SetScalingTechnique", &CCParams<CryptoContextCKKSRNS>::SetScalingTechnique)
        .def("SetNumLargeDigits", &CCParams<CryptoContextCKKSRNS>::SetNumLargeDigits)
        .def("SetKeySwitchTechnique", &CCParams<CryptoContextCKKSRNS>::SetKeySwitchTechnique)
        .def("SetFirstModSize", &CCParams<CryptoContextCKKSRNS>::SetFirstModSize)
        .def("SetDigitSize", &CCParams<CryptoContextCKKSRNS>::SetDigitSize)
        .def("SetSecretKeyDist", &CCParams<CryptoContextCKKSRNS>::SetSecretKeyDist)
        .def("SetSecurityLevel", &CCParams<CryptoContextCKKSRNS>::SetSecurityLevel)
        .def("SetRingDim", &CCParams<CryptoContextCKKSRNS>::SetRingDim)
        .def("SetScalingModSize", &CCParams<CryptoContextCKKSRNS>::SetScalingModSize)

        // getters
        .def("GetPlaintextModulus", &CCParams<CryptoContextCKKSRNS>::GetPlaintextModulus)
        .def("GetMultiplicativeDepth", &CCParams<CryptoContextCKKSRNS>::GetMultiplicativeDepth)
        .def("GetScalingModSize", &CCParams<CryptoContextCKKSRNS>::GetScalingModSize)
        .def("GetBatchSize", &CCParams<CryptoContextCKKSRNS>::GetBatchSize)
        .def("GetScalingTechnique", &CCParams<CryptoContextCKKSRNS>::GetScalingTechnique);
}

void bind_crypto_context(py::module &m)
{
    py::class_<CryptoContextImpl<DCRTPoly>, std::shared_ptr<CryptoContextImpl<DCRTPoly>>>(m, "CryptoContext")
        .def(py::init<>())
        .def("GetKeyGenLevel", &CryptoContextImpl<DCRTPoly>::GetKeyGenLevel)
        .def("SetKeyGenLevel", &CryptoContextImpl<DCRTPoly>::SetKeyGenLevel)
        .def("get_ptr", [](const CryptoContext<DCRTPoly> &self)
             { std::cout << "CC shared ptr (python cc)" << self->GetCryptoParameters().get() << std::endl; })
        //.def("GetScheme",&CryptoContextImpl<DCRTPoly>::GetScheme)
        //.def("GetCryptoParameters", &CryptoContextImpl<DCRTPoly>::GetCryptoParameters)
        .def("GetRingDimension", &CryptoContextImpl<DCRTPoly>::GetRingDimension)
        .def("Enable", static_cast<void (CryptoContextImpl<DCRTPoly>::*)(PKESchemeFeature)>(&CryptoContextImpl<DCRTPoly>::Enable), "Enable a feature for the CryptoContext")
        .def("KeyGen", &CryptoContextImpl<DCRTPoly>::KeyGen, "Generate a key pair with public and private keys")
        .def("EvalMultKeyGen", &CryptoContextImpl<DCRTPoly>::EvalMultKeyGen, "Generate the evaluation key for multiplication")
        .def("EvalRotateKeyGen", &CryptoContextImpl<DCRTPoly>::EvalRotateKeyGen, "Generate the evaluation key for rotation",
             py::arg("privateKey"), py::arg("indexList"), py::arg("publicKey") = nullptr)
        .def("MakePackedPlaintext", &CryptoContextImpl<DCRTPoly>::MakePackedPlaintext, "Make a plaintext from a vector of integers",
             py::arg("value"), py::arg("depth") = 1, py::arg("level") = 0)
        .def("MakeCKKSPackedPlaintext", static_cast<Plaintext (CryptoContextImpl<DCRTPoly>::*)(const std::vector<std::complex<double>> &, size_t, uint32_t, const std::shared_ptr<ParmType>, usint) const>(&CryptoContextImpl<DCRTPoly>::MakeCKKSPackedPlaintext), "Make a CKKS plaintext from a vector of complex doubles",
             py::arg("value"),
             py::arg("depth") = static_cast<size_t>(1),
             py::arg("level") = static_cast<uint32_t>(0),
             py::arg("params") = py::none(),
             py::arg("slots") = 0)
        .def("MakeCKKSPackedPlaintext", static_cast<Plaintext (CryptoContextImpl<DCRTPoly>::*)(const std::vector<double> &, size_t, uint32_t, const std::shared_ptr<ParmType>, usint) const>(&CryptoContextImpl<DCRTPoly>::MakeCKKSPackedPlaintext), "Make a CKKS plaintext from a vector of doubles",
             py::arg("value"),
             py::arg("depth") = static_cast<size_t>(1),
             py::arg("level") = static_cast<uint32_t>(0),
             py::arg("params") = py::none(),
             py::arg("slots") = 0)
        .def("EvalRotate", &CryptoContextImpl<DCRTPoly>::EvalRotate, "Rotate a ciphertext")
        .def("EvalFastRotationPrecompute", &EvalFastRotationPrecomputeWrapper)
        .def("EvalFastRotation", &EvalFastRotationWrapper)
        .def("Encrypt", static_cast<Ciphertext<DCRTPoly> (CryptoContextImpl<DCRTPoly>::*)(const PublicKey<DCRTPoly>, Plaintext) const>(&CryptoContextImpl<DCRTPoly>::Encrypt),
             "Encrypt a plaintext using public key")
        .def("Decrypt", static_cast<Plaintext (*)(CryptoContext<DCRTPoly> &, const PrivateKey<DCRTPoly>, ConstCiphertext<DCRTPoly>)>(&DecryptWrapper),
             "Decrypt a ciphertext using private key")
        .def("Decrypt", static_cast<Plaintext (*)(CryptoContext<DCRTPoly> &, ConstCiphertext<DCRTPoly>, const PrivateKey<DCRTPoly>)>(&DecryptWrapper),
             "Decrypt a ciphertext using private key")
        //.def("EvalAdd", static_cast<Ciphertext<DCRTPoly> (CryptoContextImpl<DCRTPoly>::*)(ConstCiphertext<DCRTPoly>, ConstCiphertext<DCRTPoly>) const>(&CryptoContextImpl<DCRTPoly>::EvalAdd), "Add two ciphertexts")

        .def("EvalAdd", [](const CryptoContext<DCRTPoly> &self, ConstCiphertext<DCRTPoly> ct1, ConstCiphertext<DCRTPoly> ct2)
             {
            // Identical if the parameters and the schemes are identical... the exact
        // same object, OR the same type and the same values
        auto a = ct1->GetCryptoContext().get();
        auto b = self.get();
        std::cout << "Comparing shared CryptoContexts: " << std::endl;
        std::cout << "ct1 ---" << a << std::endl;
        std::cout << "self --" << b << std::endl;
        if(a!=b){
            std::cout << "CryptoContexts are not identical" << std::endl;
        }
        std::cout << "Comparing params: " << std::endl;
        std::cout << "ct1 ---" << a->GetCryptoParameters().get() << std::endl;
        std::cout << "self --" << b->GetCryptoParameters().get() << std::endl;
        if (a->GetCryptoParameters().get() == b->GetCryptoParameters().get()) {
            std::cout << "Params are identical" << std::endl;
        }
        else {
            std::cout << "type ids:"<< std::endl;
            std::cout << "ct1 ---" << typeid(*a->GetCryptoParameters().get()).name() << std::endl;
            std::cout << "self --" << typeid(*b->GetCryptoParameters().get()).name() << std::endl;
            if (typeid(*a->GetCryptoParameters().get()) != typeid(*b->GetCryptoParameters().get())) {
                std::cout << "Params typeid are not identical" << std::endl;
            }
            std::cout << "Comparing params *values: " << std::endl;
            std::cout << "ct1 ---" << *a->GetCryptoParameters().get() << std::endl;
            std::cout << "self --" << *b->GetCryptoParameters().get() << std::endl;
            if (*a->GetCryptoParameters().get() != *b->GetCryptoParameters().get())
                std::cout << "Params * values are not identical" << std::endl;
        }
        std::cout << "Comparing schemes: " << std::endl;
        std::cout << "ct1 ---" << a->GetScheme().get() << std::endl;
        std::cout << "self --" << b->GetScheme().get() << std::endl;
        if (a->GetScheme().get() == b->GetScheme().get()) {
            std::cout << "Schemes are identical" << std::endl;
        }
        else {
            std::cout << "Scheme type ids:"<< std::endl;
            std::cout << "ct1 ---" << typeid(*a->GetScheme().get()).name() << std::endl;
            std::cout << "self --" << typeid(*b->GetScheme().get()).name() << std::endl;
            if (typeid(*a->GetScheme().get()) != typeid(*b->GetScheme().get())) {
                std::cout << "Scheme typeid are not identical" << std::endl;
            }
            std::cout << "Comparing scheme *values: " << std::endl;
            std::cout << "ct1 ---" << *a->GetScheme().get() << std::endl;
            std::cout << "self --" << *b->GetScheme().get() << std::endl;
            if (*a->GetScheme().get() != *b->GetScheme().get())
                std::cout << "Scheme * values are not identical" << std::endl;
        }
            return self->EvalAdd(ct1, ct2); })
        .def("EvalAdd", static_cast<Ciphertext<DCRTPoly> (CryptoContextImpl<DCRTPoly>::*)(ConstCiphertext<DCRTPoly>, double) const>(&CryptoContextImpl<DCRTPoly>::EvalAdd), "Add a ciphertext with a scalar")
        .def("EvalSub", static_cast<Ciphertext<DCRTPoly> (CryptoContextImpl<DCRTPoly>::*)(ConstCiphertext<DCRTPoly>, ConstCiphertext<DCRTPoly>) const>(&CryptoContextImpl<DCRTPoly>::EvalSub), "Subtract two ciphertexts")
        .def("EvalSub", static_cast<Ciphertext<DCRTPoly> (CryptoContextImpl<DCRTPoly>::*)(ConstCiphertext<DCRTPoly>, double) const>(&CryptoContextImpl<DCRTPoly>::EvalSub), "Subtract double from ciphertext")
        .def("EvalSub", static_cast<Ciphertext<DCRTPoly> (CryptoContextImpl<DCRTPoly>::*)(double, ConstCiphertext<DCRTPoly>) const>(&CryptoContextImpl<DCRTPoly>::EvalSub), "Subtract ciphertext from double")
        .def("EvalMult", static_cast<Ciphertext<DCRTPoly> (CryptoContextImpl<DCRTPoly>::*)(ConstCiphertext<DCRTPoly>, ConstCiphertext<DCRTPoly>) const>(&CryptoContextImpl<DCRTPoly>::EvalMult), "Multiply two ciphertexts")
        .def("EvalMult", static_cast<Ciphertext<DCRTPoly> (CryptoContextImpl<DCRTPoly>::*)(ConstCiphertext<DCRTPoly>, double) const>(&CryptoContextImpl<DCRTPoly>::EvalMult), "Multiply a ciphertext with a scalar")
        .def("EvalLogistic", &CryptoContextImpl<DCRTPoly>::EvalLogistic,
             py::arg("ciphertext"),
             py::arg("a"),
             py::arg("b"),
             py::arg("degree"))
        .def("EvalChebyshevFunction", &CryptoContextImpl<DCRTPoly>::EvalChebyshevFunction,
             py::arg("func"),
             py::arg("ciphertext"),
             py::arg("a"),
             py::arg("b"),
             py::arg("degree"))
        .def("EvalPoly", &CryptoContextImpl<DCRTPoly>::EvalPoly,
             py::arg("ciphertext"),
             py::arg("coefficients"))
        .def("Rescale", &CryptoContextImpl<DCRTPoly>::Rescale, "Rescale a ciphertext")
        .def("EvalBootstrapSetup", &CryptoContextImpl<DCRTPoly>::EvalBootstrapSetup,
             py::arg("levelBudget") = std::vector<uint32_t>({5, 4}),
             py::arg("dim1") = std::vector<uint32_t>({0, 0}),
             py::arg("slots") = 0,
             py::arg("correctionFactor") = 0)
        .def("EvalBootstrapKeyGen", &CryptoContextImpl<DCRTPoly>::EvalBootstrapKeyGen,
             py::arg("privateKey"),
             py::arg("slots"))
        .def("EvalBootstrap", &CryptoContextImpl<DCRTPoly>::EvalBootstrap,
             py::arg("ciphertext"),
             py::arg("numIterations") = 1,
             py::arg("precision") = 0)
        .def_static(
            "ClearEvalMultKeys", []()
            { CryptoContextImpl<DCRTPoly>::ClearEvalMultKeys(); },
            "Clear the evaluation keys for multiplication")
        .def_static(
            "ClearEvalAutomorphismKeys", []()
            { CryptoContextImpl<DCRTPoly>::ClearEvalAutomorphismKeys(); },
            "Clear the evaluation keys for rotation")
        // .def("SerializeEvalMultKey",&SerializeEvalMultKeyWrapper<SerType::SERBINARY>,
        //     py::arg("filename"),
        //     py::arg("sertype"),
        //     py::arg("id") = "",
        //     "Serialize an evaluation key for multiplication")
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
        .def("DeserializeEvalMultKey", [](CryptoContext<DCRTPoly> &self, const std::string &filename, const SerType::SERBINARY &sertype)
             {
                        std::ifstream emkeys(filename, std::ios::in | std::ios::binary);
                         if (!emkeys.is_open()) {
                            std::cerr << "I cannot read serialization from " << filename << std::endl;
                         }
                        bool res;
                        res = self->DeserializeEvalMultKey<SerType::SERBINARY>(emkeys, sertype);
                        return res; })
        // .def("DeserializeEvalMultKey",&DeserializeEvalMultKeyWrapper<SerType::SERBINARY>,
        //     py::arg("filename"),
        //     py::arg("sertype"),
        //     "Deserialize an evaluation key for multiplication")
        .def("DeserializeEvalAutomorphismKey", [](std::shared_ptr<CryptoContextImpl<DCRTPoly>> &self, const std::string &filename, const SerType::SERBINARY &sertype)
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
    m.def("GenCryptoContext", &GenCryptoContext<CryptoContextCKKSRNS>);
    m.def("ReleaseAllContexts", &CryptoContextFactory<DCRTPoly>::ReleaseAllContexts);
    m.def("GetAllContexts", &CryptoContextFactory<DCRTPoly>::GetAllContexts);
}

int get_native_int(){
    #if NATIVEINT == 128 && !defined(__EMSCRIPTEN__)
        return 128;
    #else
        return 64;    
    #endif
}
void bind_enums_and_constants(py::module &m)
{
    /* ---- PKE enums ---- */ 
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
    py::class_<SerType::SERJSON>(m, "SERJSON");
    py::class_<SerType::SERBINARY>(m, "SERBINARY");
    m.attr("JSON") = py::cast(SerType::JSON);
    m.attr("BINARY") = py::cast(SerType::BINARY);

    // Scaling Techniques
    py::enum_<ScalingTechnique>(m, "ScalingTechnique")
       .value("FIXEDMANUAL", ScalingTechnique::FIXEDMANUAL)
       .value("FIXEDAUTO", ScalingTechnique::FIXEDAUTO)
       .value("FLEXIBLEAUTO", ScalingTechnique::FLEXIBLEAUTO)
       .value("FLEXIBLEAUTOEXT", ScalingTechnique::FLEXIBLEAUTOEXT)
       .value("NORESCALE", ScalingTechnique::NORESCALE)
       .value("INVALID_RS_TECHNIQUE", ScalingTechnique::INVALID_RS_TECHNIQUE);
    // Key Switching Techniques
    py::enum_<KeySwitchTechnique>(m, "KeySwitchTechnique")
        .value("INVALID_KS_TECH", KeySwitchTechnique::INVALID_KS_TECH)
        .value("BV", KeySwitchTechnique::BV)
        .value("HYBRID", KeySwitchTechnique::HYBRID);
    // Secret Key Dist
    py::enum_<SecretKeyDist>(m, "SecretKeyDist")
        .value("GAUSSIAN", SecretKeyDist::GAUSSIAN)
        .value("UNIFORM_TERNARY", SecretKeyDist::UNIFORM_TERNARY)
        .value("SPARsE_TERNARY", SecretKeyDist::SPARSE_TERNARY);

    /* ---- CORE enums ---- */ 
    // Security Level
    py::enum_<SecurityLevel>(m,"SecurityLevel")
        .value("HEStd_128_classic", SecurityLevel::HEStd_128_classic)
        .value("HEStd_192_classic", SecurityLevel::HEStd_192_classic)
        .value("HEStd_256_classic", SecurityLevel::HEStd_256_classic)
        .value("HEStd_NotSet", SecurityLevel::HEStd_NotSet);

    
    //Parameters Type
    /*TODO (Oliveira): If we expose Poly's and ParmType, this block will go somewhere else */
    using ParmType = typename DCRTPoly::Params;
    py::class_<ParmType, std::shared_ptr<ParmType>>(m, "ParmType");

    //NATIVEINT function
    m.def("get_native_int", &get_native_int);
}

void bind_keys(py::module &m)
{
    py::class_<PublicKeyImpl<DCRTPoly>, std::shared_ptr<PublicKeyImpl<DCRTPoly>>>(m, "PublicKey")
        .def(py::init<>());
    py::class_<PrivateKeyImpl<DCRTPoly>, std::shared_ptr<PrivateKeyImpl<DCRTPoly>>>(m, "PrivateKey");
    py::class_<KeyPair<DCRTPoly>>(m, "KeyPair")
        .def_readwrite("publicKey", &KeyPair<DCRTPoly>::publicKey)
        .def_readwrite("secretKey", &KeyPair<DCRTPoly>::secretKey);
}

void bind_encodings(py::module &m)
{
    py::class_<PlaintextImpl, std::shared_ptr<PlaintextImpl>>(m, "Plaintext")
        .def("GetScalingFactor", &PlaintextImpl::GetScalingFactor)
        .def("SetScalingFactor", &PlaintextImpl::SetScalingFactor)
        .def("GetLength", &PlaintextImpl::GetLength)
        .def("GetSchemeID", &PlaintextImpl::GetSchemeID)
        .def("SetLength", &PlaintextImpl::SetLength)
        .def("IsEncoded", &PlaintextImpl::IsEncoded)
        .def("GetLogPrecision", &PlaintextImpl::GetLogPrecision)
        //.def("GetEncondingParams", &PlaintextImpl::GetEncondingParams)
        .def("Encode", &PlaintextImpl::Encode)
        .def("Decode", &PlaintextImpl::Decode)
        .def("GetCKKSPackedValue", &PlaintextImpl::GetCKKSPackedValue)
        .def("__repr__", [](const PlaintextImpl &p)
             {
        std::stringstream ss;
        ss << "<Plaintext Object: ";
        p.PrintValue(ss);
        ss << ">";
        return ss.str(); })
        .def("__str__", [](const PlaintextImpl &p)
             {
        std::stringstream ss;
        p.PrintValue(ss);
        return ss.str(); });
}

void bind_ciphertext(py::module &m)
{
    py::class_<CiphertextImpl<DCRTPoly>, std::shared_ptr<CiphertextImpl<DCRTPoly>>>(m, "Ciphertext")
        .def(py::init<>())
        .def("__add__", [](const Ciphertext<DCRTPoly> &a, const Ciphertext<DCRTPoly> &b)
             {return a + b; },py::is_operator(),pybind11::keep_alive<0, 1>())
       // .def(py::self + py::self);
    // .def("GetDepth", &CiphertextImpl<DCRTPoly>::GetDepth)
    // .def("SetDepth", &CiphertextImpl<DCRTPoly>::SetDepth)
     .def("GetLevel", &CiphertextImpl<DCRTPoly>::GetLevel)
     .def("SetLevel", &CiphertextImpl<DCRTPoly>::SetLevel)
     .def("get_ptr",[](const Ciphertext<DCRTPoly> &self){
        std::cout<< "cryptoparameters shared ptr (python)" << self->GetCryptoContext()->GetCryptoParameters().get() << std::endl;});
    // .def("GetHopLevel", &CiphertextImpl<DCRTPoly>::GetHopLevel)
    // .def("SetHopLevel", &CiphertextImpl<DCRTPoly>::SetHopLevel)
    // .def("GetScalingFactor", &CiphertextImpl<DCRTPoly>::GetScalingFactor)
    // .def("SetScalingFactor", &CiphertextImpl<DCRTPoly>::SetScalingFactor)
    // .def("GetSlots", &CiphertextImpl<DCRTPoly>::GetSlots)
    // .def("SetSlots", &CiphertextImpl<DCRTPoly>::SetSlots);
}

void bind_schemes(py::module &m){
    /*Bind schemes specific functionalities like bootstrapping functions and multiparty*/
    py::class_<FHECKKSRNS>(m, "FHECKKSRNS")
        .def(py::init<>())
        //.def_static("GetBootstrapDepth", &FHECKKSRNS::GetBootstrapDepth)
        .def_static("GetBootstrapDepth", static_cast<uint32_t (*)(uint32_t, const std::vector<uint32_t>&, SecretKeyDist)>(&FHECKKSRNS::GetBootstrapDepth));                               
    
}

PYBIND11_MODULE(openfhe, m)
{
    m.doc() = "Open-Source Fully Homomorphic Encryption Library";
    // pke library
    bind_parameters(m);
    bind_enums_and_constants(m);
    bind_crypto_context(m);
    bind_keys(m);
    bind_encodings(m);
    bind_ciphertext(m);
    bind_serialization(m);
    bind_schemes(m);
    // binfhe library
    bind_binfhe_enums(m);
    bind_binfhe_context(m);
    bind_binfhe_keys(m);
    bind_binfhe_ciphertext(m);
}
