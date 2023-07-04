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
#include "binfhe_bindings.h"

using namespace lbcrypto;
namespace py = pybind11;

template <typename T>
void bind_parameters(py::module &m,const std::string name)
{
    py::class_<CCParams<T>, Params>(m, name.c_str())
        .def(py::init<>())
        // getters
        .def("GetPlaintextModulus", &CCParams<T>::GetPlaintextModulus)
        .def("GetScheme", &CCParams<T>::GetScheme)
        .def("GetDigitSize", &CCParams<T>::GetDigitSize)
        .def("GetStandardDeviation", &CCParams<T>::GetStandardDeviation)
        .def("GetSecretKeyDist", &CCParams<T>::GetSecretKeyDist)
        .def("GetMaxRelinSkDeg", &CCParams<T>::GetMaxRelinSkDeg)
        .def("GetPREMode", &CCParams<T>::GetPREMode)
        .def("GetMultipartyMode", &CCParams<T>::GetMultipartyMode)
        .def("GetExecutionMode", &CCParams<T>::GetExecutionMode)
        .def("GetDecryptionNoiseMode", &CCParams<T>::GetDecryptionNoiseMode)
        .def("GetNoiseEstimate", &CCParams<T>::GetNoiseEstimate)
        .def("GetDesiredPrecision", &CCParams<T>::GetDesiredPrecision)
        .def("GetStatisticalSecurity", &CCParams<T>::GetStatisticalSecurity)
        .def("GetNumAdversarialQueries", &CCParams<T>::GetNumAdversarialQueries)
        .def("GetThresholdNumOfParties", &CCParams<T>::GetThresholdNumOfParties)
        .def("GetKeySwitchTechnique", &CCParams<T>::GetKeySwitchTechnique)
        .def("GetScalingTechnique", &CCParams<T>::GetScalingTechnique)
        .def("GetBatchSize", &CCParams<T>::GetBatchSize)
        .def("GetFirstModSize", &CCParams<T>::GetFirstModSize)
        .def("GetNumLargeDigits", &CCParams<T>::GetNumLargeDigits)
        .def("GetMultiplicativeDepth", &CCParams<T>::GetMultiplicativeDepth)
        .def("GetScalingModSize", &CCParams<T>::GetScalingModSize)
        .def("GetSecurityLevel", &CCParams<T>::GetSecurityLevel)
        .def("GetRingDim", &CCParams<T>::GetRingDim)
        .def("GetEvalAddCount", &CCParams<T>::GetEvalAddCount)
        .def("GetKeySwitchCount", &CCParams<T>::GetKeySwitchCount)
        .def("GetEncryptionTechnique", &CCParams<T>::GetEncryptionTechnique)
        .def("GetMultiplicationTechnique", &CCParams<T>::GetMultiplicationTechnique)
        .def("GetMultiHopModSize", &CCParams<T>::GetMultiHopModSize)
        // setters
        .def("SetPlaintextModulus", &CCParams<T>::SetPlaintextModulus)
        .def("SetDigitSize", &CCParams<T>::SetDigitSize)
        .def("SetStandardDeviation", &CCParams<T>::SetStandardDeviation)
        .def("SetSecretKeyDist", &CCParams<T>::SetSecretKeyDist)
        .def("SetMaxRelinSkDeg", &CCParams<T>::SetMaxRelinSkDeg)
        .def("SetPREMode", &CCParams<T>::SetPREMode)
        .def("SetMultipartyMode", &CCParams<T>::SetMultipartyMode)
        .def("SetExecutionMode", &CCParams<T>::SetExecutionMode)
        .def("SetDecryptionNoiseMode", &CCParams<T>::SetDecryptionNoiseMode)
        .def("SetNoiseEstimate", &CCParams<T>::SetNoiseEstimate)
        .def("SetDesiredPrecision", &CCParams<T>::SetDesiredPrecision)
        .def("SetStatisticalSecurity", &CCParams<T>::SetStatisticalSecurity)
        .def("SetNumAdversarialQueries", &CCParams<T>::SetNumAdversarialQueries)
        .def("SetThresholdNumOfParties", &CCParams<T>::SetThresholdNumOfParties)
        .def("SetKeySwitchTechnique", &CCParams<T>::SetKeySwitchTechnique)
        .def("SetScalingTechnique", &CCParams<T>::SetScalingTechnique)
        .def("SetBatchSize", &CCParams<T>::SetBatchSize)
        .def("SetFirstModSize", &CCParams<T>::SetFirstModSize)
        .def("SetNumLargeDigits", &CCParams<T>::SetNumLargeDigits)
        .def("SetMultiplicativeDepth", &CCParams<T>::SetMultiplicativeDepth)
        .def("SetScalingModSize", &CCParams<T>::SetScalingModSize)
        .def("SetSecurityLevel", &CCParams<T>::SetSecurityLevel)
        .def("SetRingDim", &CCParams<T>::SetRingDim)
        .def("SetEvalAddCount", &CCParams<T>::SetEvalAddCount)
        .def("SetKeySwitchCount", &CCParams<T>::SetKeySwitchCount)
        .def("SetEncryptionTechnique", &CCParams<T>::SetEncryptionTechnique)
        .def("SetMultiplicationTechnique", &CCParams<T>::SetMultiplicationTechnique)
        .def("SetMultiHopModSize", &CCParams<T>::SetMultiHopModSize)
        .def("__str__",[](const CCParams<T> &params) {
            std::stringstream stream;
            stream << params;
            return stream.str();
        });

        //

}

void bind_crypto_context(py::module &m)
{
    py::class_<CryptoContextImpl<DCRTPoly>, std::shared_ptr<CryptoContextImpl<DCRTPoly>>>(m, "CryptoContext")
        .def(py::init<>())
        .def("GetKeyGenLevel", &CryptoContextImpl<DCRTPoly>::GetKeyGenLevel)
        .def("SetKeyGenLevel", &CryptoContextImpl<DCRTPoly>::SetKeyGenLevel)
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
        .def("MakeCKKSPackedPlaintext",static_cast<Plaintext (CryptoContextImpl<DCRTPoly>::*)(const std::vector<std::complex<double>>&,size_t, uint32_t,const std::shared_ptr<ParmType>, usint) const>(&CryptoContextImpl<DCRTPoly>::MakeCKKSPackedPlaintext), "Make a CKKS plaintext from a vector of complex doubles",
            py::arg("value"),
            py::arg("depth") = static_cast<size_t>(1),
            py::arg("level") = static_cast<uint32_t>(0),
            py::arg("params") = py::none(),
            py::arg("slots") = 0)
        .def("MakeCKKSPackedPlaintext",static_cast<Plaintext (CryptoContextImpl<DCRTPoly>::*)(const std::vector<double>&,size_t, uint32_t,const std::shared_ptr<ParmType>, usint) const>(&CryptoContextImpl<DCRTPoly>::MakeCKKSPackedPlaintext), "Make a CKKS plaintext from a vector of doubles",
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
        .def("Decrypt", static_cast<Plaintext (*)(CryptoContext<DCRTPoly>&, const PrivateKey<DCRTPoly>, ConstCiphertext<DCRTPoly>)>(&DecryptWrapper),
             "Decrypt a ciphertext using private key")
        .def("Decrypt", static_cast<Plaintext (*)(CryptoContext<DCRTPoly>&, ConstCiphertext<DCRTPoly>,const PrivateKey<DCRTPoly>)>(&DecryptWrapper),
             "Decrypt a ciphertext using private key")
        .def("EvalAdd", static_cast<Ciphertext<DCRTPoly> (CryptoContextImpl<DCRTPoly>::*)(ConstCiphertext<DCRTPoly>, ConstCiphertext<DCRTPoly>) const>(&CryptoContextImpl<DCRTPoly>::EvalAdd), "Add two ciphertexts")
        .def("EvalAdd", static_cast<Ciphertext<DCRTPoly> (CryptoContextImpl<DCRTPoly>::*)(ConstCiphertext<DCRTPoly>, double) const>(&CryptoContextImpl<DCRTPoly>::EvalAdd), "Add a ciphertext with a scalar")
        .def("EvalAddInPlace", static_cast<void (CryptoContextImpl<DCRTPoly>::*)(Ciphertext<DCRTPoly> &, ConstCiphertext<DCRTPoly>) const>(&CryptoContextImpl<DCRTPoly>::EvalAddInPlace))
        .def("EvalAddInPlace", static_cast<void (CryptoContextImpl<DCRTPoly>::*)(Ciphertext<DCRTPoly> &, ConstPlaintext) const>(&CryptoContextImpl<DCRTPoly>::EvalAddInPlace))
        .def("EvalAddInPlace", static_cast<void (CryptoContextImpl<DCRTPoly>::*)(ConstPlaintext, Ciphertext<DCRTPoly> &) const>(&CryptoContextImpl<DCRTPoly>::EvalAddInPlace))
        .def("EvalAddMutable", static_cast<Ciphertext<DCRTPoly> (CryptoContextImpl<DCRTPoly>::*)(Ciphertext<DCRTPoly>&, Ciphertext<DCRTPoly>&) const>(&CryptoContextImpl<DCRTPoly>::EvalAddMutable))
        .def("EvalAddMutable", static_cast<Ciphertext<DCRTPoly> (CryptoContextImpl<DCRTPoly>::*)(Ciphertext<DCRTPoly>&, Plaintext) const>(&CryptoContextImpl<DCRTPoly>::EvalAddMutable))
        .def("EvalAddMutable", static_cast<Ciphertext<DCRTPoly> (CryptoContextImpl<DCRTPoly>::*)(Plaintext, Ciphertext<DCRTPoly>&) const>(&CryptoContextImpl<DCRTPoly>::EvalAddMutable))
        .def("EvalSub", static_cast<Ciphertext<DCRTPoly> (CryptoContextImpl<DCRTPoly>::*)(ConstCiphertext<DCRTPoly>, ConstCiphertext<DCRTPoly>) const>(&CryptoContextImpl<DCRTPoly>::EvalSub), "Subtract two ciphertexts")
        .def("EvalSub", static_cast<Ciphertext<DCRTPoly> (CryptoContextImpl<DCRTPoly>::*)(ConstCiphertext<DCRTPoly>, double) const>(&CryptoContextImpl<DCRTPoly>::EvalSub), "Subtract double from ciphertext")
        .def("EvalSub", static_cast<Ciphertext<DCRTPoly> (CryptoContextImpl<DCRTPoly>::*)(double, ConstCiphertext<DCRTPoly>) const>(&CryptoContextImpl<DCRTPoly>::EvalSub), "Subtract ciphertext from double")
        .def("EvalMult", static_cast<Ciphertext<DCRTPoly> (CryptoContextImpl<DCRTPoly>::*)(ConstCiphertext<DCRTPoly>, ConstCiphertext<DCRTPoly>) const>(&CryptoContextImpl<DCRTPoly>::EvalMult), "Multiply two ciphertexts")
        .def("EvalMult", static_cast<Ciphertext<DCRTPoly> (CryptoContextImpl<DCRTPoly>::*)(ConstCiphertext<DCRTPoly>, double) const>(&CryptoContextImpl<DCRTPoly>::EvalMult), "Multiply a ciphertext with a scalar")
        .def("EvalNegate",&CryptoContextImpl<DCRTPoly>::EvalNegate)
        .def("EvalNegateInPlace",&CryptoContextImpl<DCRTPoly>::EvalNegateInPlace)
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
            py::arg("levelBudget") = std::vector<uint32_t>({5,4}),
            py::arg("dim1") = std::vector<uint32_t>({0,0}),
            py::arg("slots") = 0,
            py::arg("correctionFactor") = 0            )
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
    m.def("GenCryptoContext", &GenCryptoContext<CryptoContextCKKSRNS>);
    m.def("ReleaseAllContexts", &CryptoContextFactory<DCRTPoly>::ReleaseAllContexts);
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
    m.attr("INVALID_SCHEME") = py::cast(SCHEME::INVALID_SCHEME);
    m.attr("CKKSRNS_SCHEME") = py::cast(SCHEME::CKKSRNS_SCHEME);
    m.attr("BFVRNS_SCHEME") = py::cast(SCHEME::BFVRNS_SCHEME);
    m.attr("BGVRNS_SCHEME") = py::cast(SCHEME::BGVRNS_SCHEME);

    // PKE Features
    py::enum_<PKESchemeFeature>(m, "PKESchemeFeature")
        .value("PKE", PKESchemeFeature::PKE)
        .value("KEYSWITCH", PKESchemeFeature::KEYSWITCH)
        .value("PRE", PKESchemeFeature::PRE)
        .value("LEVELEDSHE", PKESchemeFeature::LEVELEDSHE)
        .value("ADVANCEDSHE", PKESchemeFeature::ADVANCEDSHE)
        .value("MULTIPARTY", PKESchemeFeature::MULTIPARTY)
        .value("FHE", PKESchemeFeature::FHE);
    m.attr("PKE") = py::cast(PKESchemeFeature::PKE);
    m.attr("KEYSWITCH") = py::cast(PKESchemeFeature::KEYSWITCH);
    m.attr("PRE") = py::cast(PKESchemeFeature::PRE);
    m.attr("LEVELEDSHE") = py::cast(PKESchemeFeature::LEVELEDSHE);
    m.attr("ADVANCEDSHE") = py::cast(PKESchemeFeature::ADVANCEDSHE);
    m.attr("MULTIPARTY") = py::cast(PKESchemeFeature::MULTIPARTY);
    m.attr("FHE") = py::cast(PKESchemeFeature::FHE);

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
    m.attr("FIXEDMANUAL") = py::cast(ScalingTechnique::FIXEDMANUAL);
    m.attr("FIXEDAUTO") = py::cast(ScalingTechnique::FIXEDAUTO);
    m.attr("FLEXIBLEAUTO") = py::cast(ScalingTechnique::FLEXIBLEAUTO);
    m.attr("FLEXIBLEAUTOEXT") = py::cast(ScalingTechnique::FLEXIBLEAUTOEXT);
    m.attr("NORESCALE") = py::cast(ScalingTechnique::NORESCALE);
    m.attr("INVALID_RS_TECHNIQUE") = py::cast(ScalingTechnique::INVALID_RS_TECHNIQUE);

    // Key Switching Techniques
    py::enum_<KeySwitchTechnique>(m, "KeySwitchTechnique")
        .value("INVALID_KS_TECH", KeySwitchTechnique::INVALID_KS_TECH)
        .value("BV", KeySwitchTechnique::BV)
        .value("HYBRID", KeySwitchTechnique::HYBRID);
    m.attr("INVALID_KS_TECH") = py::cast(KeySwitchTechnique::INVALID_KS_TECH);
    m.attr("BV") = py::cast(KeySwitchTechnique::BV);
    m.attr("HYBRID") = py::cast(KeySwitchTechnique::HYBRID);

    // Secret Key Dist
    py::enum_<SecretKeyDist>(m, "SecretKeyDist")
        .value("GAUSSIAN", SecretKeyDist::GAUSSIAN)
        .value("UNIFORM_TERNARY", SecretKeyDist::UNIFORM_TERNARY)
        .value("SPARSE_TERNARY", SecretKeyDist::SPARSE_TERNARY);
    m.attr("GAUSSIAN") = py::cast(SecretKeyDist::GAUSSIAN);
    m.attr("UNIFORM_TERNARY") = py::cast(SecretKeyDist::UNIFORM_TERNARY);
    m.attr("SPARSE_TERNARY") = py::cast(SecretKeyDist::SPARSE_TERNARY);

    // ProxyReEncryptionMode
    py::enum_<ProxyReEncryptionMode>(m, "ProxyReEncryptionMode")
        .value("NOT_SET", ProxyReEncryptionMode::NOT_SET)
        .value("INDCPA", ProxyReEncryptionMode::INDCPA)
        .value("FIXED_NOISE_HRA", ProxyReEncryptionMode::FIXED_NOISE_HRA)
        .value("NOISE_FLOODING_HRA", ProxyReEncryptionMode::NOISE_FLOODING_HRA)
        .value("DIVIDE_AND_ROUND_HRA", ProxyReEncryptionMode::DIVIDE_AND_ROUND_HRA);
    m.attr("NOT_SET") = py::cast(ProxyReEncryptionMode::NOT_SET);
    m.attr("INDCPA") = py::cast(ProxyReEncryptionMode::INDCPA);
    m.attr("FIXED_NOISE_HRA") = py::cast(ProxyReEncryptionMode::FIXED_NOISE_HRA);
    m.attr("NOISE_FLOODING_HRA") = py::cast(ProxyReEncryptionMode::NOISE_FLOODING_HRA);
    m.attr("DIVIDE_AND_ROUND_HRA") = py::cast(ProxyReEncryptionMode::DIVIDE_AND_ROUND_HRA);
    
    // MultipartyMode
    py::enum_<MultipartyMode>(m, "MultipartyMode")
        .value("INVALID_MULTIPARTY_MODE", MultipartyMode::INVALID_MULTIPARTY_MODE)
        .value("FIXED_NOISE_MULTIPARTY", MultipartyMode::FIXED_NOISE_MULTIPARTY)
        .value("NOISE_FLOODING_MULTIPARTY", MultipartyMode::NOISE_FLOODING_MULTIPARTY);
    m.attr("INVALID_MULTIPARTY_MODE") = py::cast(MultipartyMode::INVALID_MULTIPARTY_MODE);
    m.attr("FIXED_NOISE_MULTIPARTY") = py::cast(MultipartyMode::FIXED_NOISE_MULTIPARTY);
    m.attr("NOISE_FLOODING_MULTIPARTY") = py::cast(MultipartyMode::NOISE_FLOODING_MULTIPARTY);

    // ExecutionMode
    py::enum_<ExecutionMode>(m, "ExecutionMode")
        .value("EXEC_EVALUATION", ExecutionMode::EXEC_EVALUATION)
        .value("EXEC_NOISE_ESTIMATION", ExecutionMode::EXEC_NOISE_ESTIMATION);
    m.attr("EXEC_EVALUATION") = py::cast(ExecutionMode::EXEC_EVALUATION);
    m.attr("EXEC_NOISE_ESTIMATION") = py::cast(ExecutionMode::EXEC_NOISE_ESTIMATION);

    // DecryptionNoiseMode
    py::enum_<DecryptionNoiseMode>(m, "DecryptionNoiseMode")
        .value("FIXED_NOISE_DECRYPT", DecryptionNoiseMode::FIXED_NOISE_DECRYPT)
        .value("NOISE_FLOODING_DECRYPT", DecryptionNoiseMode::NOISE_FLOODING_DECRYPT);
    m.attr("FIXED_NOISE_DECRYPT") = py::cast(DecryptionNoiseMode::FIXED_NOISE_DECRYPT);
    m.attr("NOISE_FLOODING_DECRYPT") = py::cast(DecryptionNoiseMode::NOISE_FLOODING_DECRYPT);

    // EncryptionTechnique
    py::enum_<EncryptionTechnique>(m, "EncryptionTechnique")
        .value("STANDARD", EncryptionTechnique::STANDARD)
        .value("EXTENDED", EncryptionTechnique::EXTENDED);
    m.attr("STANDARD") = py::cast(EncryptionTechnique::STANDARD);
    m.attr("EXTENDED") = py::cast(EncryptionTechnique::EXTENDED);

    // MultiplicationTechnique
    py::enum_<MultiplicationTechnique>(m, "MultiplicationTechnique")
        .value("BEHZ", MultiplicationTechnique::BEHZ)
        .value("HPS", MultiplicationTechnique::HPS)
        .value("HPSPOVERQ", MultiplicationTechnique::HPSPOVERQ)
        .value("HPSPOVERQLEVELED", MultiplicationTechnique::HPSPOVERQLEVELED);
    m.attr("BEHZ") = py::cast(MultiplicationTechnique::BEHZ);
    m.attr("HPS") = py::cast(MultiplicationTechnique::HPS);
    m.attr("HPSPOVERQ") = py::cast(MultiplicationTechnique::HPSPOVERQ);
    m.attr("HPSPOVERQLEVELED") = py::cast(MultiplicationTechnique::HPSPOVERQLEVELED);

    /* ---- CORE enums ---- */ 
    // Security Level
    py::enum_<SecurityLevel>(m,"SecurityLevel")
        .value("HEStd_128_classic", SecurityLevel::HEStd_128_classic)
        .value("HEStd_192_classic", SecurityLevel::HEStd_192_classic)
        .value("HEStd_256_classic", SecurityLevel::HEStd_256_classic)
        .value("HEStd_NotSet", SecurityLevel::HEStd_NotSet);
    m.attr("HEStd_128_classic") = py::cast(SecurityLevel::HEStd_128_classic);
    m.attr("HEStd_192_classic") = py::cast(SecurityLevel::HEStd_192_classic);
    m.attr("HEStd_256_classic") = py::cast(SecurityLevel::HEStd_256_classic);
    m.attr("HEStd_NotSet") = py::cast(SecurityLevel::HEStd_NotSet);
    
    //Parameters Type
    /*TODO (Oliveira): If we expose Poly's and ParmType, this block will go somewhere else */
    using ParmType = typename DCRTPoly::Params;
    py::class_<ParmType, std::shared_ptr<ParmType>>(m, "ParmType");

    //NATIVEINT function
    m.def("get_native_int", &get_native_int);

    // Params
    py::class_<Params>(m, "Params");
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
     .def("SetLevel", &CiphertextImpl<DCRTPoly>::SetLevel);
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
    bind_enums_and_constants(m);
    bind_parameters<CryptoContextBFVRNS>(m,"CCParamsBFVRNS");
    bind_parameters<CryptoContextBGVRNS>(m,"CCParamsBGVRNS");
    bind_parameters<CryptoContextCKKSRNS>(m,"CCParamsCKKSRNS");
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
