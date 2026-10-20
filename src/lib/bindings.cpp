//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2023-2025, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//
// Author TPOC: contact@openfhe.org
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//==================================================================================
#include "bindings.h"
#include "integer_conversions.h"

#include "openfhe.h"

#include "key/key-ser.h"
#include "math/chebyshev.h"
#include "binfhe_bindings.h"

#include <pybind11/stl.h>
#include <pybind11/stl_bind.h>
#include <pybind11/complex.h>
#include <pybind11/functional.h>
#include <pybind11/iostream.h>
#include <pybind11/numpy.h>


#include "cryptocontext_docs.h"
#include "cryptoparameters_docs.h"
#include "plaintext_docs.h"
#include "ciphertext_docs.h"

using namespace lbcrypto;
using CC = CryptoContextImpl<DCRTPoly>;
namespace py = pybind11;

// PyIntToInteger only range-checks types the IsNativeInteger trait recognizes; if an
// OpenFHE change stops NativeInteger from matching it, oversized Python ints would
// silently wrap again, so turn that into a build error instead.
static_assert(openfhe_python::IsNativeInteger<NativeInteger>::value,
              "IsNativeInteger does not detect NativeInteger; PyIntToInteger would lose its overflow check");

// disable the PYBIND11 template-based conversion for this type
PYBIND11_MAKE_OPAQUE(std::map<uint32_t, EvalKey<DCRTPoly>>);

inline std::shared_ptr<CryptoParametersRNS> GetParamsRNSChecked(const CryptoContext<DCRTPoly>& self, const std::string& func) {
    auto ptr = std::dynamic_pointer_cast<CryptoParametersRNS>(self->GetCryptoParameters());
    if (!ptr)
        OPENFHE_THROW("Failed to cast to CryptoParametersRNS in " + func + "()");
    return ptr;
}


void bind_DCRTPoly(py::module &m) {
  py::class_<DCRTPoly>(m, "DCRTPoly",
      "Ring element in double-CRT (RNS) representation, the element type underlying the "
      "DCRT-based schemes (BFV, BGV, CKKS); treated as an opaque object in Python.")
      .def(py::init<>());
}

template <typename T>
void bind_parameters(py::module &m, const std::string name) {
    py::class_<CCParams<T>>(m, name.c_str(), ccparams_doc)
        .def(py::init<>())
        // getters
        .def("GetPlaintextModulus", &CCParams<T>::GetPlaintextModulus,
            py::doc("Get the plaintext modulus (used by BGV/BFV)."))
        .def("GetScheme", &CCParams<T>::GetScheme,
            py::doc("Get the scheme type."))
        .def("GetDigitSize", &CCParams<T>::GetDigitSize,
            py::doc("Get the digit size used in BV key switching."))
        .def("GetStandardDeviation", &CCParams<T>::GetStandardDeviation,
            py::doc("Get the standard deviation of the Gaussian error distribution."))
        .def("GetSecretKeyDist", &CCParams<T>::GetSecretKeyDist,
            py::doc("Get the secret key distribution."))
        .def("GetMaxRelinSkDeg", &CCParams<T>::GetMaxRelinSkDeg,
            py::doc("Get the maximum power of the secret key for which relinearization keys are generated."))
        .def("GetPREMode", &CCParams<T>::GetPREMode,
            py::doc("Get the proxy re-encryption security mode."))
        .def("GetMultipartyMode", &CCParams<T>::GetMultipartyMode,
            py::doc("Get the multiparty security mode."))
        .def("GetExecutionMode", &CCParams<T>::GetExecutionMode,
            py::doc("Get the execution mode (evaluation or noise estimation)."))
        .def("GetDecryptionNoiseMode", &CCParams<T>::GetDecryptionNoiseMode,
            py::doc("Get the decryption noise mode (fixed noise or noise flooding)."))
        .def("GetNoiseEstimate", &CCParams<T>::GetNoiseEstimate,
            py::doc("Get the noise estimate obtained in the noise-estimation execution mode."))
        .def("GetDesiredPrecision", &CCParams<T>::GetDesiredPrecision,
            py::doc("Get the desired precision for 128-bit CKKS."))
        .def("GetStatisticalSecurity", &CCParams<T>::GetStatisticalSecurity,
            py::doc("Get the statistical security parameter (bits) used for noise flooding."))
        .def("GetNumAdversarialQueries", &CCParams<T>::GetNumAdversarialQueries,
            py::doc("Get the assumed bound on the number of adversarial queries used for noise flooding."))
        .def("GetThresholdNumOfParties", &CCParams<T>::GetThresholdNumOfParties,
            py::doc(ccparams_GetThresholdNumOfParties_docs))
        .def("GetKeySwitchTechnique", &CCParams<T>::GetKeySwitchTechnique,
            py::doc("Get the key switching technique (BV or HYBRID)."))
        .def("GetScalingTechnique", &CCParams<T>::GetScalingTechnique,
            py::doc("Get the rescaling/modulus switching technique (CKKS/BGV)."))
        .def("GetBatchSize", &CCParams<T>::GetBatchSize,
            py::doc("Get the maximum batch size (number of packed slots)."))
        .def("GetFirstModSize", &CCParams<T>::GetFirstModSize,
            py::doc("Get the bit size of the first ciphertext prime."))
        .def("GetNumLargeDigits", &CCParams<T>::GetNumLargeDigits,
            py::doc("Get the number of digits used in HYBRID key switching."))
        .def("GetMultiplicativeDepth", &CCParams<T>::GetMultiplicativeDepth,
            py::doc("Get the multiplicative depth the parameters support."))
        .def("GetScalingModSize", &CCParams<T>::GetScalingModSize,
            py::doc("Get the bit size of the scaling ciphertext primes."))
        .def("GetSecurityLevel", &CCParams<T>::GetSecurityLevel,
            py::doc("Get the security level according to the HE standard."))
        .def("GetRingDim", &CCParams<T>::GetRingDim,
            py::doc("Get the polynomial ring dimension."))
        .def("GetEvalAddCount", &CCParams<T>::GetEvalAddCount,
            py::doc("Get the maximum number of additions assumed for BGV/BFV noise estimation."))
        .def("GetKeySwitchCount", &CCParams<T>::GetKeySwitchCount,
            py::doc("Get the maximum number of key switching operations assumed for BGV/BFV noise estimation."))
        .def("GetEncryptionTechnique", &CCParams<T>::GetEncryptionTechnique,
            py::doc("Get the encryption technique (BFV)."))
        .def("GetMultiplicationTechnique", &CCParams<T>::GetMultiplicationTechnique,
            py::doc("Get the multiplication technique (BFV)."))
        .def("GetPRENumHops", &CCParams<T>::GetPRENumHops,
            py::doc("Get the number of hops supported for proxy re-encryption."))
        .def("GetInteractiveBootCompressionLevel", &CCParams<T>::GetInteractiveBootCompressionLevel,
            py::doc("Get the compression level for interactive multiparty CKKS bootstrapping."))
        .def("GetCompositeDegree", &CCParams<T>::GetCompositeDegree,
            py::doc("Get the composite degree used by CKKS composite scaling."))
        .def("GetRegisterWordSize", &CCParams<T>::GetRegisterWordSize,
            py::doc("Get the target hardware register word size for CKKS composite scaling."))
        .def("GetCKKSDataType", &CCParams<T>::GetCKKSDataType,
            py::doc("Get the CKKS data type (real or complex)."))
        // setters
        .def("SetPlaintextModulus", &CCParams<T>::SetPlaintextModulus, py::arg("plaintextModulus"),
            py::doc("Set the plaintext modulus (used by BGV/BFV)."))
        .def("SetDigitSize", &CCParams<T>::SetDigitSize, py::arg("digitSize"),
            py::doc("Set the digit size used in BV key switching."))
        .def("SetStandardDeviation", &CCParams<T>::SetStandardDeviation, py::arg("standardDeviation"),
            py::doc("Set the standard deviation of the Gaussian error distribution."))
        .def("SetSecretKeyDist", &CCParams<T>::SetSecretKeyDist, py::arg("secretKeyDist"),
            py::doc("Set the secret key distribution."))
        .def("SetMaxRelinSkDeg", &CCParams<T>::SetMaxRelinSkDeg, py::arg("maxRelinSkDeg"),
            py::doc("Set the maximum power of the secret key for which relinearization keys are generated."))
        .def("SetPREMode", &CCParams<T>::SetPREMode, py::arg("PREMode"),
            py::doc("Set the proxy re-encryption security mode."))
        .def("SetMultipartyMode", &CCParams<T>::SetMultipartyMode, py::arg("multipartyMode"),
            py::doc("Set the multiparty security mode."))
        .def("SetExecutionMode", &CCParams<T>::SetExecutionMode, py::arg("executionMode"),
            py::doc("Set the execution mode (evaluation or noise estimation)."))
        .def("SetDecryptionNoiseMode", &CCParams<T>::SetDecryptionNoiseMode, py::arg("decryptionNoiseMode"),
            py::doc("Set the decryption noise mode (fixed noise or noise flooding)."))
        .def("SetNoiseEstimate", &CCParams<T>::SetNoiseEstimate, py::arg("noiseEstimate"),
            py::doc("Set the noise estimate obtained in the noise-estimation execution mode."))
        .def("SetDesiredPrecision", &CCParams<T>::SetDesiredPrecision, py::arg("desiredPrecision"),
            py::doc("Set the desired precision for 128-bit CKKS."))
        .def("SetStatisticalSecurity", &CCParams<T>::SetStatisticalSecurity, py::arg("statisticalSecurity"),
            py::doc("Set the statistical security parameter (bits) used for noise flooding."))
        .def("SetNumAdversarialQueries", &CCParams<T>::SetNumAdversarialQueries, py::arg("numAdversarialQueries"),
            py::doc("Set the assumed bound on the number of adversarial queries used for noise flooding."))
        .def("SetThresholdNumOfParties", &CCParams<T>::SetThresholdNumOfParties, py::arg("thresholdNumOfParties"),
            py::doc("Set the number of parties in a threshold application."))
        .def("SetKeySwitchTechnique", &CCParams<T>::SetKeySwitchTechnique, py::arg("keySwitchTechnique"),
            py::doc("Set the key switching technique (BV or HYBRID)."))
        .def("SetScalingTechnique", &CCParams<T>::SetScalingTechnique, py::arg("scalingTechnique"),
            py::doc("Set the rescaling/modulus switching technique (CKKS/BGV)."))
        .def("SetBatchSize", &CCParams<T>::SetBatchSize, py::arg("batchSize"),
            py::doc("Set the maximum batch size (number of packed slots)."))
        .def("SetFirstModSize", &CCParams<T>::SetFirstModSize, py::arg("firstModSize"),
            py::doc("Set the bit size of the first ciphertext prime."))
        .def("SetNumLargeDigits", &CCParams<T>::SetNumLargeDigits, py::arg("numLargeDigits"),
            py::doc("Set the number of digits used in HYBRID key switching."))
        .def("SetMultiplicativeDepth", &CCParams<T>::SetMultiplicativeDepth, py::arg("multiplicativeDepth"),
            py::doc("Set the multiplicative depth the parameters must support."))
        .def("SetScalingModSize", &CCParams<T>::SetScalingModSize, py::arg("scalingModSize"),
            py::doc("Set the bit size of the scaling ciphertext primes."))
        .def("SetSecurityLevel", &CCParams<T>::SetSecurityLevel, py::arg("securityLevel"),
            py::doc("Set the security level according to the HE standard."))
        .def("SetRingDim", &CCParams<T>::SetRingDim, py::arg("ringDim"),
            py::doc("Set the polynomial ring dimension."))
        .def("SetEvalAddCount", &CCParams<T>::SetEvalAddCount, py::arg("evalAddCount"),
            py::doc("Set the maximum number of additions assumed for BGV/BFV noise estimation."))
        .def("SetKeySwitchCount", &CCParams<T>::SetKeySwitchCount, py::arg("keySwitchCount"),
            py::doc("Set the maximum number of key switching operations assumed for BGV/BFV noise estimation."))
        .def("SetEncryptionTechnique", &CCParams<T>::SetEncryptionTechnique, py::arg("encryptionTechnique"),
            py::doc("Set the encryption technique (BFV)."))
        .def("SetMultiplicationTechnique", &CCParams<T>::SetMultiplicationTechnique, py::arg("multiplicationTechnique"),
            py::doc("Set the multiplication technique (BFV)."))
        .def("SetPRENumHops", &CCParams<T>::SetPRENumHops, py::arg("PRENumHops"),
            py::doc("Set the number of hops supported for proxy re-encryption."))
        .def("SetInteractiveBootCompressionLevel", &CCParams<T>::SetInteractiveBootCompressionLevel, py::arg("interactiveBootCompressionLevel"),
            py::doc("Set the compression level for interactive multiparty CKKS bootstrapping."))
        .def("SetCompositeDegree", &CCParams<T>::SetCompositeDegree, py::arg("compositeDegree"),
            py::doc("Set the composite degree used by CKKS composite scaling."))
        .def("SetRegisterWordSize", &CCParams<T>::SetRegisterWordSize, py::arg("registerWordSize"),
            py::doc("Set the target hardware register word size for CKKS composite scaling."))
        .def("SetCKKSDataType", &CCParams<T>::SetCKKSDataType, py::arg("ckksDataType"),
            py::doc("Set the CKKS data type (real or complex)."))
        .def("__str__",[](const CCParams<T> &params) {
            std::stringstream stream;
            stream << params;
            return stream.str();
        });
}

template <typename T>
void bind_crypto_context_templates(py::class_<CC, std::shared_ptr<CC>>& cls) {
    cls.def("EvalChebyshevSeries",
            static_cast<Ciphertext<DCRTPoly> (CC::*)(
                ConstCiphertext<DCRTPoly>&,
                const std::vector<T>&,
                double,
                double
            ) const>(&CC::EvalChebyshevSeries),
            py::arg("ciphertext"),
            py::arg("coefficients"),
            py::arg("a"),
            py::arg("b"),
            py::doc(cc_EvalChebyshevSeries_docs), release_gil)
        .def("EvalChebyshevSeriesLinear",
            static_cast<Ciphertext<DCRTPoly> (CC::*)(
                ConstCiphertext<DCRTPoly>&,
                const std::vector<T>&,
                double,
                double
            ) const>(&CC::EvalChebyshevSeriesLinear),
            py::arg("ciphertext"),
            py::arg("coefficients"),
            py::arg("a"),
            py::arg("b"),
            py::doc(cc_EvalChebyshevSeriesLinear_docs), release_gil)
        .def("EvalChebyshevSeriesPS",
            static_cast<Ciphertext<DCRTPoly> (CC::*)(
                ConstCiphertext<DCRTPoly>&,
                const std::vector<T>&,
                double,
                double
            ) const>(&CC::EvalChebyshevSeriesPS),
            py::arg("ciphertext"),
            py::arg("coefficients"),
            py::arg("a"),
            py::arg("b"),
            py::doc(cc_EvalChebyshevSeriesPS_docs), release_gil)
        .def("EvalLinearWSum",
            static_cast<Ciphertext<DCRTPoly> (CC::*)(
                std::vector<ReadOnlyCiphertext<DCRTPoly>>&,
                const std::vector<T>&
            ) const>(&CC::EvalLinearWSum),
            py::arg("ciphertextVec"),
            py::arg("constantVec"),
            py::doc(cc_EvalLinearWSum_docs), release_gil)
        .def("EvalLinearWSumMutable",
            static_cast<Ciphertext<DCRTPoly> (CC::*)(
                const std::vector<T>&,
                std::vector<Ciphertext<DCRTPoly>>&
            ) const>(&CC::EvalLinearWSumMutable),
            py::arg("constantsVec"),
            py::arg("ciphertextVec"),
            py::doc(cc_EvalLinearWSumMutable_docs), release_gil)
        .def("EvalPoly",
            static_cast<Ciphertext<DCRTPoly> (CC::*)(
                ConstCiphertext<DCRTPoly>&,
                const std::vector<T>&
            ) const>(&CC::EvalPoly),
            py::arg("ciphertext"),
            py::arg("coefficients"),
            py::doc(cc_EvalPoly_docs), release_gil)
        .def("EvalPolyLinear",
            static_cast<Ciphertext<DCRTPoly> (CC::*)(
                ConstCiphertext<DCRTPoly>&,
                const std::vector<T>&
            ) const>(&CC::EvalPolyLinear),
            py::arg("ciphertext"),
            py::arg("coefficients"),
            py::doc(cc_EvalPolyLinear_docs), release_gil)
        .def("EvalPolyPS",
            static_cast<Ciphertext<DCRTPoly> (CC::*)(
                ConstCiphertext<DCRTPoly>&,
                const std::vector<T>&
            ) const>(&CC::EvalPolyPS),
            py::arg("ciphertext"),
            py::arg("coefficients"),
            py::doc(cc_EvalPolyPS_docs), release_gil)
        .def("EvalChebyPolys",
            static_cast<std::shared_ptr<seriesPowers<DCRTPoly>> (CC::*)(
                ConstCiphertext<DCRTPoly>&, const std::vector<T>&, double, double
            ) const>(&CC::EvalChebyPolys),
            py::arg("ciphertext"), py::arg("coefficients"), py::arg("a"), py::arg("b"),
            py::doc(cc_EvalChebyPolys_docs), release_gil)
        .def("EvalChebyshevSeriesWithPrecomp",
            static_cast<Ciphertext<DCRTPoly> (CC::*)(
                std::shared_ptr<seriesPowers<DCRTPoly>>, const std::vector<T>&
            ) const>(&CC::EvalChebyshevSeriesWithPrecomp),
            py::arg("polys"), py::arg("coefficients"),
            py::doc(cc_EvalChebyshevSeriesWithPrecomp_docs), release_gil)
        .def("EvalPolyWithPrecomp",
            static_cast<Ciphertext<DCRTPoly> (CC::*)(
                std::shared_ptr<seriesPowers<DCRTPoly>>, const std::vector<T>&
            ) const>(&CC::EvalPolyWithPrecomp),
            py::arg("powers"), py::arg("coefficients"),
            py::doc(cc_EvalPolyWithPrecomp_docs), release_gil)
        .def("EvalPowers",
            static_cast<std::shared_ptr<seriesPowers<DCRTPoly>> (CC::*)(
                ConstCiphertext<DCRTPoly>&, const std::vector<T>&
            ) const>(&CC::EvalPowers),
            py::arg("ciphertext"), py::arg("coefficients"),
            py::doc(cc_EvalPowers_docs), release_gil);
}

void bind_eval_add_family(py::class_<CC, std::shared_ptr<CC>>& cls) {
    cls.def("EvalAdd", static_cast<Ciphertext<DCRTPoly> (CC::*)(ConstCiphertext<DCRTPoly>&, ConstCiphertext<DCRTPoly>&) const>(&CC::EvalAdd),
        py::arg("ciphertext1"),
        py::arg("ciphertext2"),
        py::doc(cc_EvalAdd_docs), release_gil);
    cls.def("EvalAdd", static_cast<Ciphertext<DCRTPoly> (CC::*)(ConstCiphertext<DCRTPoly>&, Plaintext&) const>(&CC::EvalAdd),
        py::arg("ciphertext"),
        py::arg("plaintext"),
        py::doc(cc_EvalAddPlaintext_docs), release_gil);
    cls.def("EvalAdd", static_cast<Ciphertext<DCRTPoly> (CC::*)(Plaintext&, ConstCiphertext<DCRTPoly>&) const>(&CC::EvalAdd),
        py::arg("plaintext"),
        py::arg("ciphertext"),
        py::doc(cc_EvalAddPlaintext_docs), release_gil);
}
template <typename ScalarT>
void bind_eval_add_scalar_overloads(py::class_<CC, std::shared_ptr<CC>>& cls) {
    cls.def("EvalAdd", static_cast<Ciphertext<DCRTPoly> (CC::*)(ConstCiphertext<DCRTPoly>&, ScalarT) const>(&CC::EvalAdd),
        py::arg("ciphertext"),
        py::arg("scalar"),
        py::doc(cc_EvalAddfloat_docs), release_gil);
    cls.def("EvalAdd", static_cast<Ciphertext<DCRTPoly> (CC::*)(ScalarT, ConstCiphertext<DCRTPoly>&) const>(&CC::EvalAdd),
        py::arg("scalar"),
        py::arg("ciphertext"),
        py::doc(cc_EvalAddfloat_docs), release_gil);
}

void bind_eval_addinplace_family(py::class_<CC, std::shared_ptr<CC>>& cls) {
    cls.def("EvalAddInPlace", static_cast<void (CC::*)(Ciphertext<DCRTPoly>&, ConstCiphertext<DCRTPoly>&) const>(&CC::EvalAddInPlace),
        py::arg("ciphertext1"),
        py::arg("ciphertext2"),
        py::doc(cc_EvalAddInPlace_docs), release_gil);
    cls.def("EvalAddInPlace", static_cast<void (CC::*)(Ciphertext<DCRTPoly>&, Plaintext&) const>(&CC::EvalAddInPlace),
        py::arg("ciphertext"),
        py::arg("plaintext"),
        py::doc(cc_EvalAddInPlacePlaintext_docs), release_gil);
    cls.def("EvalAddInPlace", static_cast<void (CC::*)(Plaintext&, Ciphertext<DCRTPoly>&) const>(&CC::EvalAddInPlace),
        py::arg("plaintext"),
        py::arg("ciphertext"),
        py::doc(cc_EvalAddInPlacePlaintext_docs), release_gil);
}
template <typename ScalarT>
void bind_eval_addinplace_scalar_overloads(py::class_<CC, std::shared_ptr<CC>>& cls) {
    cls.def("EvalAddInPlace", static_cast<void (CC::*)(Ciphertext<DCRTPoly>&, ScalarT) const>(&CC::EvalAddInPlace),
        py::arg("ciphertext"),
        py::arg("scalar"),
        py::doc("In-place homomorphic addition of a scalar: ciphertext += scalar."), release_gil);
    cls.def("EvalAddInPlace", static_cast<void (CC::*)(ScalarT, Ciphertext<DCRTPoly>&) const>(&CC::EvalAddInPlace),
        py::arg("scalar"),
        py::arg("ciphertext"),
        py::doc("In-place homomorphic addition of a scalar: ciphertext += scalar."), release_gil);
}

void bind_eval_sub_family(py::class_<CC, std::shared_ptr<CC>>& cls) {
    cls.def("EvalSub", static_cast<Ciphertext<DCRTPoly> (CC::*)(ConstCiphertext<DCRTPoly>&, ConstCiphertext<DCRTPoly>&) const>(&CC::EvalSub),
        py::arg("ciphertext1"),
        py::arg("ciphertext2"),
        py::doc(cc_EvalSub_docs), release_gil);
    cls.def("EvalSub", static_cast<Ciphertext<DCRTPoly> (CC::*)(ConstCiphertext<DCRTPoly>&, Plaintext&) const>(&CC::EvalSub),
        py::arg("ciphertext"),
        py::arg("plaintext"),
        py::doc(cc_EvalSubPlaintext_docs), release_gil);
    cls.def("EvalSub", static_cast<Ciphertext<DCRTPoly> (CC::*)(Plaintext&, ConstCiphertext<DCRTPoly>&) const>(&CC::EvalSub),
        py::arg("plaintext"),
        py::arg("ciphertext"),
        py::doc("Homomorphic subtraction of the ciphertext from the plaintext: plaintext - ciphertext."), release_gil);
}
template <typename ScalarT>
void bind_eval_sub_scalar_overloads(py::class_<CC, std::shared_ptr<CC>>& cls) {
    cls.def("EvalSub", static_cast<Ciphertext<DCRTPoly> (CC::*)(ConstCiphertext<DCRTPoly>&, ScalarT) const>(&CC::EvalSub),
        py::arg("ciphertext"),
        py::arg("scalar"),
        py::doc(cc_EvalSubfloat_docs), release_gil);
    cls.def("EvalSub", static_cast<Ciphertext<DCRTPoly> (CC::*)(ScalarT, ConstCiphertext<DCRTPoly>&) const>(&CC::EvalSub),
        py::arg("scalar"),
        py::arg("ciphertext"),
        py::doc("Homomorphic subtraction of the ciphertext from a scalar: scalar - ciphertext."), release_gil);
}

void bind_eval_subinplace_family(py::class_<CC, std::shared_ptr<CC>>& cls) {
    cls.def("EvalSubInPlace", static_cast<void (CC::*)(Ciphertext<DCRTPoly>&, ConstCiphertext<DCRTPoly>&) const>(&CC::EvalSubInPlace),
        py::arg("ciphertext1"),
        py::arg("ciphertext2"),
        py::doc(cc_EvalSubInPlace_docs), release_gil);
    cls.def("EvalSubInPlace", static_cast<void (CC::*)(Ciphertext<DCRTPoly>&, ConstPlaintext&) const>(&CC::EvalSubInPlace),
        py::arg("ciphertext"),
        py::arg("plaintext"),
        py::doc("In-place homomorphic subtraction of a plaintext: ciphertext -= plaintext."), release_gil);
    cls.def("EvalSubInPlace", static_cast<void (CC::*)(Plaintext&, Ciphertext<DCRTPoly>&) const>(&CC::EvalSubInPlace),
        py::arg("plaintext"),
        py::arg("ciphertext"),
        py::doc("In-place computation of plaintext - ciphertext; the result is stored in the ciphertext argument."), release_gil);
}
template <typename ScalarT>
void bind_eval_subinplace_scalar_overloads(py::class_<CC, std::shared_ptr<CC>>& cls) {
    cls.def("EvalSubInPlace", static_cast<void (CC::*)(Ciphertext<DCRTPoly>&, ScalarT) const>(&CC::EvalSubInPlace),
        py::arg("ciphertext"),
        py::arg("scalar"),
        py::doc(cc_EvalSubInPlacefloat_docs), release_gil);
    cls.def("EvalSubInPlace", static_cast<void (CC::*)(ScalarT, Ciphertext<DCRTPoly>&) const>(&CC::EvalSubInPlace),
        py::arg("scalar"),
        py::arg("ciphertext"),
        py::doc("In-place computation of scalar - ciphertext; the result is stored in the ciphertext argument."), release_gil);
}

void bind_eval_mult_family(py::class_<CC, std::shared_ptr<CC>>& cls) {
    cls.def("EvalMult", static_cast<Ciphertext<DCRTPoly> (CC::*)(ConstCiphertext<DCRTPoly>&, ConstCiphertext<DCRTPoly>&) const>(&CC::EvalMult),
        py::arg("ciphertext1"),
        py::arg("ciphertext2"),
        py::doc(cc_EvalMult_docs), release_gil);
    cls.def("EvalMult", static_cast<Ciphertext<DCRTPoly> (CC::*)(ConstCiphertext<DCRTPoly>&, ConstPlaintext&) const>(&CC::EvalMult),
        py::arg("ciphertext"),
        py::arg("plaintext"),
        py::doc(cc_EvalMultPlaintext_docs), release_gil);
    cls.def("EvalMult", static_cast<Ciphertext<DCRTPoly> (CC::*)(ConstPlaintext&, ConstCiphertext<DCRTPoly>&) const>(&CC::EvalMult),
        py::arg("plaintext"),
        py::arg("ciphertext"),
        py::doc(cc_EvalMultPlaintext_docs), release_gil);
}
template <typename ScalarT>
void bind_eval_mult_scalar_overloads(py::class_<CC, std::shared_ptr<CC>>& cls) {
    cls.def("EvalMult", static_cast<Ciphertext<DCRTPoly> (CC::*)(ConstCiphertext<DCRTPoly>&, ScalarT) const>(&CC::EvalMult),
        py::arg("ciphertext"),
        py::arg("scalar"),
        py::doc(cc_EvalMultfloat_docs), release_gil);
    cls.def("EvalMult", static_cast<Ciphertext<DCRTPoly> (CC::*)(ScalarT, ConstCiphertext<DCRTPoly>&) const>(&CC::EvalMult),
        py::arg("scalar"),
        py::arg("ciphertext"),
        py::doc(cc_EvalMultfloat_docs), release_gil);
}

template <typename ScalarT>
void bind_eval_multinplace_scalar_overloads(py::class_<CC, std::shared_ptr<CC>>& cls) {
    cls.def("EvalMultInPlace", static_cast<void (CC::*)(Ciphertext<DCRTPoly>&, ScalarT) const>(&CC::EvalMultInPlace),
        py::arg("ciphertext"),
        py::arg("scalar"),
        py::doc("In-place homomorphic multiplication by a scalar: ciphertext *= scalar."), release_gil);
    cls.def("EvalMultInPlace", static_cast<void (CC::*)(ScalarT, Ciphertext<DCRTPoly>&) const>(&CC::EvalMultInPlace),
        py::arg("scalar"),
        py::arg("ciphertext"),
        py::doc("In-place homomorphic multiplication by a scalar: ciphertext *= scalar."), release_gil);
}

void bind_crypto_context(py::module &m) {
    //Parameters Type
    // TODO (Oliveira): If we expose Poly's and ParmType, this block will go somewhere else
    using ParmType = typename DCRTPoly::Params;
    using ParmTypePtr = std::shared_ptr<ParmType>;
    py::class_<ParmType, ParmTypePtr>(m, "ParmType",
        "Element (ring) parameters of a DCRTPoly: the ciphertext modulus, ring dimension "
        "and cyclotomic order.")
        .def("GetModulus",
            [](const ParmType& self) { return openfhe_python::IntegerToPyInt(self.GetModulus()); },
            py::doc("Get the ciphertext modulus (the product of all RNS moduli)."))
        .def("GetRingDimension", &ParmType::GetRingDimension,
            py::doc("Get the ring dimension N (the polynomials live in Z_Q[x]/(X^N+1))."))
        .def("GetCyclotomicOrder", &ParmType::GetCyclotomicOrder,
            py::doc("Get the cyclotomic order (2N for power-of-two cyclotomics)."));

    py::class_<SchemeBase<DCRTPoly>, std::shared_ptr<SchemeBase<DCRTPoly>>>(m, "SchemeBase",
        "Scheme implementation object of a crypto context (returned by CryptoContext.GetScheme); "
        "treated as an opaque object in Python.");

    auto cc_class = py::class_<CryptoContextImpl<DCRTPoly>, std::shared_ptr<CryptoContextImpl<DCRTPoly>>>(m, "CryptoContext",
        "Crypto context for the DCRTPoly-based schemes (BFV, BGV, CKKS): the main API object "
        "holding the scheme implementation, crypto parameters and precomputations, with methods "
        "for key generation, encoding, encryption and homomorphic evaluation. Create it with "
        "GenCryptoContext(params).");

    // numpy fast paths, registered before the std::vector overloads so that float64 and
    // complex128 arrays are encoded from their buffers instead of converting every
    // element through a Python object. The double overload comes first: on the
    // converting pass it claims every real-valued input via a safe cast, while complex
    // values fail that cast and fall through to the complex overload.
    cc_class.def("MakeCKKSPackedPlaintext",
        [](const CC& self, const py::array_t<double, py::array::c_style>& value,
           size_t noiseScaleDeg, uint32_t level, const py::object& params,
           uint32_t slots) {
            if (value.ndim() != 1)
                throw py::value_error("MakeCKKSPackedPlaintext expects a one-dimensional array");
            // params is taken as py::object and converted by hand: pybind11 only
            // loads None into a holder type on its converting second overload pass,
            // so a shared_ptr parameter with a None default would force every call
            // through two dispatch passes (converting the value argument twice).
            auto parms = params.is_none() ? nullptr : params.cast<std::shared_ptr<ParmType>>();
            const double* data = value.data();
            const auto n = static_cast<size_t>(value.shape(0));
            py::gil_scoped_release release;
            return self.MakeCKKSPackedPlaintext(std::vector<double>(data, data + n),
                                                noiseScaleDeg, level, parms, slots);
        },
        py::arg("value"),
        py::arg("noiseScaleDeg") = 1,
        py::arg("level") = 0,
        py::arg("params") = py::none(),
        py::arg("slots") = 0,
        py::doc("Encode a 1-D numpy array of real numbers into a CKKS packed plaintext "
                "(fast path: the values are read from the array buffer instead of "
                "element-wise Python conversion)."));
    cc_class.def("MakeCKKSPackedPlaintext",
        [](const CC& self, const py::array_t<std::complex<double>, py::array::c_style>& value,
           size_t noiseScaleDeg, uint32_t level, const py::object& params,
           uint32_t slots) {
            if (value.ndim() != 1)
                throw py::value_error("MakeCKKSPackedPlaintext expects a one-dimensional array");
            // see the real-valued overload above for why params is a py::object
            auto parms = params.is_none() ? nullptr : params.cast<std::shared_ptr<ParmType>>();
            const std::complex<double>* data = value.data();
            const auto n = static_cast<size_t>(value.shape(0));
            py::gil_scoped_release release;
            return self.MakeCKKSPackedPlaintext(std::vector<std::complex<double>>(data, data + n),
                                                noiseScaleDeg, level, parms, slots);
        },
        py::arg("value"),
        py::arg("noiseScaleDeg") = 1,
        py::arg("level") = 0,
        py::arg("params") = py::none(),
        py::arg("slots") = 0,
        py::doc("Encode a 1-D numpy array of complex numbers into a CKKS packed plaintext "
                "(fast path: the values are read from the array buffer instead of "
                "element-wise Python conversion)."));
    cc_class.def("MakePackedPlaintext",
        [](const CC& self, const py::array_t<int64_t, py::array::c_style>& value,
           size_t noiseScaleDeg, uint32_t level) {
            if (value.ndim() != 1)
                throw py::value_error("MakePackedPlaintext expects a one-dimensional array");
            const int64_t* data = value.data();
            const auto n = static_cast<size_t>(value.shape(0));
            py::gil_scoped_release release;
            return self.MakePackedPlaintext(std::vector<int64_t>(data, data + n),
                                            noiseScaleDeg, level);
        },
        py::arg("value"),
        py::arg("noiseScaleDeg") = 1,
        py::arg("level") = 0,
        py::doc("Encode a 1-D numpy array of integers into a packed plaintext "
                "(fast path: the values are read from the array buffer instead of "
                "element-wise Python conversion)."));
    cc_class.def("MakeCoefPackedPlaintext",
        [](const CC& self, const py::array_t<int64_t, py::array::c_style>& value,
           size_t noiseScaleDeg, uint32_t level) {
            if (value.ndim() != 1)
                throw py::value_error("MakeCoefPackedPlaintext expects a one-dimensional array");
            const int64_t* data = value.data();
            const auto n = static_cast<size_t>(value.shape(0));
            py::gil_scoped_release release;
            return self.MakeCoefPackedPlaintext(std::vector<int64_t>(data, data + n),
                                                noiseScaleDeg, level);
        },
        py::arg("value"),
        py::arg("noiseScaleDeg") = 1,
        py::arg("level") = 0,
        py::doc("Encode a 1-D numpy array of integers into a coefficient-packed plaintext "
                "(fast path: the values are read from the array buffer instead of "
                "element-wise Python conversion)."));

    cc_class.def(py::init<>())
        .def("ClearAllCKKSCaches", &CC::ClearAllCKKSCaches,
            py::doc(cc_ClearAllCKKSCaches_docs))
        .def("ClearSchemeSwitchPrecom", &CC::ClearSchemeSwitchPrecom,
            py::doc(cc_ClearSchemeSwitchPrecom_docs))
        .def("ComposedEvalMult", &CC::ComposedEvalMult,
            py::arg("ciphertext1"), py::arg("ciphertext2"),
            py::doc(cc_ComposedEvalMult_docs), release_gil)
        .def("GetKeyGenLevel", &CryptoContextImpl<DCRTPoly>::GetKeyGenLevel, cc_GetKeyGenLevel_docs)
        .def("SetKeyGenLevel", &CryptoContextImpl<DCRTPoly>::SetKeyGenLevel,
            py::arg("level"),
            py::doc(cc_SetKeyGenLevel_docs))
        .def("get_ptr",[](const CryptoContext<DCRTPoly> &self) {
            std::cout << "CC shared ptr (python cc)" << self << std::endl; },
            py::doc("Debug helper: print the address held by the shared CryptoContext pointer."))
        .def("GetRingDimension", &CryptoContextImpl<DCRTPoly>::GetRingDimension, cc_GetRingDimension_docs)
        .def("GetPlaintextModulus",
            [](CryptoContext<DCRTPoly>& self) {
                return self->GetCryptoParameters()->GetPlaintextModulus();
            },
            py::doc(cc_GetPlaintextModulus_docs))
        .def("GetBatchSize",
            [](CryptoContext<DCRTPoly>& self) {
                return self->GetCryptoParameters()->GetBatchSize();
            },
            py::doc("Get the maximum batch size (number of packed slots)."))
        .def("GetModulus",
            [](CryptoContext<DCRTPoly>& self) {
                return self->GetCryptoParameters()
                            ->GetElementParams()
                            ->GetModulus()
                            .ConvertToDouble();
            },
            py::doc(cc_GetModulus_docs))
        .def("GetModulusCKKS",
            [](CryptoContext<DCRTPoly>& self) {
                auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(self->GetCryptoParameters());
                if (!cryptoParams)
                    OPENFHE_THROW("std::dynamic_pointer_cast<CryptoParametersCKKSRNS>() failed");
                return cryptoParams->GetElementParams()->GetParams()[0]->GetModulus().ConvertToInt<uint64_t>();
            },
            py::doc("Get the first RNS modulus q_0 of a CKKS crypto context."))
        .def("GetScalingFactorReal",
            [](CryptoContext<DCRTPoly>& self, uint32_t level) {
                auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(self->GetCryptoParameters());
                if (!cryptoParams)
                    OPENFHE_THROW("std::dynamic_pointer_cast<CryptoParametersRNS>() failed");
                return cryptoParams->GetScalingFactorReal(level);
            },
            py::arg("level"),
            py::doc(cc_GetScalingFactorReal_docs))
        .def("GetScalingTechnique",
            [](CryptoContext<DCRTPoly>& self) {
                const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(self->GetCryptoParameters());
                if (!cryptoParams)
                    OPENFHE_THROW("std::dynamic_pointer_cast<CryptoParametersRNS>() failed");
                return cryptoParams->GetScalingTechnique();
            },
            py::doc("Get the rescaling/modulus switching technique (CKKS/BGV)."))
        .def("GetDigitSize",
            [](CryptoContext<DCRTPoly>& self) {
                return self->GetCryptoParameters()->GetDigitSize();
            },
            py::doc("Get the digit size used in BV key switching."))
        .def("GetCyclotomicOrder", &CryptoContextImpl<DCRTPoly>::GetCyclotomicOrder, cc_GetCyclotomicOrder_docs)
        .def("GetEncodingParams", &CC::GetEncodingParams,
            py::doc(cc_GetEncodingParams_docs))
        .def("GetElementParams",
            [](const CC& self) {
                return self.GetCryptoParameters()->GetElementParams();
            },
            py::doc(cc_GetElementParams_docs))
        .def("GetRootOfUnity", [](const CC& self) {
                return openfhe_python::IntegerToPyInt(self.GetRootOfUnity());
            },
            py::doc(cc_GetRootOfUnity_docs))
        .def("GetScheme", &CC::GetScheme,
            py::doc(cc_GetScheme_docs))
        .def("getSchemeId", &CC::getSchemeId,
            py::doc(cc_getSchemeId_docs))
        .def("setSchemeId", &CC::setSchemeId, py::arg("schemeTag"),
            py::doc(cc_setSchemeId_docs))
        .def("GetCKKSDataType", &CryptoContextImpl<DCRTPoly>::GetCKKSDataType,
            py::doc("Get the CKKS data type (real or complex)."))
        .def("GetCKKSBootCorrectionFactor", &CC::GetCKKSBootCorrectionFactor,
            py::doc("Get the correction factor of CKKS bootstrapping (the number of bits the message "
                    "is scaled down by in total before the approximate modular reduction to improve "
                    "precision), as set by EvalBootstrapSetup. Supported only in CKKS."))
        .def("SetCKKSBootCorrectionFactor", &CC::SetCKKSBootCorrectionFactor, py::arg("cf"),
            py::doc("Set the correction factor of CKKS bootstrapping. Supported only in CKKS."))
        .def("GetNoiseEstimate", [](CryptoContext<DCRTPoly>& self) {
            return GetParamsRNSChecked(self, "GetNoiseEstimate")->GetNoiseEstimate();
        },
            py::doc("Get the noise estimate used for CKKS noise flooding (RNS schemes only)."))
        .def("SetNoiseEstimate", [](CryptoContext<DCRTPoly>& self, double noiseEstimate) {
            GetParamsRNSChecked(self, "SetNoiseEstimate")->SetNoiseEstimate(noiseEstimate);
            },
            py::arg("noiseEstimate"),
            py::doc("Set the noise estimate used for CKKS noise flooding (RNS schemes only)."))
        .def("GetMultiplicativeDepth", [](CryptoContext<DCRTPoly>& self) {
            return GetParamsRNSChecked(self, "GetMultiplicativeDepth")->GetMultiplicativeDepth();
        },
            py::doc("Get the multiplicative depth supported by the crypto parameters (RNS schemes only)."))
        .def("SetMultiplicativeDepth", [](CryptoContext<DCRTPoly>& self, uint32_t multiplicativeDepth) {
            GetParamsRNSChecked(self, "SetMultiplicativeDepth")->SetMultiplicativeDepth(multiplicativeDepth);
            },
            py::arg("multiplicativeDepth"),
            py::doc("Set the multiplicative depth recorded in the crypto parameters (RNS schemes only)."))
        .def("GetEvalAddCount", [](CryptoContext<DCRTPoly>& self) {
            return GetParamsRNSChecked(self, "GetEvalAddCount")->GetEvalAddCount();
        },
            py::doc("Get the maximum number of additions assumed for BGV/BFV noise estimation "
                    "(RNS schemes only)."))
        .def("SetEvalAddCount", [](CryptoContext<DCRTPoly>& self, uint32_t evalAddCount) {
            GetParamsRNSChecked(self, "SetEvalAddCount")->SetEvalAddCount(evalAddCount);
            },
            py::arg("evalAddCount"),
            py::doc("Set the maximum number of additions assumed for BGV/BFV noise estimation "
                    "(RNS schemes only)."))
        .def("GetKeySwitchCount", [](CryptoContext<DCRTPoly>& self) {
                return GetParamsRNSChecked(self, "GetKeySwitchCount")->GetKeySwitchCount();
            },
            py::doc("Get the maximum number of key switching operations assumed for BGV/BFV noise "
                    "estimation (RNS schemes only)."))
        .def("SetKeySwitchCount", [](CryptoContext<DCRTPoly>& self, uint32_t keySwitchCount) {
                GetParamsRNSChecked(self, "SetKeySwitchCount")->SetKeySwitchCount(keySwitchCount);
            },
            py::arg("keySwitchCount"),
            py::doc("Set the maximum number of key switching operations assumed for BGV/BFV noise "
                    "estimation (RNS schemes only)."))
        .def("GetPRENumHops", [](CryptoContext<DCRTPoly>& self) {
                return GetParamsRNSChecked(self, "GetPRENumHops")->GetPRENumHops();
            },
            py::doc("Get the number of hops supported for proxy re-encryption (RNS schemes only)."))
        .def("SetPRENumHops", [](CryptoContext<DCRTPoly>& self, uint32_t PRENumHops) {
                GetParamsRNSChecked(self, "SetPRENumHops")->SetPRENumHops(PRENumHops);
            },
            py::arg("PRENumHops"),
            py::doc("Set the number of hops supported for proxy re-encryption (RNS schemes only)."))
        .def("GetRegisterWordSize", [](CryptoContext<DCRTPoly>& self) {
                return GetParamsRNSChecked(self, "GetRegisterWordSize")->GetRegisterWordSize();
            },
            py::doc("Get the target hardware register word size for CKKS composite scaling "
                    "(RNS schemes only)."))
        .def("GetCompositeDegree", [](CryptoContext<DCRTPoly>& self) {
                return GetParamsRNSChecked(self, "GetCompositeDegree")->GetCompositeDegree();
            },
            py::doc("Get the composite degree used by CKKS composite scaling (RNS schemes only)."))
        .def("GetKeySwitchTechnique", [](CryptoContext<DCRTPoly>& self) {
                return GetParamsRNSChecked(self, "GetKeySwitchTechnique")->GetKeySwitchTechnique();
            },
            py::doc("Get the key switching technique (BV or HYBRID; RNS schemes only)."))
        .def("Enable", py::overload_cast<PKESchemeFeature>(&CryptoContextImpl<DCRTPoly>::Enable),
            py::arg("feature"),
            py::doc(cc_Enable_docs))
        .def("KeyGen", &CryptoContextImpl<DCRTPoly>::KeyGen, cc_KeyGen_docs, release_gil)
        .def("SparseKeyGen", &CC::SparseKeyGen,
            py::doc(cc_SparseKeyGen_docs), release_gil)
        .def("EvalMultKeyGen", &CryptoContextImpl<DCRTPoly>::EvalMultKeyGen,
            py::arg("privateKey"),
            py::doc(cc_EvalMultKeyGen_docs), release_gil)
        .def("EvalMultKeysGen", &CryptoContextImpl<DCRTPoly>::EvalMultKeysGen,
            py::arg("privateKey"),
            py::doc(cc_EvalMultKeysGen_docs), release_gil)
        .def("EvalRotateKeyGen", &CryptoContextImpl<DCRTPoly>::EvalRotateKeyGen,
            py::arg("privateKey"),
            py::arg("indexList"),
            py::doc(cc_EvalRotateKeyGen_docs), release_gil)
        .def("MakeStringPlaintext", &CryptoContextImpl<DCRTPoly>::MakeStringPlaintext,
            py::arg("str"),
            py::doc(cc_MakeStringPlaintext_docs), release_gil)
        .def("MakePackedPlaintext", &CryptoContextImpl<DCRTPoly>::MakePackedPlaintext,
            py::arg("value"),
            py::arg("noiseScaleDeg") = 1,
            py::arg("level") = 0,
            py::doc(cc_MakePackedPlaintext_docs), release_gil)
        .def("MakeCoefPackedPlaintext", &CryptoContextImpl<DCRTPoly>::MakeCoefPackedPlaintext,
            py::arg("value"),
            py::arg("noiseScaleDeg") = 1,
            py::arg("level") = 0,
            py::doc(cc_MakeCoefPackedPlaintext_docs), release_gil)
        // TODO (Oliveira): allow user to specify different params values
        .def("MakeCKKSPackedPlaintext",
            [](const CC& self, const std::vector<std::complex<double>>& value, size_t noiseScaleDeg,
               uint32_t level, const py::object& params, uint32_t slots) {
                // see the numpy overload above for why params is a py::object
                auto parms = params.is_none() ? nullptr : params.cast<std::shared_ptr<ParmType>>();
                py::gil_scoped_release release;
                return self.MakeCKKSPackedPlaintext(value, noiseScaleDeg, level, parms, slots);
            },
            py::arg("value"),
            py::arg("noiseScaleDeg") = 1,
            py::arg("level") = 0,
            py::arg("params") = py::none(),
            py::arg("slots") = 0,
            py::doc(cc_MakeCKKSPackedPlaintextComplex_docs))
        .def("MakeCKKSPackedPlaintext",
            [](const CC& self, const std::vector<double>& value, size_t noiseScaleDeg,
               uint32_t level, const py::object& params, uint32_t slots) {
                // see the numpy overload above for why params is a py::object
                auto parms = params.is_none() ? nullptr : params.cast<std::shared_ptr<ParmType>>();
                py::gil_scoped_release release;
                return self.MakeCKKSPackedPlaintext(value, noiseScaleDeg, level, parms, slots);
            },
            py::arg("value"),
            py::arg("noiseScaleDeg") = 1,
            py::arg("level") = 0,
            py::arg("params") = py::none(),
            py::arg("slots") = 0,
            py::doc(cc_MakeCKKSPlaintextReal_docs))
        .def("EvalAutomorphism",
            [](const CC& self,
               ConstCiphertext<DCRTPoly>& ciphertext,
               uint32_t i,
               const std::shared_ptr<std::map<uint32_t, EvalKey<DCRTPoly>>>& evalKeyMap) {
                return self.EvalAutomorphism(ciphertext, i, *evalKeyMap);
            },
            py::arg("ciphertext"),
            py::arg("i"),
            py::arg("evalKeyMap"),
            py::doc(cc_EvalAutomorphism_docs), release_gil)
        .def("EvalRotate", &CryptoContextImpl<DCRTPoly>::EvalRotate,
            py::arg("ciphertext"),
            py::arg("index"),
            py::doc(cc_EvalRotate_docs), release_gil)
        .def("EvalFastRotationPrecompute",
            [](CryptoContext<DCRTPoly>& self, ConstCiphertext<DCRTPoly> ciphertext) {
                auto precomp = self->EvalFastRotationPrecompute(ciphertext);
                auto cipherdigits = std::make_shared<CiphertextImpl<DCRTPoly>>(self);
                cipherdigits->SetElements(*precomp);
                return cipherdigits;
            },
            py::arg("ciphertext"),
            py::doc(cc_EvalFastRotationPreCompute_docs), release_gil)
        .def("EvalFastRotation",
            [](CryptoContext<DCRTPoly>& self,
                ConstCiphertext<DCRTPoly> ciphertext,
                uint32_t index,
                uint32_t m,
                ConstCiphertext<DCRTPoly> digits) {
                return self->EvalFastRotation(ciphertext, index, m, std::make_shared<std::vector<DCRTPoly>>(digits->GetElements()));
            },
            py::arg("ciphertext"),
            py::arg("index"),
            py::arg("m"),
            py::arg("digits"),
            py::doc(cc_EvalFastRotation_docs), release_gil)
        .def("EvalFastRotation",
            [](CryptoContext<DCRTPoly>& self,
                ConstCiphertext<DCRTPoly> ciphertext,
                uint32_t index,
                ConstCiphertext<DCRTPoly> digits) {
                return self->EvalFastRotation(ciphertext, index, std::make_shared<std::vector<DCRTPoly>>(digits->GetElements()));
            },
            py::arg("ciphertext"),
            py::arg("index"),
            py::arg("digits"),
            py::doc(cc_EvalFastRotation_docs), release_gil)
        .def("EvalFastRotationExt",
            [](CryptoContext<DCRTPoly>& self,
                ConstCiphertext<DCRTPoly> ciphertext,
                uint32_t index,
                ConstCiphertext<DCRTPoly> digits,
                bool addFirst) {
                return self->EvalFastRotationExt(ciphertext, index, std::make_shared<std::vector<DCRTPoly>>(digits->GetElements()), addFirst);
            },
            py::arg("ciphertext"),
            py::arg("index"),
            py::arg("digits"),
            py::arg("addFirst"),
            py::doc(cc_EvalFastRotationExt_docs))
        .def("EvalAtIndexKeyGen", &CryptoContextImpl<DCRTPoly>::EvalAtIndexKeyGen,
            py::arg("privateKey"),
            py::arg("indexList"),
            py::doc(cc_EvalAtIndexKeyGen_docs), release_gil)
        .def("EvalAtIndex", &CryptoContextImpl<DCRTPoly>::EvalAtIndex,
            py::arg("ciphertext"),
            py::arg("index"),
            py::doc(cc_EvalAtIndex_docs), release_gil)
        .def("Encrypt",
            py::overload_cast<const PublicKey<DCRTPoly>&, ConstPlaintext&>(&CryptoContextImpl<DCRTPoly>::Encrypt, py::const_),
            py::arg("publicKey"),
            py::arg("plaintext"),
            py::doc(cc_EncryptPubkey_docs), release_gil)
       .def("Encrypt",
            py::overload_cast<const PrivateKey<DCRTPoly>&, ConstPlaintext&>(&CryptoContextImpl<DCRTPoly>::Encrypt, py::const_),
            py::arg("privateKey"),
            py::arg("plaintext"),
            py::doc(cc_EncryptPrivkey_docs), release_gil)
        .def("Decrypt",
            [](CryptoContext<DCRTPoly>& self, const PrivateKey<DCRTPoly> privKey, ConstCiphertext<DCRTPoly> ct) {
                Plaintext result;
                self->Decrypt(privKey, ct, &result);
                return result;
            },
            py::arg("privateKey"),
            py::arg("ciphertext"),
            py::doc(cc_Decrypt_docs), release_gil)
        .def("Decrypt",
            [](CryptoContext<DCRTPoly>& self, ConstCiphertext<DCRTPoly> ct, const PrivateKey<DCRTPoly> privKey) {
                Plaintext result;
                self->Decrypt(privKey, ct, &result);
                return result;
            },
            py::arg("ciphertext"),
            py::arg("privateKey"),
            py::doc(cc_Decrypt_docs), release_gil)
        .def("KeySwitchGen", &CryptoContextImpl<DCRTPoly>::KeySwitchGen,
            py::arg("oldPrivateKey"),
            py::arg("newPrivateKey"),
            py::doc(cc_KeySwitchGen_docs), release_gil)
        .def("KeySwitch", &CC::KeySwitch, py::arg("ciphertext"), py::arg("evalKey"),
            py::doc(cc_KeySwitch_docs), release_gil)
        .def("KeySwitchInPlace", &CC::KeySwitchInPlace, py::arg("ciphertext"), py::arg("evalKey"),
            py::doc(cc_KeySwitchInPlace_docs), release_gil)
        .def("KeySwitchDown", &CC::KeySwitchDown, py::arg("ciphertext"),
            py::doc(cc_KeySwitchDown_docs), release_gil)
        .def("KeySwitchDownFirstElement", &CC::KeySwitchDownFirstElement, py::arg("ciphertext"),
            py::doc(cc_KeySwitchDownFirstElement_docs), release_gil)
        .def("KeySwitchExt", &CC::KeySwitchExt, py::arg("ciphertext"), py::arg("addFirst"),
            py::doc(cc_KeySwitchExt_docs), release_gil)
        .def("EvalAddMutable",
            py::overload_cast<Ciphertext<DCRTPoly>&, Ciphertext<DCRTPoly>&>(&CryptoContextImpl<DCRTPoly>::EvalAddMutable, py::const_),
            py::arg("ciphertext1"),
            py::arg("ciphertext2"),
            py::doc(cc_EvalAddMutable_docs), release_gil)
        .def("EvalAddMutable",
            py::overload_cast<Ciphertext<DCRTPoly>&, Plaintext&>(&CryptoContextImpl<DCRTPoly>::EvalAddMutable, py::const_),
            py::arg("ciphertext"),
            py::arg("plaintext"),
            py::doc(cc_EvalAddMutablePlaintext_docs), release_gil)
        .def("EvalAddMutable", py::overload_cast<Plaintext&, Ciphertext<DCRTPoly>&>(&CryptoContextImpl<DCRTPoly>::EvalAddMutable, py::const_),
            py::arg("plaintext"),
            py::arg("ciphertext"),
            py::doc(cc_EvalAddMutablePlaintext_docs), release_gil)
        .def("EvalAddMutableInPlace", &CryptoContextImpl<DCRTPoly>::EvalAddMutableInPlace,
            py::arg("ciphertext1"),
            py::arg("ciphertext2"),
            py::doc(cc_EvalAddMutableInPlace_docs), release_gil)
        .def("EvalSubMutable",
            py::overload_cast<Ciphertext<DCRTPoly>&, Ciphertext<DCRTPoly>&>(&CryptoContextImpl<DCRTPoly>::EvalSubMutable, py::const_),
            py::arg("ciphertext1"),
            py::arg("ciphertext2"),
            py::doc(cc_EvalSubMutable_docs), release_gil)
        .def("EvalSubMutable",
            py::overload_cast<Ciphertext<DCRTPoly>&,Plaintext&>(&CryptoContextImpl<DCRTPoly>::EvalSubMutable, py::const_),
            py::arg("ciphertext"),
            py::arg("plaintext"),
            py::doc(cc_EvalSubMutablePlaintext_docs), release_gil)
        .def("EvalSubMutable",
            py::overload_cast<Plaintext&, Ciphertext<DCRTPoly>&>(&CryptoContextImpl<DCRTPoly>::EvalSubMutable, py::const_),
            py::arg("plaintext"),
            py::arg("ciphertext"),
            py::doc("Homomorphic subtraction of the ciphertext from the plaintext (plaintext - ciphertext) "
                    "for mutable ciphertexts; scaling factors may be adjusted."), release_gil)
        .def("EvalSubMutableInPlace", &CryptoContextImpl<DCRTPoly>::EvalSubMutableInPlace,
            py::arg("ciphertext1"),
            py::arg("ciphertext2"),
            py::doc(cc_EvalSubMutableInPlace_docs), release_gil)
        .def("EvalMultMutable",
            py::overload_cast<Ciphertext<DCRTPoly>&, Ciphertext<DCRTPoly>&>(&CryptoContextImpl<DCRTPoly>::EvalMultMutable, py::const_),
            py::arg("ciphertext1"),
            py::arg("ciphertext2"),
            py::doc(cc_EvalMultMutable_docs), release_gil)
        .def("EvalMultMutable",
            py::overload_cast<Ciphertext<DCRTPoly>&, Plaintext&>(&CryptoContextImpl<DCRTPoly>::EvalMultMutable, py::const_),
            py::arg("ciphertext"),
            py::arg("plaintext"),
            py::doc(cc_EvalMultMutablePlaintext_docs), release_gil)
        .def("EvalMultMutable",
            py::overload_cast<Plaintext&, Ciphertext<DCRTPoly>&>(&CryptoContextImpl<DCRTPoly>::EvalMultMutable, py::const_),
            py::arg("plaintext"),
            py::arg("ciphertext"),
            py::doc(cc_EvalMultMutablePlaintext_docs), release_gil)
        .def("EvalMultMutableInPlace", &CryptoContextImpl<DCRTPoly>::EvalMultMutableInPlace,
            py::arg("ciphertext1"),
            py::arg("ciphertext2"),
            py::doc(cc_EvalMultMutableInPlace_docs), release_gil)
        .def("EvalSquare", &CryptoContextImpl<DCRTPoly>::EvalSquare,
            py::arg("ciphertext"),
            py::doc(cc_EvalSquare_docs), release_gil)
        .def("EvalSquareMutable", &CryptoContextImpl<DCRTPoly>::EvalSquareMutable,
            py::arg("ciphertext"),
            py::doc(cc_EvalSquareMutable_docs), release_gil)
        .def("EvalSquareInPlace", &CryptoContextImpl<DCRTPoly>::EvalSquareInPlace,
            py::arg("ciphertext"),
            py::doc(cc_EvalSquareInPlace_docs), release_gil)
        .def("EvalMultNoRelin", &CryptoContextImpl<DCRTPoly>::EvalMultNoRelin,
            py::arg("ciphertext1"),
            py::arg("ciphertext2"),
            py::doc(cc_EvalMultNoRelin_docs), release_gil)
        .def("EvalMultNoRelinNoCheck", &CC::EvalMultNoRelinNoCheck,
            py::arg("ciphertext1"), py::arg("ciphertext2"),
            py::doc(cc_EvalMultNoRelinNoCheck_docs), release_gil)
        .def("EvalMultNoCheck", [](const CC& self, ConstCiphertext<DCRTPoly>& ciphertext, const py::int_& scalar) {
                const auto value = openfhe_python::PyIntToInteger<NativeInteger>(scalar);
                py::gil_scoped_release release;
                return self.EvalMultNoCheck(ciphertext, value);
            }, py::arg("ciphertext"), py::arg("scalar"),
            py::doc(cc_EvalMultNoCheck_docs))
        .def("EvalAddInPlaceNoCheck", &CC::EvalAddInPlaceNoCheck,
            py::arg("ciphertext1"), py::arg("ciphertext2"),
            py::doc(cc_EvalAddInPlaceNoCheck_docs), release_gil)
        .def("Relinearize", &CryptoContextImpl<DCRTPoly>::Relinearize,
            py::arg("ciphertext"),
            py::doc(cc_Relinearize_docs), release_gil)
        .def("RelinearizeInPlace", &CryptoContextImpl<DCRTPoly>::RelinearizeInPlace,
            py::arg("ciphertext"),
            py::doc(cc_RelinearizeInPlace_docs), release_gil)
        .def("EvalMultAndRelinearize", &CryptoContextImpl<DCRTPoly>::EvalMultAndRelinearize,
            py::arg("ciphertext1"),
            py::arg("ciphertext2"),
            py::doc(cc_EvalMultAndRelinearize_docs), release_gil)
        .def("LevelReduce", &CC::LevelReduce,
            py::arg("ciphertext"), py::arg("evalKey"), py::arg("levels") = 1,
            py::doc(cc_LevelReduce_docs), release_gil)
        .def("LevelReduceInPlace", &CC::LevelReduceInPlace,
            py::arg("ciphertext"), py::arg("evalKey"), py::arg("levels") = 1,
            py::doc(cc_LevelReduceInPlace_docs), release_gil)
        .def("EvalNegate", &CryptoContextImpl<DCRTPoly>::EvalNegate,
            py::arg("ciphertext"),
            py::doc(cc_EvalNegate_docs), release_gil)
        .def("EvalNegateInPlace", &CryptoContextImpl<DCRTPoly>::EvalNegateInPlace,
            py::arg("ciphertext"),
            py::doc(cc_EvalNegateInPlace_docs), release_gil)
        .def("EvalLogistic", &CryptoContextImpl<DCRTPoly>::EvalLogistic,
            py::arg("ciphertext"),
            py::arg("a"),
            py::arg("b"),
            py::arg("degree"),
            py::doc(cc_EvalLogistic_docs), release_gil)
        .def("EvalChebyshevFunction", &CryptoContextImpl<DCRTPoly>::EvalChebyshevFunction,
            py::arg("func"),
            py::arg("ciphertext"),
            py::arg("a"),
            py::arg("b"),
            py::arg("degree"),
            py::doc(cc_EvalChebyshevFunction_docs), release_gil)
        .def("EvalSin", &CryptoContextImpl<DCRTPoly>::EvalSin,
            py::arg("ciphertext"),
            py::arg("a"),
            py::arg("b"),
            py::arg("degree"),
            py::doc(cc_EvalSin_docs), release_gil)
        .def("EvalCos", &CryptoContextImpl<DCRTPoly>::EvalCos,
            py::arg("ciphertext"),
            py::arg("a"),
            py::arg("b"),
            py::arg("degree"),
            py::doc(cc_EvalCos_docs), release_gil)
        .def("EvalDivide", &CryptoContextImpl<DCRTPoly>::EvalDivide,
            py::arg("ciphertext"),
            py::arg("a"),
            py::arg("b"),
            py::arg("degree"),
            py::doc(cc_EvalDivide_docs), release_gil)
        .def("EvalSumKeyGen", &CryptoContextImpl<DCRTPoly>::EvalSumKeyGen,
            py::arg("privateKey"),
            py::doc(cc_EvalSumKeyGen_docs), release_gil)
        .def("EvalSumRowsKeyGen",
            [](CryptoContextImpl<DCRTPoly>& self,
                const PrivateKey<DCRTPoly> privateKey,
                uint32_t rowSize,
                uint32_t subringDim) {
                return self.EvalSumRowsKeyGen(privateKey, rowSize, subringDim);
            },
            py::arg("privateKey"),
            py::arg("rowSize") = 0,
            py::arg("subringDim") = 0,
            py::doc(cc_EvalSumRowsKeyGen_docs), release_gil)
        .def("EvalSumRowsKeyGen",
            [](CryptoContextImpl<DCRTPoly>& self,
                const PrivateKey<DCRTPoly> privateKey,
                const PublicKey<DCRTPoly> publicKey,
                uint32_t rowSize,
                uint32_t subringDim) {
                return self.EvalSumRowsKeyGen(privateKey, publicKey, rowSize, subringDim);
            },
            py::arg("privateKey"),
            py::arg("publicKey"),
            py::arg("rowSize") = 0,
            py::arg("subringDim") = 0,
            py::doc(cc_EvalSumRowsKeyGen_docs), release_gil)
        // TODO (Oliveira, R.): Solve pointer handling bug when dealing with EvalKeyMap object for the next functions 
        .def("EvalSumColsKeyGen", &CryptoContextImpl<DCRTPoly>::EvalSumColsKeyGen,
            py::arg("privateKey"),
            py::doc(cc_EvalSumColsKeyGen_docs), release_gil)
        .def("EvalSum", &CryptoContextImpl<DCRTPoly>::EvalSum,
            py::arg("ciphertext"),
            py::arg("batchSize"),
            py::doc(cc_EvalSum_docs), release_gil)
        .def("EvalSumRows", &CryptoContextImpl<DCRTPoly>::EvalSumRows,
            py::arg("ciphertext"),
            py::arg("numRows"),
            py::arg("evalSumKeyMap"),
            py::arg("subringDim") = 0,
            py::doc(cc_EvalSumRows_docs), release_gil)
        .def("EvalSumCols", &CryptoContextImpl<DCRTPoly>::EvalSumCols,
            py::arg("ciphertext"),
            py::arg("numCols"),
            py::arg("evalSumKeyMap"),
            py::doc(cc_EvalSumCols_docs), release_gil)
        .def("EvalInnerProduct",
            py::overload_cast<ConstCiphertext<DCRTPoly>&, ConstCiphertext<DCRTPoly>&, uint32_t>(&CryptoContextImpl<DCRTPoly>::EvalInnerProduct, py::const_),
            py::arg("ciphertext1"),
            py::arg("ciphertext2"),
            py::arg("batchSize"),
            py::doc(cc_EvalInnerProduct_docs), release_gil)
        .def("EvalInnerProduct",
            py::overload_cast<ConstCiphertext<DCRTPoly>&, ConstPlaintext&, uint32_t>(&CryptoContextImpl<DCRTPoly>::EvalInnerProduct, py::const_),
            py::arg("ciphertext"),
            py::arg("plaintext"),
            py::arg("batchSize"),
            py::doc(cc_EvalInnerProductPlaintext_docs), release_gil)
        .def("MultipartyKeyGen",
            py::overload_cast<PublicKey<DCRTPoly>, bool, bool>(&CryptoContextImpl<DCRTPoly>::MultipartyKeyGen),
            py::arg("publicKey"),
            py::arg("makeSparse") = false,
            py::arg("fresh") = false,
            py::doc(cc_MultipartyKeyGen_docs), release_gil)
        .def("MultipartyKeyGen",
            py::overload_cast<const std::vector<PrivateKey<DCRTPoly>>&>(&CryptoContextImpl<DCRTPoly>::MultipartyKeyGen),
            py::arg("privateKeyVec"),
            py::doc(cc_MultipartyKeyGen_vector_docs), release_gil)
        .def("MultipartyDecryptLead", &CryptoContextImpl<DCRTPoly>::MultipartyDecryptLead,
            py::arg("ciphertextVec"),
            py::arg("privateKey"),
            py::doc(cc_MultipartyDecryptLead_docs), release_gil)
        .def("MultipartyDecryptMain", &CryptoContextImpl<DCRTPoly>::MultipartyDecryptMain,
            py::arg("ciphertextVec"),
            py::arg("privateKey"),
            py::doc(cc_MultipartyDecryptMain_docs), release_gil)
        .def("MultipartyDecryptFusion",
            [](CryptoContext<DCRTPoly>& self, const std::vector<Ciphertext<DCRTPoly>>& partialCiphertextVec) {
                Plaintext result;
                self->MultipartyDecryptFusion(partialCiphertextVec, &result);
                return result;
            },
            py::arg("partialCiphertextVec"),
            py::doc(cc_MultipartyDecryptFusion_docs), release_gil)
        .def("ShareKeys", &CC::ShareKeys,
            py::arg("privateKey"), py::arg("N"), py::arg("threshold"), py::arg("index"), py::arg("shareType"),
            py::doc(cc_ShareKeys_docs), release_gil)
        .def("RecoverSharedKey", &CC::RecoverSharedKey,
            py::arg("privateKey"), py::arg("shares"), py::arg("N"), py::arg("threshold"), py::arg("shareType"),
            py::doc(cc_RecoverSharedKey_docs), release_gil)
        .def("MultiKeySwitchGen", &CryptoContextImpl<DCRTPoly>::MultiKeySwitchGen,
            py::arg("originalPrivateKey"),
            py::arg("newPrivateKey"),
            py::arg("evalKey"),
            py::doc(cc_MultiKeySwitchGen_docs), release_gil)
        .def("MultiEvalAtIndexKeyGen",
            [](CryptoContextImpl<DCRTPoly>* self,
                const PrivateKey<DCRTPoly>& privateKey,
                std::shared_ptr<std::map<unsigned int, EvalKey<DCRTPoly>>> evalKeyMap,
                const std::vector<int32_t>& indexList,
                const std::string& keyTag = "") {
                return self->MultiEvalAtIndexKeyGen(privateKey, evalKeyMap, indexList, keyTag);
            },
            py::arg("privateKey"),
            py::arg("evalKeyMap"),
            py::arg("indexList"),
            py::arg("keyTag") = "",
            py::doc(cc_MultiEvalAtIndexKeyGen_docs), release_gil)
        .def("MultiEvalAutomorphismKeyGen", &CC::MultiEvalAutomorphismKeyGen,
            py::arg("privateKey"), py::arg("evalKeyMap"), py::arg("indexList"), py::arg("keyTag") = "",
            py::doc(cc_MultiEvalAutomorphismKeyGen_docs), release_gil)
        .def("MultiEvalSumKeyGen", &CryptoContextImpl<DCRTPoly>::MultiEvalSumKeyGen,
            py::arg("privateKey"),
            py::arg("evalKeyMap"),
            py::arg("keyTag") = "",
            py::doc(cc_MultiEvalSumKeyGen_docs), release_gil)
        .def("MultiAddEvalAutomorphismKeys", &CryptoContextImpl<DCRTPoly>::MultiAddEvalAutomorphismKeys,
            py::arg("evalKeyMap1"),
            py::arg("evalKeyMap2"),
            py::arg("keyTag") = "",
            py::doc(cc_MultiAddEvalAutomorphismKeys_docs), release_gil)
        .def("MultiAddPubKeys", &CryptoContextImpl<DCRTPoly>::MultiAddPubKeys,
            py::arg("publicKey1"),
            py::arg("publicKey2"),
            py::arg("keyTag") = "",
            py::doc(cc_MultiAddPubKeys_docs), release_gil)
        .def("MultiAddEvalKeys", &CryptoContextImpl<DCRTPoly>::MultiAddEvalKeys,
            py::arg("evalKey1"),
            py::arg("evalKey2"),
            py::arg("keyTag") = "",
            py::doc(cc_MultiAddEvalKeys_docs), release_gil)
        .def("MultiAddEvalMultKeys", &CryptoContextImpl<DCRTPoly>::MultiAddEvalMultKeys,
            py::arg("evalKey1"),
            py::arg("evalKey2"),
            py::arg("keyTag") = "",
            py::doc(cc_MultiAddEvalMultKeys_docs), release_gil)
        .def("IntBootDecrypt",&CryptoContextImpl<DCRTPoly>::IntBootDecrypt,
            py::arg("privateKey"),
            py::arg("ciphertext"),
            py::doc(cc_IntBootDecrypt_docs), release_gil)
        .def("IntBootEncrypt",&CryptoContextImpl<DCRTPoly>::IntBootEncrypt,
            py::arg("publicKey"),
            py::arg("ciphertext"),
            py::doc(cc_IntBootEncrypt_docs), release_gil)
        .def("IntBootAdd",&CryptoContextImpl<DCRTPoly>::IntBootAdd,
            py::arg("ciphertext1"),
            py::arg("ciphertext2"),
            py::doc(cc_IntBootAdd_docs), release_gil)
        .def("IntBootAdjustScale",&CryptoContextImpl<DCRTPoly>::IntBootAdjustScale,
            py::arg("ciphertext"),
            py::doc(cc_IntBootAdjustScale_docs), release_gil)
        .def("IntMPBootAdjustScale",&CryptoContextImpl<DCRTPoly>::IntMPBootAdjustScale,
            py::arg("ciphertext"),
            py::doc(cc_IntMPBootAdjustScale_docs), release_gil)
        /////////////////////////////////////////////////////////
        // static_cast seems to be better than py::overload_cast for overloaded functions (even it doesn't look pretty):
        // 1. compiler tells your exactly what doesn’t match
        // 2. never silently selects the wrong overload if only one is visible
        /////////////////////////////////////////////////////////
        .def("IntMPBootRandomElementGen",
            static_cast<Ciphertext<DCRTPoly> (CC::*)(PublicKey<DCRTPoly>) const>(&CC::IntMPBootRandomElementGen),
            py::arg("publicKey"),
            py::doc(cc_IntMPBootRandomElementGenPublicKey_docs), release_gil)
        .def("IntMPBootRandomElementGen",
            static_cast<Ciphertext<DCRTPoly> (CC::*)(ConstCiphertext<DCRTPoly>&) const>(&CC::IntMPBootRandomElementGen),
            py::arg("ciphertext"),
            py::doc(cc_IntMPBootRandomElementGenCiphertext_docs), release_gil)
        .def("IntMPBootDecrypt", &CryptoContextImpl<DCRTPoly>::IntMPBootDecrypt,
            py::arg("privateKey"),
            py::arg("ciphertext"),
            py::arg("a"),
            py::doc(cc_IntMPBootDecrypt_docs), release_gil)
        .def("IntMPBootAdd", &CryptoContextImpl<DCRTPoly>::IntMPBootAdd,
            py::arg("sharePairVec"),
            py::doc(cc_IntMPBootAdd_docs), release_gil)
        .def("IntMPBootEncrypt", &CryptoContextImpl<DCRTPoly>::IntMPBootEncrypt,
            py::arg("publicKey"),
            py::arg("sharePair"),
            py::arg("a"),
            py::arg("ciphertext"),
            py::doc(cc_IntMPBootEncrypt_docs), release_gil)
        .def("MultiMultEvalKey", &CryptoContextImpl<DCRTPoly>::MultiMultEvalKey,
            py::arg("privateKey"),
            py::arg("evalKey"),
            py::arg("keyTag") = "",
            py::doc(cc_MultiMultEvalKey_docs), release_gil)
        .def("MultiAddEvalSumKeys", &CryptoContextImpl<DCRTPoly>::MultiAddEvalSumKeys,
            py::arg("evalKeyMap1"),
            py::arg("evalKeyMap2"),
            py::arg("keyTag") = "",
            py::doc(cc_MultiAddEvalSumKeys_docs), release_gil)
        .def("EvalMerge", &CryptoContextImpl<DCRTPoly>::EvalMerge,
            py::arg("ciphertextVec"),
            py::doc(cc_EvalMerge_docs), release_gil)
        .def("ReKeyGen",
            py::overload_cast<const PrivateKey<DCRTPoly>, const PublicKey<DCRTPoly>>(&CryptoContextImpl<DCRTPoly>::ReKeyGen, py::const_),
            py::arg("oldPrivateKey"),
            py::arg("newPublicKey"),
            py::doc(cc_ReKeyGen_docs), release_gil)
        .def("ReEncrypt", &CryptoContextImpl<DCRTPoly>::ReEncrypt,
            py::arg("ciphertext"),
            py::arg("evalKey"),
            py::arg("publicKey") = py::none(),
            py::doc(cc_ReEncrypt_docs), release_gil)
        .def("Rescale", &CryptoContextImpl<DCRTPoly>::Rescale,
            py::arg("ciphertext"),
            py::doc(cc_Rescale_docs), release_gil)
        .def("RescaleInPlace", &CryptoContextImpl<DCRTPoly>::RescaleInPlace,
            py::arg("ciphertext"),
            py::doc(cc_RescaleInPlace_docs), release_gil)
        .def("ModReduce", &CryptoContextImpl<DCRTPoly>::ModReduce,
            py::arg("ciphertext"),
            py::doc(cc_ModReduce_docs), release_gil)
        .def("ModReduceInPlace", &CryptoContextImpl<DCRTPoly>::ModReduceInPlace,
            py::arg("ciphertext"),
            py::doc(cc_ModReduceInPlace_docs), release_gil)
        .def("EvalBootstrapSetup", &CryptoContextImpl<DCRTPoly>::EvalBootstrapSetup,
            py::arg("levelBudget") = std::vector<uint32_t>({5, 4}),
            py::arg("dim1") = std::vector<uint32_t>({0, 0}),
            py::arg("slots") = 0,
            py::arg("correctionFactor") = 0,
            py::arg("precompute")= true,
            py::arg("BTSlotsEncoding")= false,
            py::doc(cc_EvalBootstrapSetup_docs), release_gil)
        .def("EvalBootstrapKeyGen", &CryptoContextImpl<DCRTPoly>::EvalBootstrapKeyGen,
            py::arg("privateKey"),
            py::arg("slots"),
            py::doc(cc_EvalBootstrapKeyGen_docs), release_gil)
        .def("EvalBootstrapPrecompute", &CC::EvalBootstrapPrecompute, py::arg("slots") = 0,
            py::doc(cc_EvalBootstrapPrecompute_docs), release_gil)
        .def("EvalBootstrap", &CryptoContextImpl<DCRTPoly>::EvalBootstrap,
            py::arg("ciphertext"),
            py::arg("numIterations") = 1,
            py::arg("precision") = 0,
            py::doc(cc_EvalBootstrap_docs), release_gil)
        .def("EvalBootstrapStCFirst", &CC::EvalBootstrapStCFirst,
            py::arg("ciphertext"), py::arg("numIterations") = 1, py::arg("precision") = 0,
            py::doc(cc_EvalBootstrapStCFirst_docs), release_gil)
        .def_static("ClearStaticMapsAndVectors", &CryptoContextImpl<DCRTPoly>::ClearStaticMapsAndVectors,
            py::doc("Clear various static caches within the library (evaluation-key maps and the "
                    "context registry)."))
        .def("EvalCKKStoFHEWSetup", &CryptoContextImpl<DCRTPoly>::EvalCKKStoFHEWSetup,
            py::arg("schswchparams"),
            py::doc(cc_EvalCKKStoFHEWSetup_docs), release_gil)
        .def("EvalCKKStoFHEWKeyGen", &CryptoContextImpl<DCRTPoly>::EvalCKKStoFHEWKeyGen,
            py::arg("keyPair"),
            py::arg("lwesk"),
            py::doc(cc_EvalCKKStoFHEWKeyGen_docs), release_gil)
        .def("EvalCKKStoFHEWPrecompute", &CryptoContextImpl<DCRTPoly>::EvalCKKStoFHEWPrecompute,
            py::arg("scale") = 1.0,
            py::doc(cc_EvalCKKStoFHEWPrecompute_docs), release_gil)
        .def("EvalCKKStoFHEW", &CryptoContextImpl<DCRTPoly>::EvalCKKStoFHEW,
            py::arg("ciphertext"),
            py::arg("numCtxts") = 0,
            py::doc(cc_EvalCKKStoFHEW_docs), release_gil)
        .def("EvalFHEWtoCKKSSetup", &CryptoContextImpl<DCRTPoly>::EvalFHEWtoCKKSSetup,
            py::arg("ccLWE"),
            py::arg("numSlotsCKKS") = 0,
            py::arg("logQ") = 25,
            py::doc(cc_EvalFHEWtoCKKSSetup_docs), release_gil)
        .def("EvalFHEWtoCKKSKeyGen", &CryptoContextImpl<DCRTPoly>::EvalFHEWtoCKKSKeyGen,
            py::arg("keyPair"),
            py::arg("lwesk"),
            py::arg("numSlots") = 0,
            py::arg("numCtxts") = 0,
            py::arg("dim1") = 0,
            py::arg("L") = 0,
            py::doc(cc_EvalFHEWtoCKKSKeyGen_docs), release_gil)
        .def("EvalFHEWtoCKKS", &CryptoContextImpl<DCRTPoly>::EvalFHEWtoCKKS,
            py::arg("LWECiphertexts"),
            py::arg("numCtxts") = 0,
            py::arg("numSlots") = 0,
            py::arg("p") = 4,
            py::arg("pmin") = 0.0,
            py::arg("pmax") = 2.0,
            py::arg("dim1") = 0,
            py::doc(cc_EvalFHEWtoCKKS_docs), release_gil)
        .def("EvalSchemeSwitchingSetup", &CryptoContextImpl<DCRTPoly>::EvalSchemeSwitchingSetup,
            py::arg("schswchparams"),
            py::doc(cc_EvalSchemeSwitchingSetup_docs), release_gil)
        .def("SetBinCCForSchemeSwitch", &CC::SetBinCCForSchemeSwitch, py::arg("binFHEContext"),
            py::doc(cc_SetBinCCForSchemeSwitch_docs))
        .def("SetParamsFromCKKSCryptocontext", &CC::SetParamsFromCKKSCryptocontext, py::arg("params"),
            py::doc(cc_SetParamsFromCKKSCryptocontext_docs))
        .def("GetSwkFC", &CC::GetSwkFC,
            py::doc(cc_GetSwkFC_docs))
        .def("SetSwkFC", &CC::SetSwkFC, py::arg("switchingKey"),
            py::doc(cc_SetSwkFC_docs))
        //void EvalSchemeSwitchingKeyGen(const KeyPair<DCRTPoly> &keyPair, ConstLWEPrivateKey &lwesk, uint32_t numValues = 0, bool oneHot = true, bool alt = false, uint32_t dim1CF = 0, uint32_t dim1FC = 0, uint32_t LCF = 1, uint32_t LFC = 0)
        .def("EvalSchemeSwitchingKeyGen", &CryptoContextImpl<DCRTPoly>::EvalSchemeSwitchingKeyGen,
            py::arg("keyPair"),
            py::arg("lwesk"),
            py::doc(cc_EvalSchemeSwitchingKeyGen_docs), release_gil)
        .def("EvalCompareSwitchPrecompute", &CryptoContextImpl<DCRTPoly>::EvalCompareSwitchPrecompute,
            py::arg("pLWE") = 0,
            py::arg("scaleSign") = 1.0,
            py::arg("unit") = false,
            py::doc(cc_EvalCompareSwitchPrecompute_docs), release_gil)
        .def("EvalCompareSchemeSwitching", &CryptoContextImpl<DCRTPoly>::EvalCompareSchemeSwitching,
            py::arg("ciphertext1"),
            py::arg("ciphertext2"),
            py::arg("numCtxts") = 0,
            py::arg("numSlots") = 0,
            py::arg("pLWE") = 0,
            py::arg("scaleSign") = 1.0,
            py::arg("unit") = false,
            py::doc(cc_EvalCompareSchemeSwitching_docs), release_gil)
        .def("EvalMinSchemeSwitching", &CryptoContextImpl<DCRTPoly>::EvalMinSchemeSwitching,
            py::arg("ciphertext"),
            py::arg("publicKey"),
            py::arg("numValues") = 0,
            py::arg("numSlots") = 0,
            py::arg("pLWE") = 0,
            py::arg("scaleSign") = 1.0,
            py::doc(cc_EvalMinSchemeSwitching_docs), release_gil)
        .def("EvalMinSchemeSwitchingAlt", &CryptoContextImpl<DCRTPoly>::EvalMinSchemeSwitchingAlt,
            py::arg("ciphertext"),
            py::arg("publicKey"),
            py::arg("numValues") = 0,
            py::arg("numSlots") = 0,
            py::arg("pLWE") = 0,
            py::arg("scaleSign") = 1.0,
            py::doc(cc_EvalMinSchemeSwitchingAlt_docs), release_gil)
        .def("EvalMaxSchemeSwitching", &CryptoContextImpl<DCRTPoly>::EvalMaxSchemeSwitching,
            py::arg("ciphertext"),
            py::arg("publicKey"),
            py::arg("numValues") = 0,
            py::arg("numSlots") = 0,
            py::arg("pLWE") = 0,
            py::arg("scaleSign") = 1.0,
            py::doc(cc_EvalMaxSchemeSwitching_docs), release_gil)
        .def("EvalMaxSchemeSwitchingAlt", &CryptoContextImpl<DCRTPoly>::EvalMaxSchemeSwitchingAlt,
            py::arg("ciphertext"),
            py::arg("publicKey"),
            py::arg("numValues") = 0,
            py::arg("numSlots") = 0,
            py::arg("pLWE") = 0,
            py::arg("scaleSign") = 1.0,
            py::doc(cc_EvalMaxSchemeSwitchingAlt_docs), release_gil)
        //TODO (Oliveira, R.): Solve pointer handling bug when returning EvalKeyMap objects for the next functions
        .def("EvalAutomorphismKeyGen",
            py::overload_cast<const PrivateKey<DCRTPoly>, const std::vector<uint32_t>&>(&CryptoContextImpl<DCRTPoly>::EvalAutomorphismKeyGen, py::const_),
            py::arg("privateKey"),
            py::arg("indexList"),
            py::doc(cc_EvalAutomorphismKeyGen_docs), release_gil)
        .def("Compress", &CryptoContextImpl<DCRTPoly>::Compress,
            py::arg("ciphertext"),
            py::arg("towersLeft") = 1,
            py::arg("noiseScaleDeg") = 1,
            py::doc("Compress the ciphertext down to the given number of RNS towers, "
                    "reducing its size before storage or transmission."), release_gil)
        .def("EvalMultMany", &CryptoContextImpl<DCRTPoly>::EvalMultMany,
            py::arg("ciphertextVec"),
            py::doc("Homomorphic multiplication of multiple ciphertexts using a binary tree approach, "
                    "with relinearization to two elements after each multiplication. Assumes each "
                    "multiplication stays within the supported ring size, and throws otherwise."), release_gil)
        .def("EvalAddMany", &CryptoContextImpl<DCRTPoly>::EvalAddMany,
            py::arg("ciphertextVec"),
            py::doc("Homomorphic addition of multiple ciphertexts (null entries are skipped). The "
                    "result never aliases an input, so it is always safe to mutate."), release_gil)
        .def("EvalAddManyInPlace", &CryptoContextImpl<DCRTPoly>::EvalAddManyInPlace,
            py::arg("ciphertextVec"),
            py::doc("In-place homomorphic addition of multiple ciphertexts (null entries are skipped; "
                    "the vector is modified to store intermediate results and the result is also left "
                    "in slot 0)."), release_gil)
        .def("FindAutomorphismIndex", [](const CryptoContextImpl<DCRTPoly>& self, int32_t idx) {
                return self.FindAutomorphismIndex(static_cast<uint32_t>(idx));
            },
            py::arg("idx"),
            py::doc(cc_FindAutomorphismIndex_docs))
        .def("FindAutomorphismIndices", [](const CryptoContextImpl<DCRTPoly>& self, const std::vector<int32_t>& idxList) {
                // The C++ API carries signed rotation offsets in uint32_t values.
                return self.FindAutomorphismIndices(std::vector<uint32_t>(idxList.begin(), idxList.end()));
            },
            py::arg("idxList"),
            py::doc(cc_FindAutomorphismIndices_docs))
        .def("GetEvalSumKeyMap",
            [](CryptoContext<DCRTPoly>& self, const std::string& keyTag) {
                return std::make_shared<std::map<uint32_t, EvalKey<DCRTPoly>>>(CryptoContextImpl<DCRTPoly>::GetEvalSumKeyMap(keyTag));
            },
            py::arg("keyTag"),
            py::doc(cc_GetEvalSumKeyMap_docs))
        .def("GetBinCCForSchemeSwitch", &CryptoContextImpl<DCRTPoly>::GetBinCCForSchemeSwitch,
            py::doc("Get the BinFHE context used for CKKS <-> FHEW scheme switching."))
        .def_static("InsertEvalSumKey", &CryptoContextImpl<DCRTPoly>::InsertEvalSumKey,
            py::arg("evalKeyMap"),
            py::arg("keyTag") = "",
            py::doc(cc_InsertEvalSumKey_docs))
        .def_static("InsertEvalMultKey", &CryptoContextImpl<DCRTPoly>::InsertEvalMultKey,
            py::arg("evalKeyVec"),
            py::arg("keyTag") = "",
            py::doc(cc_InsertEvalMultKey_docs))
        .def_static("InsertEvalAutomorphismKey", &CryptoContextImpl<DCRTPoly>::InsertEvalAutomorphismKey,
            py::arg("evalKeyMap"),
            py::arg("keyTag") = "",
            py::doc(cc_InsertEvalAutomorphismKey_docs))
        .def_static("ClearEvalAutomorphismKeys",
            static_cast<void (*)()>(&CryptoContextImpl<DCRTPoly>::ClearEvalAutomorphismKeys),
            cc_ClearEvalAutomorphismKeys_docs
            )
        // it is safer to return by value instead of by reference (GetEvalMultKeyVector returns a const reference to std::vector)
        .def_static("GetEvalMultKeyVector", [](const std::string& keyTag) {
                return CryptoContextImpl<DCRTPoly>::GetEvalMultKeyVector(keyTag);
            },
            py::arg("keyTag") = "",
            py::doc(cc_GetEvalMultKeyVector_docs))
        .def_static("GetEvalAutomorphismKeyMap", &CryptoContextImpl<DCRTPoly>::GetEvalAutomorphismKeyMapPtr,
            py::arg("keyTag") = "",
            py::doc(cc_GetEvalAutomorphismKeyMap_docs))
        .def_static("GetExistingEvalAutomorphismKeyIndices", [](const std::string& keyTag) {
                const auto indices = CryptoContextImpl<DCRTPoly>::GetExistingEvalAutomorphismKeyIndices(keyTag);
                return std::vector<uint32_t>(indices.begin(), indices.end());
            },
            py::arg("keyTag") = "",
            py::doc(cc_GetExistingEvalAutomorphismKeyIndices_docs))
        .def_static("GetAllEvalAutomorphismKeys", []() {
                py::dict result;
                for (const auto& [keyTag, keys] : CC::GetAllEvalAutomorphismKeys())
                    result[py::str(keyTag)] = py::cast(keys);
                return result;
            },
            py::doc(cc_GetAllEvalAutomorphismKeys_docs))
        .def_static("GetAllEvalMultKeys", []() {
                py::dict result;
                for (const auto& [keyTag, keys] : CC::GetAllEvalMultKeys())
                    result[py::str(keyTag)] = py::cast(keys);
                return result;
            },
            py::doc(cc_GetAllEvalMultKeys_docs))
        .def_static("GetAllEvalSumKeys", []() {
                py::dict result;
                for (const auto& [keyTag, keys] : CC::GetAllEvalSumKeys())
                    result[py::str(keyTag)] = py::cast(keys);
                return result;
            },
            py::doc(cc_GetAllEvalSumKeys_docs))
        .def_static("GetEvalAutomorphismNoKeyIndices", &CC::GetEvalAutomorphismNoKeyIndices,
            py::arg("keyTag"), py::arg("indices"),
            py::doc(cc_GetEvalAutomorphismNoKeyIndices_docs))
        .def_static("GetUniqueValues", &CC::GetUniqueValues,
            py::arg("oldValues"), py::arg("newValues"),
            py::doc(cc_GetUniqueValues_docs))
        .def_static("GetPlaintextForDecrypt", &CC::GetPlaintextForDecrypt,
            py::arg("encodingType"), py::arg("elementParams"), py::arg("encodingParams"),
            py::arg("ckksDataType") = CKKSDataType::REAL,
            py::doc(cc_GetPlaintextForDecrypt_docs))
        .def("SerializedObjectName", &CC::SerializedObjectName,
            py::doc(cc_SerializedObjectName_docs))
        .def_static("SerializedVersion", &CC::SerializedVersion,
            py::doc(cc_SerializedVersion_docs))
        .def_static("SerializeEvalSumKey", [](const std::string& filename, const SerType::SERBINARY& sertype,
                                               const std::string& keyTag) {
                std::ofstream outfile(filename, std::ios::out | std::ios::binary);
                if (!outfile.is_open()) {
                    std::cerr << "I cannot write serialization to " << filename << std::endl;
                    return false;
                }
                bool res = CC::SerializeEvalSumKey<SerType::SERBINARY>(outfile, sertype, keyTag);
                outfile.close();
                return res;
            }, py::arg("filename"), py::arg("sertype"), py::arg("keyTag") = "",
            py::doc(cc_SerializeEvalSumKey_docs), release_gil)
        .def_static("SerializeEvalSumKey", [](const std::string& filename, const SerType::SERJSON& sertype,
                                               const std::string& keyTag) {
                std::ofstream outfile(filename, std::ios::out | std::ios::binary);
                if (!outfile.is_open()) {
                    std::cerr << "I cannot write serialization to " << filename << std::endl;
                    return false;
                }
                bool res = CC::SerializeEvalSumKey<SerType::SERJSON>(outfile, sertype, keyTag);
                outfile.close();
                return res;
            }, py::arg("filename"), py::arg("sertype"), py::arg("keyTag") = "",
            py::doc(cc_SerializeEvalSumKey_docs), release_gil)
        // the CryptoContext overloads serialize only the keys belonging to the given context
        .def_static("SerializeEvalSumKey", [](const std::string& filename, const SerType::SERBINARY& sertype,
                                               const CryptoContext<DCRTPoly> cryptoContext) {
                std::ofstream outfile(filename, std::ios::out | std::ios::binary);
                if (!outfile.is_open()) {
                    std::cerr << "I cannot write serialization to " << filename << std::endl;
                    return false;
                }
                bool res = CC::SerializeEvalSumKey<SerType::SERBINARY>(outfile, sertype, cryptoContext);
                outfile.close();
                return res;
            }, py::arg("filename"), py::arg("sertype"), py::arg("cryptoContext"),
            py::doc(cc_SerializeEvalSumKeyByContext_docs), release_gil)
        .def_static("SerializeEvalSumKey", [](const std::string& filename, const SerType::SERJSON& sertype,
                                               const CryptoContext<DCRTPoly> cryptoContext) {
                std::ofstream outfile(filename, std::ios::out | std::ios::binary);
                if (!outfile.is_open()) {
                    std::cerr << "I cannot write serialization to " << filename << std::endl;
                    return false;
                }
                bool res = CC::SerializeEvalSumKey<SerType::SERJSON>(outfile, sertype, cryptoContext);
                outfile.close();
                return res;
            }, py::arg("filename"), py::arg("sertype"), py::arg("cryptoContext"),
            py::doc(cc_SerializeEvalSumKeyByContext_docs), release_gil)
        .def_static("SerializeEvalMultKey", [](const std::string &filename, const SerType::SERBINARY &sertype, std::string keyTag = "") {
                std::ofstream outfile(filename, std::ios::out | std::ios::binary);
                if (!outfile.is_open()) {
                    std::cerr << "I cannot write serialization to " << filename << std::endl;
                    return false;
                }
                bool res = CryptoContextImpl<DCRTPoly>::SerializeEvalMultKey<SerType::SERBINARY>(outfile, sertype, keyTag);
                outfile.close();
                return res;
            },
            py::arg("filename"),
            py::arg("sertype"),
            py::arg("keyTag") = "",
            py::doc(cc_SerializeEvalMultKey_docs), release_gil)
        .def_static("SerializeEvalMultKey", [](const std::string &filename, const SerType::SERJSON &sertype, std::string keyTag = "") {
                std::ofstream outfile(filename, std::ios::out | std::ios::binary);
                if (!outfile.is_open()) {
                    std::cerr << "I cannot write serialization to " << filename << std::endl;
                    return false;
                }
                bool res = CryptoContextImpl<DCRTPoly>::SerializeEvalMultKey<SerType::SERJSON>(outfile, sertype, keyTag);
                outfile.close();
                return res;
            },
            py::arg("filename"),
            py::arg("sertype"),
            py::arg("keyTag") = "",
            py::doc(cc_SerializeEvalMultKey_docs), release_gil)
        .def_static("SerializeEvalAutomorphismKey", [](const std::string &filename, const SerType::SERBINARY &sertype, std::string keyTag = "") {
                std::ofstream outfile(filename, std::ios::out | std::ios::binary);
                if (!outfile.is_open()) {
                    std::cerr << "I cannot write serialization to " << filename << std::endl;
                    return false;
                }
                bool res = CryptoContextImpl<DCRTPoly>::SerializeEvalAutomorphismKey<SerType::SERBINARY>(outfile, sertype, keyTag);
                outfile.close();
                return res;
            },
            py::arg("filename"),
            py::arg("sertype"),
            py::arg("keyTag") = "",
            py::doc(cc_SerializeEvalAutomorphismKey_docs), release_gil)
        .def_static("SerializeEvalAutomorphismKey", [](const std::string &filename, const SerType::SERJSON &sertype, std::string keyTag = "") {
                std::ofstream outfile(filename, std::ios::out | std::ios::binary);
                if (!outfile.is_open()) {
                    std::cerr << "I cannot write serialization to " << filename << std::endl;
                    return false;
                }
                bool res = CryptoContextImpl<DCRTPoly>::SerializeEvalAutomorphismKey<SerType::SERJSON>(outfile, sertype, keyTag);
                outfile.close();
                return res;
            },
            py::arg("filename"),
            py::arg("sertype"),
            py::arg("keyTag") = "",
            py::doc(cc_SerializeEvalAutomorphismKey_docs), release_gil)
        .def_static("DeserializeEvalSumKey", [](const std::string& filename, const SerType::SERBINARY& sertype) {
                std::ifstream infile(filename, std::ios::in | std::ios::binary);
                if (!infile.is_open()) {
                    std::cerr << "I cannot read serialization from " << filename << std::endl;
                    return false;
                }
                return CC::DeserializeEvalSumKey<SerType::SERBINARY>(infile, sertype);
            }, py::arg("filename"), py::arg("sertype"),
            py::doc(cc_DeserializeEvalSumKey_docs), release_gil)
        .def_static("DeserializeEvalSumKey", [](const std::string& filename, const SerType::SERJSON& sertype) {
                std::ifstream infile(filename, std::ios::in | std::ios::binary);
                if (!infile.is_open()) {
                    std::cerr << "I cannot read serialization from " << filename << std::endl;
                    return false;
                }
                return CC::DeserializeEvalSumKey<SerType::SERJSON>(infile, sertype);
            }, py::arg("filename"), py::arg("sertype"),
            py::doc(cc_DeserializeEvalSumKey_docs), release_gil)
        .def_static("DeserializeEvalMultKey", [](const std::string &filename, const SerType::SERBINARY &sertype) {
                std::ifstream emkeys(filename, std::ios::in | std::ios::binary);
                if (!emkeys.is_open()) {
                    std::cerr << "I cannot read serialization from " << filename << std::endl;
                    return false;
                }
                return CryptoContextImpl<DCRTPoly>::DeserializeEvalMultKey<SerType::SERBINARY>(emkeys, sertype);
            },
            py::arg("filename"),
            py::arg("sertype"),
            py::doc(cc_DeserializeEvalMultKey_docs), release_gil)
        .def_static("DeserializeEvalMultKey", [](const std::string &filename, const SerType::SERJSON &sertype) {
                std::ifstream emkeys(filename, std::ios::in | std::ios::binary);
                if (!emkeys.is_open()) {
                    std::cerr << "I cannot read serialization from " << filename << std::endl;
                    return false;
                }
                return CryptoContextImpl<DCRTPoly>::DeserializeEvalMultKey<SerType::SERJSON>(emkeys, sertype);
            },
            py::arg("filename"),
            py::arg("sertype"),
            py::doc(cc_DeserializeEvalMultKey_docs), release_gil)
        .def_static("DeserializeEvalAutomorphismKey", [](const std::string &filename, const SerType::SERBINARY &sertype) {
                std::ifstream erkeys(filename, std::ios::in | std::ios::binary);
                if (!erkeys.is_open()) {
                    std::cerr << "I cannot read serialization from " << filename << std::endl;
                    return false;
                }
                return CryptoContextImpl<DCRTPoly>::DeserializeEvalAutomorphismKey<SerType::SERBINARY>(erkeys, sertype);
            },
            py::arg("filename"),
            py::arg("sertype"),
            py::doc(cc_DeserializeEvalAutomorphismKey_docs), release_gil)
        .def_static("DeserializeEvalAutomorphismKey", [](const std::string &filename, const SerType::SERJSON &sertype) {
                std::ifstream erkeys(filename, std::ios::in | std::ios::binary);
                if (!erkeys.is_open()) {
                    std::cerr << "I cannot read serialization from " << filename << std::endl;
                    return false;
                }
                return CryptoContextImpl<DCRTPoly>::DeserializeEvalAutomorphismKey<SerType::SERJSON>(erkeys, sertype);
            },
            py::arg("filename"),
            py::arg("sertype"),
            py::doc(cc_DeserializeEvalAutomorphismKey_docs), release_gil);

    bind_fbt_crypto_context(cc_class);

    bind_crypto_context_templates<int64_t>(cc_class);
    bind_crypto_context_templates<double>(cc_class);
    bind_crypto_context_templates<std::complex<double>>(cc_class);

    bind_eval_add_family(cc_class);
    bind_eval_add_scalar_overloads<double>(cc_class);
    bind_eval_add_scalar_overloads<std::complex<double>>(cc_class);

    bind_eval_addinplace_family(cc_class);
    bind_eval_addinplace_scalar_overloads<double>(cc_class);
    bind_eval_addinplace_scalar_overloads<std::complex<double>>(cc_class);

    bind_eval_sub_family(cc_class);
    bind_eval_sub_scalar_overloads<double>(cc_class);
    bind_eval_sub_scalar_overloads<std::complex<double>>(cc_class);

    bind_eval_subinplace_family(cc_class);
    bind_eval_subinplace_scalar_overloads<double>(cc_class);
    bind_eval_subinplace_scalar_overloads<std::complex<double>>(cc_class);

    bind_eval_mult_family(cc_class);
    bind_eval_mult_scalar_overloads<double>(cc_class);
    bind_eval_mult_scalar_overloads<std::complex<double>>(cc_class);

    bind_eval_multinplace_scalar_overloads<double>(cc_class);
    bind_eval_multinplace_scalar_overloads<std::complex<double>>(cc_class);

    // Generator Functions
    m.def("GenCryptoContext", &GenCryptoContext<CryptoContextBFVRNS>,
        py::arg("params"),
        py::doc("Generate a BFV RNS crypto context from the given CCParamsBFVRNS parameters."), release_gil);
    m.def("GenCryptoContext", &GenCryptoContext<CryptoContextBGVRNS>,
        py::arg("params"),
        py::doc("Generate a BGV RNS crypto context from the given CCParamsBGVRNS parameters."), release_gil);
    m.def("GenCryptoContext", &GenCryptoContext<CryptoContextCKKSRNS>,
        py::arg("params"),
        py::doc("Generate a CKKS RNS crypto context from the given CCParamsCKKSRNS parameters."), release_gil);

    m.def("GetAllContexts", &CryptoContextFactory<DCRTPoly>::GetAllContexts,
        py::doc("Return all crypto contexts registered in the library-wide context registry."));

    m.def("ReleaseAllContexts", &CryptoContextFactory<DCRTPoly>::ReleaseAllContexts,
        py::doc("Release all registered crypto contexts: clears their CKKS caches and the static "
                "evaluation-key maps, empties the registry and returns freed memory to the system."));

    m.def("ClearEvalMultKeys", static_cast<void (*)()>(&CryptoContextImpl<DCRTPoly>::ClearEvalMultKeys),
        py::doc("Clear the entire static EvalMult key cache."));
    m.def("ClearEvalSumKeys", static_cast<void (*)()>(&CryptoContextImpl<DCRTPoly>::ClearEvalSumKeys),
        py::doc("Clear the entire static EvalSum key cache."));
}

int get_native_int() {
    #if NATIVEINT == 128 && !defined(__EMSCRIPTEN__)
        return 128;
    #elif NATIVEINT == 32
        return 32;
    #else
        return 64;
    #endif
}

void bind_enums_and_constants(py::module &m) {
    /* ---- PKE enums ---- */ 
    // Scheme Types
    py::enum_<SCHEME>(m, "SCHEME")
        .value("INVALID_SCHEME", SCHEME::INVALID_SCHEME)
        .value("CKKSRNS_SCHEME", SCHEME::CKKSRNS_SCHEME)
        .value("BFVRNS_SCHEME", SCHEME::BFVRNS_SCHEME)
        .value("BGVRNS_SCHEME", SCHEME::BGVRNS_SCHEME)
        .export_values();

    // PKE Features
    py::enum_<PKESchemeFeature>(m, "PKESchemeFeature")
        .value("PKE", PKESchemeFeature::PKE)
        .value("KEYSWITCH", PKESchemeFeature::KEYSWITCH)
        .value("PRE", PKESchemeFeature::PRE)
        .value("LEVELEDSHE", PKESchemeFeature::LEVELEDSHE)
        .value("ADVANCEDSHE", PKESchemeFeature::ADVANCEDSHE)
        .value("MULTIPARTY", PKESchemeFeature::MULTIPARTY)
        .value("FHE", PKESchemeFeature::FHE)
        .value("SCHEMESWITCH", PKESchemeFeature::SCHEMESWITCH)
        .export_values();

    // Plaintext enums
    py::enum_<Format>(m, "Format")
        .value("EVALUATION", Format::EVALUATION)
        .value("COEFFICIENT", Format::COEFFICIENT)
        .export_values();
    py::enum_<PlaintextEncodings>(m, "PlaintextEncodings")
        .value("INVALID_ENCODING", PlaintextEncodings::INVALID_ENCODING)
        .value("COEF_PACKED_ENCODING", PlaintextEncodings::COEF_PACKED_ENCODING)
        .value("PACKED_ENCODING", PlaintextEncodings::PACKED_ENCODING)
        .value("STRING_ENCODING", PlaintextEncodings::STRING_ENCODING)
        .value("CKKS_PACKED_ENCODING", PlaintextEncodings::CKKS_PACKED_ENCODING)
        .export_values();
    // Serialization Types
    py::class_<SerType::SERJSON>(m, "SERJSON",
        "Serialization format tag for human-readable JSON; pass JSON (its instance) as the "
        "sertype argument of the (de)serialization functions.");
    py::class_<SerType::SERBINARY>(m, "SERBINARY",
        "Serialization format tag for the compact binary format; pass BINARY (its instance) as "
        "the sertype argument of the (de)serialization functions.");
    m.attr("JSON") = py::cast(SerType::JSON);
    m.attr("BINARY") = py::cast(SerType::BINARY);

    // Scaling Techniques
    py::enum_<ScalingTechnique>(m, "ScalingTechnique")
       .value("FIXEDMANUAL", ScalingTechnique::FIXEDMANUAL)
       .value("FIXEDAUTO", ScalingTechnique::FIXEDAUTO)
       .value("FLEXIBLEAUTO", ScalingTechnique::FLEXIBLEAUTO)
       .value("FLEXIBLEAUTOEXT", ScalingTechnique::FLEXIBLEAUTOEXT)
       .value("NORESCALE", ScalingTechnique::NORESCALE)
       .value("COMPOSITESCALINGAUTO", ScalingTechnique::COMPOSITESCALINGAUTO)
       .value("COMPOSITESCALINGMANUAL", ScalingTechnique::COMPOSITESCALINGMANUAL)
       .value("INVALID_RS_TECHNIQUE", ScalingTechnique::INVALID_RS_TECHNIQUE)
       .export_values();

    // Key Switching Techniques
    py::enum_<KeySwitchTechnique>(m, "KeySwitchTechnique")
        .value("INVALID_KS_TECH", KeySwitchTechnique::INVALID_KS_TECH)
        .value("BV", KeySwitchTechnique::BV)
        .value("HYBRID", KeySwitchTechnique::HYBRID)
        .export_values();

    // Secret Key Dist
    py::enum_<SecretKeyDist>(m, "SecretKeyDist")
        .value("GAUSSIAN", SecretKeyDist::GAUSSIAN)
        .value("UNIFORM_TERNARY", SecretKeyDist::UNIFORM_TERNARY)
        .value("SPARSE_TERNARY", SecretKeyDist::SPARSE_TERNARY)
        .value("SPARSE_ENCAPSULATED", SecretKeyDist::SPARSE_ENCAPSULATED)
        .export_values();

    // ProxyReEncryptionMode
    py::enum_<ProxyReEncryptionMode>(m, "ProxyReEncryptionMode")
        .value("NOT_SET", ProxyReEncryptionMode::NOT_SET)
        .value("INDCPA", ProxyReEncryptionMode::INDCPA)
        .value("FIXED_NOISE_HRA", ProxyReEncryptionMode::FIXED_NOISE_HRA)
        .value("NOISE_FLOODING_HRA", ProxyReEncryptionMode::NOISE_FLOODING_HRA)
        .export_values();

    // MultipartyMode
    py::enum_<MultipartyMode>(m, "MultipartyMode")
        .value("INVALID_MULTIPARTY_MODE", MultipartyMode::INVALID_MULTIPARTY_MODE)
        .value("FIXED_NOISE_MULTIPARTY", MultipartyMode::FIXED_NOISE_MULTIPARTY)
        .value("NOISE_FLOODING_MULTIPARTY", MultipartyMode::NOISE_FLOODING_MULTIPARTY)
        .export_values();

    // ExecutionMode
    py::enum_<ExecutionMode>(m, "ExecutionMode")
        .value("EXEC_EVALUATION", ExecutionMode::EXEC_EVALUATION)
        .value("EXEC_NOISE_ESTIMATION", ExecutionMode::EXEC_NOISE_ESTIMATION)
        .export_values();

    // DecryptionNoiseMode
    py::enum_<DecryptionNoiseMode>(m, "DecryptionNoiseMode")
        .value("FIXED_NOISE_DECRYPT", DecryptionNoiseMode::FIXED_NOISE_DECRYPT)
        .value("NOISE_FLOODING_DECRYPT", DecryptionNoiseMode::NOISE_FLOODING_DECRYPT)
        .export_values();

    // EncryptionTechnique
    py::enum_<EncryptionTechnique>(m, "EncryptionTechnique")
        .value("STANDARD", EncryptionTechnique::STANDARD)
        .value("EXTENDED", EncryptionTechnique::EXTENDED)
        .export_values();

    // MultiplicationTechnique
    py::enum_<MultiplicationTechnique>(m, "MultiplicationTechnique")
        .value("BEHZ", MultiplicationTechnique::BEHZ)
        .value("HPS", MultiplicationTechnique::HPS)
        .value("HPSPOVERQ", MultiplicationTechnique::HPSPOVERQ)
        .value("HPSPOVERQLEVELED", MultiplicationTechnique::HPSPOVERQLEVELED)
        .export_values();

    // Compression Leval
    py::enum_<CompressionLevel>(m,"CompressionLevel")
        .value("COMPACT", CompressionLevel::COMPACT)
        .value("SLACK", CompressionLevel::SLACK)
        .export_values();

    py::enum_<CKKSDataType>(m,"CKKSDataType")
        .value("REAL", CKKSDataType::REAL)
        .value("COMPLEX", CKKSDataType::COMPLEX)
        .export_values();

    /* ---- CORE enums ---- */ 
    // Security Level
    py::enum_<SecurityLevel>(m,"SecurityLevel")
        .value("HEStd_128_classic", SecurityLevel::HEStd_128_classic)
        .value("HEStd_192_classic", SecurityLevel::HEStd_192_classic)
        .value("HEStd_256_classic", SecurityLevel::HEStd_256_classic)
        .value("HEStd_128_quantum", SecurityLevel::HEStd_128_quantum)
        .value("HEStd_192_quantum", SecurityLevel::HEStd_192_quantum)
        .value("HEStd_256_quantum", SecurityLevel::HEStd_256_quantum)
        .value("HEStd_NotSet", SecurityLevel::HEStd_NotSet)
        .export_values();

    //NATIVEINT function
    m.def("get_native_int", &get_native_int,
        py::doc("Return the native integer bit width the library was built with (64 or 128)."));
}

void bind_keys(py::module &m) {
    py::class_<PublicKeyImpl<DCRTPoly>, std::shared_ptr<PublicKeyImpl<DCRTPoly>>>(m, "PublicKey",
        "Public encryption key of a DCRTPoly-based scheme, generated by CryptoContext.KeyGen().")
        .def(py::init<>())
        .def("GetCryptoContext", &PublicKeyImpl<DCRTPoly>::GetCryptoContext,
            py::doc(key_GetCryptoContext_docs))
        .def("GetKeyTag", &PublicKeyImpl<DCRTPoly>::GetKeyTag,
            py::doc("Get the tag identifying the secret key this public key belongs to."))
        .def("SetKeyTag", &PublicKeyImpl<DCRTPoly>::SetKeyTag, py::arg("keyTag"),
            py::doc("Set the tag identifying the secret key this public key belongs to."));
    py::class_<PrivateKeyImpl<DCRTPoly>, std::shared_ptr<PrivateKeyImpl<DCRTPoly>>>(m, "PrivateKey",
        "Secret decryption key of a DCRTPoly-based scheme, generated by CryptoContext.KeyGen().")
        .def(py::init<>())
        // a key created without a CryptoContext cannot be passed to RecoverSharedKey()
        .def(py::init<const CryptoContext<DCRTPoly>&>(), py::arg("cryptoContext"))
        .def("GetCryptoContext", &PrivateKeyImpl<DCRTPoly>::GetCryptoContext,
            py::doc("Get the CryptoContext this key was generated for."))
        .def("GetKeyTag", &PrivateKeyImpl<DCRTPoly>::GetKeyTag,
            py::doc("Get the tag identifying this secret key."))
        .def("SetKeyTag", &PrivateKeyImpl<DCRTPoly>::SetKeyTag, py::arg("keyTag"),
            py::doc("Set the tag identifying this secret key."));
    py::class_<KeyPair<DCRTPoly>>(m, "KeyPair",
        "Pair of a public key and the matching secret key, as returned by CryptoContext.KeyGen().")
        .def_readwrite("publicKey", &KeyPair<DCRTPoly>::publicKey,
            "The public key of the pair.")
        .def_readwrite("secretKey", &KeyPair<DCRTPoly>::secretKey,
            "The secret key of the pair.")
        .def("good", &KeyPair<DCRTPoly>::good,kp_good_docs);
    py::class_<EvalKeyImpl<DCRTPoly>, std::shared_ptr<EvalKeyImpl<DCRTPoly>>>(m, "EvalKey",
        "Evaluation key (for relinearization, rotation or key switching), generated by the "
        "CryptoContext key-generation methods; treated as an opaque object in Python.")
        .def(py::init<>())
        .def("GetKeyTag", &EvalKeyImpl<DCRTPoly>::GetKeyTag,
            py::doc("Get the tag identifying the secret key this evaluation key belongs to."))
        .def("SetKeyTag", &EvalKeyImpl<DCRTPoly>::SetKeyTag, py::arg("keyTag"),
            py::doc("Set the tag identifying the secret key this evaluation key belongs to."));
    py::class_<std::map<uint32_t, EvalKey<DCRTPoly>>, std::shared_ptr<std::map<uint32_t, EvalKey<DCRTPoly>>>>(m, "EvalKeyMap",
        "Opaque map from automorphism indices to evaluation keys, as produced by the rotation "
        "and summation key-generation methods and consumed by the key-insertion and "
        "serialization functions.")
        .def(py::init<>());
}

// PlaintextImpl is an abstract class, so we should use a helper (trampoline) class
class PlaintextImpl_helper : public PlaintextImpl {
public:
    using PlaintextImpl::PlaintextImpl; // inherited constructors

    // the PlaintextImpl virtual functions' overrides
    bool Encode() override {
        PYBIND11_OVERRIDE_PURE(
            bool,          // return type
            PlaintextImpl, // parent class
            Encode         // function name
                           // no arguments
        );
    }
    bool Decode() override {
        PYBIND11_OVERRIDE_PURE(
            bool,          // return type
            PlaintextImpl, // parent class
            Decode         // function name
                           // no arguments
        );
    }
    bool Decode(size_t depth, double scalingFactor, ScalingTechnique scalTech, ExecutionMode executionMode) override {
        PYBIND11_OVERRIDE(
            bool,          // return type
            PlaintextImpl, // parent class
            Decode,        // function name
            depth, scalingFactor, scalTech, executionMode // arguments
        );
    }
    size_t GetLength() const override {
        PYBIND11_OVERRIDE_PURE(
            size_t,        // return type
            PlaintextImpl, // parent class
            GetLength      // function name
                           // no arguments
        );
    }
    void SetLength(size_t newSize) override {
        PYBIND11_OVERRIDE(
            void,          // return type
            PlaintextImpl, // parent class
            SetLength,     // function name
            newSize        // arguments
        );
    }
    double GetLogError() const override {
        PYBIND11_OVERRIDE(double, PlaintextImpl, GetLogError);
    }
    double GetLogPrecision() const override {
        PYBIND11_OVERRIDE(double, PlaintextImpl, GetLogPrecision);
    }
    const std::string& GetStringValue() const override {
        PYBIND11_OVERRIDE(const std::string&, PlaintextImpl, GetStringValue);
    }
    const std::vector<int64_t>& GetCoefPackedValue() const override {
        PYBIND11_OVERRIDE(const std::vector<int64_t>&, PlaintextImpl, GetCoefPackedValue);
    }
    const std::vector<int64_t>& GetPackedValue() const override {
        PYBIND11_OVERRIDE(const std::vector<int64_t>&, PlaintextImpl, GetPackedValue);
    }
    const std::vector<std::complex<double>>& GetCKKSPackedValue() const override {
        PYBIND11_OVERRIDE(const std::vector<std::complex<double>>&, PlaintextImpl, GetCKKSPackedValue);
    }
    std::vector<double> GetRealPackedValue() const override {
        PYBIND11_OVERRIDE(std::vector<double>, PlaintextImpl, GetRealPackedValue);
    }
    void SetStringValue(const std::string& str) override {
        PYBIND11_OVERRIDE(void, PlaintextImpl, SetStringValue, str);
    }
    void SetIntVectorValue(const std::vector<int64_t>& vec) override {
        PYBIND11_OVERRIDE(void, PlaintextImpl, SetIntVectorValue, vec);
    }
    std::string GetFormattedValues(int64_t precision) const override {
        PYBIND11_OVERRIDE(std::string, PlaintextImpl, GetFormattedValues, precision);
    }
};

void bind_encodings(py::module &m) {
    py::class_<EncodingParamsImpl, EncodingParams>(m, "EncodingParams",
        "Parameters of the plaintext encoding: the plaintext modulus, batch size and plaintext "
        "generator (returned by CryptoContext.GetEncodingParams).")
        .def("GetPlaintextModulus", &EncodingParamsImpl::GetPlaintextModulus,
            py::doc(encparams_GetPlaintextModulus_docs))
        .def("GetBatchSize", &EncodingParamsImpl::GetBatchSize,
            py::doc(encparams_GetBatchSize_docs))
        .def("GetPlaintextGenerator", &EncodingParamsImpl::GetPlaintextGenerator,
            py::doc(encparams_GetPlaintextGenerator_docs));

    auto ptx_class = py::class_<PlaintextImpl, std::shared_ptr<PlaintextImpl>, PlaintextImpl_helper>(m, "Plaintext",
        "Plaintext encoded for one of the DCRTPoly-based schemes, produced by the CryptoContext "
        "Make*Plaintext methods and by decryption; holds the encoded values together with the "
        "encoding metadata (level, scaling factor, number of slots, ...).");
    ptx_class
        .def("GetScalingFactor", &PlaintextImpl::GetScalingFactor, ptx_GetScalingFactor_docs)
        .def("GetScalingFactorInt", [](const PlaintextImpl& self) {
                return openfhe_python::IntegerToPyInt(self.GetScalingFactorInt());
            },
            py::doc(ptx_GetScalingFactorInt_docs))
        .def("SetScalingFactorInt", [](PlaintextImpl& self, const py::int_& sf) {
                self.SetScalingFactorInt(openfhe_python::PyIntToInteger<NativeInteger>(sf));
            }, py::arg("sf"),
            py::doc(ptx_SetScalingFactorInt_docs))
        .def("SetScalingFactor", &PlaintextImpl::SetScalingFactor,
            py::arg("sf"),
            py::doc(ptx_SetScalingFactor_docs))
        .def("GetSchemeID", &PlaintextImpl::GetSchemeID, ptx_GetSchemeID_docs)
        .def("GetEncodingType", &PlaintextImpl::GetEncodingType,
            py::doc(ptx_GetEncodingType_docs))
        .def("GetEncodingParams", &PlaintextImpl::GetEncodingParams,
            py::doc(ptx_GetEncodingParams_docs))
        .def("GetCKKSDataType", &PlaintextImpl::GetCKKSDataType,
            py::doc(ptx_GetCKKSDataType_docs))
        .def("SetCKKSDataType", &PlaintextImpl::SetCKKSDataType, py::arg("dataType"),
            py::doc(ptx_SetCKKSDataType_docs))
        .def("GetElementRingDimension", &PlaintextImpl::GetElementRingDimension,
            py::doc(ptx_GetElementRingDimension_docs))
        .def("GetElementModulus", [](const PlaintextImpl& self) {
                return openfhe_python::IntegerToPyInt(self.GetElementModulus());
            },
            py::doc(ptx_GetElementModulus_docs))
        .def("GetLength", &PlaintextImpl::GetLength, ptx_GetLength_docs)
        .def("SetLength", &PlaintextImpl::SetLength,
            py::arg("newSize"),
            py::doc(ptx_SetLength_docs))
        .def("IsEncoded", &PlaintextImpl::IsEncoded, ptx_IsEncoded_docs)
        .def("GetLogPrecision", &PlaintextImpl::GetLogPrecision, ptx_GetLogPrecision_docs)
        .def("Encode", &PlaintextImpl::Encode, ptx_Encode_docs, release_gil)
        .def("Decode", py::overload_cast<>(&PlaintextImpl::Decode), ptx_Decode_docs, release_gil)
        .def("Decode", py::overload_cast<size_t, double, ScalingTechnique, ExecutionMode>(&PlaintextImpl::Decode),
            py::arg("depth"), py::arg("scalingFactor"), py::arg("scalTech"), py::arg("executionMode"),
            py::doc(ptx_Decode_docs), release_gil)
        .def("LowBound", &PlaintextImpl::LowBound, ptx_LowBound_docs)
        .def("HighBound", &PlaintextImpl::HighBound, ptx_HighBound_docs)
        .def("SetFormat", &PlaintextImpl::SetFormat,
            py::arg("fmt"),
            py::doc(ptx_SetFormat_docs), release_gil)
        .def("GetCoefPackedValue", &PlaintextImpl::GetCoefPackedValue,
            py::doc("Get the plaintext value as a list of signed integers (COEF_PACKED encoding)."))
        .def("GetPackedValue", &PlaintextImpl::GetPackedValue,
            py::doc("Get the plaintext value as a list of signed integers (PACKED encoding)."))
        .def("GetCKKSPackedValue", &PlaintextImpl::GetCKKSPackedValue, ptx_GetCKKSPackedValue_docs)
        .def("GetRealPackedValue", &PlaintextImpl::GetRealPackedValue, ptx_GetRealPackedValue_docs)
        .def("GetLevel", &PlaintextImpl::GetLevel,
            py::doc("Get the level of the plaintext (the number of levels already consumed)."))
        .def("SetLevel", &PlaintextImpl::SetLevel, py::arg("level"),
            py::doc("Set the level of the plaintext (the number of levels already consumed)."))
        .def("GetNoiseScaleDeg", &PlaintextImpl::GetNoiseScaleDeg,
            py::doc("Get the degree of the scaling factor for the encoded message."))
        .def("SetNoiseScaleDeg", &PlaintextImpl::SetNoiseScaleDeg, py::arg("noiseScaleDeg"),
            py::doc("Set the degree of the scaling factor for the encoded message."))
        .def("GetSlots", &PlaintextImpl::GetSlots,
            py::doc("Get the number of packed slots."))
        .def("SetSlots", &PlaintextImpl::SetSlots, py::arg("slots"),
            py::doc("Set the number of packed slots."))
        .def("GetLogError", &PlaintextImpl::GetLogError,
            py::doc("Get log2 of the estimated standard deviation of the CKKS approximation error."))
        .def("GetLogPrecision", &PlaintextImpl::GetLogPrecision)
        .def("GetStringValue", &PlaintextImpl::GetStringValue,
            py::doc("Get the plaintext value as a string (STRING encoding)."))
        .def("SetStringValue", &PlaintextImpl::SetStringValue, py::arg("value"),
            py::doc("Set the plaintext value from a string (STRING encoding)."))
        .def("SetIntVectorValue", &PlaintextImpl::SetIntVectorValue, py::arg("value"),
            py::doc("Set the plaintext value from a list of integers (COEF_PACKED or PACKED encoding)."))
        .def("GetFormattedValues", &PlaintextImpl::GetFormattedValues, py::arg("precision"),
            py::doc("Return the plaintext values as a string, with floating-point values printed "
                    "at the given precision."))
        .def("__repr__", [](const PlaintextImpl &p) {
                std::stringstream ss;
                ss << "<Plaintext Object: " << p << ">";
                return ss.str();
            })
        .def("__str__", [](const PlaintextImpl &p) {
                std::stringstream ss;
                ss << p;
                return ss.str();
            });

    // numpy fast paths for decoding
    ptx_class.def("GetRealPackedValueArray",
        [](const PlaintextImpl& self) {
            auto* values = new std::vector<double>(self.GetRealPackedValue());
            py::capsule owner(values, [](void* p) { delete static_cast<std::vector<double>*>(p); });
            return py::array_t<double>(static_cast<py::ssize_t>(values->size()), values->data(), owner);
        },
        py::doc("Get the plaintext value as a 1-D numpy float64 array (CKKS_PACKED encoding). "
                "Equivalent to GetRealPackedValue, but hands the values to numpy without "
                "materializing a Python list."));
    ptx_class.def("GetCKKSPackedValueArray",
        [](const PlaintextImpl& self) {
            auto* values = new std::vector<std::complex<double>>(self.GetCKKSPackedValue());
            py::capsule owner(values, [](void* p) { delete static_cast<std::vector<std::complex<double>>*>(p); });
            return py::array_t<std::complex<double>>(static_cast<py::ssize_t>(values->size()), values->data(), owner);
        },
        py::doc("Get the plaintext value as a 1-D numpy complex128 array (CKKS_PACKED encoding). "
                "Equivalent to GetCKKSPackedValue, but hands the values to numpy without "
                "materializing a Python list."));
    ptx_class.def("GetPackedValueArray",
        [](const PlaintextImpl& self) {
            auto* values = new std::vector<int64_t>(self.GetPackedValue());
            py::capsule owner(values, [](void* p) { delete static_cast<std::vector<int64_t>*>(p); });
            return py::array_t<int64_t>(static_cast<py::ssize_t>(values->size()), values->data(), owner);
        },
        py::doc("Get the plaintext value as a 1-D numpy int64 array (PACKED encoding). "
                "Equivalent to GetPackedValue, but hands the values to numpy without "
                "materializing a Python list."));
    ptx_class.def("GetCoefPackedValueArray",
        [](const PlaintextImpl& self) {
            auto* values = new std::vector<int64_t>(self.GetCoefPackedValue());
            py::capsule owner(values, [](void* p) { delete static_cast<std::vector<int64_t>*>(p); });
            return py::array_t<int64_t>(static_cast<py::ssize_t>(values->size()), values->data(), owner);
        },
        py::doc("Get the plaintext value as a 1-D numpy int64 array (COEF_PACKED encoding). "
                "Equivalent to GetCoefPackedValue, but hands the values to numpy without "
                "materializing a Python list."));
}

void bind_ciphertext(py::module &m) {
    py::class_<CiphertextImpl<DCRTPoly>, std::shared_ptr<CiphertextImpl<DCRTPoly>>>(m, "Ciphertext",
        "Ciphertext of one of the DCRTPoly-based schemes (BFV, BGV, CKKS), produced by "
        "CryptoContext.Encrypt and the homomorphic evaluation methods.")
        .def(py::init<>())
        .def("__add__", [](const Ciphertext<DCRTPoly> &a, const Ciphertext<DCRTPoly> &b) {
                return a + b;
            },
            py::is_operator(), pybind11::keep_alive<0, 1>(),
            py::doc("Homomorphic addition of two ciphertexts: returns a new ciphertext encrypting "
                    "the element-wise sum."), release_gil)
        // .def(py::self + py::self);
        // .def("GetDepth", &CiphertextImpl<DCRTPoly>::GetDepth)
        // .def("SetDepth", &CiphertextImpl<DCRTPoly>::SetDepth)
        .def("GetLevel", &CiphertextImpl<DCRTPoly>::GetLevel, ctx_GetLevel_docs)
        .def("SetLevel", &CiphertextImpl<DCRTPoly>::SetLevel,
            py::arg("level"),
            py::doc(ctx_SetLevel_docs))
        .def("Clone", &CiphertextImpl<DCRTPoly>::Clone,
            py::doc("Return a deep copy of the ciphertext."), release_gil)
        .def("CloneEmpty", &CiphertextImpl<DCRTPoly>::CloneEmpty,
            py::doc(ctx_CloneEmpty_docs))
        .def("NumberCiphertextElements", &CiphertextImpl<DCRTPoly>::NumberCiphertextElements,
            py::doc(ctx_NumberCiphertextElements_docs))
        .def("RemoveElement",
            [](Ciphertext<DCRTPoly>& self, uint32_t index) {
                self->GetElements().erase(self->GetElements().begin() + index);
            },
            py::arg("index"),
            py::doc(cc_RemoveElement_docs))
        .def("GetHopLevel", &CiphertextImpl<DCRTPoly>::GetHopLevel,
            py::doc(ctx_GetHopLevel_docs))
        .def("SetHopLevel", &CiphertextImpl<DCRTPoly>::SetHopLevel, py::arg("hopLevel"),
            py::doc(ctx_SetHopLevel_docs))
        .def("GetScalingFactor", &CiphertextImpl<DCRTPoly>::GetScalingFactor,
            py::doc("Get the CKKS scaling factor of the ciphertext."))
        .def("SetScalingFactor", &CiphertextImpl<DCRTPoly>::SetScalingFactor, py::arg("sf"),
            py::doc("Set the CKKS scaling factor of the ciphertext."))
        .def("GetScalingFactorInt", [](const CiphertextImpl<DCRTPoly>& self) {
                return openfhe_python::IntegerToPyInt(self.GetScalingFactorInt());
            },
            py::doc(ctx_GetScalingFactorInt_docs))
        .def("SetScalingFactorInt", [](CiphertextImpl<DCRTPoly>& self, const py::int_& sf) {
                self.SetScalingFactorInt(openfhe_python::PyIntToInteger<NativeInteger>(sf));
            }, py::arg("sf"),
            py::doc(ctx_SetScalingFactorInt_docs))
        .def("GetSlots", &CiphertextImpl<DCRTPoly>::GetSlots,
            py::doc("Get the number of packed slots."))
        .def("SetSlots", &CiphertextImpl<DCRTPoly>::SetSlots, py::arg("slots"),
            py::doc("Set the number of packed slots."))
        .def("GetNoiseScaleDeg", &CiphertextImpl<DCRTPoly>::GetNoiseScaleDeg,
            py::doc("Get the degree of the scaling factor for the encrypted message."))
        .def("SetNoiseScaleDeg", &CiphertextImpl<DCRTPoly>::SetNoiseScaleDeg, py::arg("noiseScaleDeg"),
            py::doc("Set the degree of the scaling factor for the encrypted message."))
        .def("GetCryptoContext", &CiphertextImpl<DCRTPoly>::GetCryptoContext,
            py::doc("Get the CryptoContext this ciphertext belongs to."))
        .def("GetKeyTag", &CiphertextImpl<DCRTPoly>::GetKeyTag,
            py::doc("Get the tag of the key the ciphertext was encrypted with."))
        .def("GetEncodingType", &CiphertextImpl<DCRTPoly>::GetEncodingType,
            py::doc("Get the plaintext encoding type the ciphertext carries."))
        .def("SetEncodingType", &CiphertextImpl<DCRTPoly>::SetEncodingType, py::arg("encodingType"),
            py::doc(ctx_SetEncodingType_docs))
        .def("SetKeyTag", &CiphertextImpl<DCRTPoly>::SetKeyTag, py::arg("keyTag"),
            py::doc(ctx_SetKeyTag_docs))
        .def("GetElements", [](const CiphertextImpl<DCRTPoly>& self) -> const std::vector<DCRTPoly>& {
                return self.GetElements();
            },
            py::return_value_policy::reference_internal,
            py::doc("Return a copy of the ciphertext's ring elements."))
        .def("GetElementsMutable", [](CiphertextImpl<DCRTPoly>& self) -> std::vector<DCRTPoly>& {
                return self.GetElements();
            },
            py::return_value_policy::reference_internal,
            py::doc("Return a mutable Python list copied from the ciphertext's ring elements; "
                    "call SetElements to apply changes."))
        .def("SetElements", [](CiphertextImpl<DCRTPoly>& self, const std::vector<DCRTPoly>& elems) {
                self.SetElements(elems);
            },
            py::arg("elements"),
            py::doc("Replace the ciphertext's ring elements with the given elements."), release_gil)
        .def("SetElementsMove", [](CiphertextImpl<DCRTPoly>& self, std::vector<DCRTPoly>&& elems) {
                self.SetElements(std::move(elems));
            },
            py::arg("elements"),
            py::doc("Replace the ciphertext's ring elements; the C++ vector converted from the "
                    "given list is moved into the ciphertext, the Python list is not consumed."));
}

void bind_sch_swch_params(py::module &m) {
    py::class_<SchSwchParams>(m, "SchSwchParams",
        "Parameters for switching between CKKS and FHEW/TFHE.\n\n"
        "The getters raise an exception until the object has been populated from a CKKS\n"
        "cryptocontext (see CryptoContext.SetParamsFromCKKSCryptocontext). The initial CKKS\n"
        "modulus, ring dimension, scaling modulus size and batch size are filled in\n"
        "internally during that call and are not intended to be set by users.")
        .def(py::init<>())
        .def("GetSecurityLevelCKKS", &SchSwchParams::GetSecurityLevelCKKS,
            py::doc("Get the security level of the CKKS cryptocontext."))
        .def("GetSecurityLevelFHEW", &SchSwchParams::GetSecurityLevelFHEW,
            py::doc("Get the security level of the FHEW cryptocontext."))
        .def("GetArbitraryFunctionEvaluation", &SchSwchParams::GetArbitraryFunctionEvaluation,
            py::doc("Get whether arbitrary function evaluation is needed in FHEW."))
        .def("GetUseDynamicModeFHEW", &SchSwchParams::GetUseDynamicModeFHEW,
            py::doc("Get whether the dynamic mode is used in FHEW."))
        .def("GetComputeArgmin", &SchSwchParams::GetComputeArgmin,
            py::doc("Get whether argmin is computed."))
        .def("GetOneHotEncoding", &SchSwchParams::GetOneHotEncoding,
            py::doc("Get whether the argmin result is one-hot encoded."))
        .def("GetUseAltArgmin", &SchSwchParams::GetUseAltArgmin,
            py::doc("Get whether the alternative argmin method is used."))
        .def("GetNumSlotsCKKS", &SchSwchParams::GetNumSlotsCKKS,
            py::doc("Get the number of CKKS slots to switch."))
        .def("GetNumValues", &SchSwchParams::GetNumValues,
            py::doc("Get the number of values used in argmin computations."))
        .def("GetCtxtModSizeFHEWLargePrec", &SchSwchParams::GetCtxtModSizeFHEWLargePrec,
            py::doc("Get the FHEW ciphertext modulus size for large-precision evaluation."))
        .def("GetCtxtModSizeFHEWIntermedSwch", &SchSwchParams::GetCtxtModSizeFHEWIntermedSwch,
            py::doc("Get the FHEW ciphertext modulus size for the intermediate switching."))
        .def("GetBStepLTrCKKStoFHEW", &SchSwchParams::GetBStepLTrCKKStoFHEW,
            py::doc("Get the baby step of the CKKS-to-FHEW linear transform."))
        .def("GetBStepLTrFHEWtoCKKS", &SchSwchParams::GetBStepLTrFHEWtoCKKS,
            py::doc("Get the baby step of the FHEW-to-CKKS linear transform."))
        .def("GetLevelLTrCKKStoFHEW", &SchSwchParams::GetLevelLTrCKKStoFHEW,
            py::doc("Get the level of the CKKS-to-FHEW linear transform."))
        .def("GetLevelLTrFHEWtoCKKS", &SchSwchParams::GetLevelLTrFHEWtoCKKS,
            py::doc("Get the level of the FHEW-to-CKKS linear transform."))
        .def("GetInitialCKKSModulus", &SchSwchParams::GetInitialCKKSModulus,
            py::doc("Get the initial CKKS modulus (the value itself, not its bit size)."))
        .def("GetRingDimension", &SchSwchParams::GetRingDimension,
            py::doc("Get the CKKS ring dimension."))
        .def("GetScalingModSize", &SchSwchParams::GetScalingModSize,
            py::doc("Get the CKKS scaling modulus size."))
        .def("GetBatchSize", &SchSwchParams::GetBatchSize,
            py::doc("Get the CKKS batch size."))
        .def("SetSecurityLevelCKKS", &SchSwchParams::SetSecurityLevelCKKS, py::arg("securityLevelCKKS"),
            py::doc("Set the security level of the CKKS cryptocontext."))
        .def("SetSecurityLevelFHEW", &SchSwchParams::SetSecurityLevelFHEW, py::arg("securityLevelFHEW"),
            py::doc("Set the security level of the FHEW cryptocontext."))
        .def("SetArbitraryFunctionEvaluation", &SchSwchParams::SetArbitraryFunctionEvaluation, py::arg("arbitraryFunctionEvaluation"),
            py::doc("Set whether arbitrary function evaluation is needed in FHEW."))
        .def("SetUseDynamicModeFHEW", &SchSwchParams::SetUseDynamicModeFHEW, py::arg("useDynamicModeFHEW"),
            py::doc("Set whether the dynamic mode is used in FHEW."))
        .def("SetComputeArgmin", &SchSwchParams::SetComputeArgmin, py::arg("computeArgmin"),
            py::doc("Set whether argmin is computed."))
        .def("SetOneHotEncoding", &SchSwchParams::SetOneHotEncoding, py::arg("oneHotEncoding"),
            py::doc("Set whether the argmin result is one-hot encoded."))
        .def("SetUseAltArgmin", &SchSwchParams::SetUseAltArgmin, py::arg("useAltArgmin"),
            py::doc("Set whether the alternative argmin method is used."))
        .def("SetNumSlotsCKKS", &SchSwchParams::SetNumSlotsCKKS, py::arg("numSlotsCKKS"),
            py::doc("Set the number of CKKS slots to switch."))
        .def("SetNumValues", &SchSwchParams::SetNumValues, py::arg("numValues"),
            py::doc("Set the number of values used in argmin computations."))
        .def("SetCtxtModSizeFHEWLargePrec", &SchSwchParams::SetCtxtModSizeFHEWLargePrec, py::arg("ctxtModSizeFHEWLargePrec"),
            py::doc("Set the FHEW ciphertext modulus size for large-precision evaluation."))
        .def("SetCtxtModSizeFHEWIntermedSwch", &SchSwchParams::SetCtxtModSizeFHEWIntermedSwch, py::arg("ctxtModSizeFHEWIntermedSwch"),
            py::doc("Set the FHEW ciphertext modulus size for the intermediate switching."))
        .def("SetBStepLTrCKKStoFHEW", &SchSwchParams::SetBStepLTrCKKStoFHEW, py::arg("bStepLTrCKKStoFHEW"),
            py::doc("Set the baby step of the CKKS-to-FHEW linear transform."))
        .def("SetBStepLTrFHEWtoCKKS", &SchSwchParams::SetBStepLTrFHEWtoCKKS, py::arg("bStepLTrFHEWtoCKKS"),
            py::doc("Set the baby step of the FHEW-to-CKKS linear transform."))
        .def("SetLevelLTrCKKStoFHEW", &SchSwchParams::SetLevelLTrCKKStoFHEW, py::arg("levelLTrCKKStoFHEW"),
            py::doc("Set the level of the CKKS-to-FHEW linear transform."))
        .def("SetLevelLTrFHEWtoCKKS", &SchSwchParams::SetLevelLTrFHEWtoCKKS, py::arg("levelLTrFHEWtoCKKS"),
            py::doc("Set the level of the FHEW-to-CKKS linear transform."))
        .def("SetInitialCKKSModulus", &SchSwchParams::SetInitialCKKSModulus, py::arg("initialCKKSModulus"),
            py::doc("Set the initial CKKS modulus (populated internally from the CKKS cryptocontext; "
                    "not intended for user configuration)."))
        .def("SetRingDimension", &SchSwchParams::SetRingDimension, py::arg("ringDimension"),
            py::doc("Set the CKKS ring dimension (populated internally from the CKKS cryptocontext; "
                    "not intended for user configuration)."))
        .def("SetScalingModSize", &SchSwchParams::SetScalingModSize, py::arg("scalingModSize"),
            py::doc("Set the CKKS scaling modulus size (populated internally from the CKKS cryptocontext; "
                    "not intended for user configuration)."))
        .def("SetBatchSize", &SchSwchParams::SetBatchSize, py::arg("batchSize"),
            py::doc("Set the CKKS batch size (populated internally from the CKKS cryptocontext; "
                    "not intended for user configuration)."))
        .def("SetParamsFromCKKSCryptocontextCalled", &SchSwchParams::SetParamsFromCKKSCryptocontextCalled,
            py::doc(schswchparams_SetParamsFromCKKSCryptocontextCalled_docs))
        .def("__str__", [](const SchSwchParams &params) {
                std::stringstream stream;
                stream << params;
                return stream.str();
            });
}

void bind_utils(py::module& m) {
    m.def("EnablePrecomputeCRTTablesAfterDeserializaton", &EnablePrecomputeCRTTablesAfterDeserializaton,
          py::doc(utils_EnablePrecomputeCRTTablesAfterDeserializaton_docs));
    m.def("DisablePrecomputeCRTTablesAfterDeserializaton", &DisablePrecomputeCRTTablesAfterDeserializaton,
          py::doc(utils_DisablePrecomputeCRTTablesAfterDeserializaton_docs));
}

void bind_free_functions(py::module& m) {
    m.def("EvalChebyshevCoefficients", &EvalChebyshevCoefficients,
          py::arg("func"),
          py::arg("a"),
          py::arg("b"),
          py::arg("degree"),
          py::doc("Compute the Chebyshev coefficients of the given degree approximating the function "
                  "func over [a, b]: f(x) ~ coeffs[0]/2 + sum_{i>=1} coeffs[i]*T_i(x), where T_i are "
                  "Chebyshev polynomials of the first kind (note that the first coefficient is "
                  "divided by two). The coefficients are used by EvalChebyshevSeries."));
    m.def("EvalChebyshevFunctionPtxt", &EvalChebyshevFunctionPtxt,
          py::arg("func"),
          py::arg("ptxt"),
          py::arg("a"),
          py::arg("b"),
          py::arg("degree"),
          py::doc("Cleartext version of CryptoContext.EvalChebyshevFunction: evaluate the Chebyshev "
                  "approximation of func of the given degree over [a, b] on each of the plaintext "
                  "inputs and return the results."));
}

#ifndef OPENFHE_PYTHON_VERSION_STR
    #define OPENFHE_PYTHON_VERSION_STR "unknown"
#endif

PYBIND11_MODULE(openfhe, m) {
    // numpy is a required runtime dependency (see requirements.txt): the numpy
    // bindings load it lazily on first use, which would surface a missing install
    // as a confusing mid-computation error. Import it eagerly so the failure
    // happens here, with a message that names the fix.
    try {
        py::module_::import("numpy");
    } catch (const py::error_already_set&) {
        throw py::import_error(
            "the openfhe module requires numpy (see requirements.txt): pip install numpy");
    }
    // sequence of function calls matters
    m.doc() = "Open-Source Fully Homomorphic Encryption Library";
    m.attr("__version__") = OPENFHE_PYTHON_VERSION_STR;
    bind_DCRTPoly(m);
    // binfhe library
    bind_binfhe_enums(m);
    bind_binfhe_ciphertext(m);
    bind_binfhe_keys(m);
    bind_binfhe_context(m);
    bind_binfhe_serialization(m);
    // pke library
    bind_enums_and_constants(m);
    bind_parameters<CryptoContextBFVRNS>(m,"CCParamsBFVRNS");
    bind_parameters<CryptoContextBGVRNS>(m,"CCParamsBGVRNS");
    bind_parameters<CryptoContextCKKSRNS>(m,"CCParamsCKKSRNS");
    bind_encodings(m);
    bind_ciphertext(m);
    bind_keys(m);
    bind_crypto_context(m);
    bind_serialization(m);
    bind_sch_swch_params(m);
    bind_fbt(m);
    bind_utils(m);
    bind_free_functions(m);
}
