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

#include "openfhe.h"

#include "key/key-ser.h"
#include "binfhe_bindings.h"

#include <pybind11/stl.h>
#include <pybind11/stl_bind.h>
#include <pybind11/complex.h>
#include <pybind11/functional.h>
#include <pybind11/iostream.h>


#include "cryptocontext_docs.h"
#include "cryptoparameters_docs.h"
#include "plaintext_docs.h"
#include "ciphertext_docs.h"

using namespace lbcrypto;
namespace py = pybind11;

// disable the PYBIND11 template-based conversion for this type
PYBIND11_MAKE_OPAQUE(std::map<uint32_t, EvalKey<DCRTPoly>>);

inline std::shared_ptr<CryptoParametersRNS> GetParamsRNSChecked(const CryptoContext<DCRTPoly>& self, const std::string& func) {
    auto ptr = std::dynamic_pointer_cast<CryptoParametersRNS>(self->GetCryptoParameters());
    if (!ptr)
        OPENFHE_THROW("Failed to cast to CryptoParametersRNS in " + func + "()");
    return ptr;
}

void bind_DCRTPoly(py::module &m) {
  py::class_<DCRTPoly>(m, "DCRTPoly").def(py::init<>());
}

template <typename T>
void bind_parameters(py::module &m, const std::string name) {
    py::class_<CCParams<T>>(m, name.c_str())
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
        //.def("GetThresholdNumOfParties", &CCParams<T>::GetThresholdNumOfParties)
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
        .def("GetPRENumHops", &CCParams<T>::GetPRENumHops)
        .def("GetInteractiveBootCompressionLevel", &CCParams<T>::GetInteractiveBootCompressionLevel)
        .def("GetCompositeDegree", &CCParams<T>::GetCompositeDegree)
        .def("GetRegisterWordSize", &CCParams<T>::GetRegisterWordSize)
        .def("GetCKKSDataType", &CCParams<T>::GetCKKSDataType)
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
        .def("SetPRENumHops", &CCParams<T>::SetPRENumHops)
        .def("SetInteractiveBootCompressionLevel", &CCParams<T>::SetInteractiveBootCompressionLevel)
        .def("SetCompositeDegree", &CCParams<T>::SetCompositeDegree)
        .def("SetRegisterWordSize", &CCParams<T>::SetRegisterWordSize)
        .def("SetCKKSDataType", &CCParams<T>::SetCKKSDataType)
        .def("__str__",[](const CCParams<T> &params) {
            std::stringstream stream;
            stream << params;
            return stream.str();
        });
}

template <typename T>
void bind_crypto_context_templates(py::class_<CryptoContextImpl<DCRTPoly>, std::shared_ptr<CryptoContextImpl<DCRTPoly>>>& cls) {
    cls.def("EvalChebyshevSeries",
            static_cast<Ciphertext<DCRTPoly> (CryptoContextImpl<DCRTPoly>::*)(
                ConstCiphertext<DCRTPoly>&,
                const std::vector<T>&,
                double,
                double
            ) const>(&CryptoContextImpl<DCRTPoly>::EvalChebyshevSeries),
            py::arg("ciphertext"),
            py::arg("coefficients"),
            py::arg("a"),
            py::arg("b"),
            py::doc(cc_EvalChebyshevSeries_docs))
        .def("EvalChebyshevSeriesLinear",
            static_cast<Ciphertext<DCRTPoly> (CryptoContextImpl<DCRTPoly>::*)(
                ConstCiphertext<DCRTPoly>&,
                const std::vector<T>&,
                double,
                double
            ) const>(&CryptoContextImpl<DCRTPoly>::EvalChebyshevSeriesLinear),
            py::arg("ciphertext"),
            py::arg("coefficients"),
            py::arg("a"),
            py::arg("b"),
            py::doc(cc_EvalChebyshevSeriesLinear_docs))
        .def("EvalChebyshevSeriesPS",
            static_cast<Ciphertext<DCRTPoly> (CryptoContextImpl<DCRTPoly>::*)(
                ConstCiphertext<DCRTPoly>&,
                const std::vector<T>&,
                double,
                double
            ) const>(&CryptoContextImpl<DCRTPoly>::EvalChebyshevSeriesPS),
            py::arg("ciphertext"),
            py::arg("coefficients"),
            py::arg("a"),
            py::arg("b"),
            py::doc(cc_EvalChebyshevSeriesPS_docs))
        .def("EvalLinearWSum",
            static_cast<Ciphertext<DCRTPoly> (CryptoContextImpl<DCRTPoly>::*)(
                std::vector<ReadOnlyCiphertext<DCRTPoly>>&,
                const std::vector<T>&
            ) const>(&CryptoContextImpl<DCRTPoly>::EvalLinearWSum),
            py::arg("ciphertextVec"),
            py::arg("constantVec"),
            py::doc("Evaluate a weighted sum of ciphertexts using scalar coefficients"))
        .def("EvalLinearWSumMutable",
            static_cast<Ciphertext<DCRTPoly> (CryptoContextImpl<DCRTPoly>::*)(
                const std::vector<T>&,
                std::vector<Ciphertext<DCRTPoly>>&
            ) const>(&CryptoContextImpl<DCRTPoly>::EvalLinearWSumMutable),
            py::arg("constantsVec"),
            py::arg("ciphertextVec"),
            py::doc("Evaluate a weighted sum (mutable version) with given coefficients"))
        .def("EvalPoly",
            static_cast<Ciphertext<DCRTPoly> (CryptoContextImpl<DCRTPoly>::*)(
                ConstCiphertext<DCRTPoly>&,
                const std::vector<T>&
            ) const>(&CryptoContextImpl<DCRTPoly>::EvalPoly),
            py::arg("ciphertext"),
            py::arg("coefficients"),
            py::doc(cc_EvalPoly_docs))
        .def("EvalPolyLinear",
            static_cast<Ciphertext<DCRTPoly> (CryptoContextImpl<DCRTPoly>::*)(
                ConstCiphertext<DCRTPoly>&,
                const std::vector<T>&
            ) const>(&CryptoContextImpl<DCRTPoly>::EvalPolyLinear),
            py::arg("ciphertext"),
            py::arg("coefficients"),
            py::doc(cc_EvalPolyLinear_docs))
        .def("EvalPolyPS",
            static_cast<Ciphertext<DCRTPoly> (CryptoContextImpl<DCRTPoly>::*)(
                ConstCiphertext<DCRTPoly>&,
                const std::vector<T>&
            ) const>(&CryptoContextImpl<DCRTPoly>::EvalPolyPS),
            py::arg("ciphertext"),
            py::arg("coefficients"),
            py::doc(cc_EvalPolyPS_docs))
    ;
}

void bind_crypto_context(py::module &m) {
    //Parameters Type
    // TODO (Oliveira): If we expose Poly's and ParmType, this block will go somewhere else
    using ParmType = typename DCRTPoly::Params;
    using ParmTypePtr = std::shared_ptr<ParmType>;
    py::class_<ParmType, ParmTypePtr>(m, "ParmType");

    auto cc_class = py::class_<CryptoContextImpl<DCRTPoly>, std::shared_ptr<CryptoContextImpl<DCRTPoly>>>(m, "CryptoContext");

    cc_class.def(py::init<>())
        .def("GetKeyGenLevel", &CryptoContextImpl<DCRTPoly>::GetKeyGenLevel, cc_GetKeyGenLevel_docs)
        .def("SetKeyGenLevel", &CryptoContextImpl<DCRTPoly>::SetKeyGenLevel,
            py::arg("level"),
            py::doc(cc_SetKeyGenLevel_docs))
        .def("get_ptr",[](const CryptoContext<DCRTPoly> &self) {
            std::cout << "CC shared ptr (python cc)" << self << std::endl; })
        .def("GetRingDimension", &CryptoContextImpl<DCRTPoly>::GetRingDimension, cc_GetRingDimension_docs)
        .def("GetPlaintextModulus",
            [](CryptoContext<DCRTPoly>& self) {
                return self->GetCryptoParameters()->GetPlaintextModulus();
            },
            py::doc(cc_GetPlaintextModulus_docs))
        .def("GetBatchSize",
            [](CryptoContext<DCRTPoly>& self) {
                return self->GetCryptoParameters()->GetBatchSize();
            })
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
            })
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
            })
        .def("GetDigitSize",
            [](CryptoContext<DCRTPoly>& self) {
                return self->GetCryptoParameters()->GetDigitSize();
            })
        .def("GetCyclotomicOrder", &CryptoContextImpl<DCRTPoly>::GetCyclotomicOrder, cc_GetCyclotomicOrder_docs)
        .def("GetCKKSDataType", &CryptoContextImpl<DCRTPoly>::GetCKKSDataType)
        .def("GetNoiseEstimate", [](CryptoContext<DCRTPoly>& self) {
            return GetParamsRNSChecked(self, "GetNoiseEstimate")->GetNoiseEstimate();
        })
        .def("SetNoiseEstimate", [](CryptoContext<DCRTPoly>& self, double noiseEstimate) {
            GetParamsRNSChecked(self, "SetNoiseEstimate")->SetNoiseEstimate(noiseEstimate);
            },
            py::arg("noiseEstimate"))
        .def("GetMultiplicativeDepth", [](CryptoContext<DCRTPoly>& self) {
            return GetParamsRNSChecked(self, "GetMultiplicativeDepth")->GetMultiplicativeDepth();
        })
        .def("SetMultiplicativeDepth", [](CryptoContext<DCRTPoly>& self, uint32_t multiplicativeDepth) {
            GetParamsRNSChecked(self, "SetMultiplicativeDepth")->SetMultiplicativeDepth(multiplicativeDepth);
            },
            py::arg("multiplicativeDepth"))
        .def("GetEvalAddCount", [](CryptoContext<DCRTPoly>& self) {
            return GetParamsRNSChecked(self, "GetEvalAddCount")->GetEvalAddCount();
        })
        .def("SetEvalAddCount", [](CryptoContext<DCRTPoly>& self, uint32_t evalAddCount) {
            GetParamsRNSChecked(self, "SetEvalAddCount")->SetEvalAddCount(evalAddCount);
            },
            py::arg("evalAddCount"))
        .def("GetKeySwitchCount", [](CryptoContext<DCRTPoly>& self) {
                return GetParamsRNSChecked(self, "GetKeySwitchCount")->GetKeySwitchCount();
            })
        .def("SetKeySwitchCount", [](CryptoContext<DCRTPoly>& self, uint32_t keySwitchCount) {
                GetParamsRNSChecked(self, "SetKeySwitchCount")->SetKeySwitchCount(keySwitchCount);
            },
            py::arg("keySwitchCount"))
        .def("GetPRENumHops", [](CryptoContext<DCRTPoly>& self) {
                return GetParamsRNSChecked(self, "GetPRENumHops")->GetPRENumHops();
            })
        .def("SetPRENumHops", [](CryptoContext<DCRTPoly>& self, uint32_t PRENumHops) {
                GetParamsRNSChecked(self, "SetPRENumHops")->SetPRENumHops(PRENumHops);
            },
            py::arg("PRENumHops"))
        .def("GetRegisterWordSize", [](CryptoContext<DCRTPoly>& self) {
                return GetParamsRNSChecked(self, "GetRegisterWordSize")->GetRegisterWordSize();
            })
        .def("GetCompositeDegree", [](CryptoContext<DCRTPoly>& self) {
                return GetParamsRNSChecked(self, "GetCompositeDegree")->GetCompositeDegree();
            })
        .def("Enable", py::overload_cast<PKESchemeFeature>(&CryptoContextImpl<DCRTPoly>::Enable),
            py::arg("feature"),
            py::doc(cc_Enable_docs))
        .def("KeyGen", &CryptoContextImpl<DCRTPoly>::KeyGen, cc_KeyGen_docs)
        .def("EvalMultKeyGen", &CryptoContextImpl<DCRTPoly>::EvalMultKeyGen,
            py::arg("privateKey"),
            py::doc(cc_EvalMultKeyGen_docs))
        .def("EvalMultKeysGen", &CryptoContextImpl<DCRTPoly>::EvalMultKeysGen,
            py::arg("privateKey"),
            py::doc(cc_EvalMultKeysGen_docs))
        .def("EvalRotateKeyGen", &CryptoContextImpl<DCRTPoly>::EvalRotateKeyGen,
            py::arg("privateKey"),
            py::arg("indexList"),
            py::arg("publicKey") = py::none(),
            py::doc(cc_EvalRotateKeyGen_docs))
        .def("MakeStringPlaintext", &CryptoContextImpl<DCRTPoly>::MakeStringPlaintext,
            py::arg("str"),
            py::doc(cc_MakeStringPlaintext_docs))
        .def("MakePackedPlaintext", &CryptoContextImpl<DCRTPoly>::MakePackedPlaintext,
            py::arg("value"),
            py::arg("noiseScaleDeg") = 1,
            py::arg("level") = 0,
            py::doc(cc_MakePackedPlaintext_docs))
        .def("MakeCoefPackedPlaintext", &CryptoContextImpl<DCRTPoly>::MakeCoefPackedPlaintext,
            py::arg("value"),
            py::arg("noiseScaleDeg ") = 1,
            py::arg("level") = 0,
            py::doc(cc_MakeCoefPackedPlaintext_docs))
        // TODO (Oliveira): allow user to specify different params values
        .def("MakeCKKSPackedPlaintext",
            py::overload_cast<
                const std::vector<std::complex<double>>&, size_t, uint32_t,
                const std::shared_ptr<ParmType>, uint32_t
            >(&CryptoContextImpl<DCRTPoly>::MakeCKKSPackedPlaintext, py::const_),
            py::arg("value"),
            py::arg("noiseScaleDeg") = 1,
            py::arg("level") = 0,
            py::arg("params") = py::none(),
            py::arg("slots") = 0,
            py::doc(cc_MakeCKKSPackedPlaintextComplex_docs))
        .def("MakeCKKSPackedPlaintext",
            py::overload_cast<
                const std::vector<double>&, size_t, uint32_t,
                const std::shared_ptr<ParmType>, uint32_t
            >(&CryptoContextImpl<DCRTPoly>::MakeCKKSPackedPlaintext, py::const_),
            py::arg("value"),
            py::arg("noiseScaleDeg") = 1,
            py::arg("level") = 0,
            py::arg("params") = py::none(),
            py::arg("slots") = 0,
            py::doc(cc_MakeCKKSPlaintextReal_docs))
        .def("EvalRotate", &CryptoContextImpl<DCRTPoly>::EvalRotate,
            py::arg("ciphertext"),
            py::arg("index"),
            py::doc(cc_EvalRotate_docs))
        .def("EvalFastRotationPrecompute",
            [](CryptoContext<DCRTPoly>& self, ConstCiphertext<DCRTPoly> ciphertext) {
                auto precomp = self->EvalFastRotationPrecompute(ciphertext);
                auto cipherdigits = std::make_shared<CiphertextImpl<DCRTPoly>>(self);
                cipherdigits->SetElements(*precomp);
                return cipherdigits;
            },
            py::arg("ciphertext"),
            py::doc(cc_EvalFastRotationPreCompute_docs))
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
            py::doc(cc_EvalFastRotation_docs))
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
            py::arg("publicKey") = py::none(),
            py::doc(cc_EvalAtIndexKeyGen_docs))
        .def("EvalAtIndex", &CryptoContextImpl<DCRTPoly>::EvalAtIndex,
            py::arg("ciphertext"),
            py::arg("index"),
            py::doc(cc_EvalAtIndex_docs))
        .def("Encrypt",
            py::overload_cast<const PublicKey<DCRTPoly>&, ConstPlaintext&>(&CryptoContextImpl<DCRTPoly>::Encrypt, py::const_),
            py::arg("publicKey"),
            py::arg("plaintext"),
            py::doc(cc_Encrypt_docs))
        .def("Decrypt",
            [](CryptoContext<DCRTPoly>& self, const PrivateKey<DCRTPoly> privKey, ConstCiphertext<DCRTPoly> ct) {
                Plaintext result;
                self->Decrypt(privKey, ct, &result);
                return result;
            },
            py::arg("privateKey"),
            py::arg("ciphertext"),
            py::doc(cc_Decrypt_docs))
        .def("Decrypt",
            [](CryptoContext<DCRTPoly>& self, ConstCiphertext<DCRTPoly> ct, const PrivateKey<DCRTPoly> privKey) {
                Plaintext result;
                self->Decrypt(privKey, ct, &result);
                return result;
            },
            py::arg("ciphertext"),
            py::arg("privateKey"),
            py::doc(cc_Decrypt_docs))
        .def("KeySwitchGen", &CryptoContextImpl<DCRTPoly>::KeySwitchGen,
            py::arg("oldPrivateKey"),
            py::arg("newPrivateKey"),
            py::doc(cc_KeySwitchGen_docs))
        .def("EvalAdd",
            py::overload_cast<ConstCiphertext<DCRTPoly>&, ConstCiphertext<DCRTPoly>&>(&CryptoContextImpl<DCRTPoly>::EvalAdd, py::const_),
            py::arg("ciphertext1"),
            py::arg("ciphertext2"),
            py::doc(cc_EvalAdd_docs))
        .def("EvalAdd",
            py::overload_cast<ConstCiphertext<DCRTPoly>&, double>(&CryptoContextImpl<DCRTPoly>::EvalAdd, py::const_),
            py::arg("ciphertext"),
            py::arg("scalar"),
            py::doc(cc_EvalAddfloat_docs))
        .def("EvalAdd",
            py::overload_cast<ConstCiphertext<DCRTPoly>&, Plaintext&>(&CryptoContextImpl<DCRTPoly>::EvalAdd, py::const_),
            py::arg("ciphertext"),
            py::arg("plaintext"),
            py::doc(cc_EvalAddPlaintext_docs))
        .def("EvalAddInPlace",
            py::overload_cast<Ciphertext<DCRTPoly>&, ConstCiphertext<DCRTPoly>&>(&CryptoContextImpl<DCRTPoly>::EvalAddInPlace, py::const_),
            py::arg("ciphertext1"),
            py::arg("ciphertext2"),
            py::doc(cc_EvalAddInPlace_docs))
        .def("EvalAddInPlace",
            py::overload_cast<Ciphertext<DCRTPoly>&, Plaintext&>(&CryptoContextImpl<DCRTPoly>::EvalAddInPlace, py::const_),
            py::arg("ciphertext"),
            py::arg("plaintext"),
            py::doc(cc_EvalAddInPlacePlaintext_docs))
        .def("EvalAddInPlace",
            py::overload_cast<Plaintext&, Ciphertext<DCRTPoly>&>(&CryptoContextImpl<DCRTPoly>::EvalAddInPlace, py::const_),
            py::arg("plaintext"),
            py::arg("ciphertext"),
            py::doc(""))  // TODO (dsuponit): replace this with an actual docstring
        .def("EvalAddInPlace",
            py::overload_cast<Ciphertext<DCRTPoly>&, double>(&CryptoContextImpl<DCRTPoly>::EvalAddInPlace, py::const_),
            py::arg("ciphertext"),
            py::arg("scalar"),
            py::doc(""))  // TODO (dsuponit): replace this with an actual docstring
        .def("EvalAddInPlace",
            py::overload_cast<double, Ciphertext<DCRTPoly>&>(&CryptoContextImpl<DCRTPoly>::EvalAddInPlace, py::const_),
            py::arg("scalar"),
            py::arg("ciphertext"),
            py::doc(""))  // TODO (dsuponit): replace this with an actual docstring
        .def("EvalAddMutable",
            py::overload_cast<Ciphertext<DCRTPoly>&, Ciphertext<DCRTPoly>&>(&CryptoContextImpl<DCRTPoly>::EvalAddMutable, py::const_),
            py::arg("ciphertext1"),
            py::arg("ciphertext2"),
            py::doc(cc_EvalAddMutable_docs))
        .def("EvalAddMutable",
            py::overload_cast<Ciphertext<DCRTPoly>&, Plaintext&>(&CryptoContextImpl<DCRTPoly>::EvalAddMutable, py::const_),
            py::arg("ciphertext"),
            py::arg("plaintext"),
            py::doc(cc_EvalAddMutablePlaintext_docs))
        .def("EvalAddMutable", py::overload_cast<Plaintext&, Ciphertext<DCRTPoly>&>(&CryptoContextImpl<DCRTPoly>::EvalAddMutable, py::const_),
            py::arg("plaintext"),
            py::arg("ciphertext"),
            py::doc(""))  // TODO (dsuponit): replace this with an actual docstring
        .def("EvalAddMutableInPlace", &CryptoContextImpl<DCRTPoly>::EvalAddMutableInPlace,
            py::arg("ciphertext1"),
            py::arg("ciphertext2"),
            py::doc(cc_EvalAddMutableInPlace_docs))
        .def("EvalSub",
            py::overload_cast<ConstCiphertext<DCRTPoly>&, ConstCiphertext<DCRTPoly>&>(&CryptoContextImpl<DCRTPoly>::EvalSub, py::const_),
            py::arg("ciphertext1"),
            py::arg("ciphertext2"),
            py::doc(cc_EvalSub_docs))
        .def("EvalSub",
            py::overload_cast<ConstCiphertext<DCRTPoly>&, double>(&CryptoContextImpl<DCRTPoly>::EvalSub, py::const_),
            py::arg("ciphertext"),
            py::arg("scalar"),
            py::doc(cc_EvalSubfloat_docs))
        .def("EvalSub",
            py::overload_cast<double, ConstCiphertext<DCRTPoly>&>(&CryptoContextImpl<DCRTPoly>::EvalSub, py::const_),
            py::arg("scalar"),
            py::arg("ciphertext"),
            py::doc(""))  // TODO (dsuponit): replace this with an actual docstring
        .def("EvalSub",
            py::overload_cast<ConstCiphertext<DCRTPoly>&, Plaintext&>(&CryptoContextImpl<DCRTPoly>::EvalSub, py::const_),
            py::arg("ciphertext"),
            py::arg("plaintext"),
            py::doc(cc_EvalSubPlaintext_docs))
        .def("EvalSub",
            py::overload_cast<Plaintext&, ConstCiphertext<DCRTPoly>&>(&CryptoContextImpl<DCRTPoly>::EvalSub, py::const_),
            py::arg("plaintext"),
            py::arg("ciphertext"),
            py::doc(""))  // TODO (dsuponit): replace this with an actual docstring
        .def("EvalSubInPlace",
            py::overload_cast<Ciphertext<DCRTPoly>&, ConstCiphertext<DCRTPoly>&>(&CryptoContextImpl<DCRTPoly>::EvalSubInPlace, py::const_),
            py::arg("ciphertext1"),
            py::arg("ciphertext2"),
            py::doc(cc_EvalSubInPlace_docs))
        .def("EvalSubInPlace",
            py::overload_cast<Ciphertext<DCRTPoly>&, double>(&CryptoContextImpl<DCRTPoly>::EvalSubInPlace, py::const_),
            py::arg("ciphertext"),
            py::arg("scalar"),
            py::doc(cc_EvalSubInPlacefloat_docs))
        .def("EvalSubInPlace",
            py::overload_cast<double, Ciphertext<DCRTPoly>&>(&CryptoContextImpl<DCRTPoly>::EvalSubInPlace, py::const_),
            py::arg("scalar"),
            py::arg("ciphertext"),
            py::doc(""))  // TODO (dsuponit): replace this with an actual docstring
        .def("EvalSubInPlace",
            py::overload_cast<Ciphertext<DCRTPoly>&, ConstPlaintext&>(
                &CryptoContextImpl<DCRTPoly>::EvalSubInPlace, py::const_),
            py::arg("ciphertext"),
            py::arg("plaintext"),
            py::doc(""))  // TODO (dsuponit): replace this with an actual docstring
        .def("EvalSubInPlace",
            py::overload_cast<Plaintext&, Ciphertext<DCRTPoly>&>(
                &CryptoContextImpl<DCRTPoly>::EvalSubInPlace, py::const_),
            py::arg("plaintext"),
            py::arg("ciphertext"),
            py::doc(""))  // TODO (dsuponit): replace this with an actual docstring
        .def("EvalSubMutable",
            py::overload_cast<Ciphertext<DCRTPoly>&, Ciphertext<DCRTPoly>&>(&CryptoContextImpl<DCRTPoly>::EvalSubMutable, py::const_),
            py::arg("ciphertext1"),
            py::arg("ciphertext2"),
            py::doc(cc_EvalSubMutable_docs))
        .def("EvalSubMutable",
            py::overload_cast<Ciphertext<DCRTPoly>&,Plaintext&>(&CryptoContextImpl<DCRTPoly>::EvalSubMutable, py::const_),
            py::arg("ciphertext"),
            py::arg("plaintext"),
            py::doc(cc_EvalSubMutablePlaintext_docs))
        .def("EvalSubMutable",
            py::overload_cast<Plaintext&, Ciphertext<DCRTPoly>&>(&CryptoContextImpl<DCRTPoly>::EvalSubMutable, py::const_),
            py::arg("plaintext"),
            py::arg("ciphertext"),
            py::doc(""))  // TODO (dsuponit): replace this with an actual docstring
        .def("EvalSubMutableInPlace", &CryptoContextImpl<DCRTPoly>::EvalSubMutableInPlace,
            py::arg("ciphertext1"),
            py::arg("ciphertext2"),
            py::doc(cc_EvalSubMutableInPlace_docs))
        .def("EvalMult",
            py::overload_cast<ConstCiphertext<DCRTPoly>&, ConstCiphertext<DCRTPoly>&>(&CryptoContextImpl<DCRTPoly>::EvalMult, py::const_),
            py::arg("ciphertext1"),
            py::arg("ciphertext2"),
            py::doc(cc_EvalMult_docs))
        .def("EvalMult",
            py::overload_cast<ConstCiphertext<DCRTPoly>&, double>(&CryptoContextImpl<DCRTPoly>::EvalMult, py::const_),
            py::arg("ciphertext"),
            py::arg("scalar"),
            py::doc(cc_EvalMultfloat_docs))
        .def("EvalMult",
            py::overload_cast<ConstCiphertext<DCRTPoly>&, ConstPlaintext&>(&CryptoContextImpl<DCRTPoly>::EvalMult, py::const_),
            py::arg("ciphertext"),
            py::arg("plaintext"),
            py::doc(cc_EvalMultPlaintext_docs))
        .def("EvalMult",
            py::overload_cast<ConstPlaintext&, ConstCiphertext<DCRTPoly>&>(&CryptoContextImpl<DCRTPoly>::EvalMult, py::const_),
            py::arg("plaintext"),
            py::arg("ciphertext"),
            py::doc(""))  // TODO (dsuponit): replace this with an actual docstring
        .def("EvalMult",
            py::overload_cast<double, ConstCiphertext<DCRTPoly>&>(&CryptoContextImpl<DCRTPoly>::EvalMult, py::const_),
            py::arg("scalar"),
            py::arg("ciphertext"),
            py::doc(""))  // TODO (dsuponit): replace this with an actual docstring
        .def("EvalMultMutable",
            py::overload_cast<Ciphertext<DCRTPoly>&, Ciphertext<DCRTPoly>&>(&CryptoContextImpl<DCRTPoly>::EvalMultMutable, py::const_),
            py::arg("ciphertext1"),
            py::arg("ciphertext2"),
            py::doc(cc_EvalMultMutable_docs))
        .def("EvalMultMutable",
            py::overload_cast<Ciphertext<DCRTPoly>&, Plaintext&>(&CryptoContextImpl<DCRTPoly>::EvalMultMutable, py::const_),
            py::arg("ciphertext"),
            py::arg("plaintext"),
            py::doc(cc_EvalMultMutablePlaintext_docs))
        .def("EvalMultMutable",
            py::overload_cast<Plaintext&, Ciphertext<DCRTPoly>&>(&CryptoContextImpl<DCRTPoly>::EvalMultMutable, py::const_),
            py::arg("plaintext"),
            py::arg("ciphertext"),
            py::doc(""))  // TODO (dsuponit): replace this with an actual docstring
        .def("EvalMultMutableInPlace", &CryptoContextImpl<DCRTPoly>::EvalMultMutableInPlace,
            py::arg("ciphertext1"),
            py::arg("ciphertext2"),
            py::doc(cc_EvalMultMutableInPlace_docs))
        .def("EvalSquare", &CryptoContextImpl<DCRTPoly>::EvalSquare,
            py::arg("ciphertext"),
            py::doc(cc_EvalSquare_docs))
        .def("EvalSquareMutable", &CryptoContextImpl<DCRTPoly>::EvalSquareMutable,
            py::arg("ciphertext"),
            py::doc(cc_EvalSquareMutable_docs))
        .def("EvalSquareInPlace", &CryptoContextImpl<DCRTPoly>::EvalSquareInPlace,
            py::arg("ciphertext"),
            py::doc(cc_EvalSquareInPlace_docs))
        .def("EvalMultNoRelin", &CryptoContextImpl<DCRTPoly>::EvalMultNoRelin,
            py::arg("ciphertext1"),
            py::arg("ciphertext2"),
            py::doc(cc_EvalMultNoRelin_docs))
        .def("Relinearize", &CryptoContextImpl<DCRTPoly>::Relinearize,
            py::arg("ciphertext"),
            py::doc(cc_Relinearize_docs))
        .def("RelinearizeInPlace", &CryptoContextImpl<DCRTPoly>::RelinearizeInPlace,
            py::arg("ciphertext"),
            py::doc(cc_RelinearizeInPlace_docs))
        .def("EvalMultAndRelinearize", &CryptoContextImpl<DCRTPoly>::EvalMultAndRelinearize,
            py::arg("ciphertext1"),
            py::arg("ciphertext2"),
            py::doc(cc_EvalMultAndRelinearize_docs))
        .def("EvalNegate", &CryptoContextImpl<DCRTPoly>::EvalNegate,
            py::arg("ciphertext"),
            py::doc(cc_EvalNegate_docs))
        .def("EvalNegateInPlace", &CryptoContextImpl<DCRTPoly>::EvalNegateInPlace,
            py::arg("ciphertext"),
            py::doc(cc_EvalNegateInPlace_docs))
        .def("EvalLogistic", &CryptoContextImpl<DCRTPoly>::EvalLogistic,
            py::arg("ciphertext"),
            py::arg("a"),
            py::arg("b"),
            py::arg("degree"),
            py::doc(cc_EvalLogistic_docs))
        .def("EvalChebyshevFunction", &CryptoContextImpl<DCRTPoly>::EvalChebyshevFunction,
            py::arg("func"),
            py::arg("ciphertext"),
            py::arg("a"),
            py::arg("b"),
            py::arg("degree"),
            py::doc(cc_EvalChebyshevFunction_docs))
        .def("EvalSin", &CryptoContextImpl<DCRTPoly>::EvalSin,
            py::arg("ciphertext"),
            py::arg("a"),
            py::arg("b"),
            py::arg("degree"),
            py::doc(cc_EvalSin_docs))
        .def("EvalCos", &CryptoContextImpl<DCRTPoly>::EvalCos,
            py::arg("ciphertext"),
            py::arg("a"),
            py::arg("b"),
            py::arg("degree"),
            py::doc(cc_EvalCos_docs))
        .def("EvalDivide", &CryptoContextImpl<DCRTPoly>::EvalDivide,
            py::arg("ciphertext"),
            py::arg("a"),
            py::arg("b"),
            py::arg("degree"),
            py::doc(cc_EvalDivide_docs))
        .def("EvalSumKeyGen", &CryptoContextImpl<DCRTPoly>::EvalSumKeyGen,
            py::arg("privateKey"),
            py::arg("publicKey") = py::none(),
            py::doc(cc_EvalSumKeyGen_docs))
        //TODO (Oliveira, R.): Solve pointer handling bug when dealing with EvalKeyMap object for the next functions 
        .def("EvalSumRowsKeyGen", &CryptoContextImpl<DCRTPoly>::EvalSumRowsKeyGen,
            py::arg("privateKey"),
            py::arg("publicKey") = py::none(),
            py::arg("rowSize") = 0,
            py::arg("subringDim") = 0,
            py::doc(cc_EvalSumRowsKeyGen_docs))
        .def("EvalSumColsKeyGen", &CryptoContextImpl<DCRTPoly>::EvalSumColsKeyGen,
            py::arg("privateKey"),
            py::arg("publicKey") = py::none(),
            py::doc(cc_EvalSumColsKeyGen_docs))
        .def("EvalSum", &CryptoContextImpl<DCRTPoly>::EvalSum,
            py::arg("ciphertext"),
            py::arg("batchSize"),
            py::doc(cc_EvalSum_docs))
        .def("EvalSumRows", &CryptoContextImpl<DCRTPoly>::EvalSumRows,
            py::arg("ciphertext"),
            py::arg("numRows"),
            py::arg("evalSumKeyMap"),
            py::arg("subringDim") = 0,
            py::doc(cc_EvalSumRows_docs))
        .def("EvalSumCols", &CryptoContextImpl<DCRTPoly>::EvalSumCols,
            py::arg("ciphertext"),
            py::arg("numCols"),
            py::arg("evalSumKeyMap"),
            py::doc(cc_EvalSumCols_docs))
        .def("EvalInnerProduct",
            py::overload_cast<ConstCiphertext<DCRTPoly>&, ConstCiphertext<DCRTPoly>&, uint32_t>(&CryptoContextImpl<DCRTPoly>::EvalInnerProduct, py::const_),
            py::arg("ciphertext1"),
            py::arg("ciphertext2"),
            py::arg("batchSize"),
            py::doc(cc_EvalInnerProduct_docs))
        .def("EvalInnerProduct",
            py::overload_cast<ConstCiphertext<DCRTPoly>&, ConstPlaintext&, uint32_t>(&CryptoContextImpl<DCRTPoly>::EvalInnerProduct, py::const_),
            py::arg("ciphertext"),
            py::arg("plaintext"),
            py::arg("batchSize"),
            py::doc(cc_EvalInnerProductPlaintext_docs))
        .def("MultipartyKeyGen",
            py::overload_cast<PublicKey<DCRTPoly>, bool, bool>(&CryptoContextImpl<DCRTPoly>::MultipartyKeyGen),
            py::arg("publicKey"),
            py::arg("makeSparse") = false,
            py::arg("fresh") = false,
            py::doc(cc_MultipartyKeyGen_docs))
        .def("MultipartyKeyGen",
            py::overload_cast<const std::vector<PrivateKey<DCRTPoly>>&>(&CryptoContextImpl<DCRTPoly>::MultipartyKeyGen),
            py::arg("privateKeyVec"),
            py::doc(cc_MultipartyKeyGen_vector_docs))
        .def("MultipartyDecryptLead", &CryptoContextImpl<DCRTPoly>::MultipartyDecryptLead,
            py::arg("ciphertextVec"),
            py::arg("privateKey"),
            py::doc(cc_MultipartyDecryptLead_docs))
        .def("MultipartyDecryptMain", &CryptoContextImpl<DCRTPoly>::MultipartyDecryptMain,
            py::arg("ciphertextVec"),
            py::arg("privateKey"),
            py::doc(cc_MultipartyDecryptMain_docs))
        .def("MultipartyDecryptFusion",
            [](CryptoContext<DCRTPoly>& self, const std::vector<Ciphertext<DCRTPoly>>& partialCiphertextVec) {
                Plaintext result;
                self->MultipartyDecryptFusion(partialCiphertextVec, &result);
                return result;
            },
            py::arg("partialCiphertextVec"),
            py::doc(cc_MultipartyDecryptFusion_docs))
        .def("MultiKeySwitchGen", &CryptoContextImpl<DCRTPoly>::MultiKeySwitchGen,
            py::arg("originalPrivateKey"),
            py::arg("newPrivateKey"),
            py::arg("evalKey"),
            py::doc(cc_MultiKeySwitchGen_docs))
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
            py::doc(cc_MultiEvalAtIndexKeyGen_docs))
        .def("MultiEvalSumKeyGen", &CryptoContextImpl<DCRTPoly>::MultiEvalSumKeyGen,
            py::arg("privateKey"),
            py::arg("evalKeyMap"),
            py::arg("keyTag") = "",
            py::doc(cc_MultiEvalSumKeyGen_docs))
        .def("MultiAddEvalAutomorphismKeys", &CryptoContextImpl<DCRTPoly>::MultiAddEvalAutomorphismKeys,
            py::arg("evalKeyMap1"),
            py::arg("evalKeyMap2"),
            py::arg("keyTag") = "",
            py::doc(cc_MultiAddEvalAutomorphismKeys_docs))
        .def("MultiAddPubKeys", &CryptoContextImpl<DCRTPoly>::MultiAddPubKeys,
            py::arg("publicKey1"),
            py::arg("publicKey2"),
            py::arg("keyTag") = "",
            py::doc(cc_MultiAddPubKeys_docs))
        .def("MultiAddEvalKeys", &CryptoContextImpl<DCRTPoly>::MultiAddEvalKeys,
            py::arg("evalKey1"),
            py::arg("evalKey2"),
            py::arg("keyTag") = "",
            py::doc(cc_MultiAddEvalKeys_docs))
        .def("MultiAddEvalMultKeys", &CryptoContextImpl<DCRTPoly>::MultiAddEvalMultKeys,
            py::arg("evalKey1"),
            py::arg("evalKey2"),
            py::arg("keyTag") = "",
            py::doc(cc_MultiAddEvalMultKeys_docs))
        .def("IntBootDecrypt",&CryptoContextImpl<DCRTPoly>::IntBootDecrypt,
            py::arg("privateKey"),
            py::arg("ciphertext"),
            py::doc(cc_IntBootDecrypt_docs))
        .def("IntBootEncrypt",&CryptoContextImpl<DCRTPoly>::IntBootEncrypt,
            py::arg("publicKey"),
            py::arg("ciphertext"),
            py::doc(cc_IntBootEncrypt_docs))
        .def("IntBootAdd",&CryptoContextImpl<DCRTPoly>::IntBootAdd,
            py::arg("ciphertext1"),
            py::arg("ciphertext2"),
            py::doc(cc_IntBootAdd_docs))
        .def("IntBootAdjustScale",&CryptoContextImpl<DCRTPoly>::IntBootAdjustScale,
            py::arg("ciphertext"),
            py::doc(cc_IntBootAdjustScale_docs))
        .def("IntMPBootAdjustScale",&CryptoContextImpl<DCRTPoly>::IntMPBootAdjustScale,
            py::arg("ciphertext"),
            py::doc(cc_IntMPBootAdjustScale_docs))
        .def("IntMPBootRandomElementGen", &CryptoContextImpl<DCRTPoly>::IntMPBootRandomElementGen,
            py::arg("publicKey"),
            py::doc(cc_IntMPBootRandomElementGen_docs))
        .def("IntMPBootDecrypt", &CryptoContextImpl<DCRTPoly>::IntMPBootDecrypt,
            py::arg("privateKey"),
            py::arg("ciphertext"),
            py::arg("a"),
            py::doc(cc_IntMPBootDecrypt_docs))
        .def("IntMPBootAdd", &CryptoContextImpl<DCRTPoly>::IntMPBootAdd,
            py::arg("sharePairVec"),
            py::doc(cc_IntMPBootAdd_docs))
        .def("IntMPBootEncrypt", &CryptoContextImpl<DCRTPoly>::IntMPBootEncrypt,
            py::arg("publicKey"),
            py::arg("sharePair"),
            py::arg("a"),
            py::arg("ciphertext"),
            py::doc(cc_IntMPBootEncrypt_docs))
        .def("MultiMultEvalKey", &CryptoContextImpl<DCRTPoly>::MultiMultEvalKey,
            py::arg("privateKey"),
            py::arg("evalKey"),
            py::arg("keyTag") = "",
            py::doc(cc_MultiMultEvalKey_docs))
        .def("MultiAddEvalSumKeys", &CryptoContextImpl<DCRTPoly>::MultiAddEvalSumKeys,
            py::arg("evalKeyMap1"),
            py::arg("evalKeyMap2"),
            py::arg("keyTag") = "",
            py::doc(cc_MultiAddEvalSumKeys_docs))
        .def("EvalMerge", &CryptoContextImpl<DCRTPoly>::EvalMerge,
            py::arg("ciphertextVec"),
            py::doc(cc_EvalMerge_docs))
        .def("ReKeyGen",
            py::overload_cast<const PrivateKey<DCRTPoly>, const PublicKey<DCRTPoly>>(&CryptoContextImpl<DCRTPoly>::ReKeyGen, py::const_),
            py::arg("oldPrivateKey"),
            py::arg("newPublicKey"),
            py::doc(cc_ReKeyGen_docs))
        .def("ReEncrypt", &CryptoContextImpl<DCRTPoly>::ReEncrypt,
            py::arg("ciphertext"),
            py::arg("evalKey"),
            py::arg("publicKey") = py::none(),
            py::doc(cc_ReEncrypt_docs))
        .def("Rescale", &CryptoContextImpl<DCRTPoly>::Rescale,
            py::arg("ciphertext"),
            py::doc(cc_Rescale_docs))
        .def("RescaleInPlace", &CryptoContextImpl<DCRTPoly>::RescaleInPlace,
            py::arg("ciphertext"),
            py::doc(cc_RescaleInPlace_docs))
        .def("ModReduce", &CryptoContextImpl<DCRTPoly>::ModReduce,
            py::arg("ciphertext"),
            py::doc(cc_ModReduce_docs))
        .def("ModReduceInPlace", &CryptoContextImpl<DCRTPoly>::ModReduceInPlace,
            py::arg("ciphertext"),
            py::doc(cc_ModReduceInPlace_docs))
        .def("EvalBootstrapSetup", &CryptoContextImpl<DCRTPoly>::EvalBootstrapSetup,
            py::arg("levelBudget") = std::vector<uint32_t>({5, 4}),
            py::arg("dim1") = std::vector<uint32_t>({0, 0}),
            py::arg("slots") = 0,
            py::arg("correctionFactor") = 0,
            py::arg("precompute")= true,
            py::doc(cc_EvalBootstrapSetup_docs))
        .def("EvalBootstrapKeyGen", &CryptoContextImpl<DCRTPoly>::EvalBootstrapKeyGen,
            py::arg("privateKey"),
            py::arg("slots"),
            py::doc(cc_EvalBootstrapKeyGen_docs))
        .def("EvalBootstrap", &CryptoContextImpl<DCRTPoly>::EvalBootstrap,
            py::arg("ciphertext"),
            py::arg("numIterations") = 1,
            py::arg("precision") = 0,
            py::doc(cc_EvalBootstrap_docs))
        .def("EvalCKKStoFHEWSetup", &CryptoContextImpl<DCRTPoly>::EvalCKKStoFHEWSetup,
            py::arg("schswchparams"),
            py::doc(cc_EvalCKKStoFHEWSetup_docs))
        .def("EvalCKKStoFHEWKeyGen", &CryptoContextImpl<DCRTPoly>::EvalCKKStoFHEWKeyGen,
            py::arg("keyPair"),
            py::arg("lwesk"),
            py::doc(cc_EvalCKKStoFHEWKeyGen_docs))
        .def("EvalCKKStoFHEWPrecompute", &CryptoContextImpl<DCRTPoly>::EvalCKKStoFHEWPrecompute,
            py::arg("scale") = 1.0,
            py::doc(cc_EvalCKKStoFHEWPrecompute_docs))
        .def("EvalCKKStoFHEW", &CryptoContextImpl<DCRTPoly>::EvalCKKStoFHEW,
            py::arg("ciphertext"),
            py::arg("numCtxts") = 0,
            py::doc(cc_EvalCKKStoFHEW_docs))
        .def("EvalFHEWtoCKKSSetup", &CryptoContextImpl<DCRTPoly>::EvalFHEWtoCKKSSetup,
            py::arg("ccLWE"),
            py::arg("numSlotsCKKS") = 0,
            py::arg("logQ") = 25,
            py::doc(cc_EvalFHEWtoCKKSSetup_docs))
        .def("EvalFHEWtoCKKSKeyGen", &CryptoContextImpl<DCRTPoly>::EvalFHEWtoCKKSKeyGen,
            py::arg("keyPair"),
            py::arg("lwesk"),
            py::arg("numSlots") = 0,
            py::arg("numCtxts") = 0,
            py::arg("dim1") = 0,
            py::arg("L") = 0,
            py::doc(cc_EvalFHEWtoCKKSKeyGen_docs))
        .def("EvalFHEWtoCKKS", &CryptoContextImpl<DCRTPoly>::EvalFHEWtoCKKS,
            py::arg("LWECiphertexts"),
            py::arg("numCtxts") = 0,
            py::arg("numSlots") = 0,
            py::arg("p") = 4,
            py::arg("pmin") = 0.0,
            py::arg("pmax") = 2.0,
            py::arg("dim1") = 0,
            py::doc(cc_EvalFHEWtoCKKS_docs))
        .def("EvalSchemeSwitchingSetup", &CryptoContextImpl<DCRTPoly>::EvalSchemeSwitchingSetup,
            py::arg("schswchparams"),
            py::doc(cc_EvalSchemeSwitchingSetup_docs))
        //void EvalSchemeSwitchingKeyGen(const KeyPair<DCRTPoly> &keyPair, ConstLWEPrivateKey &lwesk, uint32_t numValues = 0, bool oneHot = true, bool alt = false, uint32_t dim1CF = 0, uint32_t dim1FC = 0, uint32_t LCF = 1, uint32_t LFC = 0)
        .def("EvalSchemeSwitchingKeyGen", &CryptoContextImpl<DCRTPoly>::EvalSchemeSwitchingKeyGen,
            py::arg("keyPair"),
            py::arg("lwesk"),
            py::doc(cc_EvalSchemeSwitchingKeyGen_docs))
        .def("EvalCompareSwitchPrecompute", &CryptoContextImpl<DCRTPoly>::EvalCompareSwitchPrecompute,
            py::arg("pLWE") = 0,
            py::arg("scaleSign") = 1.0,
            py::arg("unit") = false,
            py::doc(cc_EvalCompareSwitchPrecompute_docs))
        .def("EvalCompareSchemeSwitching", &CryptoContextImpl<DCRTPoly>::EvalCompareSchemeSwitching,
            py::arg("ciphertext1"),
            py::arg("ciphertext2"),
            py::arg("numCtxts") = 0,
            py::arg("numSlots") = 0,
            py::arg("pLWE") = 0,
            py::arg("scaleSign") = 1.0,
            py::arg("unit") = false,
            py::doc(cc_EvalCompareSchemeSwitching_docs))
        .def("EvalMinSchemeSwitching", &CryptoContextImpl<DCRTPoly>::EvalMinSchemeSwitching,
            py::arg("ciphertext"),
            py::arg("publicKey"),
            py::arg("numValues") = 0,
            py::arg("numSlots") = 0,
            py::arg("pLWE") = 0,
            py::arg("scaleSign") = 1.0,
            py::doc(cc_EvalMinSchemeSwitching_docs))
        .def("EvalMinSchemeSwitchingAlt", &CryptoContextImpl<DCRTPoly>::EvalMinSchemeSwitchingAlt,
            py::arg("ciphertext"),
            py::arg("publicKey"),
            py::arg("numValues") = 0,
            py::arg("numSlots") = 0,
            py::arg("pLWE") = 0,
            py::arg("scaleSign") = 1.0,
            py::doc(cc_EvalMinSchemeSwitchingAlt_docs))
        .def("EvalMaxSchemeSwitching", &CryptoContextImpl<DCRTPoly>::EvalMaxSchemeSwitching,
            py::arg("ciphertext"),
            py::arg("publicKey"),
            py::arg("numValues") = 0,
            py::arg("numSlots") = 0,
            py::arg("pLWE") = 0,
            py::arg("scaleSign") = 1.0,
            py::doc(cc_EvalMaxSchemeSwitching_docs))
        .def("EvalMaxSchemeSwitchingAlt", &CryptoContextImpl<DCRTPoly>::EvalMaxSchemeSwitchingAlt,
            py::arg("ciphertext"),
            py::arg("publicKey"),
            py::arg("numValues") = 0,
            py::arg("numSlots") = 0,
            py::arg("pLWE") = 0,
            py::arg("scaleSign") = 1.0,
            py::doc(cc_EvalMaxSchemeSwitchingAlt_docs))
        //TODO (Oliveira, R.): Solve pointer handling bug when returning EvalKeyMap objects for the next functions
        // TODO (dsuponit): I'd suggest this version of EvalAutomorphismKeyGen instead:
        // .def("EvalAutomorphismKeyGen",
        //     [](const CryptoContextImpl<DCRTPoly>& cc,
        //         const PrivateKey<DCRTPoly>& privateKey,
        //         const std::vector<uint32_t>& indexList) -> py::dict {
        //         auto keyMapPtr = cc.EvalAutomorphismKeyGen(privateKey, indexList);
        //         py::dict result;
        //         for (const auto& kv : *keyMapPtr) {
        //             result[py::int_(kv.first)] = kv.second;
        //         }
        //         return result;
        //     },
        //     py::doc(cc_EvalAutomorphismKeyGen_docs))
        //     py::arg("privateKey"),
        //     py::arg("indexList"))
        .def("EvalAutomorphismKeyGen",
            py::overload_cast<const PrivateKey<DCRTPoly>, const std::vector<uint32_t>&>(&CryptoContextImpl<DCRTPoly>::EvalAutomorphismKeyGen, py::const_),
            py::arg("privateKey"),
            py::arg("indexList"),
            py::doc(cc_EvalAutomorphismKeyGen_docs))
        .def("Compress", &CryptoContextImpl<DCRTPoly>::Compress,
            py::arg("ciphertext"),
            py::arg("towersLeft"))
        .def("EvalMultMany", &CryptoContextImpl<DCRTPoly>::EvalMultMany,
            py::arg("ciphertextVec"))
        .def("EvalAddMany", &CryptoContextImpl<DCRTPoly>::EvalAddMany,
            py::arg("ciphertextVec"))
        .def("EvalAddManyInPlace", &CryptoContextImpl<DCRTPoly>::EvalAddManyInPlace,
            py::arg("ciphertextVec"))
        .def("FindAutomorphismIndex", &CryptoContextImpl<DCRTPoly>::FindAutomorphismIndex,
            py::arg("idx"),
            py::doc(cc_FindAutomorphismIndex_docs))
        .def("FindAutomorphismIndices", &CryptoContextImpl<DCRTPoly>::FindAutomorphismIndices,
            py::arg("idxList"),
            py::doc(cc_FindAutomorphismIndices_docs))
        .def("GetEvalSumKeyMap",
            [](CryptoContext<DCRTPoly>& self, const std::string& keyTag) {
                return std::make_shared<std::map<uint32_t, EvalKey<DCRTPoly>>>(CryptoContextImpl<DCRTPoly>::GetEvalSumKeyMap(keyTag));
            },
            py::arg("keyTag"),
            py::doc(cc_GetEvalSumKeyMap_docs))
        .def("GetBinCCForSchemeSwitch", &CryptoContextImpl<DCRTPoly>::GetBinCCForSchemeSwitch)
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
        .def_static("SerializeEvalMultKey", [](const std::string &filename, const SerType::SERBINARY &sertype, std::string keyTag = "") {
                std::ofstream outfile(filename, std::ios::out | std::ios::binary);
                bool res = CryptoContextImpl<DCRTPoly>::SerializeEvalMultKey<SerType::SERBINARY>(outfile, sertype, keyTag);
                outfile.close();
                return res;
            },
            py::arg("filename"),
            py::arg("sertype"),
            py::arg("keyTag") = "",
            py::doc(cc_SerializeEvalMultKey_docs))
        .def_static("SerializeEvalMultKey", [](const std::string &filename, const SerType::SERJSON &sertype, std::string keyTag = "") {
                std::ofstream outfile(filename, std::ios::out | std::ios::binary);
                bool res = CryptoContextImpl<DCRTPoly>::SerializeEvalMultKey<SerType::SERJSON>(outfile, sertype, keyTag);
                outfile.close();
                return res;
            },
            py::arg("filename"),
            py::arg("sertype"),
            py::arg("keyTag") = "",
            py::doc(cc_SerializeEvalMultKey_docs))
        .def_static("SerializeEvalAutomorphismKey", [](const std::string &filename, const SerType::SERBINARY &sertype, std::string keyTag = "") {
                std::ofstream outfile(filename, std::ios::out | std::ios::binary);
                bool res = CryptoContextImpl<DCRTPoly>::SerializeEvalAutomorphismKey<SerType::SERBINARY>(outfile, sertype, keyTag);
                outfile.close();
                return res;
            },
            py::arg("filename"),
            py::arg("sertype"),
            py::arg("keyTag") = "",
            py::doc(cc_SerializeEvalAutomorphismKey_docs))
        .def_static("SerializeEvalAutomorphismKey", [](const std::string &filename, const SerType::SERJSON &sertype, std::string keyTag = "") {
                std::ofstream outfile(filename, std::ios::out | std::ios::binary);
                bool res = CryptoContextImpl<DCRTPoly>::SerializeEvalAutomorphismKey<SerType::SERJSON>(outfile, sertype, keyTag);
                outfile.close();
                return res;
            },
            py::arg("filename"),
            py::arg("sertype"),
            py::arg("keyTag") = "",
            py::doc(cc_SerializeEvalAutomorphismKey_docs))
        .def_static("DeserializeEvalMultKey", [](const std::string &filename, const SerType::SERBINARY &sertype) {
                std::ifstream emkeys(filename, std::ios::in | std::ios::binary);
                if (!emkeys.is_open()) {
                    std::cerr << "I cannot read serialization from " << filename << std::endl;
                }
                bool res = CryptoContextImpl<DCRTPoly>::DeserializeEvalMultKey<SerType::SERBINARY>(emkeys, sertype);
                return res; 
            },
            py::arg("filename"),
            py::arg("sertype"),
            py::doc(cc_DeserializeEvalMultKey_docs))
        .def_static("DeserializeEvalMultKey", [](const std::string &filename, const SerType::SERJSON &sertype) {
                std::ifstream emkeys(filename, std::ios::in | std::ios::binary);
                if (!emkeys.is_open()) {
                    std::cerr << "I cannot read serialization from " << filename << std::endl;
                }
                bool res = CryptoContextImpl<DCRTPoly>::DeserializeEvalMultKey<SerType::SERJSON>(emkeys, sertype);
                return res;
            },
            py::arg("filename"),
            py::arg("sertype"),
            py::doc(cc_DeserializeEvalMultKey_docs))
        .def_static("DeserializeEvalAutomorphismKey", [](const std::string &filename, const SerType::SERBINARY &sertype) {
                std::ifstream erkeys(filename, std::ios::in | std::ios::binary);
                if (!erkeys.is_open()) {
                    std::cerr << "I cannot read serialization from " << filename << std::endl;
                }
                bool res = CryptoContextImpl<DCRTPoly>::DeserializeEvalAutomorphismKey<SerType::SERBINARY>(erkeys, sertype);
                return res;
            },
            py::arg("filename"),
            py::arg("sertype"),
            py::doc(cc_DeserializeEvalAutomorphismKey_docs))
        .def_static("DeserializeEvalAutomorphismKey", [](const std::string &filename, const SerType::SERJSON &sertype) {
                std::ifstream erkeys(filename, std::ios::in | std::ios::binary);
                if (!erkeys.is_open()) {
                    std::cerr << "I cannot read serialization from " << filename << std::endl;
                }
                bool res = CryptoContextImpl<DCRTPoly>::DeserializeEvalAutomorphismKey<SerType::SERJSON>(erkeys, sertype);
                return res;
            },
            py::arg("filename"),
            py::arg("sertype"),
            py::doc(cc_DeserializeEvalAutomorphismKey_docs));

    bind_crypto_context_templates<int64_t>(cc_class);
    bind_crypto_context_templates<double>(cc_class);
    bind_crypto_context_templates<std::complex<double>>(cc_class);

    // Generator Functions
    m.def("GenCryptoContext", &GenCryptoContext<CryptoContextBFVRNS>,
        py::arg("params"));
    m.def("GenCryptoContext", &GenCryptoContext<CryptoContextBGVRNS>,
        py::arg("params"));
    m.def("GenCryptoContext", &GenCryptoContext<CryptoContextCKKSRNS>,
        py::arg("params"));

    m.def("GetAllContexts", &CryptoContextFactory<DCRTPoly>::GetAllContexts);

    m.def("ReleaseAllContexts", &CryptoContextFactory<DCRTPoly>::ReleaseAllContexts);

    m.def("ClearEvalMultKeys", static_cast<void (*)()>(&CryptoContextImpl<DCRTPoly>::ClearEvalMultKeys));
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
        .value("FHE", PKESchemeFeature::FHE)
        .value("SCHEMESWITCH", PKESchemeFeature::SCHEMESWITCH);
    m.attr("PKE") = py::cast(PKESchemeFeature::PKE);
    m.attr("KEYSWITCH") = py::cast(PKESchemeFeature::KEYSWITCH);
    m.attr("PRE") = py::cast(PKESchemeFeature::PRE);
    m.attr("LEVELEDSHE") = py::cast(PKESchemeFeature::LEVELEDSHE);
    m.attr("ADVANCEDSHE") = py::cast(PKESchemeFeature::ADVANCEDSHE);
    m.attr("MULTIPARTY") = py::cast(PKESchemeFeature::MULTIPARTY);
    m.attr("FHE") = py::cast(PKESchemeFeature::FHE);
    m.attr("SCHEMESWITCH") = py::cast(PKESchemeFeature::SCHEMESWITCH);

    // Plaintext enums
    py::enum_<Format>(m, "Format")
        .value("EVALUATION", Format::EVALUATION)
        .value("COEFFICIENT", Format::COEFFICIENT);
    m.attr("EVALUATION") = py::cast(Format::EVALUATION);
    m.attr("COEFFICIENT") = py::cast(Format::COEFFICIENT);
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
       .value("COMPOSITESCALINGAUTO", ScalingTechnique::COMPOSITESCALINGAUTO)
       .value("COMPOSITESCALINGMANUAL", ScalingTechnique::COMPOSITESCALINGMANUAL)
       .value("INVALID_RS_TECHNIQUE", ScalingTechnique::INVALID_RS_TECHNIQUE);
    m.attr("FIXEDMANUAL") = py::cast(ScalingTechnique::FIXEDMANUAL);
    m.attr("FIXEDAUTO") = py::cast(ScalingTechnique::FIXEDAUTO);
    m.attr("FLEXIBLEAUTO") = py::cast(ScalingTechnique::FLEXIBLEAUTO);
    m.attr("FLEXIBLEAUTOEXT") = py::cast(ScalingTechnique::FLEXIBLEAUTOEXT);
    m.attr("NORESCALE") = py::cast(ScalingTechnique::NORESCALE);
    m.attr("COMPOSITESCALINGAUTO") = py::cast(ScalingTechnique::COMPOSITESCALINGAUTO);
    m.attr("COMPOSITESCALINGMANUAL") = py::cast(ScalingTechnique::COMPOSITESCALINGMANUAL);
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
        .value("NOISE_FLOODING_HRA", ProxyReEncryptionMode::NOISE_FLOODING_HRA);
    m.attr("NOT_SET") = py::cast(ProxyReEncryptionMode::NOT_SET);
    m.attr("INDCPA") = py::cast(ProxyReEncryptionMode::INDCPA);
    m.attr("FIXED_NOISE_HRA") = py::cast(ProxyReEncryptionMode::FIXED_NOISE_HRA);
    m.attr("NOISE_FLOODING_HRA") = py::cast(ProxyReEncryptionMode::NOISE_FLOODING_HRA);
    
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

    // Compression Leval
    py::enum_<COMPRESSION_LEVEL>(m,"COMPRESSION_LEVEL")
        .value("COMPACT", COMPRESSION_LEVEL::COMPACT)
        .value("SLACK", COMPRESSION_LEVEL::SLACK);
    m.attr("COMPACT") = py::cast(COMPRESSION_LEVEL::COMPACT);
    m.attr("SLACK") = py::cast(COMPRESSION_LEVEL::SLACK);

    py::enum_<CKKSDataType>(m,"CKKSDataType")
        .value("REAL", CKKSDataType::REAL)
        .value("COMPLEX", CKKSDataType::COMPLEX);
    m.attr("REAL") = py::cast(CKKSDataType::REAL);
    m.attr("COMPLEX") = py::cast(CKKSDataType::COMPLEX);

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
    
    //NATIVEINT function
    m.def("get_native_int", &get_native_int);
}

void bind_keys(py::module &m) {
    py::class_<PublicKeyImpl<DCRTPoly>, std::shared_ptr<PublicKeyImpl<DCRTPoly>>>(m, "PublicKey")
        .def(py::init<>())
        .def("GetKeyTag", &PublicKeyImpl<DCRTPoly>::GetKeyTag)
        .def("SetKeyTag", &PublicKeyImpl<DCRTPoly>::SetKeyTag);
    py::class_<PrivateKeyImpl<DCRTPoly>, std::shared_ptr<PrivateKeyImpl<DCRTPoly>>>(m, "PrivateKey")
        .def(py::init<>())
        .def("GetCryptoContext", &PrivateKeyImpl<DCRTPoly>::GetCryptoContext)
        .def("GetKeyTag", &PrivateKeyImpl<DCRTPoly>::GetKeyTag)
        .def("SetKeyTag", &PrivateKeyImpl<DCRTPoly>::SetKeyTag);
    py::class_<KeyPair<DCRTPoly>>(m, "KeyPair")
        .def_readwrite("publicKey", &KeyPair<DCRTPoly>::publicKey)
        .def_readwrite("secretKey", &KeyPair<DCRTPoly>::secretKey)
        .def("good", &KeyPair<DCRTPoly>::good,kp_good_docs);
    py::class_<EvalKeyImpl<DCRTPoly>, std::shared_ptr<EvalKeyImpl<DCRTPoly>>>(m, "EvalKey")
        .def(py::init<>())
        .def("GetKeyTag", &EvalKeyImpl<DCRTPoly>::GetKeyTag)
        .def("SetKeyTag", &EvalKeyImpl<DCRTPoly>::SetKeyTag);
    py::class_<std::map<uint32_t, EvalKey<DCRTPoly>>, std::shared_ptr<std::map<uint32_t, EvalKey<DCRTPoly>>>>(m, "EvalKeyMap")
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
    py::class_<PlaintextImpl, std::shared_ptr<PlaintextImpl>, PlaintextImpl_helper>(m, "Plaintext")
        .def("GetScalingFactor", &PlaintextImpl::GetScalingFactor, ptx_GetScalingFactor_docs)
        .def("SetScalingFactor", &PlaintextImpl::SetScalingFactor,
            py::arg("sf"),
            py::doc(ptx_SetScalingFactor_docs))
        .def("GetSchemeID", &PlaintextImpl::GetSchemeID, ptx_GetSchemeID_docs)
        .def("GetLength", &PlaintextImpl::GetLength, ptx_GetLength_docs)
        .def("SetLength", &PlaintextImpl::SetLength,
            py::arg("newSize"),
            py::doc(ptx_SetLength_docs))
        .def("IsEncoded", &PlaintextImpl::IsEncoded, ptx_IsEncoded_docs)
        .def("GetLogPrecision", &PlaintextImpl::GetLogPrecision, ptx_GetLogPrecision_docs)
        .def("Encode", &PlaintextImpl::Encode, ptx_Encode_docs)
        .def("Decode", py::overload_cast<>(&PlaintextImpl::Decode), ptx_Decode_docs)
        .def("Decode", py::overload_cast<size_t, double, ScalingTechnique, ExecutionMode>(&PlaintextImpl::Decode), ptx_Decode_docs)
        .def("LowBound", &PlaintextImpl::LowBound, ptx_LowBound_docs)
        .def("HighBound", &PlaintextImpl::HighBound, ptx_HighBound_docs)
        .def("SetFormat", &PlaintextImpl::SetFormat,
            py::arg("fmt"),
            py::doc(ptx_SetFormat_docs))
        .def("GetCoefPackedValue", &PlaintextImpl::GetCoefPackedValue)
        .def("GetPackedValue", &PlaintextImpl::GetPackedValue)
        .def("GetCKKSPackedValue", &PlaintextImpl::GetCKKSPackedValue, ptx_GetCKKSPackedValue_docs)
        .def("GetRealPackedValue", &PlaintextImpl::GetRealPackedValue, ptx_GetRealPackedValue_docs)
        .def("GetLevel", &PlaintextImpl::GetLevel)
        .def("SetLevel", &PlaintextImpl::SetLevel)
        .def("GetNoiseScaleDeg", &PlaintextImpl::GetNoiseScaleDeg)
        .def("SetNoiseScaleDeg", &PlaintextImpl::SetNoiseScaleDeg)
        .def("GetSlots", &PlaintextImpl::GetSlots)
        .def("SetSlots", &PlaintextImpl::SetSlots)
        .def("GetLogError", &PlaintextImpl::GetLogError)
        .def("GetLogPrecision", &PlaintextImpl::GetLogPrecision)
        .def("GetStringValue", &PlaintextImpl::GetStringValue)
        .def("SetStringValue", &PlaintextImpl::SetStringValue)
        .def("SetIntVectorValue", &PlaintextImpl::SetIntVectorValue)
        .def("GetFormattedValues", &PlaintextImpl::GetFormattedValues)
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
}

void bind_ciphertext(py::module &m) {
    py::class_<CiphertextImpl<DCRTPoly>, std::shared_ptr<CiphertextImpl<DCRTPoly>>>(m, "Ciphertext")
        .def(py::init<>())
        .def("__add__", [](const Ciphertext<DCRTPoly> &a, const Ciphertext<DCRTPoly> &b) {
                return a + b;
            },
            py::is_operator(), pybind11::keep_alive<0, 1>())
        // .def(py::self + py::self);
        // .def("GetDepth", &CiphertextImpl<DCRTPoly>::GetDepth)
        // .def("SetDepth", &CiphertextImpl<DCRTPoly>::SetDepth)
        .def("GetLevel", &CiphertextImpl<DCRTPoly>::GetLevel, ctx_GetLevel_docs)
        .def("SetLevel", &CiphertextImpl<DCRTPoly>::SetLevel,
            py::arg("level"),
            py::doc(ctx_SetLevel_docs))
        .def("Clone", &CiphertextImpl<DCRTPoly>::Clone)
        .def("RemoveElement",
            [](Ciphertext<DCRTPoly>& self, uint32_t index) {
                self->GetElements().erase(self->GetElements().begin() + index);
            },
            py::arg("index"),
            py::doc(cc_RemoveElement_docs))
        // .def("GetHopLevel", &CiphertextImpl<DCRTPoly>::GetHopLevel)
        // .def("SetHopLevel", &CiphertextImpl<DCRTPoly>::SetHopLevel)
        // .def("GetScalingFactor", &CiphertextImpl<DCRTPoly>::GetScalingFactor)
        // .def("SetScalingFactor", &CiphertextImpl<DCRTPoly>::SetScalingFactor)
        .def("GetSlots", &CiphertextImpl<DCRTPoly>::GetSlots)
        .def("SetSlots", &CiphertextImpl<DCRTPoly>::SetSlots)
        .def("GetNoiseScaleDeg", &CiphertextImpl<DCRTPoly>::GetNoiseScaleDeg)
        .def("SetNoiseScaleDeg", &CiphertextImpl<DCRTPoly>::SetNoiseScaleDeg)
        .def("GetCryptoContext", &CiphertextImpl<DCRTPoly>::GetCryptoContext)
        .def("GetEncodingType", &CiphertextImpl<DCRTPoly>::GetEncodingType)
        .def("GetElements", [](const CiphertextImpl<DCRTPoly>& self) -> const std::vector<DCRTPoly>& {
                return self.GetElements();
            },
            py::return_value_policy::reference_internal)
        .def("GetElementsMutable", [](CiphertextImpl<DCRTPoly>& self) -> std::vector<DCRTPoly>& {
                return self.GetElements();
            },
            py::return_value_policy::reference_internal)
        .def("SetElements", [](CiphertextImpl<DCRTPoly>& self, const std::vector<DCRTPoly>& elems) {
                self.SetElements(elems);
            })
        .def("SetElementsMove", [](CiphertextImpl<DCRTPoly>& self, std::vector<DCRTPoly>&& elems) {
                self.SetElements(std::move(elems));
            });
}

void bind_schemes(py::module &m) {
    // Bind schemes specific functionalities like bootstrapping functions and multiparty
    py::class_<FHECKKSRNS>(m, "FHECKKSRNS")
        .def(py::init<>())
        .def_static("GetBootstrapDepth",
            py::overload_cast<uint32_t, const std::vector<uint32_t>&, SecretKeyDist>(&FHECKKSRNS::GetBootstrapDepth),
            py::arg("depth"),
            py::arg("levelBudget"),
            py::arg("keyDist"))
        .def_static("GetBootstrapDepth",
            py::overload_cast<const std::vector<uint32_t>&, SecretKeyDist>(&FHECKKSRNS::GetBootstrapDepth),
            py::arg("levelBudget"),
            py::arg("keyDist"))
        ;
}

void bind_sch_swch_params(py::module &m) {
    py::class_<SchSwchParams>(m, "SchSwchParams")
        .def(py::init<>())
        .def("GetSecurityLevelCKKS", &SchSwchParams::GetSecurityLevelCKKS)
        .def("GetSecurityLevelFHEW", &SchSwchParams::GetSecurityLevelFHEW)
        .def("GetArbitraryFunctionEvaluation", &SchSwchParams::GetArbitraryFunctionEvaluation)
        .def("GetUseDynamicModeFHEW", &SchSwchParams::GetUseDynamicModeFHEW)
        .def("GetComputeArgmin", &SchSwchParams::GetComputeArgmin)
        .def("GetOneHotEncoding", &SchSwchParams::GetOneHotEncoding)
        .def("GetUseAltArgmin", &SchSwchParams::GetUseAltArgmin)
        .def("GetNumSlotsCKKS", &SchSwchParams::GetNumSlotsCKKS)
        .def("GetNumValues", &SchSwchParams::GetNumValues)
        .def("GetCtxtModSizeFHEWLargePrec", &SchSwchParams::GetCtxtModSizeFHEWLargePrec)
        .def("GetCtxtModSizeFHEWIntermedSwch", &SchSwchParams::GetCtxtModSizeFHEWIntermedSwch)
        .def("GetBStepLTrCKKStoFHEW", &SchSwchParams::GetBStepLTrCKKStoFHEW)
        .def("GetBStepLTrFHEWtoCKKS", &SchSwchParams::GetBStepLTrFHEWtoCKKS)
        .def("GetLevelLTrCKKStoFHEW", &SchSwchParams::GetLevelLTrCKKStoFHEW)
        .def("GetLevelLTrFHEWtoCKKS", &SchSwchParams::GetLevelLTrFHEWtoCKKS)
        .def("GetInitialCKKSModulus", &SchSwchParams::GetInitialCKKSModulus)
        .def("GetRingDimension", &SchSwchParams::GetRingDimension)
        .def("GetScalingModSize", &SchSwchParams::GetScalingModSize)
        .def("GetBatchSize", &SchSwchParams::GetBatchSize)
        .def("SetSecurityLevelCKKS", &SchSwchParams::SetSecurityLevelCKKS)
        .def("SetSecurityLevelFHEW", &SchSwchParams::SetSecurityLevelFHEW)
        .def("SetArbitraryFunctionEvaluation", &SchSwchParams::SetArbitraryFunctionEvaluation)
        .def("SetUseDynamicModeFHEW", &SchSwchParams::SetUseDynamicModeFHEW)
        .def("SetComputeArgmin", &SchSwchParams::SetComputeArgmin)
        .def("SetOneHotEncoding", &SchSwchParams::SetOneHotEncoding)
        .def("SetUseAltArgmin", &SchSwchParams::SetUseAltArgmin)
        .def("SetNumSlotsCKKS", &SchSwchParams::SetNumSlotsCKKS)
        .def("SetNumValues", &SchSwchParams::SetNumValues)
        .def("SetCtxtModSizeFHEWLargePrec", &SchSwchParams::SetCtxtModSizeFHEWLargePrec)
        .def("SetCtxtModSizeFHEWIntermedSwch", &SchSwchParams::SetCtxtModSizeFHEWIntermedSwch)
        .def("SetBStepLTrCKKStoFHEW", &SchSwchParams::SetBStepLTrCKKStoFHEW)
        .def("SetBStepLTrFHEWtoCKKS", &SchSwchParams::SetBStepLTrFHEWtoCKKS)
        .def("SetLevelLTrCKKStoFHEW", &SchSwchParams::SetLevelLTrCKKStoFHEW)
        .def("SetLevelLTrFHEWtoCKKS", &SchSwchParams::SetLevelLTrFHEWtoCKKS)
        .def("SetInitialCKKSModulus", &SchSwchParams::SetInitialCKKSModulus)
        .def("SetRingDimension", &SchSwchParams::SetRingDimension)
        .def("SetScalingModSize", &SchSwchParams::SetScalingModSize)
        .def("SetBatchSize", &SchSwchParams::SetBatchSize)
        .def("__str__", [](const SchSwchParams &params) {
                std::stringstream stream;
                stream << params;
                return stream.str();
            });
}

void bind_utils(py::module& m) {
    m.def("EnablePrecomputeCRTTablesAfterDeserializaton", &lbcrypto::EnablePrecomputeCRTTablesAfterDeserializaton,
          py::doc("Enable CRT precomputation after deserialization"));
    m.def("DisablePrecomputeCRTTablesAfterDeserializaton", &lbcrypto::DisablePrecomputeCRTTablesAfterDeserializaton,
          py::doc("Disable CRT precomputation after deserialization"));
}

PYBIND11_MODULE(openfhe, m) {
    // sequence of function calls matters
    m.doc() = "Open-Source Fully Homomorphic Encryption Library";
    bind_DCRTPoly(m);
    // binfhe library
    bind_binfhe_enums(m);
    bind_binfhe_ciphertext(m);
    bind_binfhe_keys(m);
    bind_binfhe_context(m);
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
    bind_schemes(m);
    bind_sch_swch_params(m);
    bind_utils(m);
}
