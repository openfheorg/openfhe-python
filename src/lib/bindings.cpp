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

#include <pybind11/stl.h>
#include <pybind11/stl_bind.h>
#include <pybind11/complex.h>
#include <pybind11/functional.h>
#include <pybind11/operators.h>
#include <pybind11/iostream.h>

#include "openfhe.h"

#include "key/key-ser.h"
#include "binfhe_bindings.h"

#include "cryptocontext_wrapper.h"
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

template <typename T>
void bind_parameters(py::module &m,const std::string name)
{
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

        //

}

void bind_crypto_context(py::module &m)
{
    //Parameters Type
    /*TODO (Oliveira): If we expose Poly's and ParmType, this block will go somewhere else */
    using ParmType = typename DCRTPoly::Params;
    using ParmTypePtr = std::shared_ptr<ParmType>;
    py::class_<ParmType, ParmTypePtr>(m, "ParmType");

    py::class_<CryptoContextImpl<DCRTPoly>, std::shared_ptr<CryptoContextImpl<DCRTPoly>>>(m, "CryptoContext")
        .def(py::init<>())
        .def("GetKeyGenLevel", &CryptoContextImpl<DCRTPoly>::GetKeyGenLevel, cc_GetKeyGenLevel_docs)
        .def("SetKeyGenLevel", &CryptoContextImpl<DCRTPoly>::SetKeyGenLevel, cc_SetKeyGenLevel_docs,
             py::arg("level"))
        .def("get_ptr", [](const CryptoContext<DCRTPoly> &self)
             { std::cout << "CC shared ptr (python cc)" << self << std::endl; })
        //.def("GetScheme",&CryptoContextImpl<DCRTPoly>::GetScheme)
        //.def("GetCryptoParameters", &CryptoContextImpl<DCRTPoly>::GetCryptoParameters)
        .def("GetRingDimension", &CryptoContextImpl<DCRTPoly>::GetRingDimension, cc_GetRingDimension_docs)
        .def("GetPlaintextModulus", &GetPlaintextModulusWrapper, cc_GetPlaintextModulus_docs)
        .def("GetModulus", &GetModulusWrapper, cc_GetModulus_docs)
        .def("GetModulusCKKS", &GetModulusCKKSWrapper)
        .def("GetScalingFactorReal", &GetScalingFactorRealWrapper, cc_GetScalingFactorReal_docs)
        .def("GetScalingTechnique",&GetScalingTechniqueWrapper)
        .def("GetDigitSize", &GetDigitSizeWrapper)
        .def("GetCyclotomicOrder", &CryptoContextImpl<DCRTPoly>::GetCyclotomicOrder, cc_GetCyclotomicOrder_docs)
        .def("GetCKKSDataType", &CryptoContextImpl<DCRTPoly>::GetCKKSDataType)
        .def("GetNoiseEstimate", [](CryptoContext<DCRTPoly>& self) {
            return GetParamsRNSChecked(self, "GetNoiseEstimate")->GetNoiseEstimate();
        })
        .def("SetNoiseEstimate", [](CryptoContext<DCRTPoly>& self, double noiseEstimate) {
            GetParamsRNSChecked(self, "SetNoiseEstimate")->SetNoiseEstimate(noiseEstimate);
        }, py::arg("noiseEstimate"))
        .def("GetMultiplicativeDepth", [](CryptoContext<DCRTPoly>& self) {
            return GetParamsRNSChecked(self, "GetMultiplicativeDepth")->GetMultiplicativeDepth();
        })
        .def("SetMultiplicativeDepth", [](CryptoContext<DCRTPoly>& self, uint32_t multiplicativeDepth) {
            GetParamsRNSChecked(self, "SetMultiplicativeDepth")->SetMultiplicativeDepth(multiplicativeDepth);
        }, py::arg("multiplicativeDepth"))
        .def("GetEvalAddCount", [](CryptoContext<DCRTPoly>& self) {
            return GetParamsRNSChecked(self, "GetEvalAddCount")->GetEvalAddCount();
        })
        .def("SetEvalAddCount", [](CryptoContext<DCRTPoly>& self, uint32_t evalAddCount) {
            GetParamsRNSChecked(self, "SetEvalAddCount")->SetEvalAddCount(evalAddCount);
        }, py::arg("evalAddCount"))
        .def("GetKeySwitchCount", [](CryptoContext<DCRTPoly>& self) {
            return GetParamsRNSChecked(self, "GetKeySwitchCount")->GetKeySwitchCount();
        })
        .def("SetKeySwitchCount", [](CryptoContext<DCRTPoly>& self, uint32_t keySwitchCount) {
            GetParamsRNSChecked(self, "SetKeySwitchCount")->SetKeySwitchCount(keySwitchCount);
        }, py::arg("keySwitchCount"))
        .def("GetPRENumHops", [](CryptoContext<DCRTPoly>& self) {
            return GetParamsRNSChecked(self, "GetPRENumHops")->GetPRENumHops();
        })
        .def("SetPRENumHops", [](CryptoContext<DCRTPoly>& self, uint32_t PRENumHops) {
            GetParamsRNSChecked(self, "SetPRENumHops")->SetPRENumHops(PRENumHops);
        }, py::arg("PRENumHops"))
        .def("GetRegisterWordSize", [](CryptoContext<DCRTPoly>& self) {
            return GetParamsRNSChecked(self, "GetRegisterWordSize")->GetRegisterWordSize();
        })
        .def("GetCompositeDegree", [](CryptoContext<DCRTPoly>& self) {
            return GetParamsRNSChecked(self, "GetCompositeDegree")->GetCompositeDegree();
        })
        .def("Enable", static_cast<void (CryptoContextImpl<DCRTPoly>::*)(PKESchemeFeature)>(&CryptoContextImpl<DCRTPoly>::Enable), cc_Enable_docs,
             py::arg("feature"))
        .def("KeyGen", &CryptoContextImpl<DCRTPoly>::KeyGen, cc_KeyGen_docs)
        .def("EvalMultKeyGen", &CryptoContextImpl<DCRTPoly>::EvalMultKeyGen,
             cc_EvalMultKeyGen_docs,
             py::arg("privateKey"))
        .def("EvalMultKeysGen", &CryptoContextImpl<DCRTPoly>::EvalMultKeysGen,
             cc_EvalMultKeysGen_docs,
             py::arg("privateKey"))
        .def("EvalRotateKeyGen", &CryptoContextImpl<DCRTPoly>::EvalRotateKeyGen,
             cc_EvalRotateKeyGen_docs,
             py::arg("privateKey"),
             py::arg("indexList"),
             py::arg("publicKey") = nullptr)
        .def("MakeStringPlaintext", &CryptoContextImpl<DCRTPoly>::MakeStringPlaintext,
             cc_MakeStringPlaintext_docs,
             py::arg("str"))
        .def("MakePackedPlaintext", &CryptoContextImpl<DCRTPoly>::MakePackedPlaintext,
             cc_MakePackedPlaintext_docs,
             py::arg("value"),
             py::arg("noiseScaleDeg") = 1,
             py::arg("level") = 0)
        .def("MakeCoefPackedPlaintext", &CryptoContextImpl<DCRTPoly>::MakeCoefPackedPlaintext,
            cc_MakeCoefPackedPlaintext_docs,
            py::arg("value"),
            py::arg("noiseScaleDeg ") = 1,
            py::arg("level") = 0)
        // TODO (Oliveira): allow user to specify different params values
        .def("MakeCKKSPackedPlaintext", static_cast<Plaintext (CryptoContextImpl<DCRTPoly>::*)(const std::vector<std::complex<double>> &, size_t, uint32_t, const std::shared_ptr<ParmType>, uint32_t) const>(&CryptoContextImpl<DCRTPoly>::MakeCKKSPackedPlaintext), cc_MakeCKKSPackedPlaintextComplex_docs,
             py::arg("value"),
             py::arg("scaleDeg") = static_cast<size_t>(1),
             py::arg("level") = static_cast<uint32_t>(0),
             py::arg("params") = py::none(),
             py::arg("slots") = 0)
        .def("MakeCKKSPackedPlaintext", static_cast<Plaintext (CryptoContextImpl<DCRTPoly>::*)(const std::vector<double> &, size_t, uint32_t, const std::shared_ptr<ParmType>, uint32_t) const>(&CryptoContextImpl<DCRTPoly>::MakeCKKSPackedPlaintext), cc_MakeCKKSPlaintextReal_docs,
             py::arg("value"),
             py::arg("scaleDeg") = static_cast<size_t>(1),
             py::arg("level") = static_cast<uint32_t>(0),
             py::arg("params") = py::none(),
             py::arg("slots") = 0)
        .def("EvalRotate", &CryptoContextImpl<DCRTPoly>::EvalRotate,
            cc_EvalRotate_docs,
            py::arg("ciphertext"),
            py::arg("index"))
        .def("EvalFastRotationPrecompute", &EvalFastRotationPrecomputeWrapper,
            cc_EvalFastRotationPreCompute_docs,
            py::arg("ciphertext"))
        .def("EvalFastRotation", &EvalFastRotationWrapper,
            cc_EvalFastRotation_docs,
            py::arg("ciphertext"),
            py::arg("index"),
            py::arg("m"),
            py::arg("digits"))
        .def("EvalFastRotationExt", &EvalFastRotationExtWrapper, 
            cc_EvalFastRotationExt_docs,
            py::arg("ciphertext"),
            py::arg("index"),
            py::arg("digits"),
            py::arg("addFirst"))
        .def("EvalAtIndexKeyGen", &CryptoContextImpl<DCRTPoly>::EvalAtIndexKeyGen,
            cc_EvalAtIndexKeyGen_docs,
            py::arg("privateKey"),
            py::arg("indexList"),
            py::arg("publicKey") = nullptr)
        .def("EvalAtIndex", &CryptoContextImpl<DCRTPoly>::EvalAtIndex,
            cc_EvalAtIndex_docs,
            py::arg("ciphertext"),
            py::arg("index"))
        .def("Encrypt", static_cast<Ciphertext<DCRTPoly> (CryptoContextImpl<DCRTPoly>::*)(const PublicKey<DCRTPoly>, Plaintext) const>
            (&CryptoContextImpl<DCRTPoly>::Encrypt),
            cc_Encrypt_docs,
            py::arg("publicKey"),
            py::arg("plaintext"))
        .def("Decrypt", static_cast<Plaintext (*)(CryptoContext<DCRTPoly> &, const PrivateKey<DCRTPoly>, ConstCiphertext<DCRTPoly>)>
            (&DecryptWrapper), cc_Decrypt_docs,
            py::arg("privateKey"),
            py::arg("ciphertext"))
        .def("Decrypt", static_cast<Plaintext (*)(CryptoContext<DCRTPoly> &, ConstCiphertext<DCRTPoly>, const PrivateKey<DCRTPoly>)>
            (&DecryptWrapper), cc_Decrypt_docs,
            py::arg("ciphertext"),
            py::arg("privateKey"))
        .def("KeySwitchGen", &CryptoContextImpl<DCRTPoly>::KeySwitchGen,
            cc_KeySwitchGen_docs,
            py::arg("oldPrivateKey"),
            py::arg("newPrivateKey"))
        .def("EvalAdd", static_cast<Ciphertext<DCRTPoly> (CryptoContextImpl<DCRTPoly>::*)(const ConstCiphertext<DCRTPoly>&, const ConstCiphertext<DCRTPoly>&) const>
            (&CryptoContextImpl<DCRTPoly>::EvalAdd), 
            cc_EvalAdd_docs,
            py::arg("ciphertext1"),
            py::arg("ciphertext2"))
        .def("EvalAdd", static_cast<Ciphertext<DCRTPoly> (CryptoContextImpl<DCRTPoly>::*)(const ConstCiphertext<DCRTPoly>&, double) const>
            (&CryptoContextImpl<DCRTPoly>::EvalAdd), 
            cc_EvalAddfloat_docs,
            py::arg("ciphertext"),
            py::arg("scalar"))
        .def("EvalAdd", static_cast<Ciphertext<DCRTPoly> (CryptoContextImpl<DCRTPoly>::*)(const ConstCiphertext<DCRTPoly>&, ConstPlaintext) const>
            (&CryptoContextImpl<DCRTPoly>::EvalAdd),
            cc_EvalAddPlaintext_docs,
            py::arg("ciphertext"),
            py::arg("plaintext"))
        .def("EvalAddInPlace", static_cast<void (CryptoContextImpl<DCRTPoly>::*)(Ciphertext<DCRTPoly>&, const ConstCiphertext<DCRTPoly>&) const>
            (&CryptoContextImpl<DCRTPoly>::EvalAddInPlace),
            cc_EvalAddInPlace_docs,
            py::arg("ciphertext1"),
            py::arg("ciphertext2"))
        .def("EvalAddInPlace", static_cast<void (CryptoContextImpl<DCRTPoly>::*)(Ciphertext<DCRTPoly>&, ConstPlaintext) const>
            (&CryptoContextImpl<DCRTPoly>::EvalAddInPlace),
            cc_EvalAddInPlacePlaintext_docs,
            py::arg("ciphertext"),
            py::arg("plaintext"))
        .def("EvalAddInPlace", static_cast<void (CryptoContextImpl<DCRTPoly>::*)(ConstPlaintext, Ciphertext<DCRTPoly> &) const>
            (&CryptoContextImpl<DCRTPoly>::EvalAddInPlace),
            "",
            py::arg("plaintext"),
            py::arg("ciphertext"))
        .def("EvalAddMutable", static_cast<Ciphertext<DCRTPoly> (CryptoContextImpl<DCRTPoly>::*)(Ciphertext<DCRTPoly> &, Ciphertext<DCRTPoly> &) const>
            (&CryptoContextImpl<DCRTPoly>::EvalAddMutable),
            cc_EvalAddMutable_docs,
            py::arg("ciphertext1"),
            py::arg("ciphertext2"))
        .def("EvalAddMutable", static_cast<Ciphertext<DCRTPoly> (CryptoContextImpl<DCRTPoly>::*)(Ciphertext<DCRTPoly> &, Plaintext) const>
            (&CryptoContextImpl<DCRTPoly>::EvalAddMutable),
            cc_EvalAddMutablePlaintext_docs,
            py::arg("ciphertext"),
            py::arg("plaintext"))
        .def("EvalAddMutable", static_cast<Ciphertext<DCRTPoly> (CryptoContextImpl<DCRTPoly>::*)(Plaintext, Ciphertext<DCRTPoly> &) const>
            (&CryptoContextImpl<DCRTPoly>::EvalAddMutable),
            "",
            py::arg("plaintext"),
            py::arg("ciphertext"))
        .def("EvalAddMutableInPlace", &CryptoContextImpl<DCRTPoly>::EvalAddMutableInPlace,
            cc_EvalAddMutableInPlace_docs,
            py::arg("ciphertext1"),
            py::arg("ciphertext2"))
        .def("EvalSub", static_cast<Ciphertext<DCRTPoly> (CryptoContextImpl<DCRTPoly>::*)(const ConstCiphertext<DCRTPoly>&, const ConstCiphertext<DCRTPoly>&) const>
            (&CryptoContextImpl<DCRTPoly>::EvalSub),
            cc_EvalSub_docs,
            py::arg("ciphertext1"),
            py::arg("ciphertext2"))
        .def("EvalSub", static_cast<Ciphertext<DCRTPoly> (CryptoContextImpl<DCRTPoly>::*)(const ConstCiphertext<DCRTPoly>&, double) const>
            (&CryptoContextImpl<DCRTPoly>::EvalSub),
            cc_EvalSubfloat_docs,
            py::arg("ciphertext"),
            py::arg("scalar"))
        .def("EvalSub", static_cast<Ciphertext<DCRTPoly> (CryptoContextImpl<DCRTPoly>::*)(double, const ConstCiphertext<DCRTPoly>&) const>
            (&CryptoContextImpl<DCRTPoly>::EvalSub),
            "",
            py::arg("scalar"),
            py::arg("ciphertext"))
        .def("EvalSub", static_cast<Ciphertext<DCRTPoly> (CryptoContextImpl<DCRTPoly>::*)(const ConstCiphertext<DCRTPoly>&, ConstPlaintext) const>
            (&CryptoContextImpl<DCRTPoly>::EvalSub),
            cc_EvalSubPlaintext_docs,
            py::arg("ciphertext"),
            py::arg("plaintext"))
        .def("EvalSub", static_cast<Ciphertext<DCRTPoly> (CryptoContextImpl<DCRTPoly>::*)(ConstPlaintext, const ConstCiphertext<DCRTPoly>&) const>
            (&CryptoContextImpl<DCRTPoly>::EvalSub),
            "",
            py::arg("plaintext"),
            py::arg("ciphertext"))
        .def("EvalSubInPlace", static_cast<void (CryptoContextImpl<DCRTPoly>::*)(Ciphertext<DCRTPoly> &, const ConstCiphertext<DCRTPoly>&) const>
            (&CryptoContextImpl<DCRTPoly>::EvalSubInPlace),
            cc_EvalSubInPlace_docs,
            py::arg("ciphertext1"),
            py::arg("ciphertext2"))
        .def("EvalSubInPlace", static_cast<void (CryptoContextImpl<DCRTPoly>::*)(Ciphertext<DCRTPoly> &, double) const>
            (&CryptoContextImpl<DCRTPoly>::EvalSubInPlace),
            cc_EvalSubInPlacefloat_docs,
            py::arg("ciphertext"),
            py::arg("scalar"))
        .def("EvalSubInPlace", static_cast<void (CryptoContextImpl<DCRTPoly>::*)(double, Ciphertext<DCRTPoly> &) const>
            (&CryptoContextImpl<DCRTPoly>::EvalSubInPlace),
            "",
            py::arg("scalar"),
            py::arg("ciphertext"))
        .def("EvalSubMutable", static_cast<Ciphertext<DCRTPoly> (CryptoContextImpl<DCRTPoly>::*)(Ciphertext<DCRTPoly> &, Ciphertext<DCRTPoly> &) const>
            (&CryptoContextImpl<DCRTPoly>::EvalSubMutable),
            cc_EvalSubMutable_docs,
            py::arg("ciphertext1"),
            py::arg("ciphertext2"))
        .def("EvalSubMutable", static_cast<Ciphertext<DCRTPoly> (CryptoContextImpl<DCRTPoly>::*)(Ciphertext<DCRTPoly> &, Plaintext) const>
            (&CryptoContextImpl<DCRTPoly>::EvalSubMutable),
            cc_EvalSubMutablePlaintext_docs,
            py::arg("ciphertext"),
            py::arg("plaintext"))
        .def("EvalSubMutable", static_cast<Ciphertext<DCRTPoly> (CryptoContextImpl<DCRTPoly>::*)(Plaintext, Ciphertext<DCRTPoly> &) const>
            (&CryptoContextImpl<DCRTPoly>::EvalSubMutable),
            "",
            py::arg("plaintext"),
            py::arg("ciphertext"))
        .def("EvalSubMutableInPlace", &CryptoContextImpl<DCRTPoly>::EvalSubMutableInPlace,
            cc_EvalSubMutableInPlace_docs,
            py::arg("ciphertext1"),
            py::arg("ciphertext2"))
        .def("EvalMult", static_cast<Ciphertext<DCRTPoly> (CryptoContextImpl<DCRTPoly>::*)(const ConstCiphertext<DCRTPoly>&, const ConstCiphertext<DCRTPoly>&) const>
            (&CryptoContextImpl<DCRTPoly>::EvalMult),
            cc_EvalMult_docs,
            py::arg("ciphertext1"),
            py::arg("ciphertext2"))
        .def("EvalMult", static_cast<Ciphertext<DCRTPoly> (CryptoContextImpl<DCRTPoly>::*)(const ConstCiphertext<DCRTPoly>&, double) const>
            (&CryptoContextImpl<DCRTPoly>::EvalMult),
            cc_EvalMultfloat_docs,
            py::arg("ciphertext"),
            py::arg("scalar"))
        .def("EvalMult", static_cast<Ciphertext<DCRTPoly> (CryptoContextImpl<DCRTPoly>::*)(const ConstCiphertext<DCRTPoly>&, ConstPlaintext) const>
            (&CryptoContextImpl<DCRTPoly>::EvalMult),
            cc_EvalMultPlaintext_docs,
            py::arg("ciphertext"),
            py::arg("plaintext"))
        .def("EvalMult", static_cast<Ciphertext<DCRTPoly> (CryptoContextImpl<DCRTPoly>::*)(ConstPlaintext, const ConstCiphertext<DCRTPoly>&) const>
            (&CryptoContextImpl<DCRTPoly>::EvalMult),
            "",
            py::arg("plaintext"),
            py::arg("ciphertext"))
        .def("EvalMult", static_cast<Ciphertext<DCRTPoly> (CryptoContextImpl<DCRTPoly>::*)(double, const ConstCiphertext<DCRTPoly>&) const>
            (&CryptoContextImpl<DCRTPoly>::EvalMult),
            "",
            py::arg("scalar"),
            py::arg("ciphertext"))
        .def("EvalMultMutable", static_cast<Ciphertext<DCRTPoly> (CryptoContextImpl<DCRTPoly>::*)(Ciphertext<DCRTPoly> &, Ciphertext<DCRTPoly> &) const>
            (&CryptoContextImpl<DCRTPoly>::EvalMultMutable),
            cc_EvalMultMutable_docs,
            py::arg("ciphertext1"),
            py::arg("ciphertext2"))
        .def("EvalMultMutable", static_cast<Ciphertext<DCRTPoly> (CryptoContextImpl<DCRTPoly>::*)(Ciphertext<DCRTPoly> &, Plaintext) const>
            (&CryptoContextImpl<DCRTPoly>::EvalMultMutable),
            cc_EvalMultMutablePlaintext_docs,
            py::arg("ciphertext"),
            py::arg("plaintext"))
        .def("EvalMultMutable", static_cast<Ciphertext<DCRTPoly> (CryptoContextImpl<DCRTPoly>::*)(Plaintext, Ciphertext<DCRTPoly> &) const>
            (&CryptoContextImpl<DCRTPoly>::EvalMultMutable),
            "",
            py::arg("plaintext"),
            py::arg("ciphertext"))
        .def("EvalMultMutableInPlace", &CryptoContextImpl<DCRTPoly>::EvalMultMutableInPlace,
            cc_EvalMultMutableInPlace_docs,
            py::arg("ciphertext1"),
            py::arg("ciphertext2"))
        .def("EvalSquare", &CryptoContextImpl<DCRTPoly>::EvalSquare,
            cc_EvalSquare_docs,
            py::arg("ciphertext"))
        .def("EvalSquareMutable", &CryptoContextImpl<DCRTPoly>::EvalSquareMutable,
            cc_EvalSquareMutable_docs,
            py::arg("ciphertext"))
        .def("EvalSquareInPlace", &CryptoContextImpl<DCRTPoly>::EvalSquareInPlace,
            cc_EvalSquareInPlace_docs,
            py::arg("ciphertext"))
        .def("EvalMultNoRelin", &CryptoContextImpl<DCRTPoly>::EvalMultNoRelin,
            cc_EvalMultNoRelin_docs,
            py::arg("ciphertext1"),
            py::arg("ciphertext2"))
        .def("Relinearize", &CryptoContextImpl<DCRTPoly>::Relinearize,
            cc_Relinearize_docs,
            py::arg("ciphertext"))
        .def("RelinearizeInPlace", &CryptoContextImpl<DCRTPoly>::RelinearizeInPlace,
            cc_RelinearizeInPlace_docs,
            py::arg("ciphertext"))
        .def("EvalMultAndRelinearize", &CryptoContextImpl<DCRTPoly>::EvalMultAndRelinearize,
            cc_EvalMultAndRelinearize_docs,
            py::arg("ciphertext1"),
            py::arg("ciphertext2"))
        .def("EvalNegate", &CryptoContextImpl<DCRTPoly>::EvalNegate,
            cc_EvalNegate_docs,
            py::arg("ciphertext"))
        .def("EvalNegateInPlace", &CryptoContextImpl<DCRTPoly>::EvalNegateInPlace,
            cc_EvalNegateInPlace_docs,
            py::arg("ciphertext"))
        .def("EvalLogistic", &CryptoContextImpl<DCRTPoly>::EvalLogistic,
            cc_EvalLogistic_docs,
            py::arg("ciphertext"),
            py::arg("a"),
            py::arg("b"),
            py::arg("degree"))
        .def("EvalChebyshevSeries", &CryptoContextImpl<DCRTPoly>::EvalChebyshevSeries,
            cc_EvalChebyshevSeries_docs,
            py::arg("ciphertext"),
            py::arg("coefficients"),
            py::arg("a"),
            py::arg("b"))
        .def("EvalChebyshevSeriesLinear", &CryptoContextImpl<DCRTPoly>::EvalChebyshevSeriesLinear,
            cc_EvalChebyshevSeriesLinear_docs,
            py::arg("ciphertext"),
            py::arg("coefficients"),
            py::arg("a"),
            py::arg("b"))
        .def("EvalChebyshevSeriesPS", &CryptoContextImpl<DCRTPoly>::EvalChebyshevSeriesPS,
            cc_EvalChebyshevSeriesPS_docs,
            py::arg("ciphertext"),
            py::arg("coefficients"),
            py::arg("a"),
            py::arg("b"))
        .def("EvalChebyshevFunction", &CryptoContextImpl<DCRTPoly>::EvalChebyshevFunction,
            cc_EvalChebyshevFunction_docs,
             py::arg("func"),
             py::arg("ciphertext"),
             py::arg("a"),
             py::arg("b"),
             py::arg("degree"))
        .def("EvalSin", &CryptoContextImpl<DCRTPoly>::EvalSin,
             cc_EvalSin_docs,
             py::arg("ciphertext"),
             py::arg("a"),
             py::arg("b"),
             py::arg("degree"))
        .def("EvalCos", &CryptoContextImpl<DCRTPoly>::EvalCos,
             cc_EvalCos_docs,
             py::arg("ciphertext"),
             py::arg("a"),
             py::arg("b"),
             py::arg("degree"))
        .def("EvalDivide", &CryptoContextImpl<DCRTPoly>::EvalDivide,
             cc_EvalDivide_docs,
             py::arg("ciphertext"),
             py::arg("a"),
             py::arg("b"),
             py::arg("degree"))
        .def("EvalSumKeyGen", &CryptoContextImpl<DCRTPoly>::EvalSumKeyGen,
             cc_EvalSumKeyGen_docs,
             py::arg("privateKey"),
             py::arg("publicKey") = py::none())
        //TODO (Oliveira, R.): Solve pointer handling bug when dealing with EvalKeyMap object for the next functions 
        .def("EvalSumRowsKeyGen", &CryptoContextImpl<DCRTPoly>::EvalSumRowsKeyGen,
             cc_EvalSumRowsKeyGen_docs,
             py::arg("privateKey"),
             py::arg("publicKey") = py::none(),
             py::arg("rowSize") = 0,
             py::arg("subringDim") = 0)
        .def("EvalSumColsKeyGen", &CryptoContextImpl<DCRTPoly>::EvalSumColsKeyGen,
             cc_EvalSumColsKeyGen_docs,
             py::arg("privateKey"),
             py::arg("publicKey") = py::none())
        .def("EvalSum", &CryptoContextImpl<DCRTPoly>::EvalSum,
             cc_EvalSum_docs,
             py::arg("ciphertext"),
             py::arg("batchSize"))
        .def("EvalSumRows", &CryptoContextImpl<DCRTPoly>::EvalSumRows,
             cc_EvalSumRows_docs,
             py::arg("ciphertext"),
             py::arg("numRows"),
             py::arg("evalSumKeyMap"),
             py::arg("subringDim") = 0)
        .def("EvalSumCols", &CryptoContextImpl<DCRTPoly>::EvalSumCols,
             cc_EvalSumCols_docs,
             py::arg("ciphertext"),
             py::arg("numCols"),
             py::arg("evalSumKeyMap"))
        .def("EvalInnerProduct", static_cast<Ciphertext<DCRTPoly> (CryptoContextImpl<DCRTPoly>::*)(const ConstCiphertext<DCRTPoly>&, const ConstCiphertext<DCRTPoly>&, uint32_t) const>(&CryptoContextImpl<DCRTPoly>::EvalInnerProduct),
             cc_EvalInnerProduct_docs,
             py::arg("ciphertext1"),
             py::arg("ciphertext2"),
             py::arg("batchSize"))
        .def("EvalInnerProduct", static_cast<Ciphertext<DCRTPoly> (CryptoContextImpl<DCRTPoly>::*)(const ConstCiphertext<DCRTPoly>&, ConstPlaintext, uint32_t) const>(&CryptoContextImpl<DCRTPoly>::EvalInnerProduct),
             cc_EvalInnerProductPlaintext_docs,
             py::arg("ciphertext"),
             py::arg("plaintext"),
             py::arg("batchSize"))
        .def("MultipartyKeyGen", static_cast<KeyPair<DCRTPoly> (CryptoContextImpl<DCRTPoly>::*)(const PublicKey<DCRTPoly>, bool, bool)>(&CryptoContextImpl<DCRTPoly>::MultipartyKeyGen),
             cc_MultipartyKeyGen_docs,
             py::arg("publicKey"),
             py::arg("makeSparse") = false,
             py::arg("fresh") = false)
        .def("MultipartyKeyGen", static_cast<KeyPair<DCRTPoly> (CryptoContextImpl<DCRTPoly>::*)(const std::vector<PrivateKey<DCRTPoly>> &)>(&CryptoContextImpl<DCRTPoly>::MultipartyKeyGen),
             cc_MultipartyKeyGen_vector_docs,
             py::arg("privateKeyVec"))
        .def("MultipartyDecryptLead", &CryptoContextImpl<DCRTPoly>::MultipartyDecryptLead,
             cc_MultipartyDecryptLead_docs,
             py::arg("ciphertextVec"),
             py::arg("privateKey"))
        .def("MultipartyDecryptMain", &CryptoContextImpl<DCRTPoly>::MultipartyDecryptMain,
            cc_MultipartyDecryptMain_docs,
            py::arg("ciphertextVec"),
            py::arg("privateKey"))
        .def("MultipartyDecryptFusion", &MultipartyDecryptFusionWrapper,
            cc_MultipartyDecryptFusion_docs,
            py::arg("ciphertextVec"))
        .def("MultiKeySwitchGen", &CryptoContextImpl<DCRTPoly>::MultiKeySwitchGen,
             cc_MultiKeySwitchGen_docs,
             py::arg("originalPrivateKey"),
             py::arg("newPrivateKey"),
             py::arg("evalKey"))
        .def("MultiEvalAtIndexKeyGen",
            [](CryptoContextImpl<DCRTPoly>* self,
                const PrivateKey<DCRTPoly>& privateKey,
                std::shared_ptr<std::map<unsigned int, EvalKey<DCRTPoly>>> evalKeyMap,
                const std::vector<int32_t>& indexList,
                const std::string& keyTag = "") {
              return self->MultiEvalAtIndexKeyGen(privateKey, evalKeyMap, indexList, keyTag);
             },
             cc_MultiEvalAtIndexKeyGen_docs,
             py::arg("privateKey"),
             py::arg("evalKeyMap"),
             py::arg("indexList"),
             py::arg("keyTag") = "")
        .def("MultiEvalSumKeyGen", &CryptoContextImpl<DCRTPoly>::MultiEvalSumKeyGen,
             cc_MultiEvalSumKeyGen_docs,
             py::arg("privateKey"),
             py::arg("evalKeyMap"),
             py::arg("keyTag") = "")
        .def("MultiAddEvalAutomorphismKeys", &CryptoContextImpl<DCRTPoly>::MultiAddEvalAutomorphismKeys,
            cc_MultiAddEvalAutomorphismKeys_docs,
            py::arg("evalKeyMap1"),
            py::arg("evalKeyMap1"),
            py::arg("keyTag") = "")
        .def("MultiAddPubKeys", &CryptoContextImpl<DCRTPoly>::MultiAddPubKeys,
            cc_MultiAddPubKeys_docs,
            py::arg("publicKey1"),
            py::arg("publicKey2"),
            py::arg("keyTag") = "")
        .def("MultiAddEvalKeys", &CryptoContextImpl<DCRTPoly>::MultiAddEvalKeys,
             cc_MultiAddEvalKeys_docs,
             py::arg("evalKey1"),
             py::arg("evalKey2"),
             py::arg("keyTag") = "")
        .def("MultiAddEvalMultKeys", &CryptoContextImpl<DCRTPoly>::MultiAddEvalMultKeys,
             cc_MultiAddEvalMultKeys_docs,
             py::arg("evalKey1"),
             py::arg("evalKey2"),
             py::arg("keyTag") = "")
        .def("IntBootDecrypt",&CryptoContextImpl<DCRTPoly>::IntBootDecrypt,
            cc_IntBootDecrypt_docs,
            py::arg("privateKey"),
            py::arg("ciphertext"))
        .def("IntBootEncrypt",&CryptoContextImpl<DCRTPoly>::IntBootEncrypt,
            cc_IntBootEncrypt_docs,
            py::arg("publicKey"),
            py::arg("ciphertext"))
        .def("IntBootAdd",&CryptoContextImpl<DCRTPoly>::IntBootAdd,
            cc_IntBootAdd_docs,
            py::arg("ciphertext1"),
            py::arg("ciphertext2"))
        .def("IntBootAdjustScale",&CryptoContextImpl<DCRTPoly>::IntBootAdjustScale,
            cc_IntBootAdjustScale_docs,
            py::arg("ciphertext"))
        .def("IntMPBootAdjustScale",&CryptoContextImpl<DCRTPoly>::IntMPBootAdjustScale,
             cc_IntMPBootAdjustScale_docs,
             py::arg("ciphertext"))
        .def("IntMPBootRandomElementGen", &CryptoContextImpl<DCRTPoly>::IntMPBootRandomElementGen,
             cc_IntMPBootRandomElementGen_docs,
             py::arg("publicKey"))
        .def("IntMPBootDecrypt", &CryptoContextImpl<DCRTPoly>::IntMPBootDecrypt,
             cc_IntMPBootDecrypt_docs,
             py::arg("privateKey"),
             py::arg("ciphertext"),
             py::arg("a"))
        .def("IntMPBootAdd", &CryptoContextImpl<DCRTPoly>::IntMPBootAdd,
             cc_IntMPBootAdd_docs,
             py::arg("sharePairVec"))
        .def("IntMPBootEncrypt", &CryptoContextImpl<DCRTPoly>::IntMPBootEncrypt,
             cc_IntMPBootEncrypt_docs,
             py::arg("publicKey"),
             py::arg("sharePair"),
             py::arg("a"),
             py::arg("ciphertext"))             
        .def("MultiMultEvalKey", &CryptoContextImpl<DCRTPoly>::MultiMultEvalKey,
             cc_MultiMultEvalKey_docs,
             py::arg("privateKey"),
             py::arg("evalKey"),
             py::arg("keyTag") = "")
        .def("MultiAddEvalSumKeys", &CryptoContextImpl<DCRTPoly>::MultiAddEvalSumKeys,
             cc_MultiAddEvalSumKeys_docs,
             py::arg("evalKeyMap1"),
             py::arg("evalKeyMap2"),
             py::arg("keyTag") = "")
        .def("EvalMerge", &CryptoContextImpl<DCRTPoly>::EvalMerge,
             cc_EvalMerge_docs,
             py::arg("ciphertextVec"))
             // use static_cast: inline EvalKey<Element> ReKeyGen(const PrivateKey<Element> oldPrivateKey, const PublicKey<Element> newPublicKey) const;
        .def("ReKeyGen", static_cast<EvalKey<DCRTPoly> (CryptoContextImpl<DCRTPoly>::*)(const PrivateKey<DCRTPoly>, const PublicKey<DCRTPoly>) const>(&CryptoContextImpl<DCRTPoly>::ReKeyGen),
             cc_ReKeyGen_docs,
             py::arg("oldPrivateKey"),
             py::arg("newPublicKey"))
        .def("ReEncrypt", &CryptoContextImpl<DCRTPoly>::ReEncrypt,
             cc_ReEncrypt_docs,
             py::arg("ciphertext"),
             py::arg("evalKey"),
             py::arg("publicKey") = nullptr)
        .def("EvalPoly", &CryptoContextImpl<DCRTPoly>::EvalPoly,
             cc_EvalPoly_docs,
             py::arg("ciphertext"),
             py::arg("coefficients"))
        .def("EvalPolyLinear", &CryptoContextImpl<DCRTPoly>::EvalPolyLinear,
             cc_EvalPolyLinear_docs,
             py::arg("ciphertext"),
             py::arg("coefficients"))
        .def("EvalPolyPS", &CryptoContextImpl<DCRTPoly>::EvalPolyPS,
             cc_EvalPolyPS_docs,
             py::arg("ciphertext"),
             py::arg("coefficients"))
        .def("Rescale", &CryptoContextImpl<DCRTPoly>::Rescale,
             cc_Rescale_docs,
             py::arg("ciphertext"))
        .def("RescaleInPlace", &CryptoContextImpl<DCRTPoly>::RescaleInPlace,
             cc_RescaleInPlace_docs,
             py::arg("ciphertext"))
        .def("ModReduce", &CryptoContextImpl<DCRTPoly>::ModReduce,
             cc_ModReduce_docs,
             py::arg("ciphertext"))
        .def("ModReduceInPlace", &CryptoContextImpl<DCRTPoly>::ModReduceInPlace,
             cc_ModReduceInPlace_docs,
             py::arg("ciphertext"))
        .def("EvalBootstrapSetup", &CryptoContextImpl<DCRTPoly>::EvalBootstrapSetup,
             cc_EvalBootstrapSetup_docs,
             py::arg("levelBudget") = std::vector<uint32_t>({5, 4}),
             py::arg("dim1") = std::vector<uint32_t>({0, 0}),
             py::arg("slots") = 0,
             py::arg("correctionFactor") = 0,
             py::arg("precompute")= true)
        .def("EvalBootstrapKeyGen", &CryptoContextImpl<DCRTPoly>::EvalBootstrapKeyGen,
             cc_EvalBootstrapKeyGen_docs,
             py::arg("privateKey"),
             py::arg("slots"))
        .def("EvalBootstrap", &CryptoContextImpl<DCRTPoly>::EvalBootstrap,
             cc_EvalBootstrap_docs,
             py::arg("ciphertext"),
             py::arg("numIterations") = 1,
             py::arg("precision") = 0)
        .def("EvalCKKStoFHEWSetup", &CryptoContextImpl<DCRTPoly>::EvalCKKStoFHEWSetup,
            cc_EvalCKKStoFHEWSetup_docs,
            py::arg("schswchparams"))
        .def("EvalCKKStoFHEWKeyGen", &CryptoContextImpl<DCRTPoly>::EvalCKKStoFHEWKeyGen,
             cc_EvalCKKStoFHEWKeyGen_docs,
             py::arg("keyPair"),
             py::arg("lwesk"))
        .def("EvalCKKStoFHEWPrecompute", &CryptoContextImpl<DCRTPoly>::EvalCKKStoFHEWPrecompute,
             cc_EvalCKKStoFHEWPrecompute_docs,
             py::arg("scale") = 1.0)
        .def("EvalCKKStoFHEW", &CryptoContextImpl<DCRTPoly>::EvalCKKStoFHEW,
             cc_EvalCKKStoFHEW_docs,
             py::arg("ciphertext"),
             py::arg("numCtxts") = 0)
        .def("EvalFHEWtoCKKSSetup", &CryptoContextImpl<DCRTPoly>::EvalFHEWtoCKKSSetup,
             cc_EvalFHEWtoCKKSSetup_docs,
             py::arg("ccLWE"),
             py::arg("numSlotsCKKS") = 0,
             py::arg("logQ") = 25)
        .def("EvalFHEWtoCKKSKeyGen", &CryptoContextImpl<DCRTPoly>::EvalFHEWtoCKKSKeyGen,
             cc_EvalFHEWtoCKKSKeyGen_docs,
             py::arg("keyPair"),
             py::arg("lwesk"),
             py::arg("numSlots") = 0,
             py::arg("numCtxts") = 0,
             py::arg("dim1") = 0,
             py::arg("L") = 0)
        .def("EvalFHEWtoCKKS", &CryptoContextImpl<DCRTPoly>::EvalFHEWtoCKKS,
             cc_EvalFHEWtoCKKS_docs,
             py::arg("LWECiphertexts"),
             py::arg("numCtxts") = 0,
             py::arg("numSlots") = 0,
             py::arg("p") = 4,
             py::arg("pmin") = 0.0,
             py::arg("pmax") = 2.0,
             py::arg("dim1") = 0)
        .def("EvalSchemeSwitchingSetup", &CryptoContextImpl<DCRTPoly>::EvalSchemeSwitchingSetup,
             cc_EvalSchemeSwitchingSetup_docs,
             py::arg("schswchparams"))
        //void EvalSchemeSwitchingKeyGen(const KeyPair<Element> &keyPair, ConstLWEPrivateKey &lwesk, uint32_t numValues = 0, bool oneHot = true, bool alt = false, uint32_t dim1CF = 0, uint32_t dim1FC = 0, uint32_t LCF = 1, uint32_t LFC = 0)
        .def("EvalSchemeSwitchingKeyGen", &CryptoContextImpl<DCRTPoly>::EvalSchemeSwitchingKeyGen,
             cc_EvalSchemeSwitchingKeyGen_docs,
             py::arg("keyPair"),
             py::arg("lwesk"))
        .def("EvalCompareSwitchPrecompute", &CryptoContextImpl<DCRTPoly>::EvalCompareSwitchPrecompute,
             cc_EvalCompareSwitchPrecompute_docs,
             py::arg("pLWE") = 0,
             py::arg("scaleSign") = 1.0,
             py::arg("unit") = false)
        .def("EvalCompareSchemeSwitching", &CryptoContextImpl<DCRTPoly>::EvalCompareSchemeSwitching,
             cc_EvalCompareSchemeSwitching_docs,
             py::arg("ciphertext1"),
             py::arg("ciphertext2"),
             py::arg("numCtxts") = 0,
             py::arg("numSlots") = 0,
             py::arg("pLWE") = 0,
             py::arg("scaleSign") = 1.0,
             py::arg("unit") = false)
        .def("EvalMinSchemeSwitching", &CryptoContextImpl<DCRTPoly>::EvalMinSchemeSwitching,
             cc_EvalMinSchemeSwitching_docs,
             py::arg("ciphertext"),
             py::arg("publicKey"),
             py::arg("numValues") = 0,
             py::arg("numSlots") = 0,
             py::arg("pLWE") = 0,
             py::arg("scaleSign") = 1.0)
        .def("EvalMinSchemeSwitchingAlt", &CryptoContextImpl<DCRTPoly>::EvalMinSchemeSwitchingAlt,
             cc_EvalMinSchemeSwitchingAlt_docs,
             py::arg("ciphertext"),
             py::arg("publicKey"),
             py::arg("numValues") = 0,
             py::arg("numSlots") = 0,
             py::arg("pLWE") = 0,
             py::arg("scaleSign") = 1.0)
        .def("EvalMaxSchemeSwitching", &CryptoContextImpl<DCRTPoly>::EvalMaxSchemeSwitching,
             cc_EvalMaxSchemeSwitching_docs,
             py::arg("ciphertext"),
             py::arg("publicKey"),
             py::arg("numValues") = 0,
             py::arg("numSlots") = 0,
             py::arg("pLWE") = 0,
             py::arg("scaleSign") = 1.0)
        .def("EvalMaxSchemeSwitchingAlt", &CryptoContextImpl<DCRTPoly>::EvalMaxSchemeSwitchingAlt,
             cc_EvalMaxSchemeSwitchingAlt_docs,
             py::arg("ciphertext"),
             py::arg("publicKey"),
             py::arg("numValues") = 0,
             py::arg("numSlots") = 0,
             py::arg("pLWE") = 0,
             py::arg("scaleSign") = 1.0)
        //TODO (Oliveira, R.): Solve pointer handling bug when returning EvalKeyMap objects for the next functions
        .def("EvalAutomorphismKeyGen",
            static_cast<std::shared_ptr<std::map<uint32_t, EvalKey<DCRTPoly>>> (CryptoContextImpl<DCRTPoly>::*)(const PrivateKey<DCRTPoly>, const std::vector<uint32_t>&) const>
            (&CryptoContextImpl<DCRTPoly>::EvalAutomorphismKeyGen), 
            cc_EvalAutomorphismKeyGen_docs,
            py::arg("privateKey"),
            py::arg("indexList"))
        .def("EvalLinearWSumMutable",
            static_cast<lbcrypto::Ciphertext<DCRTPoly> (lbcrypto::CryptoContextImpl<DCRTPoly>::*)(
                const std::vector<double>&,
                std::vector<std::shared_ptr<lbcrypto::CiphertextImpl<DCRTPoly> > >&
            ) const>(
            &CryptoContextImpl<DCRTPoly>::EvalLinearWSumMutable),
             py::arg("ciphertext"),
             py::arg("coefficients"))
        .def("EvalLinearWSum",
            static_cast<lbcrypto::Ciphertext<DCRTPoly> (lbcrypto::CryptoContextImpl<DCRTPoly>::*)(
            std::vector<std::shared_ptr<const lbcrypto::CiphertextImpl<DCRTPoly> > >&,const std::vector<double>&) const>(
            &CryptoContextImpl<DCRTPoly>::EvalLinearWSum),
             py::arg("ciphertext"),
             py::arg("coefficients"))
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
            cc_FindAutomorphismIndex_docs,
            py::arg("idx"))
        .def("FindAutomorphismIndices", &CryptoContextImpl<DCRTPoly>::FindAutomorphismIndices,
            cc_FindAutomorphismIndices_docs,
            py::arg("idxList"))
        .def("GetEvalSumKeyMap", &GetEvalSumKeyMapWrapper,
            cc_GetEvalSumKeyMap_docs)
        .def("GetBinCCForSchemeSwitch", &CryptoContextImpl<DCRTPoly>::GetBinCCForSchemeSwitch)
        .def_static(
            "InsertEvalSumKey", &CryptoContextImpl<DCRTPoly>::InsertEvalSumKey,
            cc_InsertEvalSumKey_docs,
            py::arg("evalKeyMap"),
            py::arg("keyTag") = "")
        .def_static(
            "InsertEvalMultKey", &CryptoContextImpl<DCRTPoly>::InsertEvalMultKey,
            cc_InsertEvalMultKey_docs,
            py::arg("evalKeyVec"),
            py::arg("keyTag") = "")
        .def_static(
            "InsertEvalAutomorphismKey", &CryptoContextImpl<DCRTPoly>::InsertEvalAutomorphismKey,
            cc_InsertEvalAutomorphismKey_docs,
            py::arg("evalKeyMap"),
            py::arg("keyTag") = "")
        .def_static(
            "ClearEvalAutomorphismKeys", []()
            { CryptoContextImpl<DCRTPoly>::ClearEvalAutomorphismKeys(); },
            cc_ClearEvalAutomorphismKeys_docs)
        // it is safer to return by value instead of by reference (GetEvalMultKeyVector returns a const reference to std::vector)
        .def_static("GetEvalMultKeyVector",
            [](const std::string& keyTag) {
              return CryptoContextImpl<DCRTPoly>::GetEvalMultKeyVector(keyTag);
            },
            cc_GetEvalMultKeyVector_docs,
            py::arg("keyTag") = "")
        .def_static("GetEvalAutomorphismKeyMap", &CryptoContextImpl<DCRTPoly>::GetEvalAutomorphismKeyMapPtr,
            cc_GetEvalAutomorphismKeyMap_docs,
            py::arg("keyTag") = "")
        .def_static(
            "SerializeEvalMultKey", [](const std::string &filename, const SerType::SERBINARY &sertype, std::string keyTag = "")
            {
              std::ofstream outfile(filename, std::ios::out | std::ios::binary);
              bool res = CryptoContextImpl<DCRTPoly>::SerializeEvalMultKey<SerType::SERBINARY>(outfile, sertype, keyTag);
              outfile.close();
              return res; },
            cc_SerializeEvalMultKey_docs,
            py::arg("filename"), py::arg("sertype"), py::arg("keyTag") = "")
        .def_static( // SerializeEvalMultKey - JSON
            "SerializeEvalMultKey", [](const std::string &filename, const SerType::SERJSON &sertype, std::string keyTag = "")
            {
              std::ofstream outfile(filename, std::ios::out | std::ios::binary);
              bool res = CryptoContextImpl<DCRTPoly>::SerializeEvalMultKey<SerType::SERJSON>(outfile, sertype, keyTag);
              outfile.close();
              return res; },
            cc_SerializeEvalMultKey_docs,
            py::arg("filename"), py::arg("sertype"), py::arg("keyTag") = "")
        .def_static( // SerializeEvalAutomorphismKey - Binary
            "SerializeEvalAutomorphismKey", [](const std::string &filename, const SerType::SERBINARY &sertype, std::string keyTag = "")
            {
              std::ofstream outfile(filename, std::ios::out | std::ios::binary);
              bool res = CryptoContextImpl<DCRTPoly>::SerializeEvalAutomorphismKey<SerType::SERBINARY>(outfile, sertype, keyTag);
              outfile.close();
              return res; },
            cc_SerializeEvalAutomorphismKey_docs,
            py::arg("filename"), py::arg("sertype"), py::arg("keyTag") = "")
        .def_static( // SerializeEvalAutomorphismKey - JSON
            "SerializeEvalAutomorphismKey", [](const std::string &filename, const SerType::SERJSON &sertype, std::string keyTag = "")
            {
              std::ofstream outfile(filename, std::ios::out | std::ios::binary);
              bool res = CryptoContextImpl<DCRTPoly>::SerializeEvalAutomorphismKey<SerType::SERJSON>(outfile, sertype, keyTag);
              outfile.close();
              return res; },
            cc_SerializeEvalAutomorphismKey_docs,
            py::arg("filename"), py::arg("sertype"), py::arg("keyTag") = "")
        .def_static("DeserializeEvalMultKey", // DeserializeEvalMultKey - Binary
        [](const std::string &filename, const SerType::SERBINARY &sertype)
                    {
              std::ifstream emkeys(filename, std::ios::in | std::ios::binary);
              if (!emkeys.is_open()) {
                std::cerr << "I cannot read serialization from " << filename << std::endl;
              }
              bool res = CryptoContextImpl<DCRTPoly>::DeserializeEvalMultKey<SerType::SERBINARY>(emkeys, sertype);
              return res; 
                        },
                        cc_DeserializeEvalMultKey_docs,
                        py::arg("filename"), py::arg("sertype"))
        .def_static("DeserializeEvalMultKey", // DeserializeEvalMultKey - JSON
        [](const std::string &filename, const SerType::SERJSON &sertype)
                    {
              std::ifstream emkeys(filename, std::ios::in | std::ios::binary);
              if (!emkeys.is_open()) {
                std::cerr << "I cannot read serialization from " << filename << std::endl;
              }
              bool res = CryptoContextImpl<DCRTPoly>::DeserializeEvalMultKey<SerType::SERJSON>(emkeys, sertype);
              return res; },
                        cc_DeserializeEvalMultKey_docs,
                        py::arg("filename"), py::arg("sertype"))
        .def_static("DeserializeEvalAutomorphismKey", // DeserializeEvalAutomorphismKey - Binary
        [](const std::string &filename, const SerType::SERBINARY &sertype)
                    {
              std::ifstream erkeys(filename, std::ios::in | std::ios::binary);
              if (!erkeys.is_open()) {
                std::cerr << "I cannot read serialization from " << filename << std::endl;
              }
              bool res = CryptoContextImpl<DCRTPoly>::DeserializeEvalAutomorphismKey<SerType::SERBINARY>(erkeys, sertype);
              return res; },
                        cc_DeserializeEvalAutomorphismKey_docs,
                        py::arg("filename"), py::arg("sertype"))
        .def_static("DeserializeEvalAutomorphismKey", // DeserializeEvalAutomorphismKey - JSON
        [](const std::string &filename, const SerType::SERJSON &sertype)
                    {
              std::ifstream erkeys(filename, std::ios::in | std::ios::binary);
              if (!erkeys.is_open()) {
                std::cerr << "I cannot read serialization from " << filename << std::endl;
              }
              bool res = CryptoContextImpl<DCRTPoly>::DeserializeEvalAutomorphismKey<SerType::SERJSON>(erkeys, sertype);
              return res; },
                        cc_DeserializeEvalAutomorphismKey_docs,
                        py::arg("filename"), py::arg("sertype"));

    // Generator Functions
    m.def("GenCryptoContext", &GenCryptoContext<CryptoContextBFVRNS>,
        py::arg("params"));
    m.def("GenCryptoContext", &GenCryptoContext<CryptoContextBGVRNS>,
        py::arg("params"));
    m.def("GenCryptoContext", &GenCryptoContext<CryptoContextCKKSRNS>,
        py::arg("params"));

    m.def("GetAllContexts", &CryptoContextFactory<DCRTPoly>::GetAllContexts);

    m.def("ReleaseAllContexts", &CryptoContextFactory<DCRTPoly>::ReleaseAllContexts);
    m.def("ClearEvalMultKeys", &ClearEvalMultKeysWrapper);
}

int get_native_int(){
    #if NATIVEINT == 128 && !defined(__EMSCRIPTEN__)
        return 128;
    #elif NATIVEINT == 32
        return 32;
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

void bind_keys(py::module &m)
{
    py::class_<PublicKeyImpl<DCRTPoly>, std::shared_ptr<PublicKeyImpl<DCRTPoly>>>(m, "PublicKey")
        .def(py::init<>())
        .def("GetKeyTag", &PublicKeyImpl<DCRTPoly>::GetKeyTag)
        .def("SetKeyTag", &PublicKeyImpl<DCRTPoly>::SetKeyTag);
    py::class_<PrivateKeyImpl<DCRTPoly>, std::shared_ptr<PrivateKeyImpl<DCRTPoly>>>(m, "PrivateKey")
        .def(py::init<>())
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
class PlaintextImpl_helper : public PlaintextImpl
{
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

void bind_encodings(py::module &m)
{
    py::class_<PlaintextImpl, std::shared_ptr<PlaintextImpl>, PlaintextImpl_helper>(m, "Plaintext")
        .def("GetScalingFactor", &PlaintextImpl::GetScalingFactor,
            ptx_GetScalingFactor_docs)
        .def("SetScalingFactor", &PlaintextImpl::SetScalingFactor,
            ptx_SetScalingFactor_docs,
            py::arg("sf"))
        .def("GetSchemeID", &PlaintextImpl::GetSchemeID,
            ptx_GetSchemeID_docs)
        .def("GetLength", &PlaintextImpl::GetLength,
            ptx_GetLength_docs)
        .def("SetLength", &PlaintextImpl::SetLength,
            ptx_SetLength_docs,
            py::arg("newSize"))
        .def("IsEncoded", &PlaintextImpl::IsEncoded,
            ptx_IsEncoded_docs)
        .def("GetLogPrecision", &PlaintextImpl::GetLogPrecision,
            ptx_GetLogPrecision_docs)
        .def("Encode", &PlaintextImpl::Encode,
            ptx_Encode_docs)
        .def("Decode", py::overload_cast<>(&PlaintextImpl::Decode),
            ptx_Decode_docs)
        .def("Decode", py::overload_cast<size_t, double, ScalingTechnique, ExecutionMode>(&PlaintextImpl::Decode),
            ptx_Decode_docs)
        .def("LowBound", &PlaintextImpl::LowBound,
            ptx_LowBound_docs)
        .def("HighBound", &PlaintextImpl::HighBound,
            ptx_HighBound_docs)
        .def("SetFormat", &PlaintextImpl::SetFormat,
            ptx_SetFormat_docs,
            py::arg("fmt"))
        .def("GetCoefPackedValue", &PlaintextImpl::GetCoefPackedValue)
        .def("GetPackedValue", &PlaintextImpl::GetPackedValue)
        .def("GetCKKSPackedValue", &PlaintextImpl::GetCKKSPackedValue,
            ptx_GetCKKSPackedValue_docs)
        .def("GetRealPackedValue", &PlaintextImpl::GetRealPackedValue,
            ptx_GetRealPackedValue_docs)
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
        .def("__repr__", [](const PlaintextImpl &p)
             {
        std::stringstream ss;
        ss << "<Plaintext Object: " << p << ">";
        return ss.str(); })
        .def("__str__", [](const PlaintextImpl &p)
             {
        std::stringstream ss;
        ss << p;
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
     .def("GetLevel", &CiphertextImpl<DCRTPoly>::GetLevel,
        ctx_GetLevel_docs)
     .def("SetLevel", &CiphertextImpl<DCRTPoly>::SetLevel,
        ctx_SetLevel_docs,
        py::arg("level"))
     .def("Clone", &CiphertextImpl<DCRTPoly>::Clone)
     .def("RemoveElement", &RemoveElementWrapper, cc_RemoveElement_docs)
    // .def("GetHopLevel", &CiphertextImpl<DCRTPoly>::GetHopLevel)
    // .def("SetHopLevel", &CiphertextImpl<DCRTPoly>::SetHopLevel)
    // .def("GetScalingFactor", &CiphertextImpl<DCRTPoly>::GetScalingFactor)
    // .def("SetScalingFactor", &CiphertextImpl<DCRTPoly>::SetScalingFactor)
     .def("GetSlots", &CiphertextImpl<DCRTPoly>::GetSlots)
     .def("SetSlots", &CiphertextImpl<DCRTPoly>::SetSlots)
     .def("GetNoiseScaleDeg", &CiphertextImpl<DCRTPoly>::GetNoiseScaleDeg)
     .def("SetNoiseScaleDeg", &CiphertextImpl<DCRTPoly>::SetNoiseScaleDeg);
}

void bind_schemes(py::module &m){
    /*Bind schemes specific functionalities like bootstrapping functions and multiparty*/
    py::class_<FHECKKSRNS>(m, "FHECKKSRNS")
        .def(py::init<>())
        //.def_static("GetBootstrapDepth", &FHECKKSRNS::GetBootstrapDepth)
        .def_static("GetBootstrapDepth", static_cast<uint32_t (*)(uint32_t, const std::vector<uint32_t>&, SecretKeyDist)>(&FHECKKSRNS::GetBootstrapDepth))
        .def_static("GetBootstrapDepth", static_cast<uint32_t (*)(const std::vector<uint32_t>&, SecretKeyDist)>(&FHECKKSRNS::GetBootstrapDepth));                               
    
}

void bind_sch_swch_params(py::module &m)
{
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
        .def("__str__",[](const SchSwchParams &params) {
            std::stringstream stream;
            stream << params;
            return stream.str();
        });
}


PYBIND11_MODULE(openfhe, m)
{
    m.doc() = "Open-Source Fully Homomorphic Encryption Library";
    // binfhe library
    bind_binfhe_enums(m);
    bind_binfhe_context(m);
    bind_binfhe_keys(m);
    bind_binfhe_ciphertext(m);
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
}
