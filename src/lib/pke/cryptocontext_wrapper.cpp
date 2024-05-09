// BSD 2-Clause License

// Copyright (c) 2023, OpenFHE

// All rights reserved.

// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:

// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.

// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.

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

#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <openfhe.h>
#include <vector>
#include <algorithm>
#include <complex> 
#include "cryptocontext_wrapper.h"

using namespace lbcrypto;
namespace py = pybind11;

Ciphertext<DCRTPoly> EvalFastRotationPrecomputeWrapper(CryptoContext<DCRTPoly> &self,ConstCiphertext<DCRTPoly> ciphertext) {
    std::shared_ptr<std::vector<DCRTPoly>> precomp = self->EvalFastRotationPrecompute(ciphertext);
    std::vector<DCRTPoly> elements = *(precomp.get());
    CiphertextImpl<DCRTPoly> cipherdigits = CiphertextImpl<DCRTPoly>(self);
    std::shared_ptr<CiphertextImpl<DCRTPoly>> cipherdigitsPtr = std::make_shared<CiphertextImpl<DCRTPoly>>(cipherdigits);
    cipherdigitsPtr->SetElements(elements);
    return cipherdigitsPtr;
}
Ciphertext<DCRTPoly> EvalFastRotationWrapper(CryptoContext<DCRTPoly>& self,ConstCiphertext<DCRTPoly> ciphertext, const usint index, const usint m,ConstCiphertext<DCRTPoly> digits) {
    
        std::vector<DCRTPoly> digitsElements = digits->GetElements();
        std::shared_ptr<std::vector<DCRTPoly>> digitsElementsPtr = std::make_shared<std::vector<DCRTPoly>>(digitsElements);
        return self->EvalFastRotation(ciphertext, index, m, digitsElementsPtr);
    }

Ciphertext<DCRTPoly> EvalFastRotationExtWrapper(CryptoContext<DCRTPoly>& self,ConstCiphertext<DCRTPoly> ciphertext, const usint index, ConstCiphertext<DCRTPoly> digits, bool addFirst) {
    std::vector<DCRTPoly> digitsElements = digits->GetElements();
    std::shared_ptr<std::vector<DCRTPoly>> digitsElementsPtr = std::make_shared<std::vector<DCRTPoly>>(digitsElements);
    return self->EvalFastRotationExt(ciphertext, index, digitsElementsPtr, addFirst);
}


Plaintext DecryptWrapper(CryptoContext<DCRTPoly>& self,ConstCiphertext<DCRTPoly> ciphertext,const PrivateKey<DCRTPoly> privateKey){
    Plaintext plaintextDecResult;
    self->Decrypt(privateKey, ciphertext,&plaintextDecResult);
    return plaintextDecResult;
}
Plaintext DecryptWrapper(CryptoContext<DCRTPoly>& self,const PrivateKey<DCRTPoly> privateKey,ConstCiphertext<DCRTPoly> ciphertext){
    Plaintext plaintextDecResult;
    self->Decrypt(privateKey, ciphertext,&plaintextDecResult);
    return plaintextDecResult;
}

Plaintext MultipartyDecryptFusionWrapper(CryptoContext<DCRTPoly>& self,const std::vector<Ciphertext<DCRTPoly>>& partialCiphertextVec){
    Plaintext plaintextDecResult;
    self->MultipartyDecryptFusion(partialCiphertextVec,&plaintextDecResult);
    return plaintextDecResult;
}

const std::map<usint, EvalKey<DCRTPoly>> EvalAutomorphismKeyGenWrapper(CryptoContext<DCRTPoly>& self,const PrivateKey<DCRTPoly> privateKey,const std::vector<usint> &indexList){
    return *(self->EvalAutomorphismKeyGen(privateKey, indexList));
}

const std::shared_ptr<std::map<usint, EvalKey<DCRTPoly>>> GetEvalSumKeyMapWrapper(CryptoContext<DCRTPoly>& self,const std::string &id){
    auto evalSumKeyMap = 
        std::make_shared<std::map<usint, EvalKey<DCRTPoly>>>(self->GetEvalSumKeyMap(id));
    return evalSumKeyMap;
}

const PlaintextModulus GetPlaintextModulusWrapper(CryptoContext<DCRTPoly>& self){
    return self->GetCryptoParameters()->GetPlaintextModulus();
}

const double GetModulusWrapper(CryptoContext<DCRTPoly>& self){
    return self->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble();
}

void RemoveElementWrapper(Ciphertext<DCRTPoly> &self, usint index){
    self->GetElements().erase(self->GetElements().begin()+index);
}
const usint GetDigitSizeWrapper(CryptoContext<DCRTPoly>& self){
    return self->GetCryptoParameters()->GetDigitSize();
}

const double GetScalingFactorRealWrapper(CryptoContext<DCRTPoly>& self, uint32_t l){
    if(self->getSchemeId()==SCHEME::CKKSRNS_SCHEME){
        const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(self->GetCryptoParameters());
        double scFactor = cryptoParams->GetScalingFactorReal(l);
        return scFactor;
    }
    else if(self->getSchemeId()==SCHEME::BFVRNS_SCHEME){
        const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersBFVRNS>(self->GetCryptoParameters());
        double scFactor = cryptoParams->GetScalingFactorReal(l);
        return scFactor;
    }
    else if(self->getSchemeId()==SCHEME::BGVRNS_SCHEME){
        const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersBGVRNS>(self->GetCryptoParameters());
        double scFactor = cryptoParams->GetScalingFactorReal(l);
        return scFactor;
    }
    else{
        OPENFHE_THROW(not_available_error, "GetScalingFactorRealWrapper: Invalid scheme");
        return 0;
    }
}

const uint64_t GetModulusCKKSWrapper(CryptoContext<DCRTPoly> &self)
{

    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(self->GetCryptoParameters());
    ILDCRTParams<DCRTPoly::Integer> elementParams = *(cryptoParams->GetElementParams());
    auto paramsQ = elementParams.GetParams();
    uint64_t modulus_CKKS_from = paramsQ[0]->GetModulus().ConvertToInt<uint64_t>();
    return modulus_CKKS_from;
}

const ScalingTechnique GetScalingTechniqueWrapper(CryptoContext<DCRTPoly> & self){
    if(self->getSchemeId()==SCHEME::CKKSRNS_SCHEME){
        const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(self->GetCryptoParameters());
        return cryptoParams->GetScalingTechnique();
    }
    else if(self->getSchemeId()==SCHEME::BFVRNS_SCHEME){
        const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersBFVRNS>(self->GetCryptoParameters());
        return cryptoParams->GetScalingTechnique();
    }
    else if(self->getSchemeId()==SCHEME::BGVRNS_SCHEME){
        const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersBGVRNS>(self->GetCryptoParameters());
        return cryptoParams->GetScalingTechnique();
    }
    else{
        OPENFHE_THROW(not_available_error, "GetScalingTechniqueWrapper: Invalid scheme");
    }

}
