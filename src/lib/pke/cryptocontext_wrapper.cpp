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
#include "cryptocontext_wrapper.h"


Ciphertext<DCRTPoly> EvalFastRotationPrecomputeWrapper(CryptoContext<DCRTPoly> &self,ConstCiphertext<DCRTPoly> ciphertext) {
    std::shared_ptr<std::vector<DCRTPoly>> precomp = self->EvalFastRotationPrecompute(ciphertext);
    std::vector<DCRTPoly> elements = *(precomp.get());
    std::shared_ptr<CiphertextImpl<DCRTPoly>> cipherdigits = std::make_shared<CiphertextImpl<DCRTPoly>>(self);
    cipherdigits->SetElements(std::move(elements));
    return cipherdigits;
}
Ciphertext<DCRTPoly> EvalFastRotationWrapper(CryptoContext<DCRTPoly>& self,ConstCiphertext<DCRTPoly> ciphertext, uint32_t index, uint32_t m,ConstCiphertext<DCRTPoly> digits) {
    
        std::vector<DCRTPoly> digitsElements = digits->GetElements();
        std::shared_ptr<std::vector<DCRTPoly>> digitsElementsPtr = std::make_shared<std::vector<DCRTPoly>>(digitsElements);
        return self->EvalFastRotation(ciphertext, index, m, digitsElementsPtr);
    }

Ciphertext<DCRTPoly> EvalFastRotationExtWrapper(CryptoContext<DCRTPoly>& self,ConstCiphertext<DCRTPoly> ciphertext, uint32_t index, ConstCiphertext<DCRTPoly> digits, bool addFirst) {
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

const std::shared_ptr<std::map<uint32_t, EvalKey<DCRTPoly>>> GetEvalSumKeyMapWrapper(CryptoContext<DCRTPoly>& self,const std::string &keyTag){
    return std::make_shared<std::map<uint32_t, EvalKey<DCRTPoly>>>(CryptoContextImpl<DCRTPoly>::GetEvalSumKeyMap(keyTag));;
}

PlaintextModulus GetPlaintextModulusWrapper(CryptoContext<DCRTPoly>& self){
    return self->GetCryptoParameters()->GetPlaintextModulus();
}

uint32_t GetBatchSizeWrapper(CryptoContext<DCRTPoly>& self){
    return self->GetCryptoParameters()->GetBatchSize();
}

double GetModulusWrapper(CryptoContext<DCRTPoly>& self){
    return self->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble();
}

void RemoveElementWrapper(Ciphertext<DCRTPoly> &self, uint32_t index){
    self->GetElements().erase(self->GetElements().begin()+index);
}
uint32_t GetDigitSizeWrapper(CryptoContext<DCRTPoly>& self){
    return self->GetCryptoParameters()->GetDigitSize();
}

double GetScalingFactorRealWrapper(CryptoContext<DCRTPoly>& self, uint32_t l){
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
        OPENFHE_THROW("Invalid scheme");
        return 0;
    }
}

uint64_t GetModulusCKKSWrapper(CryptoContext<DCRTPoly> &self)
{

    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(self->GetCryptoParameters());
    ILDCRTParams<DCRTPoly::Integer> elementParams = *(cryptoParams->GetElementParams());
    auto paramsQ = elementParams.GetParams();
    uint64_t modulus_CKKS_from = paramsQ[0]->GetModulus().ConvertToInt<uint64_t>();
    return modulus_CKKS_from;
}

ScalingTechnique GetScalingTechniqueWrapper(CryptoContext<DCRTPoly> & self){
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
        OPENFHE_THROW("Invalid scheme");
    }

}

void ClearEvalMultKeysWrapper() {
    CryptoContextImpl<DCRTPoly>::ClearEvalMultKeys();
}