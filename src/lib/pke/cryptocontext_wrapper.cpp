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

const std::map<usint, EvalKey<DCRTPoly>> EvalAutomorphismKeyGenWrapper_PublicKey(CryptoContext<DCRTPoly>& self,const PublicKey<DCRTPoly> publicKey, const PrivateKey<DCRTPoly> privateKey, const std::vector<usint> &indexList){
    return *(self->EvalAutomorphismKeyGen(publicKey, privateKey, indexList));
};