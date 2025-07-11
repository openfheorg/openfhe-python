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
#ifndef __CRYPTOCONTEXT_WRAPPER_H__
#define __CRYPTOCONTEXT_WRAPPER_H__

#include "openfhe.h"

using namespace lbcrypto;


Ciphertext<DCRTPoly> EvalFastRotationPrecomputeWrapper(CryptoContext<DCRTPoly> &self,
                                                       ConstCiphertext<DCRTPoly> ciphertext);

Ciphertext<DCRTPoly> EvalFastRotationWrapper(CryptoContext<DCRTPoly> &self,
                                             ConstCiphertext<DCRTPoly> ciphertext,
                                             uint32_t index,
                                             uint32_t m,
                                             ConstCiphertext<DCRTPoly> digits);
Ciphertext<DCRTPoly> EvalFastRotationExtWrapper(CryptoContext<DCRTPoly> &self, ConstCiphertext<DCRTPoly> ciphertext, uint32_t index, ConstCiphertext<DCRTPoly> digits, bool addFirst);

Plaintext DecryptWrapper(CryptoContext<DCRTPoly> &self,
                         ConstCiphertext<DCRTPoly> ciphertext, const PrivateKey<DCRTPoly> privateKey);
Plaintext DecryptWrapper(CryptoContext<DCRTPoly> &self,
                         const PrivateKey<DCRTPoly> privateKey, ConstCiphertext<DCRTPoly> ciphertext);
Plaintext MultipartyDecryptFusionWrapper(CryptoContext<DCRTPoly>& self,const std::vector<Ciphertext<DCRTPoly>>& partialCiphertextVec);

const std::shared_ptr<std::map<uint32_t, EvalKey<DCRTPoly>>> GetEvalSumKeyMapWrapper(CryptoContext<DCRTPoly>& self, const std::string &id);
PlaintextModulus GetPlaintextModulusWrapper(CryptoContext<DCRTPoly>& self);
uint32_t GetBatchSizeWrapper(CryptoContext<DCRTPoly>& self);
double GetModulusWrapper(CryptoContext<DCRTPoly>& self);
void RemoveElementWrapper(Ciphertext<DCRTPoly>& self, uint32_t index);
double GetScalingFactorRealWrapper(CryptoContext<DCRTPoly>& self, uint32_t l);
uint64_t GetModulusCKKSWrapper(CryptoContext<DCRTPoly>& self);
ScalingTechnique GetScalingTechniqueWrapper(CryptoContext<DCRTPoly>& self);
uint32_t GetDigitSizeWrapper(CryptoContext<DCRTPoly>& self);

void ClearEvalMultKeysWrapper();

#endif // __CRYPTOCONTEXT_WRAPPER_H__
