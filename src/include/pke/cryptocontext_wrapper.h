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

#ifndef OPENFHE_CRYPTOCONTEXT_BINDINGS_H
#define OPENFHE_CRYPTOCONTEXT_BINDINGS_H

#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <vector>
#include <algorithm>
#include <complex>
#include "openfhe.h"
#include "bindings.h"

namespace py = pybind11;
using namespace lbcrypto;
using ParmType = typename DCRTPoly::Params;

Ciphertext<DCRTPoly> EvalFastRotationPrecomputeWrapper(CryptoContext<DCRTPoly>& self,
                                                        ConstCiphertext<DCRTPoly> ciphertext);

Ciphertext<DCRTPoly> EvalFastRotationWrapper(CryptoContext<DCRTPoly>& self,
                                            ConstCiphertext<DCRTPoly> ciphertext,
                                              const usint index,
                                              const usint m,
                                              ConstCiphertext<DCRTPoly> digits);
Ciphertext<DCRTPoly> EvalFastRotationExtWrapper(CryptoContext<DCRTPoly>& self,ConstCiphertext<DCRTPoly> ciphertext, const usint index, ConstCiphertext<DCRTPoly> digits, bool addFirst);

Plaintext DecryptWrapper(CryptoContext<DCRTPoly>& self,
ConstCiphertext<DCRTPoly> ciphertext,const PrivateKey<DCRTPoly> privateKey);
Plaintext DecryptWrapper(CryptoContext<DCRTPoly>& self,
const PrivateKey<DCRTPoly> privateKey,ConstCiphertext<DCRTPoly> ciphertext);
Plaintext MultipartyDecryptFusionWrapper(CryptoContext<DCRTPoly>& self,const std::vector<Ciphertext<DCRTPoly>>& partialCiphertextVec);

const std::map<usint, EvalKey<DCRTPoly>> EvalAutomorphismKeyGenWrapper(CryptoContext<DCRTPoly>& self,const PrivateKey<DCRTPoly> privateKey,const std::vector<usint> &indexList);
const std::shared_ptr<std::map<usint, EvalKey<DCRTPoly>>> GetEvalSumKeyMapWrapper(CryptoContext<DCRTPoly>& self, const std::string &id);
const PlaintextModulus GetPlaintextModulusWrapper(CryptoContext<DCRTPoly>& self);
const double GetModulusWrapper(CryptoContext<DCRTPoly>& self);
void RemoveElementWrapper(Ciphertext<DCRTPoly>& self, usint index);
const double GetScalingFactorRealWrapper(CryptoContext<DCRTPoly>& self, uint32_t l);
const uint64_t GetModulusCKKSWrapper(CryptoContext<DCRTPoly>& self);
const ScalingTechnique GetScalingTechniqueWrapper(CryptoContext<DCRTPoly>& self);
const usint GetDigitSizeWrapper(CryptoContext<DCRTPoly>& self);
#endif // OPENFHE_CRYPTOCONTEXT_BINDINGS_H
