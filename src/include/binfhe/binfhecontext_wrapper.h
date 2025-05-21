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
#ifndef __BINFHECONTEXT_WRAPPER_H__
#define __BINFHECONTEXT_WRAPPER_H__

#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include "openfhe.h"
#include "binfhecontext.h"
#include <functional>
#include <pybind11/functional.h>

namespace py = pybind11;
using namespace lbcrypto;
LWECiphertext binfhe_EncryptWrapper(BinFHEContext &self,
                                    ConstLWEPrivateKey sk,
                                    const LWEPlaintext &m,
                                    BINFHE_OUTPUT output,
                                    LWEPlaintextModulus p,
                                    uint64_t mod);
LWEPlaintext binfhe_DecryptWrapper(BinFHEContext &self,
                                   ConstLWEPrivateKey sk,
                                   ConstLWECiphertext ct,
                                   LWEPlaintextModulus p);

uint32_t GetnWrapper(BinFHEContext &self);

const uint64_t GetqWrapper(BinFHEContext &self) ;

const uint64_t GetMaxPlaintextSpaceWrapper(BinFHEContext &self);

const uint64_t GetBetaWrapper(BinFHEContext &self);

const uint64_t GetLWECiphertextModulusWrapper(LWECiphertext &self);

std::vector<uint64_t> GenerateLUTviaFunctionWrapper(BinFHEContext &self, py::function f, uint64_t p);

NativeInteger StaticFunction(NativeInteger m, NativeInteger p);

// Define static variables to hold the state
// extern py::function static_f;

LWECiphertext EvalFuncWrapper(BinFHEContext &self, ConstLWECiphertext &ct, const std::vector<uint64_t> &LUT);

#endif // __BINFHECONTEXT_WRAPPER_H__