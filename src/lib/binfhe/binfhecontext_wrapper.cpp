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
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <openfhe.h>
#include "binfhecontext_wrapper.h"

using namespace lbcrypto;
namespace py = pybind11;

LWECiphertext binfhe_EncryptWrapper(BinFHEContext &self, ConstLWEPrivateKey sk, const LWEPlaintext &m, BINFHE_OUTPUT output,
                                    LWEPlaintextModulus p, uint64_t mod)
{
    NativeInteger mod_native_int = NativeInteger(mod);
    return self.Encrypt(sk, m, output, p, mod_native_int);
}

LWEPlaintext binfhe_DecryptWrapper(BinFHEContext &self,
                                   ConstLWEPrivateKey sk,
                                   ConstLWECiphertext ct,
                                   LWEPlaintextModulus p)
{

    LWEPlaintext result;
    self.Decrypt(sk, ct, &result, p);
    return result;
}

uint32_t GetnWrapper(BinFHEContext &self)
{
    return self.GetParams()->GetLWEParams()->Getn();
}

const uint64_t GetqWrapper(BinFHEContext &self)
{
    return self.GetParams()->GetLWEParams()->Getq().ConvertToInt<uint64_t>();
}

const uint64_t GetMaxPlaintextSpaceWrapper(BinFHEContext &self)
{
    return self.GetMaxPlaintextSpace().ConvertToInt<uint64_t>();
}

const uint64_t GetBetaWrapper(BinFHEContext &self)
{
    return self.GetBeta().ConvertToInt<uint64_t>();
}

const uint64_t GetLWECiphertextModulusWrapper(LWECiphertext &self)
{
    return self->GetModulus().ConvertToInt<uint64_t>();
}

// Define static variables to hold the state
py::function* static_f = nullptr;

// Define a static function that uses the static variables
NativeInteger StaticFunction(NativeInteger m, NativeInteger p) {
    // Convert the arguments to int
    uint64_t m_int = m.ConvertToInt<uint64_t>();
    uint64_t p_int = p.ConvertToInt<uint64_t>();
    // Call the Python function
    py::object result_py = (*static_f)(m_int, p_int);
    // Convert the result to a NativeInteger
    return NativeInteger(py::cast<uint64_t>(result_py));
}

std::vector<uint64_t> GenerateLUTviaFunctionWrapper(BinFHEContext &self, py::function f, uint64_t p)
{
    NativeInteger p_native_int = NativeInteger(p);
    static_f = &f;
    std::vector<NativeInteger> result = self.GenerateLUTviaFunction(StaticFunction, p_native_int);
    static_f = nullptr;
    std::vector<uint64_t> result_uint64_t;
    // int size_int = static_cast<int>(result.size());
    for (const auto& value : result)
    {
        result_uint64_t.push_back(value.ConvertToInt<uint64_t>());
    }
    return result_uint64_t;
}

// LWECiphertext EvalFunc(ConstLWECiphertext &ct, const std::vector<NativeInteger> &LUT) const
LWECiphertext EvalFuncWrapper(BinFHEContext &self, ConstLWECiphertext &ct, const std::vector<uint64_t> &LUT)
{
    std::vector<NativeInteger> LUT_native_int;
    LUT_native_int.reserve(LUT.size());  // Reserve space for the elements
    for (const auto& value : LUT)
    {
        LUT_native_int.push_back(NativeInteger(value));
    }
    return self.EvalFunc(ct, LUT_native_int);
}



