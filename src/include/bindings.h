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
#ifndef __BINDINGS_H__
#define __BINDINGS_H__

#include "openfhe.h"

#include <pybind11/pybind11.h>

#include <memory>

using DCRTCryptoContextClass = pybind11::class_<
    lbcrypto::CryptoContextImpl<lbcrypto::DCRTPoly>,
    std::shared_ptr<lbcrypto::CryptoContextImpl<lbcrypto::DCRTPoly>>>;

// Releases the GIL for the duration of the bound C++ call, so other Python threads can
// run (and call into OpenFHE) while heavy native work -- lattice arithmetic, key
// generation, (de)serialization -- is in progress. Only attach it to bindings whose C++
// body never touches Python objects: pybind11 converts the arguments and the return
// value while still holding the GIL, and virtual PlaintextImpl overrides re-acquire it
// inside PYBIND11_OVERRIDE. Wrappers that must touch Python objects mid-body (e.g. the
// py::bytes serialization wrappers) use a scoped pybind11::gil_scoped_release around
// their pure-C++ section instead.
//
// Thread-safety contract (the same one the OpenFHE C++ API has; Python threads are
// subject to it because these bindings run concurrently): the static evaluation-key
// maps are not synchronized, so concurrent reads (evaluation calls) are safe, but keys
// must not be generated/inserted/deserialized in one thread while another thread uses
// them.
inline constexpr auto release_gil = pybind11::call_guard<pybind11::gil_scoped_release>();

void bind_crypto_context(pybind11::module &m);
void bind_enums_and_constants(pybind11::module &m);
void bind_keys(pybind11::module &m);
void bind_encodings(pybind11::module &m);
void bind_ciphertext(pybind11::module &m);
void bind_serialization(pybind11::module &m);
void bind_sch_swch_params(pybind11::module &m);
void bind_fbt_crypto_context(DCRTCryptoContextClass &cls);
void bind_fbt(pybind11::module &m);

#endif // __BINDINGS_H__
