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
#ifndef __SERIALIZATION_H__
#define __SERIALIZATION_H__

#include <pybind11/pybind11.h>


template <typename ST>
bool SerializeEvalMultKeyWrapper(const std::string& filename, const ST& sertype, std::string id);

template <typename ST>
bool SerializeEvalAutomorphismKeyWrapper(const std::string& filename, const ST& sertype, std::string id);

template <typename ST>
bool DeserializeEvalMultKeyWrapper(const std::string& filename, const ST& sertype);

template <typename T, typename ST>
std::string SerializeToStringWrapper(const T& obj, const ST& sertype);

template <typename T, typename ST>
pybind11::bytes SerializeToBytesWrapper(const T& obj, const ST& sertype);

template <typename T, typename ST>
T DeserializeFromStringWrapper(const std::string& str, const ST& sertype);

template <typename T, typename ST>
T DeserializeFromBytesWrapper(const pybind11::bytes& bytes, const ST& sertype);

template <typename ST>
std::string SerializeEvalMultKeyToStringWrapper(const ST& sertype, const std::string& id);

template <typename ST>
pybind11::bytes SerializeEvalMultKeyToBytesWrapper(const ST& sertype, const std::string& id);

template <typename ST>
std::string SerializeEvalAutomorphismKeyToStringWrapper(const ST& sertype, const std::string& id);

template <typename ST>
pybind11::bytes SerializeEvalAutomorphismKeyToBytesWrapper(const ST& sertype, const std::string& id);

template <typename ST>
void DeserializeEvalMultKeyFromStringWrapper(const std::string& data, const ST& sertype);

template <typename ST>
void DeserializeEvalMultKeyFromBytesWrapper(const std::string& data, const ST& sertype);

template <typename ST>
void DeserializeEvalAutomorphismKeyFromStringWrapper(const std::string& data, const ST& sertype);

template <typename ST>
void DeserializeEvalAutomorphismKeyFromBytesWrapper(const std::string& data, const ST& sertype);

#endif // __SERIALIZATION_H__