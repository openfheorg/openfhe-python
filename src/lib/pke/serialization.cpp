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
// #include <pybind11/stl_bind.h> - not needed for now

#include "bindings.h"
#include "openfhe.h"
// header files needed for serialization
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"

#include "docstrings/serialization_docs.h"

#include <istream>
#include <ostream>
#include <streambuf>
#include <string>
#include <utility>

using namespace lbcrypto;
using CryptoContextDCRT = CryptoContext<DCRTPoly>;
namespace py = pybind11;

// disable the PYBIND11 template-based conversion for this type
PYBIND11_MAKE_OPAQUE(std::map<uint32_t, EvalKey<DCRTPoly>>);

namespace {

// Read-only streambuf over an existing buffer: deserialization reads straight from a
// py::bytes' (or std::string's) storage instead of copying it into a stringstream.
// The caller must keep the underlying buffer alive for the streambuf's lifetime.
class MemoryStreamBuf final : public std::streambuf {
public:
    MemoryStreamBuf(const char* data, size_t size) {
        char* p = const_cast<char*>(data);  // only ever read through the get area
        setg(p, p, p + size);
    }
};

// Output streambuf appending to a caller-owned std::string, so a serialized payload
// is produced in a single owned buffer instead of being copied out of a stringbuf.
class StringStreamBuf final : public std::streambuf {
public:
    explicit StringStreamBuf(std::string& out) : out_(out) {}

protected:
    int_type overflow(int_type ch) override {
        if (!traits_type::eq_int_type(ch, traits_type::eof()))
            out_.push_back(traits_type::to_char_type(ch));
        return traits_type::not_eof(ch);
    }
    std::streamsize xsputn(const char* s, std::streamsize count) override {
        out_.append(s, static_cast<size_t>(count));
        return count;
    }

private:
    std::string& out_;
};

// Borrow the internal buffer of a bytes object without copying it; the py::bytes
// reference held by the caller keeps the buffer alive and immutable.
std::pair<const char*, size_t> BytesView(const py::bytes& bytes) {
    char* data = nullptr;
    Py_ssize_t size = 0;
    if (PYBIND11_BYTES_AS_STRING_AND_SIZE(bytes.ptr(), &data, &size) != 0)
        throw py::error_already_set();
    return {data, static_cast<size_t>(size)};
}

}  // namespace


template <typename ST>
bool SerializeEvalBootstrapKeyWrapper(const std::string& filename, const ST& sertype, const CryptoContextDCRT& cc,
                                      const std::string& keyTag, uint32_t slots) {
    std::ofstream outfile(filename, std::ios::out | std::ios::binary);
    if (!outfile.is_open()) {
        std::cerr << "I cannot write serialization to " << filename << std::endl;
        return false;
    }
    bool res = CryptoContextImpl<DCRTPoly>::SerializeEvalBootstrapKey(outfile, sertype, cc, keyTag, slots);
    outfile.close();
    return res;
}

template <typename ST>
bool DeserializeEvalBootstrapKeyWrapper(const std::string& filename, const ST& sertype, const CryptoContextDCRT& cc,
                                        const std::string& keyTag, uint32_t slots) {
    std::ifstream keyfile(filename, std::ios::in | std::ios::binary);
    if (!keyfile.is_open()) {
        std::cerr << "I cannot read serialization from " << filename << std::endl;
        return false;
    }
    return CryptoContextImpl<DCRTPoly>::DeserializeEvalBootstrapKey(keyfile, sertype, cc, keyTag, slots);
}

template <typename ST>
bool DeserializeEvalBootstrapKeyByIndexWrapper(const std::string& filename, const ST& sertype,
                                               const std::string& keyTag, const std::vector<uint32_t>& indexList) {
    std::ifstream keyfile(filename, std::ios::in | std::ios::binary);
    if (!keyfile.is_open()) {
        std::cerr << "I cannot read serialization from " << filename << std::endl;
        return false;
    }
    return CryptoContextImpl<DCRTPoly>::DeserializeEvalBootstrapKey(keyfile, sertype, keyTag, indexList);
}

template <typename T, typename ST>
std::tuple<T, bool> DeserializeFromFileWrapper(const std::string& filename, const ST& sertype) {
    T newob;
    bool result = Serial::DeserializeFromFile<T>(filename, newob, sertype);
    return std::make_tuple(newob, result);
}
template <typename ST>
std::tuple<CryptoContextDCRT, bool> DeserializeCCWrapper(const std::string& filename, const ST& sertype) {
    CryptoContextDCRT newob;
    bool result = Serial::DeserializeFromFile<DCRTPoly>(filename, newob, sertype);
    return std::make_tuple(newob, result);
}

template <typename T, typename ST>
std::string SerializeToStringWrapper(const T& obj, const ST& sertype) {
    std::string payload;
    StringStreamBuf buf(payload);
    std::ostream oss(&buf);
    Serial::Serialize<T>(obj, oss, sertype);
    return payload;
}

template <typename T, typename ST>
py::bytes SerializeToBytesWrapper(const T& obj, const ST& sertype) {
    std::string payload;
    {
        // only the py::bytes construction below needs the GIL
        py::gil_scoped_release release;
        StringStreamBuf buf(payload);
        std::ostream oss(&buf);
        Serial::Serialize<T>(obj, oss, sertype);
    }
    return py::bytes(payload.data(), payload.size());
}

template <typename T, typename ST>
T DeserializeFromStringWrapper(const std::string& str, const ST& sertype) {
    MemoryStreamBuf buf(str.data(), str.size());
    std::istream iss(&buf);
    T obj;
    Serial::Deserialize<T>(obj, iss, sertype);
    return obj;
}

template <typename ST>
CryptoContextDCRT DeserializeCCFromStringWrapper(const std::string& str, const ST& sertype) {
    MemoryStreamBuf buf(str.data(), str.size());
    std::istream iss(&buf);
    CryptoContextDCRT obj;
    Serial::Deserialize<DCRTPoly>(obj, iss, sertype);
    return obj;
}

template <typename T, typename ST>
T DeserializeFromBytesWrapper(const py::bytes& bytes, const ST& sertype) {
    const auto [data, size] = BytesView(bytes);
    // deserialize straight from the bytes' internal buffer, which the `bytes`
    // argument keeps alive and immutable; nothing below touches Python
    py::gil_scoped_release release;
    MemoryStreamBuf buf(data, size);
    std::istream iss(&buf);
    T obj;
    Serial::Deserialize<T>(obj, iss, sertype);
    return obj;
}

template <typename ST>
CryptoContextDCRT DeserializeCCFromBytesWrapper(const py::bytes& bytes, const ST& sertype) {
    const auto [data, size] = BytesView(bytes);
    // deserialize straight from the bytes' internal buffer, which the `bytes`
    // argument keeps alive and immutable; nothing below touches Python
    py::gil_scoped_release release;
    MemoryStreamBuf buf(data, size);
    std::istream iss(&buf);
    CryptoContextDCRT obj;
    Serial::Deserialize<DCRTPoly>(obj, iss, sertype);
    return obj;
}

template <typename ST>
std::string SerializeEvalMultKeyToStringWrapper(const ST& sertype, const std::string& keyTag) {
    std::string payload;
    StringStreamBuf buf(payload);
    std::ostream oss(&buf);
    if (!CryptoContextImpl<DCRTPoly>::SerializeEvalMultKey(oss, sertype, keyTag)) {
        throw std::runtime_error("Failed to serialize EvalMultKey");
    }
    return payload;
}

template <typename ST>
py::bytes SerializeEvalMultKeyToBytesWrapper(const ST& sertype, const std::string& keyTag) {
    std::string payload;
    {
        // only the py::bytes construction below needs the GIL
        py::gil_scoped_release release;
        StringStreamBuf buf(payload);
        std::ostream oss(&buf);
        if (!CryptoContextImpl<DCRTPoly>::SerializeEvalMultKey(oss, sertype, keyTag)) {
            throw std::runtime_error("Failed to serialize EvalMultKey");
        }
    }
    return py::bytes(payload.data(), payload.size());
}

template <typename ST>
std::string SerializeEvalAutomorphismKeyToStringWrapper(const ST& sertype, const std::string& keyTag) {
    std::string payload;
    StringStreamBuf buf(payload);
    std::ostream oss(&buf);
    if (!CryptoContextImpl<DCRTPoly>::SerializeEvalAutomorphismKey(oss, sertype, keyTag)) {
        throw std::runtime_error("Failed to serialize EvalAutomorphismKey");
    }
    return payload;
}

template <typename ST>
py::bytes SerializeEvalAutomorphismKeyToBytesWrapper(const ST& sertype, const std::string& keyTag) {
    std::string payload;
    {
        // only the py::bytes construction below needs the GIL
        py::gil_scoped_release release;
        StringStreamBuf buf(payload);
        std::ostream oss(&buf);
        if (!CryptoContextImpl<DCRTPoly>::SerializeEvalAutomorphismKey(oss, sertype, keyTag)) {
            throw std::runtime_error("Failed to serialize EvalAutomorphismKey");
        }
    }
    return py::bytes(payload.data(), payload.size());
}

template <typename ST>
void DeserializeEvalMultKeyFromStringWrapper(const std::string& data, const ST& sertype) {
    MemoryStreamBuf buf(data.data(), data.size());
    std::istream iss(&buf);
    if (!CryptoContextImpl<DCRTPoly>::DeserializeEvalMultKey<ST>(iss, sertype)) {
        throw std::runtime_error("Failed to deserialize EvalMultKey");
    }
}

template <typename ST>
void DeserializeEvalMultKeyFromBytesWrapper(const py::bytes& bytes, const ST& sertype) {
    const auto [data, size] = BytesView(bytes);
    // deserialize straight from the bytes' internal buffer, which the `bytes`
    // argument keeps alive and immutable; nothing below touches Python
    py::gil_scoped_release release;
    MemoryStreamBuf buf(data, size);
    std::istream iss(&buf);
    if (!CryptoContextImpl<DCRTPoly>::DeserializeEvalMultKey<ST>(iss, sertype)) {
        throw std::runtime_error("Failed to deserialize EvalMultKey");
    }
}

template <typename ST>
void DeserializeEvalAutomorphismKeyFromStringWrapper(const std::string& data, const ST& sertype) {
    MemoryStreamBuf buf(data.data(), data.size());
    std::istream iss(&buf);
    if (!CryptoContextImpl<DCRTPoly>::DeserializeEvalAutomorphismKey<ST>(iss, sertype)) {
        throw std::runtime_error("Failed to deserialize EvalAutomorphismKey");
    }
}

template <typename ST>
void DeserializeEvalAutomorphismKeyFromBytesWrapper(const py::bytes& bytes, const ST& sertype) {
    const auto [data, size] = BytesView(bytes);
    // deserialize straight from the bytes' internal buffer, which the `bytes`
    // argument keeps alive and immutable; nothing below touches Python
    py::gil_scoped_release release;
    MemoryStreamBuf buf(data, size);
    std::istream iss(&buf);
    if (!CryptoContextImpl<DCRTPoly>::DeserializeEvalAutomorphismKey<ST>(iss, sertype)) {
        throw std::runtime_error("Failed to deserialize EvalAutomorphismKey");
    }
}

void bind_serialization(pybind11::module &m) {
    // CKKS bootstrapping key (de)serialization
    m.def("SerializeEvalBootstrapKey", &SerializeEvalBootstrapKeyWrapper<SerType::SERJSON>,
          py::arg("filename"), py::arg("sertype"), py::arg("cc"), py::arg("keyTag"), py::arg("slots"),
          py::doc(serial_SerializeEvalBootstrapKey_docs), release_gil);
    m.def("SerializeEvalBootstrapKey", &SerializeEvalBootstrapKeyWrapper<SerType::SERBINARY>,
          py::arg("filename"), py::arg("sertype"), py::arg("cc"), py::arg("keyTag"), py::arg("slots"),
          py::doc(serial_SerializeEvalBootstrapKey_docs), release_gil);
    m.def("DeserializeEvalBootstrapKey", &DeserializeEvalBootstrapKeyWrapper<SerType::SERJSON>,
          py::arg("filename"), py::arg("sertype"), py::arg("cc"), py::arg("keyTag"), py::arg("slots"),
          py::doc(serial_DeserializeEvalBootstrapKey_docs), release_gil);
    m.def("DeserializeEvalBootstrapKey", &DeserializeEvalBootstrapKeyWrapper<SerType::SERBINARY>,
          py::arg("filename"), py::arg("sertype"), py::arg("cc"), py::arg("keyTag"), py::arg("slots"),
          py::doc(serial_DeserializeEvalBootstrapKey_docs), release_gil);
    m.def("DeserializeEvalBootstrapKey", &DeserializeEvalBootstrapKeyByIndexWrapper<SerType::SERJSON>,
          py::arg("filename"), py::arg("sertype"), py::arg("keyTag"), py::arg("indexList"),
          py::doc(serial_DeserializeEvalBootstrapKeyIndex_docs), release_gil);
    m.def("DeserializeEvalBootstrapKey", &DeserializeEvalBootstrapKeyByIndexWrapper<SerType::SERBINARY>,
          py::arg("filename"), py::arg("sertype"), py::arg("keyTag"), py::arg("indexList"),
          py::doc(serial_DeserializeEvalBootstrapKeyIndex_docs), release_gil);

    // Json Serialization
    m.def("SerializeToFile", static_cast<bool (*)(const std::string &, const CryptoContextDCRT &, const SerType::SERJSON &)>(&Serial::SerializeToFile<CryptoContextDCRT>),
          py::arg("filename"), py::arg("obj"), py::arg("sertype"),
          py::doc(serial_SerializeToFile_docs), release_gil);
    m.def("DeserializeCryptoContext", static_cast<std::tuple<CryptoContextDCRT, bool> (*)(const std::string &, const SerType::SERJSON &)>(&DeserializeCCWrapper<SerType::SERJSON>),
          py::arg("filename"), py::arg("sertype"),
          py::doc(serial_DeserializeCryptoContext_docs), release_gil);
    m.def("SerializeToFile", static_cast<bool (*)(const std::string &, const PublicKey<DCRTPoly> &, const SerType::SERJSON &)>(&Serial::SerializeToFile<PublicKey<DCRTPoly>>),
          py::arg("filename"), py::arg("obj"), py::arg("sertype"),
          py::doc(serial_SerializeToFile_docs), release_gil);
    m.def("DeserializePublicKey", static_cast<std::tuple<PublicKey<DCRTPoly>,bool> (*)(const std::string&, const SerType::SERJSON&)>(&DeserializeFromFileWrapper<PublicKey<DCRTPoly>, SerType::SERJSON>),
          py::arg("filename"), py::arg("sertype"),
          py::doc(serial_DeserializePublicKey_docs), release_gil);
    m.def("SerializeToFile", static_cast<bool (*)(const std::string&, const PrivateKey<DCRTPoly>&, const SerType::SERJSON&)>(&Serial::SerializeToFile<PrivateKey<DCRTPoly>>),
          py::arg("filename"), py::arg("obj"), py::arg("sertype"),
          py::doc(serial_SerializeToFile_docs), release_gil);
    m.def("DeserializePrivateKey", static_cast<std::tuple<PrivateKey<DCRTPoly>,bool> (*)(const std::string&, const SerType::SERJSON&)>(&DeserializeFromFileWrapper<PrivateKey<DCRTPoly>, SerType::SERJSON>),
          py::arg("filename"), py::arg("sertype"),
          py::doc(serial_DeserializePrivateKey_docs), release_gil);
    m.def("SerializeToFile", static_cast<bool (*)(const std::string&, const Ciphertext<DCRTPoly>&, const SerType::SERJSON&)>(&Serial::SerializeToFile<Ciphertext<DCRTPoly>>),
          py::arg("filename"), py::arg("obj"), py::arg("sertype"),
          py::doc(serial_SerializeToFile_docs), release_gil);
    m.def("DeserializeCiphertext", static_cast<std::tuple<Ciphertext<DCRTPoly>,bool> (*)(const std::string&, const SerType::SERJSON&)>(&DeserializeFromFileWrapper<Ciphertext<DCRTPoly>, SerType::SERJSON>),
          py::arg("filename"), py::arg("sertype"),
          py::doc(serial_DeserializeCiphertext_docs), release_gil);
    m.def("SerializeToFile", static_cast<bool (*)(const std::string&, const EvalKey<DCRTPoly>&, const SerType::SERJSON&)>(&Serial::SerializeToFile<EvalKey<DCRTPoly>>),
          py::arg("filename"), py::arg("obj"), py::arg("sertype"),
          py::doc(serial_SerializeToFile_docs), release_gil);
    m.def("DeserializeEvalKey", static_cast<std::tuple<EvalKey<DCRTPoly>,bool> (*)(const std::string&, const SerType::SERJSON&)>(&DeserializeFromFileWrapper<EvalKey<DCRTPoly>, SerType::SERJSON>),
          py::arg("filename"), py::arg("sertype"),
          py::doc(serial_DeserializeEvalKey_docs), release_gil);
    m.def("SerializeToFile", static_cast<bool (*)(const std::string&, const std::shared_ptr<std::map<uint32_t, EvalKey<DCRTPoly>>>&, const SerType::SERJSON&)>(&Serial::SerializeToFile<std::shared_ptr<std::map<uint32_t, EvalKey<DCRTPoly>>>>),
          py::arg("filename"), py::arg("obj"), py::arg("sertype"),
          py::doc(serial_SerializeToFile_docs), release_gil);
    m.def("DeserializeEvalKeyMap", static_cast<std::tuple<std::shared_ptr<std::map<uint32_t, EvalKey<DCRTPoly>>>, bool> (*)(const std::string&, const SerType::SERJSON&)>(&DeserializeFromFileWrapper<std::shared_ptr<std::map<uint32_t, EvalKey<DCRTPoly>>>, SerType::SERJSON>),
          py::arg("filename"), py::arg("sertype"),
          py::doc(serial_DeserializeEvalKeyMap_docs), release_gil);

    // JSON Serialization to string
    m.def("Serialize", &SerializeToStringWrapper<CryptoContextDCRT, SerType::SERJSON>,
          py::arg("obj"), py::arg("sertype"),
          py::doc(serial_Serialize_docs), release_gil);
    m.def("DeserializeCryptoContextString", &DeserializeCCFromStringWrapper<SerType::SERJSON>,
          py::arg("str"), py::arg("sertype"),
          py::doc(serial_DeserializeCryptoContextString_docs), release_gil);
    m.def("Serialize", &SerializeToStringWrapper<PublicKey<DCRTPoly>, SerType::SERJSON>,
          py::arg("obj"), py::arg("sertype"),
          py::doc(serial_Serialize_docs), release_gil);
    m.def("DeserializePublicKeyString", &DeserializeFromStringWrapper<PublicKey<DCRTPoly>, SerType::SERJSON>,
          py::arg("str"), py::arg("sertype"),
          py::doc(serial_DeserializePublicKeyString_docs), release_gil);
    m.def("Serialize", &SerializeToStringWrapper<PrivateKey<DCRTPoly>, SerType::SERJSON>,
          py::arg("obj"), py::arg("sertype"),
          py::doc(serial_Serialize_docs), release_gil);
    m.def("DeserializePrivateKeyString", &DeserializeFromStringWrapper<PrivateKey<DCRTPoly>, SerType::SERJSON>,
          py::arg("str"), py::arg("sertype"),
          py::doc(serial_DeserializePrivateKeyString_docs), release_gil);
    m.def("Serialize", &SerializeToStringWrapper<Ciphertext<DCRTPoly>, SerType::SERJSON>,
          py::arg("obj"), py::arg("sertype"),
          py::doc(serial_Serialize_docs), release_gil);
    m.def("DeserializeCiphertextString", &DeserializeFromStringWrapper<Ciphertext<DCRTPoly>, SerType::SERJSON>,
          py::arg("str"), py::arg("sertype"),
          py::doc(serial_DeserializeCiphertextString_docs), release_gil);
    m.def("Serialize", &SerializeToStringWrapper<EvalKey<DCRTPoly>, SerType::SERJSON>,
          py::arg("obj"), py::arg("sertype"),
          py::doc(serial_Serialize_docs), release_gil);
    m.def("DeserializeEvalKeyString", &DeserializeFromStringWrapper<EvalKey<DCRTPoly>, SerType::SERJSON>,
          py::arg("str"), py::arg("sertype"),
          py::doc(serial_DeserializeEvalKeyString_docs), release_gil);
    m.def("Serialize", &SerializeToBytesWrapper<std::shared_ptr<std::map<uint32_t, EvalKey<DCRTPoly>>>, SerType::SERJSON>,
          py::arg("obj"), py::arg("sertype"),
          py::doc(serial_Serialize_docs));
    m.def("DeserializeEvalKeyMapString", &DeserializeFromBytesWrapper<std::shared_ptr<std::map<uint32_t, EvalKey<DCRTPoly>>>, SerType::SERJSON>,
          py::arg("str"), py::arg("sertype"),
          py::doc(serial_DeserializeEvalKeyMapString_docs));

    m.def("SerializeEvalMultKeyString", &SerializeEvalMultKeyToStringWrapper<SerType::SERJSON>,
          py::arg("sertype"), py::arg("keyTag") = "",
          py::doc(serial_SerializeEvalMultKeyString_docs), release_gil);
    m.def("DeserializeEvalMultKeyString",
          static_cast<void (*)(const std::string&, const SerType::SERJSON&)>(&DeserializeEvalMultKeyFromStringWrapper<SerType::SERJSON>),
          py::arg("data"), py::arg("sertype"),
          py::doc(serial_DeserializeEvalMultKeyString_docs), release_gil);
    m.def("SerializeEvalAutomorphismKeyString", &SerializeEvalAutomorphismKeyToStringWrapper<SerType::SERJSON>,
          py::arg("sertype"), py::arg("keyTag") = "",
          py::doc(serial_SerializeEvalAutomorphismKeyString_docs), release_gil);
    m.def("DeserializeEvalAutomorphismKeyString",
          static_cast<void (*)(const std::string&, const SerType::SERJSON&)>(&DeserializeEvalAutomorphismKeyFromStringWrapper<SerType::SERJSON>),
          py::arg("data"), py::arg("sertype"),
          py::doc(serial_DeserializeEvalAutomorphismKeyString_docs), release_gil);

    // Binary Serialization
    m.def("SerializeToFile", static_cast<bool (*)(const std::string&,const CryptoContextDCRT&, const SerType::SERBINARY&)>(&Serial::SerializeToFile<CryptoContextDCRT>),
          py::arg("filename"), py::arg("obj"), py::arg("sertype"),
          py::doc(serial_SerializeToFile_docs), release_gil);
    m.def("DeserializeCryptoContext", static_cast<std::tuple<CryptoContextDCRT,bool> (*)(const std::string&, const SerType::SERBINARY&)>(&DeserializeCCWrapper<SerType::SERBINARY>),
          py::arg("filename"), py::arg("sertype"),
          py::doc(serial_DeserializeCryptoContext_docs), release_gil);
    m.def("SerializeToFile", static_cast<bool (*)(const std::string&, const PublicKey<DCRTPoly>&, const SerType::SERBINARY&)>(&Serial::SerializeToFile<PublicKey<DCRTPoly>>),
          py::arg("filename"), py::arg("obj"), py::arg("sertype"),
          py::doc(serial_SerializeToFile_docs), release_gil);
    m.def("DeserializePublicKey", static_cast<std::tuple<PublicKey<DCRTPoly>,bool> (*)(const std::string&, const SerType::SERBINARY&)>(&DeserializeFromFileWrapper<PublicKey<DCRTPoly>, SerType::SERBINARY>),
          py::arg("filename"), py::arg("sertype"),
          py::doc(serial_DeserializePublicKey_docs), release_gil);
    m.def("SerializeToFile", static_cast<bool (*)(const std::string&, const PrivateKey<DCRTPoly>&, const SerType::SERBINARY&)>(&Serial::SerializeToFile<PrivateKey<DCRTPoly>>),
          py::arg("filename"), py::arg("obj"), py::arg("sertype"),
          py::doc(serial_SerializeToFile_docs), release_gil);
    m.def("DeserializePrivateKey", static_cast<std::tuple<PrivateKey<DCRTPoly>,bool> (*)(const std::string&, const SerType::SERBINARY&)>(&DeserializeFromFileWrapper<PrivateKey<DCRTPoly>, SerType::SERBINARY>),
          py::arg("filename"), py::arg("sertype"),
          py::doc(serial_DeserializePrivateKey_docs), release_gil);
    m.def("SerializeToFile", static_cast<bool (*)(const std::string&, const Ciphertext<DCRTPoly>&, const SerType::SERBINARY&)>(&Serial::SerializeToFile<Ciphertext<DCRTPoly>>),
          py::arg("filename"), py::arg("obj"), py::arg("sertype"),
          py::doc(serial_SerializeToFile_docs), release_gil);
    m.def("DeserializeCiphertext", static_cast<std::tuple<Ciphertext<DCRTPoly>,bool> (*)(const std::string&, const SerType::SERBINARY&)>(&DeserializeFromFileWrapper<Ciphertext<DCRTPoly>, SerType::SERBINARY>),
          py::arg("filename"), py::arg("sertype"),
          py::doc(serial_DeserializeCiphertext_docs), release_gil);
    m.def("SerializeToFile", static_cast<bool (*)(const std::string&, const EvalKey<DCRTPoly>&, const SerType::SERBINARY&)>(&Serial::SerializeToFile<EvalKey<DCRTPoly>>),
          py::arg("filename"), py::arg("obj"), py::arg("sertype"),
          py::doc(serial_SerializeToFile_docs), release_gil);
    m.def("DeserializeEvalKey", static_cast<std::tuple<EvalKey<DCRTPoly>,bool> (*)(const std::string&, const SerType::SERBINARY&)>(&DeserializeFromFileWrapper<EvalKey<DCRTPoly>, SerType::SERBINARY>),
          py::arg("filename"), py::arg("sertype"),
          py::doc(serial_DeserializeEvalKey_docs), release_gil);
    m.def("SerializeToFile", static_cast<bool (*)(const std::string&, const std::shared_ptr<std::map<uint32_t, EvalKey<DCRTPoly>>>&, const SerType::SERBINARY&)>(&Serial::SerializeToFile<std::shared_ptr<std::map<uint32_t, EvalKey<DCRTPoly>>>>),
          py::arg("filename"), py::arg("obj"), py::arg("sertype"),
          py::doc(serial_SerializeToFile_docs), release_gil);
    m.def("DeserializeEvalKeyMap", static_cast<std::tuple<std::shared_ptr<std::map<uint32_t, EvalKey<DCRTPoly>>>, bool> (*)(const std::string&, const SerType::SERBINARY&)>(&DeserializeFromFileWrapper<std::shared_ptr<std::map<uint32_t, EvalKey<DCRTPoly>>>, SerType::SERBINARY>),
          py::arg("filename"), py::arg("sertype"),
          py::doc(serial_DeserializeEvalKeyMap_docs), release_gil);

    // Binary Serialization to bytes
    m.def("Serialize", &SerializeToBytesWrapper<CryptoContextDCRT, SerType::SERBINARY>,
          py::arg("obj"), py::arg("sertype"),
          py::doc(serial_Serialize_docs));
    m.def("DeserializeCryptoContextString", &DeserializeCCFromBytesWrapper<SerType::SERBINARY>,
          py::arg("str"), py::arg("sertype"),
          py::doc(serial_DeserializeCryptoContextString_docs));
    m.def("Serialize", &SerializeToBytesWrapper<PublicKey<DCRTPoly>, SerType::SERBINARY>,
          py::arg("obj"), py::arg("sertype"),
          py::doc(serial_Serialize_docs));
    m.def("DeserializePublicKeyString", &DeserializeFromBytesWrapper<PublicKey<DCRTPoly>, SerType::SERBINARY>,
          py::arg("str"), py::arg("sertype"),
          py::doc(serial_DeserializePublicKeyString_docs));
    m.def("Serialize", &SerializeToBytesWrapper<PrivateKey<DCRTPoly>, SerType::SERBINARY>,
          py::arg("obj"), py::arg("sertype"),
          py::doc(serial_Serialize_docs));
    m.def("DeserializePrivateKeyString", &DeserializeFromBytesWrapper<PrivateKey<DCRTPoly>, SerType::SERBINARY>,
          py::arg("str"), py::arg("sertype"),
          py::doc(serial_DeserializePrivateKeyString_docs));
    m.def("Serialize", &SerializeToBytesWrapper<Ciphertext<DCRTPoly>, SerType::SERBINARY>,
          py::arg("obj"), py::arg("sertype"),
          py::doc(serial_Serialize_docs));
    m.def("DeserializeCiphertextString", &DeserializeFromBytesWrapper<Ciphertext<DCRTPoly>, SerType::SERBINARY>,
          py::arg("str"), py::arg("sertype"),
          py::doc(serial_DeserializeCiphertextString_docs));
    m.def("Serialize", &SerializeToBytesWrapper<EvalKey<DCRTPoly>, SerType::SERBINARY>,
          py::arg("obj"), py::arg("sertype"),
          py::doc(serial_Serialize_docs));
    m.def("DeserializeEvalKeyString", &DeserializeFromBytesWrapper<EvalKey<DCRTPoly>, SerType::SERBINARY>,
          py::arg("str"), py::arg("sertype"),
          py::doc(serial_DeserializeEvalKeyString_docs));
    m.def("Serialize", &SerializeToBytesWrapper<std::shared_ptr<std::map<uint32_t, EvalKey<DCRTPoly>>>, SerType::SERBINARY>,
          py::arg("obj"), py::arg("sertype"),
          py::doc(serial_Serialize_docs));
    m.def("DeserializeEvalKeyMapString", &DeserializeFromBytesWrapper<std::shared_ptr<std::map<uint32_t, EvalKey<DCRTPoly>>>, SerType::SERBINARY>,
          py::arg("str"), py::arg("sertype"),
          py::doc(serial_DeserializeEvalKeyMapString_docs));
    m.def("Serialize", &SerializeToBytesWrapper<std::vector<EvalKey<DCRTPoly>>, SerType::SERBINARY>,
          py::arg("obj"), py::arg("sertype"),
          py::doc(serial_Serialize_docs));
    m.def("DeserializeEvalKeyMapVectorString", &DeserializeFromBytesWrapper<std::vector<EvalKey<DCRTPoly>>, SerType::SERBINARY>,
          py::arg("str"), py::arg("sertype"),
          py::doc(serial_DeserializeEvalKeyMapVectorString_docs));

    m.def("SerializeEvalMultKeyString", &SerializeEvalMultKeyToBytesWrapper<SerType::SERBINARY>,
          py::arg("sertype"), py::arg("keyTag") = "",
          py::doc(serial_SerializeEvalMultKeyString_docs));
    m.def("DeserializeEvalMultKeyString",
          static_cast<void (*)(const py::bytes&, const SerType::SERBINARY&)>(&DeserializeEvalMultKeyFromBytesWrapper<SerType::SERBINARY>),
          py::arg("bytes"), py::arg("sertype"),
          py::doc(serial_DeserializeEvalMultKeyString_docs));
    m.def("SerializeEvalAutomorphismKeyString", &SerializeEvalAutomorphismKeyToBytesWrapper<SerType::SERBINARY>,
          py::arg("sertype"), py::arg("keyTag") = "",
          py::doc(serial_SerializeEvalAutomorphismKeyString_docs));
    m.def("DeserializeEvalAutomorphismKeyString",
          static_cast<void (*)(const py::bytes&, const SerType::SERBINARY&)>(&DeserializeEvalAutomorphismKeyFromBytesWrapper<SerType::SERBINARY>),
          py::arg("bytes"), py::arg("sertype"),
          py::doc(serial_DeserializeEvalAutomorphismKeyString_docs));
}
