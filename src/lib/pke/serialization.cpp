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
#include "openfhe.h"
#include "scheme/bfvrns/bfvrns-ser.h"
#include "scheme/bgvrns/bgvrns-ser.h"
#include "cryptocontext-ser.h"
#include "bindings.h"
#include "serialization.h"

using namespace lbcrypto;
namespace py = pybind11;

template <typename ST>
bool SerializeEvalMultKeyWrapper(const std::string& filename, const ST& sertype, std::string id)
{
    std::ofstream outfile(filename, std::ios::out | std::ios::binary);
    bool res;
    res = CryptoContextImpl<DCRTPoly>::SerializeEvalMultKey<ST>(outfile, sertype, id);
    outfile.close();
    return res;
}

void bind_serialization(pybind11::module &m) {
    // Json Serialization
    m.def("SerializeToFile", static_cast<bool (*)(const std::string&, const CryptoContext<DCRTPoly>&, const SerType::SERJSON&)>(&Serial::SerializeToFile<DCRTPoly>), py::arg("filename"), py::arg("obj"), py::arg("sertype"));
    m.def("DeserializeFromFile", static_cast<bool (*)(const std::string&, CryptoContext<DCRTPoly>& ,const SerType::SERJSON&)>(&Serial::DeserializeFromFile<DCRTPoly>), py::arg("filename"), py::arg("obj"), py::arg("sertype"));
    m.def("SerializeToFile", static_cast<bool (*)(const std::string&, const PublicKey<DCRTPoly>&, const SerType::SERJSON&)>(&Serial::SerializeToFile<PublicKey<DCRTPoly>>), py::arg("filename"), py::arg("obj"), py::arg("sertype"));
    m.def("DeserializeFromFile", static_cast<bool (*)(const std::string&, PublicKey<DCRTPoly>& ,const SerType::SERJSON&)>(&Serial::DeserializeFromFile<PublicKey<DCRTPoly>>), py::arg("filename"), py::arg("obj"), py::arg("sertype"));
    m.def("SerializeToFile", static_cast<bool (*)(const std::string&, const PrivateKey<DCRTPoly>&, const SerType::SERJSON&)>(&Serial::SerializeToFile<PrivateKey<DCRTPoly>>), py::arg("filename"), py::arg("obj"), py::arg("sertype"));
    m.def("DeserializeFromFile", static_cast<bool (*)(const std::string&, PrivateKey<DCRTPoly>& ,const SerType::SERJSON&)>(&Serial::DeserializeFromFile<PrivateKey<DCRTPoly>>), py::arg("filename"), py::arg("obj"), py::arg("sertype"));
    m.def("SerializeToFile", static_cast<bool (*)(const std::string&, const Ciphertext<DCRTPoly>&, const SerType::SERJSON&)>(&Serial::SerializeToFile<Ciphertext<DCRTPoly>>), py::arg("filename"), py::arg("obj"), py::arg("sertype"));
    m.def("DeserializeFromFile", static_cast<bool (*)(const std::string&, Ciphertext<DCRTPoly>& ,const SerType::SERJSON&)>(&Serial::DeserializeFromFile<Ciphertext<DCRTPoly>>), py::arg("filename"), py::arg("obj"), py::arg("sertype"));
    // Binary Serialization
    m.def("SerializeToFile", static_cast<bool (*)(const std::string&, const CryptoContext<DCRTPoly>&, const SerType::SERBINARY&)>(&Serial::SerializeToFile<DCRTPoly>), py::arg("filename"), py::arg("obj"), py::arg("sertype"));
    m.def("DeserializeFromFile", static_cast<bool (*)(const std::string&, CryptoContext<DCRTPoly>& ,const SerType::SERBINARY&)>(&Serial::DeserializeFromFile<DCRTPoly>), py::arg("filename"), py::arg("obj"), py::arg("sertype"));
    m.def("SerializeToFile", static_cast<bool (*)(const std::string&, const PublicKey<DCRTPoly>&, const SerType::SERBINARY&)>(&Serial::SerializeToFile<PublicKey<DCRTPoly>>), py::arg("filename"), py::arg("obj"), py::arg("sertype"));
    m.def("DeserializeFromFile", static_cast<bool (*)(const std::string&, PublicKey<DCRTPoly>& ,const SerType::SERBINARY&)>(&Serial::DeserializeFromFile<PublicKey<DCRTPoly>>), py::arg("filename"), py::arg("obj"), py::arg("sertype"));
    m.def("SerializeToFile", static_cast<bool (*)(const std::string&, const PrivateKey<DCRTPoly>&, const SerType::SERBINARY&)>(&Serial::SerializeToFile<PrivateKey<DCRTPoly>>), py::arg("filename"), py::arg("obj"), py::arg("sertype"));
    m.def("DeserializeFromFile", static_cast<bool (*)(const std::string&, PrivateKey<DCRTPoly>& ,const SerType::SERBINARY&)>(&Serial::DeserializeFromFile<PrivateKey<DCRTPoly>>), py::arg("filename"), py::arg("obj"), py::arg("sertype"));
    m.def("SerializeToFile", static_cast<bool (*)(const std::string&, const Ciphertext<DCRTPoly>&, const SerType::SERBINARY&)>(&Serial::SerializeToFile<Ciphertext<DCRTPoly>>), py::arg("filename"), py::arg("obj"), py::arg("sertype"));
    m.def("DeserializeFromFile", static_cast<bool (*)(const std::string&, Ciphertext<DCRTPoly>& ,const SerType::SERBINARY&)>(&Serial::DeserializeFromFile<Ciphertext<DCRTPoly>>), py::arg("filename"), py::arg("obj"), py::arg("sertype"));
    
    
}


