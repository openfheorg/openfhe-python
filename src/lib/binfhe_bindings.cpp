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
#include "binfhe_bindings.h"

#include "openfhe.h"
#include "binfhecontext.h"
#include "binfhecontext-ser.h"
#include "binfhecontext_docs.h"
#include "binfhecontext_wrapper.h"

#include <pybind11/stl.h>
#include <pybind11/operators.h>

#include "cereal/archives/binary.hpp"

#include <map>
#include <string>
#include <tuple>

using namespace lbcrypto;
namespace py = pybind11;

void bind_binfhe_enums(py::module &m) {
     py::enum_<BINFHE_PARAMSET>(m, "BINFHE_PARAMSET")
          .value("TOY", BINFHE_PARAMSET::TOY)
          .value("MEDIUM", BINFHE_PARAMSET::MEDIUM)
          .value("STD128_LMKCDEY", BINFHE_PARAMSET::STD128_LMKCDEY)
          .value("STD128_AP", BINFHE_PARAMSET::STD128_AP)
          .value("STD128", BINFHE_PARAMSET::STD128)
          .value("STD192", BINFHE_PARAMSET::STD192)
          .value("STD256", BINFHE_PARAMSET::STD256)
          .value("STD128Q", BINFHE_PARAMSET::STD128Q)
          .value("STD128Q_LMKCDEY", BINFHE_PARAMSET::STD128Q_LMKCDEY)
          .value("STD192Q", BINFHE_PARAMSET::STD192Q)
          .value("STD256Q", BINFHE_PARAMSET::STD256Q)
          .value("STD128_3", BINFHE_PARAMSET::STD128_3)
          .value("STD128_3_LMKCDEY", BINFHE_PARAMSET::STD128_3_LMKCDEY)
          .value("STD128Q_3", BINFHE_PARAMSET::STD128Q_3)
          .value("STD128Q_3_LMKCDEY", BINFHE_PARAMSET::STD128Q_3_LMKCDEY)
          .value("STD192Q_3", BINFHE_PARAMSET::STD192Q_3)
          .value("STD256Q_3", BINFHE_PARAMSET::STD256Q_3)
          .value("STD128_4", BINFHE_PARAMSET::STD128_4)
          .value("STD128_4_LMKCDEY", BINFHE_PARAMSET::STD128_4_LMKCDEY)
          .value("STD128Q_4", BINFHE_PARAMSET::STD128Q_4)
          .value("STD128Q_4_LMKCDEY", BINFHE_PARAMSET::STD128Q_4_LMKCDEY)
          .value("STD192Q_4", BINFHE_PARAMSET::STD192Q_4)
          .value("STD256Q_4", BINFHE_PARAMSET::STD256Q_4)
          .value("SIGNED_MOD_TEST", BINFHE_PARAMSET::SIGNED_MOD_TEST);
     m.attr("TOY") = py::cast(BINFHE_PARAMSET::TOY);
     m.attr("MEDIUM") = py::cast(BINFHE_PARAMSET::MEDIUM);
     m.attr("STD128_LMKCDEY") = py::cast(BINFHE_PARAMSET::STD128_LMKCDEY);
     m.attr("STD128_AP") = py::cast(BINFHE_PARAMSET::STD128_AP);
     m.attr("STD128") = py::cast(BINFHE_PARAMSET::STD128);
     m.attr("STD192") = py::cast(BINFHE_PARAMSET::STD192);
     m.attr("STD256") = py::cast(BINFHE_PARAMSET::STD256);
     m.attr("STD128Q") = py::cast(BINFHE_PARAMSET::STD128Q);
     m.attr("STD128Q_LMKCDEY") = py::cast(BINFHE_PARAMSET::STD128Q_LMKCDEY);
     m.attr("STD192Q") = py::cast(BINFHE_PARAMSET::STD192Q);
     m.attr("STD256Q") = py::cast(BINFHE_PARAMSET::STD256Q);
     m.attr("STD128_3") = py::cast(BINFHE_PARAMSET::STD128_3);
     m.attr("STD128_3_LMKCDEY") = py::cast(BINFHE_PARAMSET::STD128_3_LMKCDEY);
     m.attr("STD128Q_3") = py::cast(BINFHE_PARAMSET::STD128Q_3);
     m.attr("STD128Q_3_LMKCDEY") = py::cast(BINFHE_PARAMSET::STD128Q_3_LMKCDEY);
     m.attr("STD192Q_3") = py::cast(BINFHE_PARAMSET::STD192Q_3);
     m.attr("STD256Q_3") = py::cast(BINFHE_PARAMSET::STD256Q_3);
     m.attr("STD128_4") = py::cast(BINFHE_PARAMSET::STD128_4);
     m.attr("STD128_4_LMKCDEY") = py::cast(BINFHE_PARAMSET::STD128_4_LMKCDEY);
     m.attr("STD128Q_4") = py::cast(BINFHE_PARAMSET::STD128Q_4);
     m.attr("STD128Q_4_LMKCDEY") = py::cast(BINFHE_PARAMSET::STD128Q_4_LMKCDEY);
     m.attr("STD192Q_4") = py::cast(BINFHE_PARAMSET::STD192Q_4);
     m.attr("STD256Q_4") = py::cast(BINFHE_PARAMSET::STD256Q_4);
     m.attr("SIGNED_MOD_TEST") = py::cast(BINFHE_PARAMSET::SIGNED_MOD_TEST);

     py::enum_<BINFHE_METHOD>(m, "BINFHE_METHOD")
          .value("INVALID_METHOD", BINFHE_METHOD::INVALID_METHOD)
          .value("AP", BINFHE_METHOD::AP)
          .value("GINX", BINFHE_METHOD::GINX)
          .value("LMKCDEY", BINFHE_METHOD::LMKCDEY);
     m.attr("INVALID_METHOD") = py::cast(BINFHE_METHOD::INVALID_METHOD);
     m.attr("GINX") = py::cast(BINFHE_METHOD::GINX);
     m.attr("AP") = py::cast(BINFHE_METHOD::AP);
     m.attr("LMKCDEY") = py::cast(BINFHE_METHOD::LMKCDEY);

     py::enum_<KEYGEN_MODE>(m, "KEYGEN_MODE")
          .value("SYM_ENCRYPT", KEYGEN_MODE::SYM_ENCRYPT)
          .value("PUB_ENCRYPT", KEYGEN_MODE::PUB_ENCRYPT);
     m.attr("SYM_ENCRYPT") = py::cast(KEYGEN_MODE::SYM_ENCRYPT);
     m.attr("PUB_ENCRYPT") = py::cast(KEYGEN_MODE::PUB_ENCRYPT);

     py::enum_<BINFHE_OUTPUT>(m, "BINFHE_OUTPUT")
          .value("INVALID_OUTPUT", BINFHE_OUTPUT::INVALID_OUTPUT)
          .value("FRESH", BINFHE_OUTPUT::FRESH)
          .value("BOOTSTRAPPED", BINFHE_OUTPUT::BOOTSTRAPPED)
          .value("LARGE_DIM", BINFHE_OUTPUT::LARGE_DIM)
          .value("SMALL_DIM", BINFHE_OUTPUT::SMALL_DIM);
     m.attr("INVALID_OUTPUT") = py::cast(BINFHE_OUTPUT::INVALID_OUTPUT);
     m.attr("FRESH") = py::cast(BINFHE_OUTPUT::FRESH);
     m.attr("BOOTSTRAPPED") = py::cast(BINFHE_OUTPUT::BOOTSTRAPPED);
     m.attr("LARGE_DIM") = py::cast(BINFHE_OUTPUT::LARGE_DIM);
     m.attr("SMALL_DIM") = py::cast(BINFHE_OUTPUT::SMALL_DIM);

     py::enum_<BINGATE>(m, "BINGATE")
          .value("OR", BINGATE::OR)
          .value("AND", BINGATE::AND)
          .value("NOR", BINGATE::NOR)
          .value("NAND", BINGATE::NAND)
          .value("XOR_FAST", BINGATE::XOR_FAST)
          .value("XNOR_FAST", BINGATE::XNOR_FAST)
          .value("XOR", BINGATE::XOR)
          .value("XNOR", BINGATE::XNOR)
          .value("MAJORITY", BINGATE::MAJORITY)
          .value("AND3", BINGATE::AND3)
          .value("OR3", BINGATE::OR3)
          .value("AND4", BINGATE::AND4)
          .value("OR4", BINGATE::OR4)
          .value("CMUX", BINGATE::CMUX);
     m.attr("OR") = py::cast(BINGATE::OR);
     m.attr("AND") = py::cast(BINGATE::AND);
     m.attr("NOR") = py::cast(BINGATE::NOR);
     m.attr("NAND") = py::cast(BINGATE::NAND);
     m.attr("XOR_FAST") = py::cast(BINGATE::XOR_FAST);
     m.attr("XNOR_FAST") = py::cast(BINGATE::XNOR_FAST);
     m.attr("XOR") = py::cast(BINGATE::XOR);
     m.attr("XNOR") = py::cast(BINGATE::XNOR);
     m.attr("MAJORITY") = py::cast(BINGATE::MAJORITY);
     m.attr("AND3") = py::cast(BINGATE::AND3);
     m.attr("OR3") = py::cast(BINGATE::OR3);
     m.attr("AND4") = py::cast(BINGATE::AND4);
     m.attr("OR4") = py::cast(BINGATE::OR4);
     m.attr("CMUX") = py::cast(BINGATE::CMUX);
}

void bind_binfhe_keys(py::module &m) {
     py::class_<LWEPrivateKeyImpl, std::shared_ptr<LWEPrivateKeyImpl>>(m, "LWEPrivateKey")
          .def(py::init<>())
          .def("GetLength", &LWEPrivateKeyImpl::GetLength)
          .def(py::self == py::self)
          .def(py::self != py::self);

     py::class_<LWEPublicKeyImpl, std::shared_ptr<LWEPublicKeyImpl>>(m, "LWEPublicKey")
          .def(py::init<>())
          .def("GetLength", &LWEPublicKeyImpl::GetLength)
          .def(py::self == py::self)
          .def(py::self != py::self);

     py::class_<LWEKeyPairImpl, std::shared_ptr<LWEKeyPairImpl>>(m, "LWEKeyPair")
          .def_readonly("publicKey", &LWEKeyPairImpl::publicKey)
          .def_readonly("secretKey", &LWEKeyPairImpl::secretKey)
          .def("good", &LWEKeyPairImpl::good);

     // struct holding the refreshing, key switching and public keys generated by BTKeyGen
     // (treated as an opaque object in Python: generate, serialize and load it)
     py::class_<RingGSWBTKey>(m, "RingGSWBTKey")
          .def(py::init<>());
}
void bind_binfhe_ciphertext(py::module &m) {
     py::class_<LWECiphertextImpl, std::shared_ptr<LWECiphertextImpl>>(m, "LWECiphertext")
          .def(py::init<>())
          .def("GetLength", &LWECiphertextImpl::GetLength)
          .def("GetModulus",
               [](LWECiphertext& self) {
                    return self->GetModulus().ConvertToInt<uint64_t>();
               })
          .def(py::self == py::self)
          .def(py::self != py::self);
}

void bind_binfhe_context(py::module &m) {
     py::class_<BinFHEContext, std::shared_ptr<BinFHEContext>>(m, "BinFHEContext")
          .def(py::init<>())
          .def("GenerateBinFHEContext",
               py::overload_cast<BINFHE_PARAMSET, BINFHE_METHOD>(&BinFHEContext::GenerateBinFHEContext),
               binfhe_GenerateBinFHEContext_parset_docs,
               py::arg("set"),
               py::arg("method") = GINX)
          // void GenerateBinFHEContext(BINFHE_PARAMSET set, bool arbFunc, uint32_t
          // logQ = 11, int64_t N = 0, BINFHE_METHOD method = GINX, bool
          // timeOptimization = false)
          .def("GenerateBinFHEContext",
               py::overload_cast<BINFHE_PARAMSET, bool, uint32_t, uint32_t, BINFHE_METHOD, bool>(&BinFHEContext::GenerateBinFHEContext),
               binfhe_GenerateBinFHEContext_docs,
               py::arg("set"),
               py::arg("arbFunc"),
               py::arg("logQ") = 11,
               py::arg("N") = 0,
               py::arg("method") = GINX,
               py::arg("timeOptimization") = false)
          .def("KeyGen", &BinFHEContext::KeyGen, binfhe_KeyGen_docs)
          .def("KeyGenN", &BinFHEContext::KeyGenN)
          .def("KeyGenPair", &BinFHEContext::KeyGenPair)
          .def("BTKeyGen", &BinFHEContext::BTKeyGen,
               binfhe_BTKeyGen_docs,
               py::arg("sk"),
               py::arg("keygenMode") = SYM_ENCRYPT,
               py::arg("internal32") = true)
          .def("Encrypt",
               [](BinFHEContext& self, ConstLWEPrivateKey sk, const LWEPlaintext& m, BINFHE_OUTPUT output, LWEPlaintextModulus p, uint64_t mod) {
                    return self.Encrypt(sk, m, output, p, NativeInteger(mod));
               },
               py::arg("sk"),
               py::arg("m"),
               py::arg("output") = BOOTSTRAPPED,
               py::arg("p") = 4,
               py::arg("mod") = 0,
               py::doc(binfhe_Encrypt_docs))
          .def("Encrypt",
               [](BinFHEContext& self, ConstLWEPublicKey pk, const LWEPlaintext& m, BINFHE_OUTPUT output, LWEPlaintextModulus p, uint64_t mod) {
                    return self.Encrypt(pk, m, output, p, NativeInteger(mod));
               },
               py::arg("pk"),
               py::arg("m"),
               py::arg("output") = SMALL_DIM,
               py::arg("p") = 4,
               py::arg("mod") = 0,
               py::doc(binfhe_Encrypt_docs))
          .def("Decrypt",
               [](BinFHEContext& self, ConstLWEPrivateKey sk, ConstLWECiphertext ct, LWEPlaintextModulus p) {
                    LWEPlaintext result;
                    self.Decrypt(sk, ct, &result, p);
                    return result;
               },
               py::arg("sk"),
               py::arg("ct"),
               py::arg("p") = 4,
               py::doc(binfhe_Decrypt_docs))
          .def("EvalBinGate",
               py::overload_cast<BINGATE, ConstLWECiphertext&, ConstLWECiphertext&, bool>(&BinFHEContext::EvalBinGate, py::const_),
               binfhe_EvalBinGate_docs,
               py::arg("gate"),
               py::arg("ct1"),
               py::arg("ct2"),
               py::arg("extended") = false)
          .def("EvalBinGate",
               py::overload_cast<BINGATE, const std::vector<LWECiphertext>&, bool>(&BinFHEContext::EvalBinGate, py::const_),
               py::arg("gate"),
               py::arg("ctvector"),
               py::arg("extended") = false)
          .def("EvalNOT", &BinFHEContext::EvalNOT,
               binfhe_EvalNOT_docs,
               py::arg("ct"))
          .def("Getn",
               [](BinFHEContext& self) {
                    return self.GetParams()->GetLWEParams()->Getn();
               })
          .def("Getq",
               [](BinFHEContext& self) {
                    return self.GetParams()->GetLWEParams()->Getq().ConvertToInt<uint64_t>();
               })
          .def("GetMaxPlaintextSpace",
               [](BinFHEContext& self) {
                    return self.GetMaxPlaintextSpace().ConvertToInt<uint64_t>();
               })
          .def("GetBeta",
               [](BinFHEContext& self) {
                    return self.GetBeta().ConvertToInt<uint64_t>();
               })
          .def("EvalDecomp", &BinFHEContext::EvalDecomp,
               binfhe_EvalDecomp_docs,
               py::arg("ct"))
          .def("EvalFloor", &BinFHEContext::EvalFloor,
               binfhe_EvalFloor_docs,
               py::arg("ct"),
               py::arg("roundbits") = 0)
          .def("GenerateLUTviaFunction", &GenerateLUTviaFunctionWrapper,
               binfhe_GenerateLUTviaFunction_docs,
               py::arg("f"),
               py::arg("p"))
          .def("EvalFunc",
               [](BinFHEContext& self, ConstLWECiphertext& ct, const std::vector<uint64_t>& LUT) {
                    std::vector<NativeInteger> nativeLUT;
                    nativeLUT.reserve(LUT.size());
                    for (auto value : LUT) {
                         nativeLUT.emplace_back(value);
                    }
                    return self.EvalFunc(ct, nativeLUT);
               },
               py::arg("ct"),
               py::arg("LUT"),
               py::doc(binfhe_EvalFunc_docs))
          .def("EvalSign", &BinFHEContext::EvalSign,
               binfhe_EvalSign_docs,
               py::arg("ct"),
               py::arg("schemeSwitch") = false)
          .def("EvalConstant", &BinFHEContext::EvalConstant)
          .def("ClearBTKeys", &BinFHEContext::ClearBTKeys)
          .def("Bootstrap", &BinFHEContext::Bootstrap, py::arg("ct"), py::arg("extended") = false)
          .def("SerializedVersion", &BinFHEContext::SerializedVersion,
               binfhe_SerializedVersion_docs)
          .def("SerializedObjectName", &BinFHEContext::SerializedObjectName,
               binfhe_SerializedObjectName_docs)
          .def("SaveJSON", &BinFHEContext::save<cereal::JSONOutputArchive>)
          .def("LoadJSON", &BinFHEContext::load<cereal::JSONInputArchive>)
          .def("SaveBinary", &BinFHEContext::save<cereal::BinaryOutputArchive>)
          .def("LoadBinary", &BinFHEContext::load<cereal::BinaryInputArchive>)
          .def("SavePortableBinary", &BinFHEContext::save<cereal::PortableBinaryOutputArchive>)
          .def("LoadPortableBinary", &BinFHEContext::load<cereal::PortableBinaryInputArchive>)
          .def("GetPublicKey", &BinFHEContext::GetPublicKey)
          .def("GetSwitchKey", &BinFHEContext::GetSwitchKey)
          .def("GetRefreshKey", &BinFHEContext::GetRefreshKey)
          .def("GetBinFHEScheme", &BinFHEContext::GetBinFHEScheme)
          .def("GetLWEScheme", &BinFHEContext::GetLWEScheme)
          .def("GetParams", &BinFHEContext::GetParams)
          .def("GetN",
               [](BinFHEContext& self) {
                    return self.GetParams()->GetLWEParams()->GetN();
               })
          .def("GetQ",
               [](BinFHEContext& self) {
                    return self.GetParams()->GetLWEParams()->GetQ().ConvertToInt<uint64_t>();
               })
          .def("GetBTKey", &BinFHEContext::GetBTKey)
          .def("BTKeyLoad", &BinFHEContext::BTKeyLoad,
               py::arg("key"),
               py::arg("internal32") = true)
          .def("GetBTKeyMap",
               [](BinFHEContext& self) {
                    return *self.GetBTKeyMap();
               })
          .def("BTKeyMapLoadSingleElement", &BinFHEContext::BTKeyMapLoadSingleElement,
               py::arg("baseG"),
               py::arg("key"));
}

// binfhe serialization helpers, following the same patterns as src/lib/pke/serialization.cpp

template <typename T, typename ST>
static std::tuple<T, bool> BinFHEDeserializeFromFileWrapper(const std::string& filename, const ST& sertype) {
    T newob;
    bool result = Serial::DeserializeFromFile<T>(filename, newob, sertype);
    return std::make_tuple(newob, result);
}

template <typename ST>
static void bind_binfhe_serialization_for_sertype(py::module &m) {
    m.def("SerializeToFile",
          static_cast<bool (*)(const std::string&, const BinFHEContext&, const ST&)>(
              &Serial::SerializeToFile<BinFHEContext>),
          py::arg("filename"), py::arg("obj"), py::arg("sertype"));
    m.def("DeserializeBinFHECryptoContext", &BinFHEDeserializeFromFileWrapper<BinFHEContext, ST>,
          py::arg("filename"), py::arg("sertype"));
    m.def("SerializeToFile",
          static_cast<bool (*)(const std::string&, const LWECiphertext&, const ST&)>(
              &Serial::SerializeToFile<LWECiphertext>),
          py::arg("filename"), py::arg("obj"), py::arg("sertype"));
    m.def("DeserializeLWECiphertext", &BinFHEDeserializeFromFileWrapper<LWECiphertext, ST>,
          py::arg("filename"), py::arg("sertype"));
    m.def("SerializeToFile",
          static_cast<bool (*)(const std::string&, const LWEPrivateKey&, const ST&)>(
              &Serial::SerializeToFile<LWEPrivateKey>),
          py::arg("filename"), py::arg("obj"), py::arg("sertype"));
    m.def("DeserializeLWEPrivateKey", &BinFHEDeserializeFromFileWrapper<LWEPrivateKey, ST>,
          py::arg("filename"), py::arg("sertype"));
    m.def("SerializeToFile",
          static_cast<bool (*)(const std::string&, const LWEPublicKey&, const ST&)>(
              &Serial::SerializeToFile<LWEPublicKey>),
          py::arg("filename"), py::arg("obj"), py::arg("sertype"));
    m.def("DeserializeLWEPublicKey", &BinFHEDeserializeFromFileWrapper<LWEPublicKey, ST>,
          py::arg("filename"), py::arg("sertype"));
    m.def("SerializeToFile",
          static_cast<bool (*)(const std::string&, const RingGSWBTKey&, const ST&)>(
              &Serial::SerializeToFile<RingGSWBTKey>),
          py::arg("filename"), py::arg("obj"), py::arg("sertype"));
    m.def("DeserializeBinFHEBTKey", &BinFHEDeserializeFromFileWrapper<RingGSWBTKey, ST>,
          py::arg("filename"), py::arg("sertype"));
}

void bind_binfhe_serialization(py::module &m) {
    bind_binfhe_serialization_for_sertype<SerType::SERJSON>(m);
    bind_binfhe_serialization_for_sertype<SerType::SERBINARY>(m);
}
