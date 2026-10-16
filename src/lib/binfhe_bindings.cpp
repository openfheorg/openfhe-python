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
#include "integer_conversions.h"

#include "openfhe.h"
#include "binfhecontext.h"
#include "binfhecontext-ser.h"
#include "binfhecontext_docs.h"
#include "binfhecontext_wrapper.h"
#include "lwe-keyswitchkey.h"

#include <pybind11/stl.h>
#include <pybind11/operators.h>

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
          .value("SIGNED_MOD_TEST", BINFHE_PARAMSET::SIGNED_MOD_TEST)
          .export_values();

     py::enum_<BINFHE_METHOD>(m, "BINFHE_METHOD")
          .value("INVALID_METHOD", BINFHE_METHOD::INVALID_METHOD)
          .value("AP", BINFHE_METHOD::AP)
          .value("GINX", BINFHE_METHOD::GINX)
          .value("LMKCDEY", BINFHE_METHOD::LMKCDEY)
          .export_values();

     py::enum_<KEYGEN_MODE>(m, "KEYGEN_MODE")
          .value("SYM_ENCRYPT", KEYGEN_MODE::SYM_ENCRYPT)
          .value("PUB_ENCRYPT", KEYGEN_MODE::PUB_ENCRYPT)
          .export_values();

     py::enum_<BINFHE_OUTPUT>(m, "BINFHE_OUTPUT")
          .value("INVALID_OUTPUT", BINFHE_OUTPUT::INVALID_OUTPUT)
          .value("FRESH", BINFHE_OUTPUT::FRESH)
          .value("BOOTSTRAPPED", BINFHE_OUTPUT::BOOTSTRAPPED)
          .value("LARGE_DIM", BINFHE_OUTPUT::LARGE_DIM)
          .value("SMALL_DIM", BINFHE_OUTPUT::SMALL_DIM)
          .export_values();

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
          .value("CMUX", BINGATE::CMUX)
          .export_values();
}

void bind_binfhe_keys(py::module &m) {
     // No default constructor: Python cannot populate the key, and BinFHEContext guards only
     // against a null pointer, so an empty-but-non-null key segfaults BTKeyGen/PubKeyGen/
     // KeySwitchGen. Keys come from KeyGen(), KeyGenN(), KeyGenPair() or deserialization.
     py::class_<LWEPrivateKeyImpl, std::shared_ptr<LWEPrivateKeyImpl>>(m, "LWEPrivateKey")
          .def("GetLength", &LWEPrivateKeyImpl::GetLength)
          .def("GetModulus",
               [](const LWEPrivateKeyImpl& self) {
                    return openfhe_python::IntegerToPyInt(self.GetModulus());
               },
              py::doc(binfhe_LWEPrivateKeyGetModulus_docs))
          .def(py::self == py::self)
          .def(py::self != py::self);

     // No default constructor for the same reason as LWEPrivateKey: an empty-but-non-null
     // public key passes the null check and Encrypt() silently produces a length-0 ciphertext.
     py::class_<LWEPublicKeyImpl, std::shared_ptr<LWEPublicKeyImpl>>(m, "LWEPublicKey")
          .def("GetLength", &LWEPublicKeyImpl::GetLength)
          .def("GetModulus",
               [](const LWEPublicKeyImpl& self) {
                    return openfhe_python::IntegerToPyInt(self.GetModulus());
               },
              py::doc(binfhe_LWEPublicKeyGetModulus_docs))
          .def(py::self == py::self)
          .def(py::self != py::self);

     py::class_<LWESwitchingKeyImpl, std::shared_ptr<LWESwitchingKeyImpl>>(m, "LWESwitchingKey")
          .def(py::init<>());

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
               [](const LWECiphertextImpl& self) {
                    return openfhe_python::IntegerToPyInt(self.GetModulus());
               })
          .def("GetptModulus",
               [](const LWECiphertextImpl& self) {
                    return openfhe_python::IntegerToPyInt(self.GetptModulus());
               },
              py::doc(binfhe_LWECiphertextGetptModulus_docs))
          .def("SetModulus",
               [](LWECiphertextImpl& self, const py::int_& modulus) {
                    self.SetModulus(openfhe_python::PyIntToInteger<NativeInteger>(modulus));
               },
               py::arg("modulus"),
              py::doc(binfhe_LWECiphertextSetModulus_docs))
          .def("SetptModulus",
               [](LWECiphertextImpl& self, const py::int_& plaintextModulus) {
                    self.SetptModulus(openfhe_python::PyIntToInteger<NativeInteger>(plaintextModulus));
               },
               py::arg("plaintextModulus"),
              py::doc(binfhe_LWECiphertextSetptModulus_docs))
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
          .def("KeySwitchGen", &BinFHEContext::KeySwitchGen,
               py::arg("sk"),
               py::arg("skN"),
               py::doc(binfhe_KeySwitchGen_docs))
          .def("PubKeyGen", &BinFHEContext::PubKeyGen,
               py::arg("sk"),
               py::doc(binfhe_PubKeyGen_docs))
          .def("SwitchCTtoqn", &BinFHEContext::SwitchCTtoqn,
               py::arg("ksk"),
               py::arg("ct"),
               py::doc(binfhe_SwitchCTtoqn_docs))
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
               py::doc(binfhe_EncryptPubKey_docs))
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
          .def("EvalConstant", &BinFHEContext::EvalConstant,
               py::arg("value"))
          .def("ClearBTKeys", &BinFHEContext::ClearBTKeys)
          .def("HasInternal32RefreshKey", &BinFHEContext::HasInternal32RefreshKey,
              py::doc(binfhe_HasInternal32RefreshKey_docs))
          .def("HasInternal32SwitchKey", &BinFHEContext::HasInternal32SwitchKey,
              py::doc(binfhe_HasInternal32SwitchKey_docs))
          .def("Bootstrap", &BinFHEContext::Bootstrap, py::arg("ct"), py::arg("extended") = false)
          .def("SerializedVersion", &BinFHEContext::SerializedVersion,
               binfhe_SerializedVersion_docs)
          .def("SerializedObjectName", &BinFHEContext::SerializedObjectName,
               binfhe_SerializedObjectName_docs)
          // note: save/load (cereal archives), GetRefreshKey, GetBinFHEScheme, GetLWEScheme and
          // GetParams are not bound: their argument/return types are not exposed to Python, so
          // the bindings could never be called successfully
          .def("GetPublicKey", &BinFHEContext::GetPublicKey)
          .def("GetSwitchKey", &BinFHEContext::GetSwitchKey,
              py::doc(binfhe_GetSwitchKey_docs))
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
