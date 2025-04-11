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

#include <pybind11/operators.h>

#include "openfhe.h"
#include "binfhecontext.h"
#include "binfhecontext_docs.h"
#include "binfhecontext_wrapper.h"

#include "cereal/archives/binary.hpp"
// #include "cereal/archives/portable_binary.hpp"
// #include "core/utils/serial.h"

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
      .value("BOOTSTRAPPED", BINFHE_OUTPUT::BOOTSTRAPPED);
  m.attr("INVALID_OUTPUT") = py::cast(BINFHE_OUTPUT::INVALID_OUTPUT);
  m.attr("FRESH") = py::cast(BINFHE_OUTPUT::FRESH);
  m.attr("BOOTSTRAPPED") = py::cast(BINFHE_OUTPUT::BOOTSTRAPPED);

  py::enum_<BINGATE>(m, "BINGATE")
      .value("OR", BINGATE::OR)
      .value("AND", BINGATE::AND)
      .value("NOR", BINGATE::NOR)
      .value("NAND", BINGATE::NAND)
      .value("XOR_FAST", BINGATE::XOR_FAST)
      .value("XNOR_FAST", BINGATE::XNOR_FAST)
      .value("XOR", BINGATE::XOR)
      .value("XNOR", BINGATE::XNOR);
  m.attr("OR") = py::cast(BINGATE::OR);
  m.attr("AND") = py::cast(BINGATE::AND);
  m.attr("NOR") = py::cast(BINGATE::NOR);
  m.attr("NAND") = py::cast(BINGATE::NAND);
  m.attr("XOR_FAST") = py::cast(BINGATE::XOR_FAST);
  m.attr("XNOR_FAST") = py::cast(BINGATE::XNOR_FAST);
  m.attr("XOR") = py::cast(BINGATE::XOR);
  m.attr("XNOR") = py::cast(BINGATE::XNOR);
}

void bind_binfhe_keys(py::module &m) {
  py::class_<LWEPrivateKeyImpl, std::shared_ptr<LWEPrivateKeyImpl>>(
      m, "LWEPrivateKey")
      .def(py::init<>())
      .def("GetLength", &LWEPrivateKeyImpl::GetLength)
      .def(py::self == py::self)
      .def(py::self != py::self);
}
void bind_binfhe_ciphertext(py::module &m) {
  py::class_<LWECiphertextImpl, std::shared_ptr<LWECiphertextImpl>>(
      m, "LWECiphertext")
      .def(py::init<>())
      .def("GetLength", &LWECiphertextImpl::GetLength)
      .def("GetModulus", &GetLWECiphertextModulusWrapper)
      .def(py::self == py::self)
      .def(py::self != py::self);
}

void bind_binfhe_context(py::module &m) {
  py::class_<BinFHEContext, std::shared_ptr<BinFHEContext>>(m, "BinFHEContext")
      .def(py::init<>())
      .def("GenerateBinFHEContext",
           static_cast<void (BinFHEContext::*)(BINFHE_PARAMSET, BINFHE_METHOD)>(
               &BinFHEContext::GenerateBinFHEContext),
           binfhe_GenerateBinFHEContext_parset_docs, py::arg("set"),
           py::arg("method") = GINX)
      // void GenerateBinFHEContext(BINFHE_PARAMSET set, bool arbFunc, uint32_t
      // logQ = 11, int64_t N = 0, BINFHE_METHOD method = GINX, bool
      // timeOptimization = false)
      .def("GenerateBinFHEContext",
           static_cast<void (BinFHEContext::*)(BINFHE_PARAMSET, bool, uint32_t,
                                               uint32_t, BINFHE_METHOD, bool)>(
               &BinFHEContext::GenerateBinFHEContext),
           binfhe_GenerateBinFHEContext_docs, py::arg("set"),
           py::arg("arbFunc"), py::arg("logQ") = 11, py::arg("N") = 0,
           py::arg("method") = GINX, py::arg("timeOptimization") = false)
      .def("KeyGen", &BinFHEContext::KeyGen, binfhe_KeyGen_docs)
      .def("KeyGenN", &BinFHEContext::KeyGenN)
      .def("KeyGenPair", &BinFHEContext::KeyGenPair)
      .def("BTKeyGen", &BinFHEContext::BTKeyGen, binfhe_BTKeyGen_docs,
           py::arg("sk"), py::arg("keygenMode") = SYM_ENCRYPT)
      .def("Encrypt", &binfhe_EncryptWrapper, binfhe_Encrypt_docs,
           py::arg("sk"), py::arg("m"), py::arg("output") = BOOTSTRAPPED,
           py::arg("p") = 4, py::arg("mod") = 0)
      .def("Decrypt", &binfhe_DecryptWrapper, binfhe_Decrypt_docs,
           py::arg("sk"), py::arg("ct"), py::arg("p") = 4)
      .def("EvalBinGate",
           static_cast<LWECiphertext (BinFHEContext::*)(
               BINGATE, ConstLWECiphertext &, ConstLWECiphertext &, bool) const>(
               &BinFHEContext::EvalBinGate),
           binfhe_EvalBinGate_docs, py::arg("gate"), py::arg("ct1"),
           py::arg("ct2"), py::arg("extended") = false)
      .def("EvalBinGate",
           static_cast<LWECiphertext (BinFHEContext::*)(
               BINGATE, const std::vector<LWECiphertext> &, bool) const>(
               &BinFHEContext::EvalBinGate),
           py::arg("gate"), py::arg("ctvector"), py::arg("extended") = false)
      .def("EvalNOT", &BinFHEContext::EvalNOT, binfhe_EvalNOT_docs,
           py::arg("ct"))
      .def("Getn", &GetnWrapper)
      .def("Getq", &GetqWrapper)
      .def("GetMaxPlaintextSpace", &GetMaxPlaintextSpaceWrapper)
      .def("GetBeta", &GetBetaWrapper)
      .def("EvalDecomp", &BinFHEContext::EvalDecomp, binfhe_EvalDecomp_docs,
           py::arg("ct"))
      .def("EvalFloor", &BinFHEContext::EvalFloor, binfhe_EvalFloor_docs,
           py::arg("ct"), py::arg("roundbits") = 0)
      .def("GenerateLUTviaFunction", &GenerateLUTviaFunctionWrapper,
           binfhe_GenerateLUTviaFunction_docs, py::arg("f"), py::arg("p"))
      .def("EvalFunc", &EvalFuncWrapper, binfhe_EvalFunc_docs, py::arg("ct"),
           py::arg("LUT"))
      .def("EvalSign", &BinFHEContext::EvalSign, binfhe_EvalSign_docs,
           py::arg("ct"), py::arg("schemeSwitch") = false)
      .def("EvalNOT", &BinFHEContext::EvalNOT)
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
      .def("SavePortableBinary",
           &BinFHEContext::save<cereal::PortableBinaryOutputArchive>)
      .def("LoadPortableBinary",
           &BinFHEContext::load<cereal::PortableBinaryInputArchive>)
      .def("GetPublicKey", &BinFHEContext::GetPublicKey)
      .def("GetSwitchKey", &BinFHEContext::GetSwitchKey)
      .def("GetRefreshKey", &BinFHEContext::GetRefreshKey)
      .def("GetBinFHEScheme", &BinFHEContext::GetBinFHEScheme)
      .def("GetLWEScheme", &BinFHEContext::GetLWEScheme)
      .def("GetParams", &BinFHEContext::GetParams);
}
