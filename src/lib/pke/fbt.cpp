//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2023-2026, Duality Technologies Inc. and other contributors
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

// Bindings for CKKS functional bootstrapping helpers: the RLWE schemelet
// (SchemeletRLWEMP), trigonometric Hermite interpolation coefficients and
// the scheme-switching data (de)serializer.

#include "bindings.h"

#include "openfhe.h"
#include "math/hermite.h"
#include "schemelet/rlwe-mp.h"
#include "scheme/ckksrns/ckksrns-utils.h"
#include "unittest/utils/schemeswitching-data-serializer.h"

#include <pybind11/complex.h>
#include <pybind11/functional.h>
#include <pybind11/stl.h>

#include <complex>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

using namespace lbcrypto;
using CC = CryptoContextImpl<DCRTPoly>;
namespace py = pybind11;

// disable the PYBIND11 template-based conversion for this type: a vector of Poly is
// treated as an opaque RLWE ciphertext produced/consumed by SchemeletRLWEMP
PYBIND11_MAKE_OPAQUE(std::vector<Poly>);

using ElementParams = ILDCRTParams<DCRTPoly::Integer>;

// Converts an arbitrary-size Python integer to BigInteger (and back) using its decimal
// string representation, as BigInteger may not fit in any native integer type.
static BigInteger FBTPyIntToBigInteger(const py::int_& value) {
    auto valueStr = py::reinterpret_steal<py::str>(PyObject_Str(value.ptr()));
    return BigInteger(valueStr.cast<std::string>());
}
static py::int_ FBTBigIntegerToPyInt(const BigInteger& value) {
    return py::reinterpret_steal<py::int_>(PyLong_FromString(value.ToString().c_str(), nullptr, 10));
}

void bind_fbt_crypto_context(DCRTCryptoContextClass &cls) {
    // Keep CKKS depth helpers on CryptoContext without exposing the scheme implementation class.
    // For functional bootstrapping, overloads taking a list of ints correspond to the optimized
    // Boolean case; overloads taking a list of complex numbers cover the general case. Lambdas
    // convert arbitrary-size Python ints to BigInteger.
    cls.def_static("GetBootstrapDepth",
            py::overload_cast<uint32_t, const std::vector<uint32_t>&, SecretKeyDist>(&FHECKKSRNS::GetBootstrapDepth),
            py::arg("depth"), py::arg("levelBudget"), py::arg("keyDist"))
        .def_static("GetBootstrapDepth",
            py::overload_cast<const std::vector<uint32_t>&, SecretKeyDist>(&FHECKKSRNS::GetBootstrapDepth),
            py::arg("levelBudget"), py::arg("keyDist"))
        .def_static("GetFBTDepth",
            [](const std::vector<uint32_t>& levelBudget, const std::vector<int64_t>& coefficients,
               const py::int_& PInput, size_t order, SecretKeyDist skd, uint32_t firstModSize) {
                return FHECKKSRNS::GetFBTDepth(levelBudget, coefficients, FBTPyIntToBigInteger(PInput), order, skd,
                                               firstModSize);
            },
            py::arg("levelBudget"), py::arg("coefficients"), py::arg("PInput"), py::arg("order"), py::arg("skd"),
            py::arg("firstModSize") = 60)
        .def_static("GetFBTDepth",
            [](const std::vector<uint32_t>& levelBudget, const std::vector<std::complex<double>>& coefficients,
               const py::int_& PInput, size_t order, SecretKeyDist skd, uint32_t firstModSize) {
                return FHECKKSRNS::GetFBTDepth(levelBudget, coefficients, FBTPyIntToBigInteger(PInput), order, skd,
                                               firstModSize);
            },
            py::arg("levelBudget"), py::arg("coefficients"), py::arg("PInput"), py::arg("order"), py::arg("skd"),
            py::arg("firstModSize") = 60)
        .def_static("GetFEFBTDepth", &FHECKKSRNS::GetFEFBTDepth<std::complex<double>>,
            py::arg("levelBudget"), py::arg("coefficients"), py::arg("skd") = SPARSE_TERNARY,
            py::arg("firstModSize") = 60)
        .def("EvalFBTSetup",
            [](CC& self, const std::vector<int64_t>& coeffs, uint32_t numSlots, const py::int_& PIn,
               const py::int_& POut, const py::int_& Bigq, const PublicKey<DCRTPoly>& pubKey,
               const std::vector<uint32_t>& dim1, const std::vector<uint32_t>& levelBudget, uint32_t lvlsAfterBoot,
               uint32_t depthLeveledComputation, size_t order) {
                self.EvalFBTSetup(coeffs, numSlots, FBTPyIntToBigInteger(PIn), FBTPyIntToBigInteger(POut),
                                  FBTPyIntToBigInteger(Bigq), pubKey, dim1, levelBudget, lvlsAfterBoot,
                                  depthLeveledComputation, order);
            },
            py::arg("coeffs"), py::arg("numSlots"), py::arg("PIn"), py::arg("POut"), py::arg("Bigq"),
            py::arg("pubKey"), py::arg("dim1"), py::arg("levelBudget"), py::arg("lvlsAfterBoot") = 0,
            py::arg("depthLeveledComputation") = 0, py::arg("order") = (size_t)1)
        .def("EvalFBTSetup",
            [](CC& self, const std::vector<std::complex<double>>& coeffs, uint32_t numSlots, const py::int_& PIn,
               const py::int_& POut, const py::int_& Bigq, const PublicKey<DCRTPoly>& pubKey,
               const std::vector<uint32_t>& dim1, const std::vector<uint32_t>& levelBudget, uint32_t lvlsAfterBoot,
               uint32_t depthLeveledComputation, size_t order) {
                self.EvalFBTSetup(coeffs, numSlots, FBTPyIntToBigInteger(PIn), FBTPyIntToBigInteger(POut),
                                  FBTPyIntToBigInteger(Bigq), pubKey, dim1, levelBudget, lvlsAfterBoot,
                                  depthLeveledComputation, order);
            },
            py::arg("coeffs"), py::arg("numSlots"), py::arg("PIn"), py::arg("POut"), py::arg("Bigq"),
            py::arg("pubKey"), py::arg("dim1"), py::arg("levelBudget"), py::arg("lvlsAfterBoot") = 0,
            py::arg("depthLeveledComputation") = 0, py::arg("order") = (size_t)1)
        .def("EvalFBT",
            [](CC& self, ConstCiphertext<DCRTPoly> ciphertext, const std::vector<int64_t>& coeffs,
               uint32_t digitBitSize, const py::int_& initialScaling, uint64_t postScaling, uint32_t levelToReduce,
               size_t order) {
                return self.EvalFBT(ciphertext, coeffs, digitBitSize, FBTPyIntToBigInteger(initialScaling), postScaling,
                                    levelToReduce, order);
            },
            py::arg("ciphertext"), py::arg("coeffs"), py::arg("digitBitSize"), py::arg("initialScaling"),
            py::arg("postScaling"), py::arg("levelToReduce") = 0, py::arg("order") = (size_t)1)
        .def("EvalFBT",
            [](CC& self, ConstCiphertext<DCRTPoly> ciphertext, const std::vector<std::complex<double>>& coeffs,
               uint32_t digitBitSize, const py::int_& initialScaling, uint64_t postScaling, uint32_t levelToReduce,
               size_t order) {
                return self.EvalFBT(ciphertext, coeffs, digitBitSize, FBTPyIntToBigInteger(initialScaling), postScaling,
                                    levelToReduce, order);
            },
            py::arg("ciphertext"), py::arg("coeffs"), py::arg("digitBitSize"), py::arg("initialScaling"),
            py::arg("postScaling"), py::arg("levelToReduce") = 0, py::arg("order") = (size_t)1)
        .def("EvalFBTNoDecoding",
            [](CC& self, ConstCiphertext<DCRTPoly> ciphertext, const std::vector<int64_t>& coeffs,
               uint32_t digitBitSize, const py::int_& initialScaling, size_t order) {
                return self.EvalFBTNoDecoding(ciphertext, coeffs, digitBitSize, FBTPyIntToBigInteger(initialScaling),
                                              order);
            },
            py::arg("ciphertext"), py::arg("coeffs"), py::arg("digitBitSize"), py::arg("initialScaling"),
            py::arg("order") = (size_t)1)
        .def("EvalFBTNoDecoding",
            [](CC& self, ConstCiphertext<DCRTPoly> ciphertext, const std::vector<std::complex<double>>& coeffs,
               uint32_t digitBitSize, const py::int_& initialScaling, size_t order) {
                return self.EvalFBTNoDecoding(ciphertext, coeffs, digitBitSize, FBTPyIntToBigInteger(initialScaling),
                                              order);
            },
            py::arg("ciphertext"), py::arg("coeffs"), py::arg("digitBitSize"), py::arg("initialScaling"),
            py::arg("order") = (size_t)1)
        .def("EvalHomDecoding", &CryptoContextImpl<DCRTPoly>::EvalHomDecoding,
            py::arg("ciphertext"), py::arg("postScaling"), py::arg("levelToReduce") = 0)
        .def("EvalMVBPrecompute",
            [](CC& self, ConstCiphertext<DCRTPoly> ciphertext, const std::vector<int64_t>& coeffs,
               uint32_t digitBitSize, const py::int_& initialScaling, size_t order) {
                return self.EvalMVBPrecompute(ciphertext, coeffs, digitBitSize, FBTPyIntToBigInteger(initialScaling),
                                              order);
            },
            py::arg("ciphertext"), py::arg("coeffs"), py::arg("digitBitSize"), py::arg("initialScaling"),
            py::arg("order") = (size_t)1)
        .def("EvalMVBPrecompute",
            [](CC& self, ConstCiphertext<DCRTPoly> ciphertext, const std::vector<std::complex<double>>& coeffs,
               uint32_t digitBitSize, const py::int_& initialScaling, size_t order) {
                return self.EvalMVBPrecompute(ciphertext, coeffs, digitBitSize, FBTPyIntToBigInteger(initialScaling),
                                              order);
            },
            py::arg("ciphertext"), py::arg("coeffs"), py::arg("digitBitSize"), py::arg("initialScaling"),
            py::arg("order") = (size_t)1)
        .def("EvalMVB", &CryptoContextImpl<DCRTPoly>::EvalMVB<int64_t>,
            py::arg("ciphertexts"), py::arg("coeffs"), py::arg("digitBitSize"), py::arg("postScaling"),
            py::arg("levelToReduce") = 0, py::arg("order") = (size_t)1)
        .def("EvalMVB", &CryptoContextImpl<DCRTPoly>::EvalMVB<std::complex<double>>,
            py::arg("ciphertexts"), py::arg("coeffs"), py::arg("digitBitSize"), py::arg("postScaling"),
            py::arg("levelToReduce") = 0, py::arg("order") = (size_t)1)
        .def("EvalMVBNoDecoding", &CryptoContextImpl<DCRTPoly>::EvalMVBNoDecoding<int64_t>,
            py::arg("ciphertexts"), py::arg("coeffs"), py::arg("digitBitSize"), py::arg("order") = (size_t)1)
        .def("EvalMVBNoDecoding", &CryptoContextImpl<DCRTPoly>::EvalMVBNoDecoding<std::complex<double>>,
            py::arg("ciphertexts"), py::arg("coeffs"), py::arg("digitBitSize"), py::arg("order") = (size_t)1)
        .def("EvalHermiteTrigSeries", &CryptoContextImpl<DCRTPoly>::EvalHermiteTrigSeries<int64_t>,
            py::arg("ciphertext"), py::arg("coefficientsCheb"), py::arg("a"), py::arg("b"),
            py::arg("coefficientsHerm"), py::arg("precomp") = (size_t)0)
        .def("EvalHermiteTrigSeries", &CryptoContextImpl<DCRTPoly>::EvalHermiteTrigSeries<std::complex<double>>,
            py::arg("ciphertext"), py::arg("coefficientsCheb"), py::arg("a"), py::arg("b"),
            py::arg("coefficientsHerm"), py::arg("precomp") = (size_t)0)
        // FE functional bootstrapping
        .def("EvalFEFuncBootstrapSetup", &CryptoContextImpl<DCRTPoly>::EvalFEFuncBootstrapSetup,
            py::arg("levelBudget") = std::vector<uint32_t>({5, 4}),
            py::arg("dim1") = std::vector<uint32_t>({0, 0}),
            py::arg("slots") = 0)
        .def("EvalFEFuncBootstrap", &CryptoContextImpl<DCRTPoly>::EvalFEFuncBootstrap,
            py::arg("ciphertext"), py::arg("coefficients"))
        .def("EvalFEFuncBootstrapPrecompute", &CryptoContextImpl<DCRTPoly>::EvalFEFuncBootstrapPrecompute,
            py::arg("ciphertext"), py::arg("coefficients"))
        .def("EvalFEFuncBootstrapWithPrecomp", &CryptoContextImpl<DCRTPoly>::EvalFEFuncBootstrapWithPrecomp,
            py::arg("powers"), py::arg("coefficients"))
        .def("ClearBootstrapPrecom", &CryptoContextImpl<DCRTPoly>::ClearBootstrapPrecom);
}

void bind_fbt(py::module &m) {
    // opaque holder for the powers of the complex exponential precomputed by
    // EvalMVBPrecompute/EvalFEFuncBootstrapPrecompute
    py::class_<seriesPowers<DCRTPoly>, std::shared_ptr<seriesPowers<DCRTPoly>>>(m, "SeriesPowers");

    // opaque holder for an RLWE ciphertext (a vector of Poly) used by SchemeletRLWEMP
    py::class_<std::vector<Poly>>(m, "PolyVector")
        .def(py::init<>())
        .def("__len__", [](const std::vector<Poly>& self) { return self.size(); })
        .def("Clone", [](const std::vector<Poly>& self) { return std::vector<Poly>(self); })
        // switches every element of the RLWE ciphertext to the given modulus
        .def("SwitchModulus",
            [](std::vector<Poly>& self, const py::int_& modulus) {
                auto mod = FBTPyIntToBigInteger(modulus);
                for (auto& poly : self)
                    poly.SwitchModulus(mod, 1, 0, 0);
            },
            py::arg("modulus"))
        // element-wise subtraction of two RLWE ciphertexts
        .def("__sub__",
            [](const std::vector<Poly>& self, const std::vector<Poly>& other) {
                if (self.size() != other.size())
                    OPENFHE_THROW("PolyVector sizes do not match");
                std::vector<Poly> result(self);
                for (size_t i = 0; i < result.size(); ++i)
                    result[i] = result[i] - other[i];
                return result;
            });

    // Multiplicative depth needed to evaluate the series with the given coefficients
    m.def("GetMultiplicativeDepthByCoeffVector", &GetMultiplicativeDepthByCoeffVector<int64_t>,
          py::arg("vec"), py::arg("isNormalized") = false);
    m.def("GetMultiplicativeDepthByCoeffVector", &GetMultiplicativeDepthByCoeffVector<std::complex<double>>,
          py::arg("vec"), py::arg("isNormalized") = false);

    // note: the element parameters type (ILDCRTParams<DCRTPoly::Integer>) returned by
    // SchemeletRLWEMP::GetElementParams is already registered as "ParmType" in bind_crypto_context

    // Trigonometric Hermite interpolation coefficients of a look-up table given as a Python function
    m.def("GetHermiteTrigCoefficients", &GetHermiteTrigCoefficients,
          py::arg("func"), py::arg("p"), py::arg("order"), py::arg("scale"));

    // Conversions between an RLWE scheme and CKKS sharing the same secret key
    py::class_<SchemeletRLWEMP>(m, "SchemeletRLWEMP")
        .def_static("GetElementParams", &SchemeletRLWEMP::GetElementParams,
            py::arg("privateKey"), py::arg("level") = 0)
        .def_static("EncryptCoeff",
            [](const std::vector<int64_t>& input, const py::int_& Q, const py::int_& p,
               const PrivateKey<DCRTPoly>& privateKey, const std::shared_ptr<ElementParams>& elementParams,
               bool bitReverse) {
                return SchemeletRLWEMP::EncryptCoeff(input, FBTPyIntToBigInteger(Q), FBTPyIntToBigInteger(p),
                                                     privateKey, elementParams, bitReverse);
            },
            py::arg("input"), py::arg("Q"), py::arg("p"), py::arg("privateKey"), py::arg("elementParams"),
            py::arg("bitReverse") = false)
        .def_static("DecryptCoeff",
            [](const std::vector<Poly>& input, const py::int_& Q, const py::int_& p,
               const PrivateKey<DCRTPoly>& privateKey, const std::shared_ptr<ElementParams>& elementParams,
               uint32_t numSlots, uint32_t length, bool bitReverse) {
                return SchemeletRLWEMP::DecryptCoeff(input, FBTPyIntToBigInteger(Q), FBTPyIntToBigInteger(p),
                                                     privateKey, elementParams, numSlots, length, bitReverse);
            },
            py::arg("input"), py::arg("Q"), py::arg("p"), py::arg("privateKey"), py::arg("elementParams"),
            py::arg("numSlots"), py::arg("length") = 0, py::arg("bitReverse") = false)
        .def_static("ModSwitch",
            [](std::vector<Poly>& input, const py::int_& Q1, const py::int_& Q2) {
                SchemeletRLWEMP::ModSwitch(input, FBTPyIntToBigInteger(Q1), FBTPyIntToBigInteger(Q2));
            },
            py::arg("input"), py::arg("Q1"), py::arg("Q2"))
        .def_static("ConvertRLWEToCKKS",
            [](const CryptoContext<DCRTPoly>& cc, const std::vector<Poly>& coeffs, const PublicKey<DCRTPoly>& pubKey,
               const py::int_& Bigq, uint32_t slots, uint32_t level) {
                return SchemeletRLWEMP::ConvertRLWEToCKKS(*cc, coeffs, pubKey, FBTPyIntToBigInteger(Bigq), slots,
                                                          level);
            },
            py::arg("cc"), py::arg("coeffs"), py::arg("pubKey"), py::arg("Bigq"), py::arg("slots"),
            py::arg("level") = 0)
        .def_static("ConvertCKKSToRLWE",
            [](ConstCiphertext<DCRTPoly> ctxt, const py::int_& Q) {
                return SchemeletRLWEMP::ConvertCKKSToRLWE(ctxt, FBTPyIntToBigInteger(Q));
            },
            py::arg("ctxt"), py::arg("Q"))
        .def_static("GetQPrime",
            [](const PublicKey<DCRTPoly>& pubKey, uint32_t lvls) {
                return FBTBigIntegerToPyInt(SchemeletRLWEMP::GetQPrime(pubKey, lvls));
            },
            py::arg("pubKey"), py::arg("lvls"));

    // Serializer/deserializer for all the data needed by CKKS <-> FHEW scheme switching
    py::class_<SchemeSwitchingDataSerializer>(m, "SchemeSwitchingDataSerializer")
        .def(py::init<CryptoContext<DCRTPoly>, PublicKey<DCRTPoly>, Ciphertext<DCRTPoly>>(),
             py::arg("cryptoContext"), py::arg("publicKey"), py::arg("RAWCiphertext"))
        .def("SetDataDirectory", &SchemeSwitchingDataSerializer::SetDataDirectory, py::arg("dir"))
        .def("Serialize", &SchemeSwitchingDataSerializer::Serialize);

    py::class_<SchemeSwitchingDataDeserializer>(m, "SchemeSwitchingDataDeserializer")
        .def(py::init<>())
        .def("SetDataDirectory", &SchemeSwitchingDataDeserializer::SetDataDirectory, py::arg("dir"))
        .def("getCryptoContext", &SchemeSwitchingDataDeserializer::getCryptoContext)
        .def("getPublicKey", &SchemeSwitchingDataDeserializer::getPublicKey)
        .def("getRAWCiphertext", &SchemeSwitchingDataDeserializer::getRAWCiphertext)
        .def("Deserialize", &SchemeSwitchingDataDeserializer::Deserialize);
}
