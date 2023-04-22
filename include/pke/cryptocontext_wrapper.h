#ifndef OPENFHE_CRYPTOCONTEXT_BINDINGS_H
#define OPENFHE_CRYPTOCONTEXT_BINDINGS_H

#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <vector>
#include <algorithm>
#include <complex>
#include "openfhe.h"
#include "bindings.h"

namespace py = pybind11;
using namespace lbcrypto;
using ParmType = typename DCRTPoly::Params;

Plaintext MakeCKKSPackedPlaintextWrapper(std::shared_ptr<CryptoContextImpl<DCRTPoly>> &self, 
            const std::vector<float> &value, 
            size_t depth, uint32_t level, 
            const std::shared_ptr<ParmType> params,
            usint slots);

Ciphertext<DCRTPoly> EvalFastRotationPrecomputeWrapper(CryptoContext<DCRTPoly>& self,
                                                        ConstCiphertext<DCRTPoly> ciphertext);

Ciphertext<DCRTPoly> EvalFastRotationWrapper(CryptoContext<DCRTPoly>& self,
                                            ConstCiphertext<DCRTPoly> ciphertext,
                                              const usint index,
                                              const usint m,
                                              ConstCiphertext<DCRTPoly> digits);

#endif // OPENFHE_CRYPTOCONTEXT_BINDINGS_H