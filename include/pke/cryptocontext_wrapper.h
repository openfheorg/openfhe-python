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

Ciphertext<DCRTPoly> EvalFastRotationPrecomputeWrapper(CryptoContext<DCRTPoly>& self,
                                                        ConstCiphertext<DCRTPoly> ciphertext);

Ciphertext<DCRTPoly> EvalFastRotationWrapper(CryptoContext<DCRTPoly>& self,
                                            ConstCiphertext<DCRTPoly> ciphertext,
                                              const usint index,
                                              const usint m,
                                              ConstCiphertext<DCRTPoly> digits);

Plaintext DecryptWrapper(CryptoContext<DCRTPoly>& self,
ConstCiphertext<DCRTPoly> ciphertext,const PrivateKey<DCRTPoly> privateKey);
Plaintext DecryptWrapper(CryptoContext<DCRTPoly>& self,
const PrivateKey<DCRTPoly> privateKey,ConstCiphertext<DCRTPoly> ciphertext);

const std::map<usint, EvalKey<DCRTPoly>> EvalAutomorphismKeyGenWrapper(CryptoContext<DCRTPoly>& self,const PrivateKey<DCRTPoly> privateKey,const std::vector<usint> &indexList);
const std::map<usint, EvalKey<DCRTPoly>> EvalAutomorphismKeyGenWrapper_PublicKey(CryptoContext<DCRTPoly>& self,const PublicKey<DCRTPoly> publicKey, const PrivateKey<DCRTPoly> privateKey, const std::vector<usint> &indexList);
#endif // OPENFHE_CRYPTOCONTEXT_BINDINGS_H