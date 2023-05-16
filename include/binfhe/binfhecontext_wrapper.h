#ifndef BINFHE_CRYPTOCONTEXT_BINDINGS_H
#define BINFHE_CRYPTOCONTEXT_BINDINGS_H

#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include "openfhe.h"
#include "binfhecontext.h"

namespace py = pybind11;
using namespace lbcrypto;
LWECiphertext binfhe_EncryptWrapper(BinFHEContext &self,
                                    ConstLWEPrivateKey sk,
                                    const LWEPlaintext &m,
                                    BINFHE_OUTPUT output,
                                    LWEPlaintextModulus p,
                                    uint64_t mod);
LWEPlaintext binfhe_DecryptWrapper(BinFHEContext &self,
                                   ConstLWEPrivateKey sk,
                                   ConstLWECiphertext ct,
                                   LWEPlaintextModulus p);

#endif // BINFHE_CRYPTOCONTEXT_BINDINGS_H