#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <openfhe.h>
#include "binfhecontext_wrapper.h"

using namespace lbcrypto;
namespace py = pybind11;

LWECiphertext binfhe_EncryptWrapper(BinFHEContext &self, ConstLWEPrivateKey sk, const LWEPlaintext &m, BINFHE_OUTPUT output,
                                    LWEPlaintextModulus p, uint64_t mod)
{
    NativeInteger mod_native_int = NativeInteger(mod);
    return self.Encrypt(sk, m, output, p, mod_native_int);
}

LWEPlaintext binfhe_DecryptWrapper(BinFHEContext &self,
                                   ConstLWEPrivateKey sk,
                                   ConstLWECiphertext ct,
                                   LWEPlaintextModulus p)
{

    LWEPlaintext result;
    self.Decrypt(sk, ct, &result, p);
    return result;
}