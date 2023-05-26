#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include "openfhe.h"
#include "bindings.h"

using namespace lbcrypto;
namespace py = pybind11;

template<typename Element>
Plaintext DecryptWrapper_standalone(Ciphertext<Element> ciphertext,const PrivateKey<Element> privateKey){
    Plaintext plaintextDecResult;
    auto cc = ciphertext->GetCryptoContext();
    cc->Decrypt(privateKey, ciphertext,&plaintextDecResult);
    return plaintextDecResult;
}
void bind_decryption(py::module &m){
    m.def("Decrypt",&DecryptWrapper_standalone<DCRTPoly>,"Decrypt a ciphertext using private key");
}