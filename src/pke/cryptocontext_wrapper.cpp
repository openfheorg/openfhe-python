#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <openfhe.h>
#include <vector>
#include <algorithm>
#include <complex> 
#include "cryptocontext_wrapper.h"

using namespace lbcrypto;
namespace py = pybind11;

Ciphertext<DCRTPoly> EvalFastRotationPrecomputeWrapper(CryptoContext<DCRTPoly> &self,ConstCiphertext<DCRTPoly> ciphertext) {
    std::shared_ptr<std::vector<DCRTPoly>> precomp = self->EvalFastRotationPrecompute(ciphertext);
    std::vector<DCRTPoly> elements = *(precomp.get());
    CiphertextImpl<DCRTPoly> cipherdigits = CiphertextImpl<DCRTPoly>(self);
    std::shared_ptr<CiphertextImpl<DCRTPoly>> cipherdigitsPtr = std::make_shared<CiphertextImpl<DCRTPoly>>(cipherdigits);
    cipherdigitsPtr->SetElements(elements);
    return cipherdigitsPtr;
}
Ciphertext<DCRTPoly> EvalFastRotationWrapper(CryptoContext<DCRTPoly>& self,ConstCiphertext<DCRTPoly> ciphertext, const usint index, const usint m,ConstCiphertext<DCRTPoly> digits) {
    
        std::vector<DCRTPoly> digitsElements = digits->GetElements();
        std::shared_ptr<std::vector<DCRTPoly>> digitsElementsPtr = std::make_shared<std::vector<DCRTPoly>>(digitsElements);
        return self->EvalFastRotation(ciphertext, index, m, digitsElementsPtr);
    }


Plaintext DecryptWrapper(CryptoContext<DCRTPoly>& self,ConstCiphertext<DCRTPoly> ciphertext,const PrivateKey<DCRTPoly> privateKey){
    Plaintext plaintextDecResult;
    self->Decrypt(privateKey, ciphertext,&plaintextDecResult);
    return plaintextDecResult;
}
Plaintext DecryptWrapper(CryptoContext<DCRTPoly>& self,const PrivateKey<DCRTPoly> privateKey,ConstCiphertext<DCRTPoly> ciphertext){
    Plaintext plaintextDecResult;
    self->Decrypt(privateKey, ciphertext,&plaintextDecResult);
    return plaintextDecResult;
}

const std::map<usint, EvalKey<DCRTPoly>> EvalAutomorphismKeyGenWrapper(CryptoContext<DCRTPoly>& self,const PrivateKey<DCRTPoly> privateKey,const std::vector<usint> &indexList){
    return *(self->EvalAutomorphismKeyGen(privateKey, indexList));
}

const std::map<usint, EvalKey<DCRTPoly>> EvalAutomorphismKeyGenWrapper_PublicKey(CryptoContext<DCRTPoly>& self,const PublicKey<DCRTPoly> publicKey, const PrivateKey<DCRTPoly> privateKey, const std::vector<usint> &indexList){
    return *(self->EvalAutomorphismKeyGen(publicKey, privateKey, indexList));
};