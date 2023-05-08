#ifndef OPENFHE_SERIALIZATION_BINDINGS_H
#define OPENFHE_SERIALIZATION_BINDINGS_H

#include <pybind11/pybind11.h>
using namespace lbcrypto;

template <typename ST>
bool SerializeEvalMultKeyWrapper(std::shared_ptr<CryptoContextImpl<DCRTPoly>> &self,const std::string &filename, const ST &sertype, std::string id);
template <typename ST>
bool SerializeEvalAutomorphismKeyWrapper(std::shared_ptr<CryptoContextImpl<DCRTPoly>> &self,const std::string &filename, const ST &sertype, std::string id);
template <typename ST>
bool DeserializeEvalMultKeyWrapper(std::shared_ptr<CryptoContextImpl<DCRTPoly>> &self, const std::string &filename, const ST &sertype);

#endif // OPENFHE_SERIALIZATION_BINDINGS_H