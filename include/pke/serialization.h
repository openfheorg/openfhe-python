#ifndef OPENFHE_SERIALIZATION_BINDINGS_H
#define OPENFHE_SERIALIZATION_BINDINGS_H

#include <pybind11/pybind11.h>
using namespace lbcrypto;

template <typename ST>
bool SerializeEvalMultKeyWrapper(CryptoContext<DCRTPoly>& self,const std::string& filename, const ST& sertype, std::string id);

template <typename ST>
bool SerializeEvalAutomorphismKeyWrapper(CryptoContext<DCRTPoly>& self,const std::string& filename, const ST& sertype, std::string id);

template <typename ST>
bool DeserializeEvalMultKeyWrapper(CryptoContext<DCRTPoly>& self, const std::string& filename, const ST& sertype);

CryptoContext<DCRTPoly> DeserializeFromFileWrapper(const std::string& filename, const SerType::SERJSON& sertype);
#endif // OPENFHE_SERIALIZATION_BINDINGS_H