#ifndef OPENFHE_SERIALIZATION_BINDINGS_H
#define OPENFHE_SERIALIZATION_BINDINGS_H

#include <pybind11/pybind11.h>
using namespace lbcrypto;

template <typename T>
bool SerializeToFileImpl(const std::string& filename, const T& obj, const std::string& sertype_str);
bool SerializeToFileInterface(const std::string& filename, const CryptoContext<DCRTPoly>& obj, const std::string& sertype_str);
bool SerializeToFileInterface(const std::string& filename, const PublicKey<DCRTPoly>& obj, const std::string& sertype_str);
bool SerializeToFileInterface(const std::string& filename, const PrivateKey<DCRTPoly>& obj, const std::string& sertype_str);

#endif // OPENFHE_SERIALIZATION_BINDINGS_H