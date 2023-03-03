#ifndef OPENFHE_BINDINGS_H
#define OPENFHE_BINDINGS_H

#include <pybind11/pybind11.h>

void bind_parameters(pybind11::module &m);
void bind_crypto_context(pybind11::module &m);
void bind_enums(pybind11::module &m);
void bind_keys(pybind11::module &m);
void bind_encodings(pybind11::module &m);
void bind_ciphertext(pybind11::module &m);
void bind_decryption(pybind11::module &m);
#endif // OPENFHE_BINDINGS_H