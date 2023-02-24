#ifndef OPENFHE_BINDINGS_H
#define OPENFHE_BINDINGS_H

#include <pybind11/pybind11.h>

void bind_parameters(pybind11::module &m);
void bind_crypto_context(pybind11::module &m);

#endif // OPENFHE_BINDINGS_H