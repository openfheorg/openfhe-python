#ifndef BINFHE_BINDINGS_H
#define BINFHE_BINDINGS_H

#include <pybind11/pybind11.h>

void bind_binfhe_enums(pybind11::module &m);
void bind_binfhe_context(pybind11::module &m);

#endif // BINFHE_BINDINGS_H