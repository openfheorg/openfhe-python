//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2023-2026, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//
// Author TPOC: contact@openfhe.org
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//==================================================================================
#ifndef OPENFHE_PYTHON_INTEGER_CONVERSIONS_H
#define OPENFHE_PYTHON_INTEGER_CONVERSIONS_H

#include <pybind11/pybind11.h>

#include <string>

namespace openfhe_python {

// Convert an arbitrary-size OpenFHE integer to a Python integer without
// narrowing through a native C++ integer type.
template <typename Integer>
pybind11::int_ IntegerToPyInt(const Integer& value) {
    PyObject* result = PyLong_FromString(value.ToString().c_str(), nullptr, 10);
    if (result == nullptr)
        throw pybind11::error_already_set();
    return pybind11::reinterpret_steal<pybind11::int_>(result);
}

// Convert an arbitrary-size Python integer through its decimal representation.
// OpenFHE integers are unsigned: a negative input is rejected here because the
// OpenFHE string parser hangs on a leading '-', and a value wider than the target
// type is rejected because the constructor silently wraps it.
template <typename Integer>
Integer PyIntToInteger(const pybind11::int_& value) {
    if (pybind11::isinstance<pybind11::bool_>(value))
        throw pybind11::type_error("expected an int, got a bool");

    PyObject* result = PyObject_Str(value.ptr());
    if (result == nullptr)
        throw pybind11::error_already_set();
    auto valueStr = pybind11::reinterpret_steal<pybind11::str>(result).cast<std::string>();

    if (!valueStr.empty() && valueStr[0] == '-')
        throw pybind11::value_error("OpenFHE integers cannot be negative, got " + valueStr);

    Integer converted(valueStr);
    if (converted.ToString() != valueStr) {
        PyErr_SetString(PyExc_OverflowError,
                        ("value too large for the target OpenFHE integer type: " + valueStr).c_str());
        throw pybind11::error_already_set();
    }
    return converted;
}

}  // namespace openfhe_python

#endif  // OPENFHE_PYTHON_INTEGER_CONVERSIONS_H
