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
#ifndef __FBT_DOCS_H__
#define __FBT_DOCS_H__

// Docstrings for the functional bootstrapping bindings in src/lib/pke/fbt.cpp.
// These constants have external linkage, so this header must be included by
// fbt.cpp only, like the other docstring headers.

const char* cc_EvalHermiteTrigSeries_docs = R"pbdoc(
    Evaluate a trigonometric Hermite series approximating exp(i*Pi/2*x) over the interval [a, b].

    :param ciphertext: input ciphertext
    :type ciphertext: Ciphertext
    :param coefficientsCheb: Chebyshev coefficients of the function to approximate
    :type coefficientsCheb: list[complex]
    :param a: lower bound of the interval
    :type a: float
    :param b: upper bound of the interval
    :type b: float
    :param coefficientsHerm: Hermite interpolation coefficients
    :type coefficientsHerm: list[int] | list[complex]
    :param precomp: precomputation selector
    :type precomp: int
    :return: the resulting ciphertext
    :rtype: Ciphertext
)pbdoc";

#endif  // __FBT_DOCS_H__
