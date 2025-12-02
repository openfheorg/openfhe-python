//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2023-2025, Duality Technologies Inc. and other contributors
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
#ifndef __CIPHERTEXT_DOCS_H__
#define __CIPHERTEXT_DOCS_H__

// GetLevel
const char* ctx_GetLevel_docs = R"pbdoc(
    Get the number of scalings performed.

    :return: The level of the ciphertext.
    :rtype: int
)pbdoc";

// SetLevel
const char* ctx_SetLevel_docs = R"pbdoc(
    Set the number of scalings.

    :param level: The level to set.
    :type level: int
)pbdoc";

//KeyPair Docs
const char* kp_good_docs = R"pbdoc(
    Checks whether both public key and secret key are non-null, or correctly initialized.

    :return: Result.
    :rtype: bool
)pbdoc";

const char* cc_RemoveElement_docs = R"pbdoc(
    Remove an element from the ciphertext inner vector given its index.

    :param index: The index of the element to remove.
    :type index: int
)pbdoc";
#endif // __CIPHERTEXT_DOCS_H__
