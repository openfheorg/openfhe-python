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
const char* ctx_CloneEmpty_docs = R"pbdoc(
    Copy the ciphertext metadata, skipping the encrypted elements.

    :return: a new ciphertext with the same context, key tag, level/scaling data and metadata but no elements
    :rtype: Ciphertext
)pbdoc";

const char* ctx_GetHopLevel_docs = R"pbdoc(
    Get the re-encryption (hop) level of the ciphertext.

    :return: the number of times the ciphertext has been re-encrypted (proxy re-encryption hops)
    :rtype: int
)pbdoc";

const char* ctx_GetScalingFactorInt_docs = R"pbdoc(
    Get the integer scaling factor of the ciphertext.

    :return: the exact integer scaling factor of the encrypted message (used by BGV)
    :rtype: int
)pbdoc";

const char* ctx_NumberCiphertextElements_docs = R"pbdoc(
    Get the number of ring elements: 2 for a fresh encryption, 3 after a multiplication.

    :return: the number of ring elements
    :rtype: int
)pbdoc";

const char* ctx_SetEncodingType_docs = R"pbdoc(
    Set the encoding type of the ciphertext.

    :param encodingType: the encoding type
    :type encodingType: PlaintextEncodings
)pbdoc";

const char* ctx_SetHopLevel_docs = R"pbdoc(
    Set the re-encryption (hop) level of the ciphertext.

    :param hopLevel: the re-encryption level
    :type hopLevel: int
)pbdoc";

const char* ctx_SetKeyTag_docs = R"pbdoc(
    Set the tag of the key used to create the ciphertext.

    :param keyTag: secret key identifier
    :type keyTag: str
)pbdoc";

const char* ctx_SetScalingFactorInt_docs = R"pbdoc(
    Set the integer scaling factor of the ciphertext.

    :param sf: the integer scaling factor
    :type sf: int
)pbdoc";

const char* key_GetCryptoContext_docs = R"pbdoc(
    Get the crypto context this key belongs to.

    :return: the crypto context (may be null for a default-constructed object)
    :rtype: CryptoContext
)pbdoc";

#endif // __CIPHERTEXT_DOCS_H__
