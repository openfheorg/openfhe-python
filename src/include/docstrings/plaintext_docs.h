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
#ifndef __PLAINTEXT_DOCS_H__
#define __PLAINTEXT_DOCS_H__

// GetScalingFactor
const char* ptx_GetScalingFactor_docs = R"doc(
    Get the scaling factor of the plaintext for CKKS-based plaintexts.

    :return: The scaling factor of the plaintext.
    :rtype: float
)doc";

// SetScalingFactor
const char* ptx_SetScalingFactor_docs = R"pbdoc(
    Set the scaling factor of the plaintext for CKKS-based plaintexts.

    :param sf: The scaling factor to set.
    :type sf: float
)pbdoc";

// GetLength
const char* ptx_GetLength_docs = R"pbdoc(
    Get method to return the length of the plaintext.

    :return: The length of the plaintext in terms of the number of bits.
    :rtype: int
)pbdoc";

// GetSchemeID
const char* ptx_GetSchemeID_docs = R"pbdoc(
    Get the encryption technique of the plaintext for BFV-based plaintexts.

    :return: The scheme ID of the plaintext.
    :rtype: SCHEME
)pbdoc";

// SetLength
const char* ptx_SetLength_docs = R"pbdoc(
    Resize the plaintext; only works for plaintexts that support a resizable vector (coefpacked).
    
    :param newSize: The new size of the plaintext.
    :type newSize: int
)pbdoc";

// IsEncoded
const char* ptx_IsEncoded_docs = R"pbdoc(
    Check if the plaintext is encoded.

    :return: True if the plaintext is encoded, False otherwise.
    :rtype: bool
)pbdoc";

// GetLogPrecision
const char* ptx_GetLogPrecision_docs = R"pbdoc(
    Get the log of the plaintext precision.

    :return: The log of the plaintext precision.
    :rtype: float
)pbdoc";

// Encode
const char* ptx_Encode_docs = R"pbdoc(
    Encode the plaintext into a polynomial.
)pbdoc";

// Decode
const char* ptx_Decode_docs = R"pbdoc(
    Decode the polynomial into a plaintext.
)pbdoc";

const char* ptx_LowBound_docs = R"pbdoc(
    Calculate and return lower bound that can be encoded with the plaintext modulus the number to encode MUST be greater than this value

    :return: floor(-p/2)
    :rtype: int
)pbdoc";

const char* ptx_HighBound_docs = R"pbdoc(
    Calculate and return upper bound that can be encoded with the plaintext modulus the number to encode MUST be less than this value

    :return: floor(p/2)
    :rtype: int
)pbdoc";

const char* ptx_SetFormat_docs = R"pbdoc(
    SetFormat - allows format to be changed for openfhe.Plaintext evaluations

    :param fmt:
    :type format: Format
)pbdoc";

// GetCKKSPackedValue
const char* ptx_GetCKKSPackedValue_docs = R"pbdoc(
    Get the packed value of the plaintext for CKKS-based plaintexts.

    :return: The packed value of the plaintext.
    :rtype: List[complex]
)pbdoc";


//GetRealPackedValue
const char* ptx_GetRealPackedValue_docs = R"pbdoc(
    Get the real component of the packed value of the plaintext for CKKS-based plaintexts.

    :return: The real-component of the packed value of the plaintext.
    :rtype: List[double]
)pbdoc";


#endif // __PLAINTEXT_DOCS_H__
