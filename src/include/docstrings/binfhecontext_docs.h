// BSD 2-Clause License

// Copyright (c) 2023, OpenFHE

// All rights reserved.

// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:

// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.

// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.

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

#ifndef BINFHECONTEXT_DOCSTRINGS_H
#define BINFHECONTEXT_DOCSTRINGS_H

// GenerateBinFHEContext
const char* binfhe_GenerateBinFHEContext_parset_docs = R"pbdoc(
    Creates a crypto context using predefined parameter sets. Recommended for most users.

    :param set: The parameter set: TOY, MEDIUM, STD128, STD192, STD256.
    :type set: BINFHE_PARAMSET
    :param method: The bootstrapping method (DM or CGGI).
    :type method: BINFHE_METHOD
    :return: The created crypto context.
    :rtype: BinFHEContext
)pbdoc";

// KeyGen
const char* binfhe_KeyGen_docs = R"pbdoc(
    Generates a secret key for the main LWE scheme.

    :return: The secret key.
    :rtype: LWEPrivateKey
)pbdoc";

// BTKeyGen
const char* binfhe_BTKeyGen_docs = R"pbdoc(
    Generates bootstrapping keys.

    :param sk: The secret key.
    :type sk: LWEPrivateKey
)pbdoc";

// Encrypt
const char* binfhe_Encrypt_docs = R"pbdoc(
    Encrypts a bit or integer using a secret key (symmetric key encryption).

    :param sk: The secret key.
    :type sk: LWEPrivateKey
    :param m: The plaintext.
    :type m: int
    :param output: FRESH to generate a fresh ciphertext, BOOTSTRAPPED to generate a refreshed ciphertext (default).
    :type output: BINFHE_OUTPUT
    :param p: Plaintext modulus (default 4).
    :type p: int
    :param mod: Encrypt according to mod instead of m_q if mod != 0.
    :type mod: int
    :return: The ciphertext.
    :rtype: LWECiphertext
)pbdoc";

// Decrypt
const char* binfhe_Decrypt_docs = R"pbdoc(
    Decrypts a ciphertext using a secret key.

    :param sk: The secret key.
    :type sk: LWEPrivateKey
    :param ct: The ciphertext.
    :type ct: LWECiphertext
    :param p: Plaintext modulus (default 4).
    :type p: int
    :return: The plaintext.
    :rtype: int
)pbdoc";

// EvalBinGate
const char* binfhe_EvalBinGate_docs = R"pbdoc(
    Evaluates a binary gate (calls bootstrapping as a subroutine).

    :param gate: The gate; can be AND, OR, NAND, NOR, XOR, or XNOR.
    :type gate: BINGATE
    :param ct1: First ciphertext.
    :type ct1: LWECiphertext
    :param ct2: Second ciphertext.
    :type ct2: LWECiphertext
    :return: The resulting ciphertext.
    :rtype: LWECiphertext
)pbdoc";

// EvalNOT
const char* binfhe_EvalNOT_docs = R"pbdoc(
    Evaluates the NOT gate.

    :param ct: The input ciphertext.
    :type ct: LWECiphertext
    :return: The resulting ciphertext.
    :rtype: LWECiphertext
)pbdoc";


#endif // BINFHECONTEXT_DOCSTRINGS_H
