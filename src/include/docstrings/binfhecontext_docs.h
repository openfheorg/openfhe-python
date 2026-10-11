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
#ifndef __BINFHECONTEXT_DOCS_H
#define __BINFHECONTEXT_DOCS_H

// GenerateBinFHEContext
const char* binfhe_GenerateBinFHEContext_parset_docs = R"pbdoc(
    Creates a crypto context using predefined parameters sets. Recommended for most users.

    :param set: the parameter set: TOY, MEDIUM, STD128, STD192, STD256 with variants
    :type set: BINFHE_PARAMSET
    :param method: the bootstrapping method (DM or CGGI or LMKCDEY)
    :type method: BINFHE_METHOD
)pbdoc";

////void GenerateBinFHEContext(BINFHE_PARAMSET set, bool arbFunc, uint32_t logQ = 11, int64_t N = 0, BINFHE_METHOD method = GINX, bool timeOptimization = false)
const char* binfhe_GenerateBinFHEContext_docs  = R"pbdoc(
    Creates a crypto context using custom parameters. Should be used with care (only for advanced users familiar with LWE parameter selection).

    :param set: The parameter set: TOY, MEDIUM, STD128, STD192, STD256 with variants.
    :type set: BINFHE_PARAMSET
    :param arbFunc:  whether need to evaluate an arbitrary function using functional bootstrapping
    :type arbFunc: bool
    :param logQ:  log(input ciphertext modulus)
    :type logQ: int
    :param N:  ring dimension for RingGSW/RLWE used in bootstrapping
    :type N: int
    :param method: the bootstrapping method (DM or CGGI or LMKCDEY)
    :type method: BINFHE_METHOD
    :param timeOptimization:  whether to use dynamic bootstrapping technique
    :type timeOptimization: bool
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
    :param keygenMode: SYM_ENCRYPT for symmetric-key or PUB_ENCRYPT for public-key bootstrapping keys
    :type keygenMode: KEYGEN_MODE
    :param internal32: whether to keep the keys in their 32-bit internal form
    :type internal32: bool
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
    :param extended: whether to use the extended variant of the gate evaluation
    :type extended: bool
)pbdoc";

// EvalNOT
const char* binfhe_EvalNOT_docs = R"pbdoc(
    Evaluates the NOT gate.

    :param ct: The input ciphertext.
    :type ct: LWECiphertext
    :return: The resulting ciphertext.
    :rtype: LWECiphertext
)pbdoc";

const char* binfhe_EvalDecomp_docs = R"pbdoc(
    Evaluate ciphertext decomposition

    :param ct: ciphertext to be bootstrapped
    :type ct: LWECiphertext
    :return: a list with the resulting ciphertexts
    :rtype: List[LWECiphertext]
)pbdoc";

const char* binfhe_EvalFloor_docs = R"pbdoc(
    Evaluate a round down function

    :param ct: ciphertext to be bootstrapped
    :type ct: LWECiphertext
    :param roundbits: number of bits to be rounded
    :type roundbits: int
    :return: the resulting ciphertext
    :rtype: LWECiphertext
)pbdoc";

const char* binfhe_GenerateLUTviaFunction_docs = R"pbdoc(
    Generate the LUT for the to-be-evaluated function

    :param f: the to-be-evaluated function on an integer message and a plaintext modulus
    :type f: function(int, int) -> int
    :param p: plaintext modulus
    :type p: int
    :return: the resulting ciphertext
    :rtype: List[int]
)pbdoc";

const char* binfhe_EvalFunc_docs = R"pbdoc(
    Evaluate an arbitrary function

    :param ct: ciphertext to be bootstrapped
    :type ct: LWECiphertext
    :param LUT: the look-up table of the to-be-evaluated function
    :type LUT: List[int]
    :return: the resulting ciphertext
    :rtype: LWECiphertext
)pbdoc";

//LWECiphertext EvalSign(ConstLWECiphertext &ct, bool schemeSwitch = false)
const char* binfhe_EvalSign_docs = R"pbdoc(
    Evaluate a sign function over large precisions

    :param ct: ciphertext to be bootstrapped
    :type ct: LWECiphertext
    :param schemeSwitch: flag that indicates if it should be compatible to scheme switching
    :type schemeSwitch: bool
    :return: the resulting ciphertext
    :rtype: LWECiphertext
)pbdoc";

const char* binfhe_SerializedVersion_docs = R"pbdoc(
   Return the serialized version number in use.

   :return: the version number
   :rtype: uint32_t   
)pbdoc";

const char* binfhe_SerializedObjectName_docs = R"pbdoc(
   Return the serialized object name

   :return: object name
   :rtype: std::string
)pbdoc";
const char* binfhe_HasInternal32RefreshKey_docs = R"pbdoc(
    Check whether the refreshing key is held in its 32-bit internal form.

    :return: true if the resident refreshing key is the 32-bit one; always false in a 32-bit NATIVEINT build
    :rtype: bool
)pbdoc";

const char* binfhe_HasInternal32SwitchKey_docs = R"pbdoc(
    Check whether the key switching key is held in its 32-bit internal form.

    :return: true if the resident switching key is the 32-bit one; always false in a 32-bit NATIVEINT build
    :rtype: bool
)pbdoc";

const char* binfhe_KeySwitchGen_docs = R"pbdoc(
    Generate a key switching key from a secret key with (Q,N) to one with (q,n).

    :param sk: new secret key
    :type sk: LWEPrivateKey
    :param skN: old secret key
    :type skN: LWEPrivateKey
    :return: the switching key
    :rtype: LWESwitchingKey
)pbdoc";

const char* binfhe_LWECiphertextGetptModulus_docs = R"pbdoc(
    Get the plaintext modulus of the ciphertext.

    :return: the plaintext modulus
    :rtype: int
)pbdoc";

const char* binfhe_LWECiphertextSetModulus_docs = R"pbdoc(
    Set the ciphertext modulus and reduce the ciphertext modulo it.

    :param modulus: the ciphertext modulus
    :type modulus: int
)pbdoc";

const char* binfhe_LWECiphertextSetptModulus_docs = R"pbdoc(
    Set the plaintext modulus of the ciphertext.

    :param plaintextModulus: the plaintext modulus
    :type plaintextModulus: int
)pbdoc";

const char* binfhe_LWEPrivateKeyGetModulus_docs = R"pbdoc(
    Get the modulus of the secret key.

    :return: the ciphertext modulus q (the modulus of the vector "a")
    :rtype: int
)pbdoc";

const char* binfhe_LWEPublicKeyGetModulus_docs = R"pbdoc(
    Get the modulus of the public key.

    :return: the ciphertext modulus q (the modulus of the vector "a")
    :rtype: int
)pbdoc";

const char* binfhe_PubKeyGen_docs = R"pbdoc(
    Generate a public key for the given LWE secret key.

    :param sk: the secret key
    :type sk: LWEPrivateKey
    :return: the public key
    :rtype: LWEPublicKey
)pbdoc";

const char* binfhe_SwitchCTtoqn_docs = R"pbdoc(
    Convert a ciphertext with modulus Q and dimension N to one with q and n.

    :param ksk: the key switching key from secret key of dimension N to secret key of dimension n
    :type ksk: LWESwitchingKey
    :param ct: the ciphertext to convert
    :type ct: LWECiphertext
    :return: the ciphertext
    :rtype: LWECiphertext
)pbdoc";

#endif // __BINFHECONTEXT_DOCS_H
