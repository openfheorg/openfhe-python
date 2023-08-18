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

#ifndef CRYPTOCONTEXT_DOCSTRINGS_H
#define CRYPTOCONTEXT_DOCSTRINGS_H

#include "pybind11/pybind11.h"
#include "pybind11/attr.h"

namespace py = pybind11;

// const char* cc_docs = R"doc(
//     test
// )doc";
// auto cc_docs2 = py::doc(cc_docs);

const char* cc_SetKeyGenLevel_docs = R"pbdoc(
    Set the level used for key generation

    :param level: the level to set the key generation to
    :type level: int
)pbdoc";

const char* cc_GetKeyGenLevel_docs = R"pbdoc(
    Get the level used for key generation

    :return: The level used for key generation
    :rtype: int
)pbdoc";

const char* cc_GetRingDimension_docs = R"pbdoc(
    Get the ring dimension used for this context

    :return: The ring dimension
    :rtype: int
)pbdoc";

const char* cc_Enable_docs = R"pbdoc(
    Enable a particular feature for use with this CryptoContext

    :param feature: the feature that should be enabled. 
                    The list of available features is defined in the PKESchemeFeature enum.
    :type feature: PKESchemeFeature
)pbdoc";

const char* cc_KeyGen_docs = R"pbdoc(
    Generate a public and private key pair

    :return: a public/secret key pair
    :rtype: KeyPair
)pbdoc";

const char* cc_EvalMultKeyGen_docs = R"pbdoc(
    EvalMultKeyGen creates a key that can be used with the OpenFHE EvalMult operator.
    The new evaluation key is stored in cryptocontext.

    :param privateKey: the private key
    :type privateKey: PrivateKey
)pbdoc";

const char* cc_EvalMultKeysGen_docs = R"pbdoc(
    EvalMultsKeyGen creates a vector evalmult keys that can be used with the OpenFHE EvalMult operator.
    The 1st key (for s^2) is used for multiplication of ciphertexts of depth 1.
    The 2nd key (for s^3) is used for multiplication of ciphertexts of depth 2, etc.
    A vector of new evaluation keys is stored in cryptocontext.

    :param privateKey: the private key
    :type privateKey: PrivateKey
)pbdoc";

const char* cc_EvalRotateKeyGen_docs = R"pbdoc(
    EvalRotateKeyGen generates evaluation keys for a list of indices

    :param privateKey: private key
    :type privateKey: PrivateKey
    :param indexList: list of integers representing the indices
    :type indexList: list
    :param publicKey: public key (used in NTRU schemes)
    :type publicKey: PublicKey
)pbdoc";

// MakeStringPlaintext
const char* cc_MakeStringPlaintext_docs = R"pbdoc(
    MakeStringPlaintext constructs a StringEncoding in this context.

    :param str: the string to convert
    :type str: str
    :return: plaintext
)pbdoc";

const char* cc_MakePackedPlaintext_docs = R"pbdoc(
    MakePackedPlaintext constructs a PackedEncoding in this context

    :param value: the vector (of integers) to convert
    :type value: list
    :param depth: is the multiplicative depth to encode the plaintext at
    :type depth: int
    :param level: is the level to encode the plaintext at
    :type level: int
    :return: plaintext
    :rtype: Plaintext
)pbdoc";

const char* cc_MakeCoefPackedPlaintext_docs = R"pbdoc(
    MakeCoefPackedPlaintext constructs a CoefPackedEncoding in this context

    :param value: the vector (of integers) to convert
    :type value: list
    :param depth: is the multiplicative depth to encode the plaintext at
    :type depth: int
    :param level: is the level to encode the plaintext at
    :type level: int
    :return: plaintext
    :rtype: Plaintext
)pbdoc";

const char* cc_MakeCKKSPackedPlaintextComplex_docs = R"pbdoc(
    COMPLEX ARITHMETIC IS NOT AVAILABLE STARTING WITH OPENFHE 1.10.6, AND THIS METHOD BE DEPRECATED. USE THE REAL-NUMBER METHOD INSTEAD. MakeCKKSPackedPlaintext constructs a CKKSPackedEncoding in this context from a vector of complex numbers

    :param value: input vector (of complex numbers)
    :type value: list
    :param scaleDeg: degree of scaling factor used to encode the vector
    :type scaleDeg: int
    :param level: level at each the vector will get encrypted
    :type level: int
    :param params: parameters to be used for the ciphertext (Only accepting params = None in this version)
    :type params: openfhe.ParmType
    :param slots: number of slots
    :type slots: int
    :return: plaintext
    :rtype: Plaintext
)pbdoc";

const char* cc_MakeCKKSPlaintextReal_docs = R"pbdoc(
    MakeCKKSPlaintext constructs a CKKSPackedEncoding in this context from a vector of real numbers

    :param value: input vector (of floats)
    :type value: list
    :param scaleDeg: degree of scaling factor used to encode the vector
    :type scaleDeg: int
    :param level: level at each the vector will get encrypted
    :type level: int
    :param params: parameters to be used for the ciphertext (Only accepting params = None in this version)
    :type params: openfhe.ParmType
    :param slots: number of slots
    :type slots: int
    :return: plaintext
    :rtype: Plaintext
)pbdoc";

const char* cc_EvalRotate_docs = R"pbdoc(
    EvalRotate rotates a ciphertext by a given index

    :param ciphertext: the ciphertext to rotate
    :type ciphertext: Ciphertext
    :param index: the index of the rotation. Positive indices correspond to left rotations and negative indices correspond to right rotations.
    :type index: int
    :return: the rotated ciphertext
    :rtype: Ciphertext
)pbdoc";

const char* cc_EvalFastRotationPreCompute_docs = R"pbdoc(
    EvalFastRotationPrecompute implements the precomputation step of hoisted automorphisms.

    Please refer to Section 5 of Halevi and Shoup, "Faster Homomorphic
    linear transformations in HELib." for more details, link:
    https://eprint.iacr.org/2018/244.

    Generally, automorphisms are performed with three steps:
    (1) The automorphism is applied to the ciphertext.
    (2) The automorphed values are decomposed into digits.
    (3) Key switching is applied to enable further computations on the ciphertext.

    Hoisted automorphisms are a technique that performs the digit decomposition for the original ciphertext first,
    and then performs the automorphism and the key switching on the decomposed digits.
    The benefit of this is that the digit decomposition is independent of the automorphism rotation index,
    so it can be reused for multiple different indices.
    This can greatly improve performance when we have to compute many automorphisms on the same ciphertext.
    This routinely happens when we do permutations (EvalPermute).

    EvalFastRotationPrecompute implements the digit decomposition step of hoisted automorphisms.

    :param ciphertext: the input ciphertext on which to do the precomputation (digit decomposition)
    :type ciphertext: Ciphertext
    :return: the precomputed ciphertext created using the digit decomposition
    :rtype: Ciphertext
)pbdoc";

const char* cc_EvalFastRotation_docs = R"pbdoc(
    EvalFastRotation implements the automorphism and key switching step of hoisted automorphisms.

    Please refer to Section 5 of Halevi and Shoup, "Faster Homomorphic
    linear transformations in HELib." for more details, link:
    https://eprint.iacr.org/2018/244.

    Generally, automorphisms are performed with three steps:
    (1) The automorphism is applied to the ciphertext.
    (2) The automorphed values are decomposed into digits.
    (3) Key switching is applied to enable further computations on the ciphertext.

    Hoisted automorphisms are a technique that performs the digit decomposition for the original ciphertext first,
    and then performs the automorphism and the key switching on the decomposed digits.
    The benefit of this is that the digit decomposition is independent of the automorphism rotation index,
    so it can be reused for multiple different indices.
    This can greatly improve performance when we have to compute many automorphisms on the same ciphertext.
    This routinely happens when we do permutations (EvalPermute).

    EvalFastRotation implements the automorphism and key switching step of hoisted automorphisms.

    This method assumes that all required rotation keys exist.
    This may not be true if we are using baby-step/giant-step key switching.
    Please refer to Section 5.1 of the above reference and EvalPermuteBGStepHoisted to see how to deal with this issue.

    :param ciphertext:  the input ciphertext to perform the automorphism on
    :type ciphertext: Ciphertext
    :param index: the index of the rotation. Positive indices correspond to left rotations and negative indices correspond to right rotations.
    :type index: int
    :param m: is the cyclotomic order
    :type m: int
    :param digits: the precomputed ciphertext created by EvalFastRotationPrecompute using the digit decomposition at the precomputation step
    :type digits: Ciphertext
    :return: the rotated ciphertext
    :rtype: Ciphertext
)pbdoc";


const char* cc_EvalFastRotationExt_docs = R"pbdoc(
    Only supported for hybrid key switching. Performs fast (hoisted) rotation and returns the results in the extended CRT basis P*Q

    :param ciphertext: input ciphertext
    :type ciphertext: Ciphertext
    :param index: the rotation index
    :type index: int
    :param digits: the precomputed ciphertext created by EvalFastRotationPrecompute
    :type digits: Ciphertext
    :param addFirst: if true, the first element c0 is also computed (otherwise ignored)
    :type addFirst: bool
    :return: resulting ciphertext
    :rtype: Ciphertext
)pbdoc";

const char* cc_EvalAtIndex_docs = R"pbdoc(
    Moves i-th slot to slot 0

    :param ciphertext: the ciphertext
    :type ciphertext: Ciphertext
    :param i: the index
    :type i: int
    :return: resulting ciphertext
    :rtype: Ciphertext
)pbdoc";

const char* cc_EvalAtIndexKeyGen_docs = R"pbdoc(
    EvalAtIndexKeyGen generates evaluation keys for a list of indices

    :param privateKey: the private key
    :type privateKey: PrivateKey
    :param indexList: list of indices
    :type indexList: list
    :param publicKey: the public key (used in NTRU schemes)
    :type publicKey: PublicKey
    :return: None
)pbdoc";

const char* cc_Encrypt_docs = R"doc(
    Encrypt a plaintext using a given public key

    :param plaintext: the plaintext to encrypt
    :type plaintext: Plaintext
    :param publicKey: the public key
    :type publicKey: PublicKey
    :return: ciphertext (or null on failure)
    :rtype: Ciphertext
)doc";

const char* cc_Decrypt_docs = R"pbdoc(
Decrypt a single ciphertext into the appropriate plaintext

:param ciphertext: ciphertext to decrypt
:type ciphertext: Ciphertext
:param privateKey: decryption key
:type privateKey: PrivateKey
:return: decrypted plaintext
:rtype: Plaintext
)pbdoc";

const char* cc_KeySwitchGen_docs = R"pbdoc(
    KeySwitchGen creates a key that can be used with the OpenFHE KeySwitch operation

    :param oldPrivateKey: input secrey key
    :type oldPrivateKey: PrivateKey
    :param newPrivateKey: output secret key
    :type newPrivateKey: PrivateKey
    :return: new evaluation key
    :rtype: EvalKey
)pbdoc";

const char* cc_EvalAdd_docs = R"pbdoc(
Add two ciphertexts

:param ct1: first ciphertext
:type ct1: Ciphertext
:param ct2: second ciphertext
:type ct2: Ciphertext
:return: resulting ciphertext
:rtype: Ciphertext
)pbdoc";

const char* cc_EvalAddfloat_docs = R"pbdoc(
EvalAdd - OpenFHE EvalAdd method for a ciphertext and constant

:param ct: ciphertext
:type ct: Ciphertext
:param constant: constant to add
:type constant: float
:return: new ciphertext for ciphertext + constant
:rtype: Ciphertext
)pbdoc";

const char* cc_EvalAddInPlace_docs = R"pbdoc(
EvalAdd - OpenFHE EvalAddInPlace method for a pair of ciphertexts

:param ct1: Input/output ciphertext
:type ct1: Ciphertext
:param ct2: Input ciphertext
:type ct2: Ciphertext
:return: ct1 contains ct1 + ct2
)pbdoc";

const char* cc_EvalAddInPlacePlaintext_docs = R"pbdoc(
EvalAdd - OpenFHE EvalAddInPlace method for a ciphertext and plaintext

:param ct: Input/output ciphertext
:type ct: Ciphertext
:param pt: Input plaintext
:type pt: Plaintext
:return: ct contains ct + pt
)pbdoc";

const char* cc_EvalAddMutable_docs = R"pbdoc(
EvalAdd - OpenFHE EvalAddMutable method for a pair of ciphertexts. This is a mutable version - input ciphertexts may get automatically rescaled, or level-reduced.

:param ct1: first ciphertext
:type ct1: Ciphertext
:param ct2: second ciphertext
:type ct2: Ciphertext
:return: new ciphertext for ct1 + ct2
:rtype: Ciphertext
)pbdoc";

const char* cc_EvalAddMutablePlaintext_docs = R"pbdoc(
EvalAdd - OpenFHE EvalAddMutable method for a ciphertext and plaintext. This is a mutable version - input ciphertexts may get automatically rescaled, or level-reduced.

:param ciphertext: ciphertext
:type ciphertext: Ciphertext
:param plaintext: plaintext
:type plaintext: Plaintext
:return: new ciphertext for ciphertext + plaintext
:rtype: Ciphertext
)pbdoc";


const char* cc_EvalAddMutableInPlace_docs = R"pbdoc(
    EvalAdd - Inplace version of EvalAddMutable

    :param ct1: Input/output ciphertext
    :type ct1: Ciphertext
    :param ct2: Input ciphertext
    :type ct2: Ciphertext
    :return: ct1 contains ct1 + ct2
)pbdoc";

const char* cc_EvalSub_docs = R"pbdoc(
EvalSub - OpenFHE EvalSub method for a pair of ciphertexts

:param ct1: first ciphertext
:type ct1: Ciphertext
:param ct2: second ciphertext
:type ct2: Ciphertext
:return: new ciphertext for ct1 - ct2
:rtype: Ciphertext
)pbdoc";

const char* cc_EvalSubfloat_docs = R"pbdoc(
EvalSub - OpenFHE EvalSub method for a ciphertext and constant

:param ciphertext: ciphertext
:type ciphertext: Ciphertext
:param constant: constant to subtract
:type constant: float
:return: new ciphertext for ciphertext - constant
:rtype: Ciphertext
)pbdoc";

const char* cc_EvalSubPlaintext_docs = R"pbdoc(
EvalSub - OpenFHE EvalSub method for a ciphertext and plaintext

:param ciphertext: ciphertext
:type ciphertext: Ciphertext
:param plaintext: plaintext
:type plaintext: Plaintext
:return: new ciphertext for ciphertext - plaintext
:rtype: Ciphertext
)pbdoc";

const char* cc_EvalSubInPlace_docs = R"pbdoc(
Inplace version of EvalSub for a pair of ciphertexts

:param ct1: Input/output ciphertext
:type ct1: Ciphertext
:param ct2: Input ciphertext
:type ct2: Ciphertext
:return: ct1 contains ct1 - ct2
)pbdoc";

const char* cc_EvalSubInPlacefloat_docs = R"pbdoc(
Inplace version of EvalSub for a ciphertext and constant

:param ciphertext: Input/output ciphertext
:type ciphertext: Ciphertext
:param constant: constant to subtract
:type constant: float
:return: ciphertext contains ciphertext - constant
)pbdoc";

// EvalSubMutable
const char* cc_EvalSubMutable_docs = R"pbdoc(
EvalSub - OpenFHE EvalSubMutable method for a pair of ciphertexts. This is a mutable version - input ciphertexts may get automatically rescaled, or level-reduced.

:param ct1: first ciphertext
:type ct1: Ciphertext
:param ct2: second ciphertext
:type ct2: Ciphertext
:return: new ciphertext for ct1 - ct2
)pbdoc";

// EvalSubMutableInPlace
const char* cc_EvalSubMutableInPlace_docs = R"pbdoc(
    EvalSub - Inplace variant for EvalSubMutable.

    :param ct1: Input/output ciphertext
    :type ct1: Ciphertext
    :param ct2: Input ciphertext
    :type ct2: Ciphertext
    :return: ct1 contains ct1 - ct2
)pbdoc";

// EvalSubMutablePlaintext
const char* cc_EvalSubMutablePlaintext_docs = R"pbdoc(
EvalSub - OpenFHE EvalSubMutable method for a ciphertext and plaintext. This is a mutable version - input ciphertexts may get automatically rescaled, or level-reduced.

:param ciphertext: ciphertext
:type ciphertext: Ciphertext
:param plaintext: plaintext
:type plaintext: Plaintext
:return: new ciphertext for ciphertext - plaintext
)pbdoc";

const char* cc_EvalMult_docs = R"pbdoc(
EvalMult - OpenFHE EvalMult method for a pair of ciphertexts - with key switching

:param ct1: first ciphertext
:type ct1: Ciphertext
:param ct2: second ciphertext
:type ct2: Ciphertext
:return: new ciphertext for ct1 * ct2
:rtype: Ciphertext
)pbdoc";

const char* cc_EvalMultfloat_docs = R"pbdoc(
EvalMult - OpenFHE EvalMult method for a ciphertext and constant

:param ciphertext: the ciphertext
:type ciphertext: Ciphertext
:param constant: constant to multiply
:type constant: float
:return: new ciphertext for ciphertext * constant
:rtype: Ciphertext
)pbdoc";

const char* cc_EvalMultPlaintext_docs = R"pbdoc(
EvalMult - OpenFHE EvalMult method for a ciphertext and plaintext

:param ciphertext: the ciphertext
:type ciphertext: Ciphertext
:param plaintext: the plaintext
:type plaintext: Plaintext
:return: new ciphertext for ciphertext * plaintext
:rtype: Ciphertext
)pbdoc";

const char* cc_EvalMultMutable_docs = R"pbdoc(
EvalMult - OpenFHE EvalMultMutable method for a pair of ciphertexts. This is a mutable version - input ciphertexts may get automatically rescaled, or level-reduced.

:param ct1: first ciphertext
:type ct1: Ciphertext
:param ct2: second ciphertext
:type ct2: Ciphertext
:return: new ciphertext for ct1 * ct2
:rtype: Ciphertext
)pbdoc";

const char* cc_EvalMultMutablePlaintext_docs = R"pbdoc(
EvalMult - OpenFHE EvalMultMutable method for a ciphertext and plaintext. This is a mutable version - input ciphertexts may get automatically rescaled, or level-reduced.

:param ciphertext: the ciphertext
:type ciphertext: Ciphertext
:param plaintext: the plaintext
:type plaintext: Plaintext
:return: new ciphertext for ciphertext * plaintext
:rtype: Ciphertext
)pbdoc";

const char* cc_EvalMultMutableInPlace_docs = R"pbdoc(
    EvalMult - OpenFHE EvalMult method for a pair of ciphertexts - with key switching. This is a mutable version - input ciphertexts may get automatically rescaled, or level-reduced.

    :param ct1: Input/output ciphertext
    :type ct1: Ciphertext
    :param ct2: Input cipherext
    :type ct2: Ciphertext
    :return: ct1 contains ct1 * ct2
)pbdoc";

const char* cc_EvalSquare_docs = R"pbdoc(
    EvalSquare - OpenFHE EvalSquare method for a ciphertext

    :param ct: the ciphertext to square
    :type ct: Ciphertext
    :return: new ciphertext for ct^2 = ct * ct
    :rtype: Ciphertext
)pbdoc";

const char* cc_EvalSquareMutable_docs = R"pbdoc(
    EvalSquare - OpenFHE EvalSquareMutable method for a ciphertext. This is a mutable version - input ciphertexts may get automatically rescaled, or level-reduced.

    :param ct: the ciphertext to square
    :type ct: Ciphertext
    :return: new ciphertext for ct^2 = ct * ct
    :rtype: Ciphertext
)pbdoc";

const char* cc_EvalSquareInPlace_docs = R"pbdoc(
    EvalSquare - OpenFHE EvalSquare method for a ciphertext. This is a mutable version - input ciphertexts may get automatically rescaled, or level-reduced.

    :param ct: Input/output ciphertext
    :type ct: Ciphertext
    :return: ct contains ct^2 = ct * ct
)pbdoc";


const char* cc_EvalMultNoRelin_docs = R"pbdoc(
    EvalMultNoRelin - OpenFHE EvalMult method for a pair of ciphertexts - no key switching (relinearization)

    :param ct1: first ciphertext
    :type ct1: Ciphertext
    :param ct2: second ciphertext
    :type ct2: Ciphertext
    :return: new ciphertext for ct1 * ct2
    :rtype: Ciphertext
)pbdoc";

const char* cc_Relinearize_docs = R"pbdoc(
    Function for relinearization of a ciphertext.

    :param ct: input ciphertext
    :type ct: Ciphertext
    :return: relienarized ciphertext
    :rtype: Ciphertext
)pbdoc";

const char* cc_RelinearizeInPlace_docs = R"pbdoc(
    Function for inplace relinearization of a ciphertext.

    :param ct: input/output ciphertext
    :type ct: Ciphertext
    :return: ct contains relienarized ciphertext
)pbdoc";

const char* cc_EvalMultAndRelinearize_docs = R"pbdoc(
    Function for evaluating multiplication on ciphertext followed by relinearization operation. Currently it assumes that the input arguments have total depth smaller than the supported depth. Otherwise, it throws an error

    :param ct1: first input ciphertext
    :type ct1: Ciphertext
    :param ct2: second input ciphertext
    :type ct2: Ciphertext
    :return: new ciphertext
    :rtype: Ciphertext
)pbdoc";

const char* cc_EvalNegate_docs = R"pbdoc(
    EvalSub - OpenFHE Negate method for a ciphertext

    :param ct: input ciphertext
    :type ct: Ciphertext
    :return: new ciphertext -ct
    :rtype: Ciphertext
)pbdoc";

const char* cc_EvalNegateInPlace_docs = R"pbdoc(
    EvalSub - Inplace OpenFHE Negate method for a ciphertext

    :param ct: input/output ciphertext
    :type ct: Ciphertext
    :return: ct contains -ct
)pbdoc";

const char* cc_EvalChebyshevSeries_docs = R"pbdoc(
    Method for evaluating Chebyshev polynomial interpolation; first the range [a,b] is mapped to [-1,1] using linear transformation 1 + 2 (x-a)/(b-a) If the degree of the polynomial is less than 5, use EvalChebyshevSeriesLinear, otherwise, use EvalChebyshevSeriesPS.

    :param ciphertext: input ciphertext
    :type ciphertext: Ciphertext
    :param coefficients: list of coefficients in Chebyshev expansion
    :type coefficients: list
    :param a: lower bound of argument for which the coefficients were found
    :type a: float
    :param b: upper bound of argument for which the coefficients were found
    :type b: float
    :return: the result of polynomial evaluation
    :rtype: Ciphertext
)pbdoc";

const char* cc_EvalChebyshevSeriesLinear_docs = R"pbdoc(
    Evaluate Chebyshev polynomial of degree less than 5.

    :param ciphertext: input ciphertext
    :type ciphertext: Ciphertext
    :param coefficients: list of coefficients in Chebyshev expansion
    :type coefficients: list
    :param a: lower bound of argument for which the coefficients were found
    :type a: float
    :param b: upper bound of argument for which the coefficients were found
    :type b: float
    :return: the result of polynomial evaluation
    :rtype: Ciphertext
)pbdoc";

const char* cc_EvalChebyshevSeriesPS_docs = R"pbdoc(
    Evaluate Chebyshev polynomial of degree greater or equal to 5.

    :param ciphertext: input ciphertext
    :type ciphertext: Ciphertext
    :param coefficients: list of coefficients in Chebyshev expansion
    :type coefficients: list
    :param a: lower bound of argument for which the coefficients were found
    :type a: float
    :param b: upper bound of argument for which the coefficients were found
    :type b: float
    :return: the result of polynomial evaluation
    :rtype: Ciphertext
)pbdoc";

const char* cc_EvalChebyshevFunction_docs = R"pbdoc(
    Method for calculating Chebyshev evaluation on a ciphertext for a smooth input function over the range [a,b].

    :param func: the function to be approximated
    :type func: function
    :param ciphertext: input ciphertext
    :type ciphertext: Ciphertext
    :param a: lower bound of argument for which the coefficients were found
    :type a: float
    :param b: upper bound of argument for which the coefficients were found
    :type b: float
    :param degree: Desired degree of approximation
    :type degree: int
    :return: the coefficients of the Chebyshev approximation.
    :rtype: Ciphertext
)pbdoc";

const char* cc_EvalSin_docs = R"pbdoc(
    Evaluate approximate sine function on a ciphertext using the Chebyshev approximation.

    :param ciphertext: input ciphertext
    :type ciphertext: Ciphertext
    :param a: lower bound of argument for which the coefficients were found
    :type a: float
    :param b: upper bound of argument for which the coefficients were found
    :type b: float
    :param degree: Desired degree of approximation
    :type degree: int
    :return: the result of polynomial evaluation.
    :rtype: Ciphertext
)pbdoc";

const char* cc_EvalCos_docs = R"pbdoc(
    Evaluate approximate cosine function on a ciphertext using the Chebyshev approximation.

    :param ciphertext: input ciphertext
    :type ciphertext: Ciphertext
    :param a: lower bound of argument for which the coefficients were found
    :type a: float
    :param b: upper bound of argument for which the coefficients were found
    :type b: float
    :param degree: Desired degree of approximation
    :type degree: int
    :return: the result of polynomial evaluation.
    :rtype: Ciphertext
)pbdoc";

const char* cc_EvalLogistic_docs = R"pbdoc(
    Evaluate approximate logistic function 1/(1 + exp(-x)) on a ciphertext using the Chebyshev approximation.

    :param ciphertext: input ciphertext
    :type ciphertext: Ciphertext
    :param a: lower bound of argument for which the coefficients were found
    :type a: float
    :param b: upper bound of argument for which the coefficients were found
    :type b: float
    :param degree: Desired degree of approximation
    :type degree: int
    :return: the result of polynomial evaluation.
    :rtype: Ciphertext
)pbdoc";

const char* cc_EvalDivide_docs = R"pbdoc(
    Evaluate approximate division function 1/x where x >= 1 on a ciphertext using the Chebyshev approximation.

    :param ciphertext: input ciphertext
    :type ciphertext: Ciphertext
    :param a: lower bound of argument for which the coefficients were found
    :type a: float
    :param b: upper bound of argument for which the coefficients were found
    :type b: float
    :param degree: Desired degree of approximation
    :type degree: int
    :return: the result of polynomial evaluation.
    :rtype: Ciphertext
)pbdoc";

const char* cc_EvalSumKeyGen_docs = R"pbdoc(
    EvalSumKeyGen generates the key map to be used by evalsum

    :param privateKey: private key
    :type privateKey: PrivateKey
    :param publicKey: public key (used in NTRU schemes)
    :type publicKey: PublicKey
    :return: None
)pbdoc";

const char* cc_EvalSumRowsKeyGen_docs = R"pbdoc(
    EvalSumRowsKeyGen generates the key map to be used by EvalSumRows

    :param privateKey: private key
    :type privateKey: PrivateKey
    :param publicKey: public key (used in NTRU schemes)
    :type publicKey: PublicKey
    :param rowSize: number of rows
    :type rowSize: int
    :param subringDim: dimension of the subring
    :type subringDim: int
    :return: dict: Evaluation key map, where the keys being integer indexes and values being EvalKey objects
)pbdoc";

const char* cc_EvalSumColsKeyGen_docs = R"pbdoc(
    EvalSumColsKeyGen generates the key map to be used by EvalSumCols

    :param privateKey: private key
    :type privateKey: PrivateKey
    :param publicKey: public key (used in NTRU schemes)
    :type publicKey: PublicKey
    :return: dict: Evaluation key map, where the keys being integer indexes and values being EvalKey objects
)pbdoc";

const char* cc_EvalSumRows_docs = R"pbdoc(

    :param ciphertext: input ciphertext
    :type ciphertext: Ciphertext
    :param rowSize: number of rows
    :type rowSize: int
    :param evalSumKeyMap: evaluation key map, where the keys being integer indexes and values being EvalKey objects
    :type evalSumKeyMap: dict
    :param subringDim: dimension of the subring
    :type subringDim: int
    :return: Ciphertext: resulting ciphertext
    :rtype: Ciphertext
)pbdoc";

const char* cc_EvalSumCols_docs = R"pbdoc(

    :param ciphertext: input ciphertext
    :type ciphertext: Ciphertext
    :param rowSize: number of rows
    :type rowSize: int
    :param evalSumKeyMap: evaluation key map, where the keys being integer indexes and values being EvalKey objects
    :type evalSumKeyMap: dict
    :return: Ciphertext: resulting ciphertext
    :rtype: Ciphertext
)pbdoc";

const char* cc_EvalInnerProduct_docs = R"pbdoc(
    Evaluates inner product in batched encoding

    :param ciphertext1: first vector
    :type ciphertext1: Ciphertext
    :param ciphertext2: second vector
    :type ciphertext2: Ciphertext
    :param batchSize: size of the batch to be summed up
    :type batchSize: int
    :return: Ciphertext: resulting ciphertext
    :rtype: Ciphertext
)pbdoc";

const char* cc_EvalInnerProductPlaintext_docs = R"pbdoc(
    Evaluates inner product in batched encoding

    :param ciphertext: first vector - ciphertext
    :type ciphertext: Ciphertext
    :param plaintext: second vector - plaintext
    :type plaintext: Plaintext
    :param batchSize: size of the batch to be summed up
    :type batchSize: int
    :return: Ciphertext: resulting ciphertext
    :rtype: Ciphertext
)pbdoc";

const char* cc_MultipartyKeyGen_docs = R"pbdoc(
    Threshold FHE: Generation of a public key derived from a previous joined public key (for prior secret shares) and the secret key share of the current party.

    :param publicKey:  joined public key from prior parties.
    :type publicKey: PublicKey
    :param makeSparse: set to true if ring reduce by a factor of 2 is to be used. NOT SUPPORTED BY ANY SCHEME ANYMORE.
    :type makeSparse: bool
    :param fresh: set to true if proxy re-encryption is used in the multi-party protocol or star topology is used
    :type fresh: bool
    :return: KeyPair: key pair including the secret share for the current party and joined public key
    :rtype: KeyPair
)pbdoc";

const char* cc_MultipartyDecryptLead_docs = R"pbdoc(
    Threshold FHE: Method for decryption operation run by the lead decryption client

    :param ciphertextVec: a list of ciphertexts
    :type ciphertextVec: list
    :param privateKey:  secret key share used for decryption. list of partially decrypted ciphertexts.
    :type privateKey: PrivateKey
    :return: Ciphertext: resulting ciphertext
    :rtype: Ciphertext
)pbdoc";

const char* cc_MultipartyDecryptMain_docs = R"pbdoc(
    Threshold FHE: "Partial" decryption computed by all parties except for the lead one

    :param ciphertextVec: a list of ciphertexts
    :type ciphertextVec: list
    :param privateKey:  secret key share used for decryption. list of partially decrypted ciphertexts.
    :type privateKey: PrivateKey
    :return: Ciphertext: resulting ciphertext
    :rtype: Ciphertext
)pbdoc";
//Plaintext MultipartyDecryptFusionWrapper(CryptoContext<DCRTPoly>& self,const std::vector<Ciphertext<DCRTPoly>>& partialCiphertextVec);
const char* cc_MultipartyDecryptFusion_docs = R"pbdoc(
    Threshold FHE: Method for combining the partially decrypted ciphertexts and getting the final decryption in the clear.

    :param partialCiphertextVec: list of "partial" decryptions
    :type partialCiphertextVec: list
    :return: Plaintext: resulting plaintext
    :rtype: Plaintext
)pbdoc";
const char* cc_EvalMerge_docs = R"pbdoc(
    Merges multiple ciphertexts with encrypted results in slot 0 into a single ciphertext The slot assignment is done based on the order of ciphertexts in the vector

    :param ciphertextVec: vector of ciphertexts to be merged.
    :type ciphertextVec: list
    :return: Ciphertext: resulting ciphertext
    :rtype: Ciphertext
)pbdoc";

const char* cc_EvalPoly_docs = R"pbdoc(
    Method for polynomial evaluation for polynomials represented as power series.

    :param ciphertext: input ciphertext
    :type ciphertext: Ciphertext
    :param coefficients: vector of coefficients in the polynomial; the size of the vector is the degree of the polynomial + 1
    :type coefficients: list
    :return: Ciphertext: the result of polynomial evaluation.
    :rtype: Ciphertext
)pbdoc";

const char* cc_EvalPolyLinear_docs = R"pbdoc(
    Method for polynomial evaluation for polynomials represented in the power series. This uses EvalPolyLinear, which uses a binary tree computation of the polynomial powers.

    :param ciphertext: input ciphertext
    :type ciphertext: Ciphertext
    :param coefficients: vector of coefficients in the polynomial; the size of the vector is the degree of the polynomial
    :type coefficients: list
    :return: Ciphertext: the result of polynomial evaluation.
    :rtype: Ciphertext
)pbdoc";

const char* cc_EvalPolyPS_docs = R"pbdoc(

    :param ciphertext: input ciphertext
    :type ciphertext: Ciphertext
    :param coefficients: vector of coefficients in the polynomial; the size of the vector is the degree of the polynomial
    :type coefficients: list
    :return: Ciphertext: the result of polynomial evaluation.
    :rtype: Ciphertext
)pbdoc";

const char* cc_Rescale_docs = R"pbdoc(
    Rescale - An alias for OpenFHE ModReduce method. This is because ModReduce is called Rescale in CKKS.

    :param ciphertext: ciphertext
    :type ciphertext: Ciphertext
    :return: Ciphertext: mod reduced ciphertext
    :rtype: Ciphertext
)pbdoc";

const char* cc_EvalBootstrapSetup_docs = R"pbdoc(
    Bootstrap functionality: There are three methods that have to be called in this specific order:

    1. EvalBootstrapSetup: computes and encodes the coefficients for encoding and decoding and stores the necessary parameters

    2. EvalBootstrapKeyGen: computes and stores the keys for rotations and conjugation

    3. EvalBootstrap: refreshes the given ciphertext Sets all parameters for the linear method for the FFT-like method

    :param levelBudget: vector of budgets for the amount of levels in encoding and decoding
    :type levelBudget: list
    :param dim1: vector of inner dimension in the baby-step giant-step routine for encoding and decodingl
    :type dim1: list
    :param slots: number of slots to be bootstraped
    :type slots: int
    :param correctionFactor: alue to rescale message by to improve precision. If set to 0, we use the default logic. This value is only used when get_native_int()=64
    :type correctionFactor: int
    :return: None
)pbdoc";

const char* cc_EvalBootstrapKeyGen_docs = R"pbdoc(
    Generates all automorphism keys for EvalBT. EvalBootstrapKeyGen uses the baby-step/giant-step strategy.

    :param privateKey: private key.
    :type privateKey: PrivateKey
    :param slots: number of slots to support permutations on.
    :type slots: int
    :return: None
)pbdoc";

const char* cc_EvalBootstrap_docs = R"pbdoc(
    Defines the bootstrapping evaluation of ciphertext using either the FFT-like method or the linear method

    :param ciphertext: the input ciphertext
    :type ciphertext: Ciphertext
    :param numIterations: number of iterations to run iterative bootstrapping (Meta-BTS). Increasing the iterations increases the precision of bootstrapping
    :type numIterations: int
    :param precision: precision of initial bootstrapping algorithm. This value is determined by the user experimentally by first running EvalBootstrap with numIterations = 1 and precision = 0 (unused).
    :type precision: int
    :return: Ciphertext: the refreshed ciphertext
    :rtype: Ciphertext
)pbdoc";

const char* cc_EvalAutomorphismKeyGen_docs = R"pbdoc(
    Generate automophism keys for a given private key; Uses the private key for encryption

    :param privateKey: private key.
    :type privateKey: PrivateKey
    :param indexList: list of automorphism indices to be computed.
    :type indexList: list
    :return: dict: returns the evaluation key
)pbdoc";

const char* cc_EvalAutomorphismKeyGenPublic_docs = R"pbdoc(
    Generate automophism keys for a given private key.

    :param publicKey: original public key.
    :type publicKey: PublicKey
    :param privateKey: original private key.
    :type privateKey: PrivateKey
    :param indexList: list of automorphism indices to be computed.
    :type indexList: list
    :return: dict: returns the evaluation keys; index 0 of the vector corresponds to plaintext index 2, index 1 to plaintex index 3, etc.
)pbdoc";

const char* cc_FindAutomorphismIndex_docs = R"pbdoc(
    Find the automorphism index for a given plaintext index

    :param idx: plaintext index
    :type idx: int
    :return: int: automorphism index
)pbdoc";

const char* cc_FindAutomorphismIndices_docs = R"pbdoc(
    Find the automorphism indices for a given list of plaintext indices

    :param idxList: list of plaintext indices
    :type idxList: list
    :return: list: list of automorphism indices
)pbdoc";

const char* cc_ClearEvalMultKeys_docs = R"pbdoc(
    ClearEvalMultKeys - flush EvalMultKey cache
)pbdoc";

const char* cc_ClearEvalAutomorphismKeys_docs = R"pbdoc(
    ClearEvalAutomorphismKeys - flush EvalAutomorphismKey cache
)pbdoc";

const char* cc_SerializeEvalAutomorphismKey_docs = R"pbdoc(
    SerializeEvalAutomorphismKey for a single EvalAuto key or all of the EvalAuto keys

    :param filename: output file
    :type filename: str
    :param sertype: serialization type
    :type sertype: SERJSON, SERBINARY
    :param id: key to serialize; empty string means all keys
    :type id: str
    :return: bool: true on success
)pbdoc";

const char* cc_SerializeEvalMultKey_docs = R"pbdoc(
    SerializeEvalMultKey for a single EvalMult key or all of the EvalMult keys

    :param filename: output file
    :type filename: str
    :param sertype: type of serialization
    :type sertype: SERJSON, SERBINARY
    :param id: for key to serialize - if empty string, serialize them all
    :type id: str
    :return: bool: true on success
)pbdoc";

const char* cc_DeserializeEvalAutomorphismKey_docs = R"pbdoc(
    DeserializeEvalAutomorphismKey deserialize all keys in the serialization deserialized keys silently replace any existing matching keys deserialization will create CryptoContext if necessary

    :param filename: path for the file to deserialize from
    :type filename: str
    :param sertype: type of serialization
    :type sertype: SERJSON, SERBINARY
    :return: bool: true on success
)pbdoc";

const char* cc_DeserializeEvalMultKey_docs = R"pbdoc(
    DeserializeEvalMultKey deserialize all keys in the serialization deserialized keys silently replace any existing matching keys deserialization will create CryptoContext if necessary

    :param filename: path for the file to deserialize from
    :type filename: str
    :param sertype: type of serialization
    :type sertype: SERJSON, SERBINARY
    :return: bool: true on success
)pbdoc";


#endif //CRYPTOCONTEXT_DOCSTRINGS_H
