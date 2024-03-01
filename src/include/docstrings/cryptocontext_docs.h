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
    For future use: setter for the level at which evaluation keys should be generated

    :param level: the level to set the key generation to
    :type level: int
)pbdoc";

const char* cc_GetKeyGenLevel_docs = R"pbdoc(
    For future use: getter for the level at which evaluation keys should be generated

    :return: The level used for key generation
    :rtype: int
)pbdoc";

const char* cc_GetRingDimension_docs = R"pbdoc(
    Get the ring dimension used for this context

    :return: The ring dimension
    :rtype: int
)pbdoc";

const char* cc_GetPlaintextModulus_docs = R"pbdoc(
    Get the plaintext modulus used for this context

    :return: The plaintext modulus
    :rtype: int
)pbdoc";

const char* cc_GetCyclotomicOrder_docs = R"pbdoc(
    Get the cyclotomic order used for this context

    :return: The cyclotomic order
    :rtype: int
)pbdoc";

const char* cc_GetModulus_docs = R"pbdoc(
    Get the cyclotomic order used for this context

    :return: The modulus
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
    EvalRotateKeyGen generates evaluation keys for a list of indices. Calls EvalAtIndexKeyGen under the hood.

    :param privateKey: private key
    :type privateKey: PrivateKey
    :param indexList: list of integers representing the indices
    :type indexList: list
    :param publicKey: public key (used in NTRU schemes)
    :type publicKey: PublicKey
)pbdoc";

const char* cc_MakeStringPlaintext_docs = R"pbdoc(
    MakeStringPlaintext constructs a StringEncoding in this context.

    :param str: string to be encoded
    :type str: str
    :return: plaintext
)pbdoc";

const char* cc_MakePackedPlaintext_docs = R"pbdoc(
    MakePackedPlaintext constructs a PackedEncoding in this context

    :param value: vector of signed integers mod t
    :type value: List[int]
    :param noiseScaleDeg: is degree of the scaling factor to encode the plaintext at
    :type noiseScaleDeg: int
    :param level: is the level to encode the plaintext at
    :type level: int
    :return: plaintext
    :rtype: Plaintext
)pbdoc";

const char* cc_MakeCoefPackedPlaintext_docs = R"pbdoc(
    MakeCoefPackedPlaintext constructs a CoefPackedEncoding in this context

    :param value: vector of signed integers mod t
    :type value: List[int]
    :param noiseScaleDeg :  is degree of the scaling factor to encode the plaintext at
    :type noiseScaleDeg : int
    :param level: is the level to encode the plaintext at
    :type level: int
    :return: plaintext
    :rtype: Plaintext
)pbdoc";

const char* cc_MakeCKKSPackedPlaintextComplex_docs = R"pbdoc(
    COMPLEX ARITHMETIC IS NOT AVAILABLE, AND THIS METHOD BE DEPRECATED. USE THE REAL-NUMBER METHOD INSTEAD. MakeCKKSPackedPlaintext constructs a CKKSPackedEncoding in this context from a vector of complex numbers

    :param value: input vector of complex numbers
    :type value: List[complex]
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
    Rotates a ciphertext by an index (positive index is a left shift, negative index is a right shift). Uses a rotation key stored in a crypto context. Calls EvalAtIndex under the hood.

    :param ciphertext: input ciphertext
    :type ciphertext: Ciphertext
    :param index: rotation index
    :type index: int
    :return: a rotated ciphertext
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
    Rotates a ciphertext by an index (positive index is a left shift, negative index is a right shift). Uses a rotation key stored in a crypto context.

    :param ciphertext: input ciphertext
    :type ciphertext: Ciphertext
    :param i: rotation index
    :type i: int
    :return: a rotated ciphertext
    :rtype: Ciphertext
)pbdoc";

const char* cc_EvalAtIndexKeyGen_docs = R"pbdoc(
    EvalAtIndexKeyGen generates evaluation keys for a list of rotation indices

    :param privateKey: the private key
    :type privateKey: PrivateKey
    :param indexList: list of indices
    :type indexList: list
    :param publicKey: the public key (used in NTRU schemes). Not used anymore.
    :type publicKey: PublicKey
    :return: None
)pbdoc";

const char* cc_Encrypt_docs = R"doc(
    Encrypt a plaintext using a given public key

    :param plaintext: plaintext
    :type plaintext: Plaintext
    :param publicKey: public key
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
Homomorphic addition of two ciphertexts

:param ciphertext1: first addend
:type ciphertext1: Ciphertext
:param ciphertext2: second addend
:type ciphertext2: Ciphertext
:return: the result as a new ciphertext
:rtype: Ciphertext
)pbdoc";

const char* cc_EvalAddfloat_docs = R"pbdoc(
EvalAdd - OpenFHE EvalAdd method for a ciphertext and a real number. Supported only in CKKS.

:param ciphertext: input ciphertext
:type ciphertext: Ciphertext
:param constant: a real number
:type constant: float
:return: new ciphertext for ciphertext + constant
:rtype: Ciphertext
)pbdoc";

const char* cc_EvalAddPlaintext_docs = R"pbdoc(
EvalAdd - OpenFHE EvalAdd method for a ciphertext and plaintext

:param ciphertext: input ciphertext
:type ciphertext: Ciphertext
:param plaintex: input plaintext
:type plaintext: Plaintext
:return: new ciphertext for ciphertext + constant
:rtype: Ciphertext
)pbdoc";

const char* cc_EvalAddInPlace_docs = R"pbdoc(
In-place homomorphic addition of two ciphertexts

:param ciphertext1: ciphertext1
:type ciphertext1: Ciphertext
:param ciphertext2: second addend
:type ciphertext2: Ciphertext
:return: ciphertext1 contains ciphertext1 + ciphertext2
)pbdoc";

const char* cc_EvalAddInPlacePlaintext_docs = R"pbdoc(
In-place addition for a ciphertext and plaintext

:param ciphertext: Input/output ciphertext
:type ciphertext: Ciphertext
:param plaintext: Input plaintext
:type plaintext: Plaintext
:return: ciphertext contains ciphertext + plaintext
)pbdoc";

const char* cc_EvalAddMutable_docs = R"pbdoc(
Homomorphic addition of two mutable ciphertexts (they can be changed during the operation)

:param ciphertext1: first addend
:type ciphertext1: Ciphertext
:param ciphertext2: second addend
:type ciphertext2: Ciphertext
:return: the result as a new ciphertext
:rtype: Ciphertext
)pbdoc";

const char* cc_EvalAddMutablePlaintext_docs = R"pbdoc(
Homomorphic addition a mutable ciphertext and plaintext

:param ciphertext: ciphertext
:type ciphertext: Ciphertext
:param plaintext: plaintext
:type plaintext: Plaintext
:return: new ciphertext for ciphertext + plaintext
:rtype: Ciphertext
)pbdoc";


const char* cc_EvalAddMutableInPlace_docs = R"pbdoc(
    Homomorphic addition a mutable ciphertext and plaintext

    :param ciphertext1: first addend
    :type ciphertext1: Ciphertext
    :param ciphertext2: second addend
    :type ciphertext2: Ciphertext
    :return: ciphertext1 contains ciphertext1 + ciphertext2
)pbdoc";

const char* cc_EvalSub_docs = R"pbdoc(
Homomorphic subtraction of two ciphertexts

:param ciphertext1: minuend
:type ciphertext1: Ciphertext
:param ciphertext2: subtrahend
:type ciphertext2: Ciphertext
:return: the result as a new ciphertext
:rtype: Ciphertext
)pbdoc";

const char* cc_EvalSubfloat_docs = R"pbdoc(
Subtraction of a ciphertext and a real number. Supported only in CKKS.

:param ciphertext: input ciphertext
:type ciphertext: Ciphertext
:param constant: a real number
:type constant: float
:return: new ciphertext for ciphertext - constant
:rtype: Ciphertext
)pbdoc";

const char* cc_EvalSubPlaintext_docs = R"pbdoc(
Subtraction of a ciphertext and a real number. Supported only in CKKS.

:param ciphertext: minuend
:type ciphertext: Ciphertext
:param plaintext: subtrahend
:type plaintext: Plaintext
:return: new ciphertext for ciphertext - plaintext
:rtype: Ciphertext
)pbdoc";

const char* cc_EvalSubInPlace_docs = R"pbdoc(
In-place homomorphic subtraction of two ciphertexts

:param ciphertext1: minuend
:type ciphertext1: Ciphertext
:param ciphertext2: subtrahend
:type ciphertext2: Ciphertext
:return: the result as a new ciphertext
)pbdoc";

const char* cc_EvalSubInPlacefloat_docs = R"pbdoc(
In-place subtraction of a ciphertext and a real number. Supported only in CKKS.

:param ciphertext: input ciphertext
:type ciphertext: Ciphertext
:param constant: a real number
:type constant: float
)pbdoc";

// EvalSubMutable
const char* cc_EvalSubMutable_docs = R"pbdoc(
Homomorphic subtraction of two mutable ciphertexts

:param ciphertext1: minuend
:type ciphertext1: Ciphertext
:param ciphertext2: subtrahend
:type ciphertext2: Ciphertext
:return: the result as a new ciphertext
)pbdoc";

// EvalSubMutableInPlace
const char* cc_EvalSubMutableInPlace_docs = R"pbdoc(
    In-place homomorphic subtraction of two mutable ciphertexts

    :param ciphertext1: minuend
    :type ciphertext1: Ciphertext
    :param ciphertext2: subtrahend
    :type ciphertext2: Ciphertext
    :return: the updated minuend
)pbdoc";

// EvalSubMutablePlaintext
const char* cc_EvalSubMutablePlaintext_docs = R"pbdoc(
Homomorphic subtraction of mutable ciphertext and plaintext

:param ciphertext: minuend
:type ciphertext: Ciphertext
:param plaintext: subtrahend
:type plaintext: Plaintext
:return: new ciphertext for ciphertext - plaintext
)pbdoc";

const char* cc_EvalMult_docs = R"pbdoc(
EvalMult - OpenFHE EvalMult method for a pair of ciphertexts (uses a relinearization key from the crypto context)

:param ciphertext1: multiplier
:type ciphertext1: Ciphertext
:param ciphertext2: multiplicand
:type ciphertext2: Ciphertext
:return: new ciphertext for ciphertext1 * ciphertext2
:rtype: Ciphertext
)pbdoc";

const char* cc_EvalMultfloat_docs = R"pbdoc(
Multiplication of a ciphertext by a real number. Supported only in CKKS.

:param ciphertext: multiplier
:type ciphertext: Ciphertext
:param constant: multiplicand
:type constant: float
:return: the result of multiplication
:rtype: Ciphertext
)pbdoc";

const char* cc_EvalMultPlaintext_docs = R"pbdoc(
Multiplication of a ciphertext by a plaintext

:param ciphertext: multiplier
:type ciphertext: Ciphertext
:param plaintext: multiplicand
:type plaintext: Plaintext
:return: the result of multiplication
:rtype: Ciphertext
)pbdoc";

const char* cc_EvalMultMutable_docs = R"pbdoc(
EvalMult - OpenFHE EvalMult method for a pair of mutable ciphertexts (uses a relinearization key from the crypto context)

:param ciphertext1: multiplier
:type ciphertext1: Ciphertext
:param ciphertext2: multiplicand
:type ciphertext2: Ciphertext
:return: new ciphertext for ciphertext1 * ciphertext2
:rtype: Ciphertext
)pbdoc";

const char* cc_EvalMultMutablePlaintext_docs = R"pbdoc(
Multiplication of mutable ciphertext and plaintext
:param ciphertext: multiplier
:type ciphertext: Ciphertext
:param plaintext: multiplicand
:type plaintext: Plaintext
:return: the result of multiplication
:rtype: Ciphertext
)pbdoc";

const char* cc_EvalMultMutableInPlace_docs = R"pbdoc(
    In-place EvalMult method for a pair of mutable ciphertexts (uses a relinearization key from the crypto context)

    :param ciphertext1: multiplier
    :type ciphertext1: Ciphertext
    :param ciphertext2: multiplicand
    :type ciphertext2: Ciphertext
)pbdoc";

const char* cc_EvalSquare_docs = R"pbdoc(
    Efficient homomorphic squaring of a ciphertext - uses a relinearization key stored in the crypto context

    :param ciphertext: input ciphertext
    :type ciphertext: Ciphertext
    :return: squared ciphertext
    :rtype: Ciphertext
)pbdoc";

const char* cc_EvalSquareMutable_docs = R"pbdoc(
    Efficient homomorphic squaring of a mutable ciphertext - uses a relinearization key stored in the crypto context

    :param ciphertext: input ciphertext
    :type ciphertext: Ciphertext
    :return: squared ciphertext
    :rtype: Ciphertext
)pbdoc";

const char* cc_EvalSquareInPlace_docs = R"pbdoc(
    In-place homomorphic squaring of a mutable ciphertext - uses a relinearization key stored in the crypto context

    :param ciphertext: input ciphertext
    :type ciphertext: Ciphertext
    :return: squared ciphertext
)pbdoc";


const char* cc_EvalMultNoRelin_docs = R"pbdoc(
    Homomorphic multiplication of two ciphertexts without relinearization

    :param ciphertext1: multiplier
    :type ciphertext1: Ciphertext
    :param ciphertext2: multiplicand
    :type ciphertext2: Ciphertext
    :return: new ciphertext for ciphertext1 * ciphertext2
    :rtype: Ciphertext
)pbdoc";

const char* cc_Relinearize_docs = R"pbdoc(
    Homomorphic multiplication of two ciphertexts withour relinearization

    :param ciphertext: input ciphertext
    :type ciphertext: Ciphertext
    :return: relinearized ciphertext
    :rtype: Ciphertext
)pbdoc";

const char* cc_RelinearizeInPlace_docs = R"pbdoc(
    In-place relinearization of a ciphertext to the lowest level (with 2 polynomials per ciphertext).

    :param ciphertext: input ciphertext
    :type ciphertext: Ciphertext
)pbdoc";

const char* cc_EvalMultAndRelinearize_docs = R"pbdoc(
    Homomorphic multiplication of two ciphertexts followed by relinearization to the lowest level

    :param ciphertext1: first input ciphertext
    :type ciphertext1: Ciphertext
    :param ciphertext2: second input ciphertext
    :type ciphertext2: Ciphertext
    :return: new ciphertext
    :rtype: Ciphertext
)pbdoc";

const char* cc_EvalNegate_docs = R"pbdoc(
    Negates a ciphertext

    :param ciphertext: input ciphertext
    :type ciphertext: Ciphertext
    :return: new ciphertext: -ciphertext
    :rtype: Ciphertext
)pbdoc";

const char* cc_EvalNegateInPlace_docs = R"pbdoc(
    In-place negation of a ciphertext

    :param ciphertext: input ciphertext
    :type ciphertext: Ciphertext
)pbdoc";

const char* cc_EvalChebyshevSeries_docs = R"pbdoc(
    Method for evaluating Chebyshev polynomial interpolation; first the range [a,b] is mapped to [-1,1] using linear transformation 1 + 2 (x-a)/(b-a) If the degree of the polynomial is less than 5, use EvalChebyshevSeriesLinear (naive linear method), otherwise, use EvalChebyshevSeriesPS (Paterson-Stockmeyer method). Supported only in CKKS.

    :param ciphertext: input ciphertext
    :type ciphertext: Ciphertext
    :param coefficients: is the vector of coefficients in Chebyshev expansion
    :type coefficients: list
    :param a: lower bound of argument for which the coefficients were found
    :type a: float
    :param b: upper bound of argument for which the coefficients were found
    :type b: float
    :return: the result of polynomial evaluation
    :rtype: Ciphertext
)pbdoc";

const char* cc_EvalChebyshevSeriesLinear_docs = R"pbdoc(
    Naive linear method for evaluating Chebyshev polynomial interpolation; first the range [a,b] is mapped to [-1,1] using linear transformation 1 + 2 (x-a)/(b-a). Supported only in CKKS.

    :param ciphertext: input ciphertext
    :type ciphertext: Ciphertext
    :param coefficients:  is the vector of coefficients in Chebyshev expansion
    :type coefficients: list
    :param a: lower bound of argument for which the coefficients were found
    :type a: float
    :param b: upper bound of argument for which the coefficients were found
    :type b: float
    :return: the result of polynomial evaluation
    :rtype: Ciphertext
)pbdoc";

const char* cc_EvalChebyshevSeriesPS_docs = R"pbdoc(
    Paterson-Stockmeyer method for evaluating Chebyshev polynomial interpolation; first the range [a,b] is mapped to [-1,1] using linear transformation 1 + 2 (x-a)/(b-a). Supported only in CKKS.

    :param ciphertext: input ciphertext
    :type ciphertext: Ciphertext
    :param coefficients: is the vector of coefficients in Chebyshev expansion
    :type coefficients: list
    :param a: lower bound of argument for which the coefficients were found
    :type a: float
    :param b: upper bound of argument for which the coefficients were found
    :type b: float
    :return: the result of polynomial evaluation
    :rtype: Ciphertext
)pbdoc";

const char* cc_EvalChebyshevFunction_docs = R"pbdoc(
    Method for calculating Chebyshev evaluation on a ciphertext for a smooth input function over the range [a,b]. Supported only in CKKS.

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
    Evaluate approximate sine function on a ciphertext using the Chebyshev approximation. Supported only in CKKS.

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
    Evaluate approximate cosine function on a ciphertext using the Chebyshev approximation. Supported only in CKKS.

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
    Evaluate approximate logistic function 1/(1 + exp(-x)) on a ciphertext using the Chebyshev approximation. Supported only in CKKS.

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
    Evaluate approximate division function 1/x where x >= 1 on a ciphertext using the Chebyshev approximation. Supported only in CKKS.

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
    EvalSumKeyGen Generates the key map to be used by EvalSum

    :param privateKey: private key
    :type privateKey: PrivateKey
    :param publicKey: public key (used in NTRU schemes)
    :type publicKey: PublicKey
    :return: None
)pbdoc";

const char* cc_EvalSumRowsKeyGen_docs = R"pbdoc(
    Generate the automorphism keys for EvalSumRows; works only for packed encoding

    :param privateKey: private key
    :type privateKey: PrivateKey
    :param publicKey: public key
    :type publicKey: PublicKey
    :param rowSize: size of rows in the matrix
    :type rowSize: int
    :param subringDim: subring dimension (set to cyclotomic order if set to 0)
    :type subringDim: int
    :return: returns the evaluation keys
    :rtype: EvalKeyMap
)pbdoc";

const char* cc_EvalSumColsKeyGen_docs = R"pbdoc(
    Generates the automorphism keys for EvalSumCols; works only for packed encoding

    :param privateKey: private key
    :type privateKey: PrivateKey
    :param publicKey: public key
    :type publicKey: PublicKey
    :return: returns the evaluation keys
    :rtype: EvalKeyMap
)pbdoc";

const char* cc_EvalSumRows_docs = R"pbdoc(
    Sums all elements over row-vectors in a matrix - works only with packed encoding

    :param ciphertext: the input ciphertext
    :type ciphertext: Ciphertext
    :param rowSize: size of rows in the matrix
    :type rowSize: int
    :param evalSumKeyMap: reference to the map of evaluation keys generated by
    :type evalSumKeyMap: EvalKeyMap
    :param subringDim: the current cyclotomic order/subring dimension. If set to 0, we use the full cyclotomic order.
    :type subringDim: int
    :return: Ciphertext: resulting ciphertext
    :rtype: Ciphertext
)pbdoc";

const char* cc_EvalSumCols_docs = R"pbdoc(
    Sums all elements over column-vectors in a matrix - works only with packed encoding

    :param ciphertext: the input ciphertext
    :type ciphertext: Ciphertext
    :param rowSize: size of rows in the matrix
    :type rowSize: int
    :param evalSumKeyMap: reference to the map of evaluation keys generated by
    :type evalSumKeyMap: EvalKeyMap
    :return: Ciphertext: resulting ciphertext
    :rtype: Ciphertext
)pbdoc";

const char* cc_EvalInnerProduct_docs = R"pbdoc(
    Evaluates inner product in packed encoding (uses EvalSum)

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
    Evaluates inner product in packed encoding (uses EvalSum)

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

const char* cc_MultipartyKeyGen_vector_docs = R"pbdoc(
    Threshold FHE: Generates a public key from a vector of secret shares. ONLY FOR DEBUGGIN PURPOSES. SHOULD NOT BE USED IN PRODUCTION.

    :param privateKeyVec: secret key shares.
    :type privateKeyVec: List[PrivateKey]
    :return KeyPair: key pair including the private for the current party and joined public key
    :rtype: KeyPair
)pbdoc";

const char* cc_MultipartyDecryptLead_docs = R"pbdoc(
    Threshold FHE: Method for decryption operation run by the lead decryption client

    :param ciphertextVec: a list of ciphertexts
    :type ciphertextVec: list
    :param privateKey:  secret key share used for decryption.
    :type privateKey: PrivateKey
    :return: list of partially decrypted ciphertexts.
    :rtype: List[Ciphertext]
)pbdoc";

const char* cc_MultipartyDecryptMain_docs = R"pbdoc(
    Threshold FHE: "Partial" decryption computed by all parties except for the lead one

    :param ciphertextVec: a list of ciphertexts
    :type ciphertextVec: list
    :param privateKey:  secret key share used for decryption.
    :type privateKey: PrivateKey
    :return: list of partially decrypted ciphertexts.
    :rtype: List[Ciphertext]
)pbdoc";

const char* cc_MultipartyDecryptFusion_docs = R"pbdoc(
    Threshold FHE: Method for combining the partially decrypted ciphertexts and getting the final decryption in the clear.

    :param partialCiphertextVec: list of "partial" decryptions
    :type partialCiphertextVec: list
    :return: Plaintext: resulting plaintext
    :rtype: Plaintext
)pbdoc";

const char* cc_MultiKeySwitchGen_docs = R"pbdoc(
    Threshold FHE: Generates a joined evaluation key from the current secret share and a prior joined evaluation key

    :param originalPrivateKey: secret key transformed from.
    :type originalPrivateKey: PrivateKey
    :param newPrivateKey: secret key transformed from.
    :type newPrivateKey: PrivateKey
    :param evalKey: the prior joined evaluation key.
    :type evalKey: EvalKey
    :return: EvalKey: the new joined evaluation key.
    :rtype: EvalKey
)pbdoc";

// TODO (Oliveira, R.) - Complete the following documentation
const char* cc_GetEvalSumKeyMap_docs = R"pbdoc(
    Get a map of summation keys (each is composed of several automorphism keys) for a specific secret key tag
    :return: EvalKeyMap: key map
    :rtype: EvalKeyMap
)pbdoc";
const char* cc_InsertEvalSumKey_docs = R"pbdoc(
    InsertEvalSumKey - add the given map of keys to the map, replacing the existing map if there

    :param evalKeyMap: key map
    :type evalKeyMap: EvalKeyMap
)pbdoc";
const char* cc_MultiEvalSumKeyGen_docs = R"pbdoc(
    Threshold FHE: Generates joined summation evaluation keys from the current secret share and prior joined summation keys

    :param privateKey: secret key share
    :type privateKey: PrivateKey
    :param evalKeyMap: a map with prior joined summation keys
    :type evalKeyMap: EvalKeyMap
    :param keyId: new key identifier used for resulting evaluation key
    :type keyId: str
    :return: EvalKeyMap: new joined summation keys
    :rtype: EvalKeyMap
)pbdoc";

const char* cc_MultiAddEvalKeys_docs = R"pbdoc(
    Threshold FHE: Adds two prior evaluation keys

    :param evalKey1: first evaluation key
    :type evalKey1: EvalKey
    :param evalKey2: second evaluation key
    :type evalKey2: EvalKey
    :param keyId: new key identifier used for resulting evaluation key
    :type keyId: str
    :return: the new joined key
    :rtype: EvalKey
)pbdoc";

const char* cc_MultiMultEvalKey_docs = R"pbdoc(
    Threshold FHE: Generates a partial evaluation key for homomorphic multiplication based on the current secret share and an existing partial evaluation key

    :param privateKey: current secret share
    :type privateKey: PrivateKey
    :param evalKey: prior evaluation key
    :type evalKey: EvalKey
    :param keyId: new key identifier used for resulting evaluation key
    :type keyId: str
    :return: the new joined key
    :rtype: EvalKey
)pbdoc";

const char* cc_MultiAddEvalSumKeys_docs = R"pbdoc(
    Threshold FHE: Adds two prior evaluation key sets for summation

    :param evalKeyMap1: first summation key set
    :type evalKeyMap1: EvalKeyMap
    :param evalKeyMap2: second summation key set
    :type evalKeyMap2: EvalKeyMap
    :param keyId: new key identifier used for resulting evaluation key
    :type keyId: str
    :return: the neew joined key set for summation
    :rtype: EvalKeyMap
)pbdoc";

const char* cc_MultiAddEvalMultKeys_docs = R"pbdoc(
    Threshold FHE: Adds two prior evaluation key sets for summation

    :param evalKey1: first evaluation key
    :type evalKey1: EvalKey
    :param evalKey2: second evaluation key
    :type evalKey2: EvalKey
    :param keyId: new key identifier used for resulting evaluation key
    :type keyId: str
    :return: the new joined key
    :rtype: EvalKey
)pbdoc";


const char* cc_IntMPBootAdjustScale_docs = R"pbdoc(
    Threshold FHE: Prepare a ciphertext for Multi-Party Interactive Bootstrapping.

    :param ciphertext: Input Ciphertext
    :type ciphertext: Ciphertext
    :return: Resulting Ciphertext
    :rtype: Ciphertext
)pbdoc";

const char* cc_IntMPBootRandomElementGen_docs = R"pbdoc(
    Threshold FHE: Generate a common random polynomial for Multi-Party Interactive Bootstrapping

    :param publicKey: the scheme public key (you can also provide the lead party's public-key)
    :type publicKey: PublicKey
    :return: Resulting ring element
    :rtype: Ciphertext
)pbdoc";

const char* cc_IntMPBootDecrypt_docs = R"pbdoc(
    Threshold FHE: Does masked decryption as part of Multi-Party Interactive Bootstrapping. Each party calls this function as part of the protocol

    :param privateKey: secret key share for party i
    :type privateKey: PrivateKey
    :param ciphertext: input ciphertext
    :type ciphertext: Ciphertext
    :param a: input common random polynomial
    :type a: Ciphertext
    :return: Resulting masked decryption
    :rtype: Ciphertext
)pbdoc";

const char* cc_IntMPBootAdd_docs = R"pbdoc(
    Threshold FHE: Aggregates a vector of masked decryptions and re-encryotion shares, which is the second step of the interactive multiparty bootstrapping procedure.

    :param sharesPairVec: vector of pair of ciphertexts, each element of this vector contains (h_0i, h_1i) - the masked-decryption and encryption shares ofparty i
    :type sharesPairVec: List[List[Ciphertext]]
    :return: aggregated pair of shares ((h_0, h_1)
    :rtype: List[Ciphertext]
)pbdoc";

const char* cc_IntMPBootEncrypt_docs = R"pbdoc(
    Threshold FHE: Does public key encryption of lead party's masked decryption as part of interactive multi-party bootstrapping, which increases the ciphertext modulus and enables future computations. This operation is done by the lead party as the final step of interactive multi-party bootstrapping.

    :param publicKey: the lead party's public key
    :type publicKey: PublicKey
    :param sharesPair: aggregated decryption and re-encryption shares
    :type sharesPair: List[Ciphertext]
    :param a: common random ring element
    :type a: Ciphertext
    :param ciphertext: input ciphertext
    :type ciphertext: Ciphertext
    :return: Resulting encryption
    :rtype: Ciphertext
)pbdoc";

const char* cc_InsertEvalMultKey_docs = R"pbdoc(
    InsertEvalMultKey - add the given vector of keys to the map, replacing the existing vector if there

    :param evalKeyVec: vector of keys
    :type evalKeyVec: List[EvalKey]
)pbdoc";

const char* cc_EvalSum_docs = R"pbdoc(
    Function for evaluating a sum of all components in a vector.

    :param ciphertext: the input ciphertext
    :type ciphertext: Ciphertext
    :param batchSize: size of the batch
    :type batchSize: int
    :return: resulting ciphertext
    :rtype: Ciphertext
)pbdoc";


const char* cc_EvalMerge_docs = R"pbdoc(
    Merges multiple ciphertexts with encrypted results in slot 0 into a single ciphertext. The slot assignment is done based on the order of ciphertexts in the vector. Requires the generation of rotation keys for the indices that are needed.

    :param ciphertextVec: vector of ciphertexts to be merged.
    :type ciphertextVec: list
    :return: resulting ciphertext
    :rtype: Ciphertext
)pbdoc";

const char* cc_ReKeyGen_docs = R"pbdoc(
    ReKeyGen produces an Eval Key that OpenFHE can use for Proxy Re-Encryption

    :param oldPrivateKey: original private key
    :type privateKey: PrivateKey
    :param newPublicKey: public key
    :type publicKey: PublicKey
    :return: new evaluation key
    :rtype: EvalKey
)pbdoc";

const char* cc_ReEncrypt_docs = R"pbdoc(
    ReEncrypt - Proxy Re-Encryption mechanism for OpenFHE

    :param ciphertext: input ciphertext
    :type ciphertext: Ciphertext
    :param evalKey: evaluation key for PRE keygen method
    :type evalKey: EvalKey
    :param publicKey: the public key of the recipient of the reencrypted ciphertext
    :type publicKey: PublicKey
    :return: the resulting ciphertext
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
    Naive method for polynomial evaluation for polynomials represented in the power series (fast only for small-degree polynomials; less than 10). Uses a binary tree computation of the polynomial powers. Supported only in CKKS.

    :param ciphertext: input ciphertext
    :type ciphertext: Ciphertext
    :param coefficients: is the vector of coefficients in the polynomial; the size of the vector is the degree of the polynomial
    :type coefficients: list
    :return: Ciphertext: the result of polynomial evaluation.
    :rtype: Ciphertext
)pbdoc";

const char* cc_EvalPolyPS_docs = R"pbdoc(
    Paterson-Stockmeyer method for evaluation for polynomials represented in the power series. Supported only in CKKS.

    :param ciphertext: input ciphertext
    :type ciphertext: Ciphertext
    :param coefficients: is the vector of coefficients in the polynomial; the size of the vector is the degree of the polynomial
    :type coefficients: list
    :return: Ciphertext: the result of polynomial evaluation.
    :rtype: Ciphertext
)pbdoc";

const char* cc_Rescale_docs = R"pbdoc(
    Rescale - An alias for OpenFHE ModReduce method. This is because ModReduce is called Rescale in CKKS.

    :param ciphertext: ciphertext
    :type ciphertext: Ciphertext
    :return: Ciphertext: rescaled ciphertext
    :rtype: Ciphertext
)pbdoc";

const char* cc_RescaleInPlace_docs = R"pbdoc(
    Rescale - An alias for OpenFHE ModReduceInPlace method. This is because ModReduceInPlace is called RescaleInPlace in CKKS.

    :param ciphertext:  ciphertext to be rescaled in-place
    :type ciphertext: Ciphertext
)pbdoc";

const char* cc_ModReduce_docs = R"pbdoc(
    ModReduce - OpenFHE ModReduce method used only for BGV/CKKS.

    :param ciphertext: ciphertext
    :type ciphertext: Ciphertext
    :return: Ciphertext: mod reduced ciphertext
    :rtype: Ciphertext
)pbdoc";

const char* cc_ModReduceInPlace_docs = R"pbdoc(
    ModReduce - OpenFHE ModReduceInPlace method used only for BGV/CKKS.

    :param ciphertext: ciphertext to be mod-reduced in-place
    :type ciphertext: Ciphertext
)pbdoc";

const char* cc_EvalBootstrapSetup_docs = R"pbdoc(
    Bootstrap functionality: There are three methods that have to be called in this specific order:

    1. EvalBootstrapSetup: computes and encodes the coefficients for encoding and decoding and stores the necessary parameters

    2. EvalBootstrapKeyGen: computes and stores the keys for rotations and conjugation

    3. EvalBootstrap: refreshes the given ciphertext Sets all parameters for both linear and FTT-like methods. Supported in CKKS only.

    :param levelBudget: vector of budgets for the amount of levels in encoding and decoding
    :type levelBudget: list
    :param dim1: vector of inner dimension in the baby-step giant-step routine for encoding and decodingl
    :type dim1: list
    :param slots: number of slots to be bootstraped
    :type slots: int
    :param correctionFactor: value to internally rescale message by to improve precision of bootstrapping. If set to 0, we use the default logic. This value is only used when NATIVE_SIZE=64.
    :type correctionFactor: int
    :return: None
)pbdoc";

const char* cc_EvalBootstrapKeyGen_docs = R"pbdoc(
    Generates all automorphism keys for EvalBootstrap. Supported in CKKS only. EvalBootstrapKeyGen uses the baby-step/giant-step strategy.

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

// TODO (Oliveira, R.) - Complete the following documentation
const char* cc_EvalCKKStoFHEWSetup_docs = "";
const char* cc_EvalCKKStoFHEWKeyGen_docs = "";
const char* cc_EvalCKKStoFHEWPrecompute_docs = "";
const char* cc_EvalCKKStoFHEW_docs = "";
const char* cc_EvalFHEWtoCKKSSetup_docs = "";
const char* cc_EvalFHEWtoCKKSKeyGen_docs = "";
const char* cc_EvalFHEWtoCKKS_docs = "";
const char* cc_EvalSchemeSwitchingSetup_docs = "";
const char* cc_EvalSchemeSwitchingKeyGen_docs = "";
const char* cc_EvalCompareSwitchPrecompute_docs = "";
const char* cc_EvalCompareSchemeSwitching_docs = "";
const char* cc_EvalMinSchemeSwitching_docs = "";
const char* cc_EvalMinSchemeSwitchingAlt_docs = "";
const char* cc_EvalMaxSchemeSwitching_docs = "";
const char* cc_EvalMaxSchemeSwitchingAlt_docs = "";

const char* cc_EvalAutomorphismKeyGen_docs = R"pbdoc(
    Generate automophism keys for a given private key; Uses the private key for encryption

    :param privateKey: private key.
    :type privateKey: PrivateKey
    :param indexList: list of automorphism indices to be computed.
    :type indexList: list
    :return: returns the evaluation key
    :rtype: EvalKeyMap
)pbdoc";

const char* cc_FindAutomorphismIndex_docs = R"pbdoc(
    Finds an automorphism index for a given vector index using a scheme-specific algorithm

    :param idx: regular vector index
    :type idx: int
    :return: the automorphism index
    :rtype: int
)pbdoc";

const char* cc_FindAutomorphismIndices_docs = R"pbdoc(
    Finds automorphism indices for a given list of vector indices using a scheme-specific algorithm

    :param idxList: list of indices
    :type idxList: List[int]
    :return: a list of automorphism indices
    :rtype: List[int]
)pbdoc";

const char* cc_ClearEvalMultKeys_docs = R"pbdoc(
    ClearEvalMultKeys - flush EvalMultKey cache for a given id

    :param id: the corresponding key id
    :type id: str
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

    :param filename: output file to serialize to
    :type filename: str
    :param sertype: type of serialization
    :type sertype: SERJSON, SERBINARY
    :param id: for key to serialize - if empty string, serialize them all
    :type id: str
    :return: bool: true on success (false on failure or no keys found)
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
