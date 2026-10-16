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

const char* cc_GetBootstrapDepthApproxMod_docs = R"pbdoc(
    Multiplicative depth of CKKS bootstrapping for a user-supplied depth of the approximate
    modular reduction. To be deprecated; prefer GetBootstrapDepth(levelBudget, keyDist).

    :param depth: depth of the Chebyshev interpolation of the approximate modular reduction;
                  the double-angle iterations of UNIFORM_TERNARY are added internally
    :type depth: int
    :param levelBudget: levels spent on CoeffsToSlots and SlotsToCoeffs, respectively
    :type levelBudget: list[int]
    :param keyDist: secret key distribution of the cryptocontext
    :type keyDist: SecretKeyDist
    :return: the multiplicative depth consumed by EvalBootstrap
    :rtype: int
)pbdoc";

const char* cc_GetBootstrapDepth_docs = R"pbdoc(
    Multiplicative depth consumed by CKKS bootstrapping: the approximate modular reduction
    (Chebyshev interpolation and double-angle iterations, selected by the secret key
    distribution) plus the CoeffsToSlots and SlotsToCoeffs level budgets. Add the number of
    levels needed after bootstrapping to obtain the multiplicative depth of the cryptocontext.

    :param levelBudget: levels spent on CoeffsToSlots and SlotsToCoeffs, respectively
    :type levelBudget: list[int]
    :param keyDist: secret key distribution of the cryptocontext
    :type keyDist: SecretKeyDist
    :return: the multiplicative depth consumed by EvalBootstrap
    :rtype: int
)pbdoc";

const char* cc_GetFBTDepth_docs = R"pbdoc(
    Multiplicative depth consumed by functional bootstrapping (EvalFBT): the CoeffsToSlots and
    SlotsToCoeffs level budgets plus the depth of the look-up table evaluation. For
    SPARSE_ENCAPSULATED, firstModSize (the size of the first modulus in bits) selects the
    approximation tables: a first modulus above 60 bits gives the sparse secret Hamming weight
    64 and uses the K = 28 tables of SPARSE_TERNARY, which need one more level than the K = 16
    tables of the default Hamming weight 32.

    :param levelBudget: levels spent on CoeffsToSlots and SlotsToCoeffs, respectively
    :type levelBudget: list[int]
    :param coefficients: trigonometric Hermite interpolation coefficients of the look-up table
                         (complex, or integer for a Boolean function of order 1)
    :type coefficients: list[int] | list[complex]
    :param PInput: plaintext modulus of the RLWE input
    :type PInput: int
    :param order: order of the trigonometric Hermite interpolation (1, 2 or 3)
    :type order: int
    :param skd: secret key distribution of the cryptocontext
    :type skd: SecretKeyDist
    :param firstModSize: size of the first modulus in bits (only used for SPARSE_ENCAPSULATED)
    :type firstModSize: int
    :return: the multiplicative depth consumed by EvalFBT
    :rtype: int
)pbdoc";

const char* cc_GetFEFBTDepth_docs = R"pbdoc(
    Multiplicative depth consumed by FE functional bootstrapping (EvalFEFuncBootstrap): the
    CoeffsToSlots and SlotsToCoeffs level budgets, the complex exponential approximation and
    its double-angle iterations (selected by the secret key distribution and, for
    SPARSE_ENCAPSULATED, by firstModSize as in GetFBTDepth), and the evaluation of the Fourier
    series.

    :param levelBudget: levels spent on CoeffsToSlots and SlotsToCoeffs, respectively
    :type levelBudget: list[int]
    :param coefficients: Fourier coefficients of the function to be evaluated
    :type coefficients: list[complex]
    :param skd: secret key distribution of the cryptocontext
    :type skd: SecretKeyDist
    :param firstModSize: size of the first modulus in bits (only used for SPARSE_ENCAPSULATED)
    :type firstModSize: int
    :return: the multiplicative depth consumed by EvalFEFuncBootstrap
    :rtype: int
)pbdoc";

const char* cc_EvalFBTSetup_docs = R"pbdoc(
    Sets up CKKS functional bootstrapping of a look-up table: computes its depth and
    precomputes the homomorphic encoding and decoding matrices with the required scalings
    folded in. Supported only in CKKS with HYBRID key switching (64-bit build). Shares the
    precomputation entry for numSlots with EvalBootstrapSetup and EvalFEFuncBootstrapSetup.

    :param coeffs: trigonometric Hermite interpolation coefficients of the look-up table
                   (complex, or integer for a Boolean function of order 1); only their number
                   is used here
    :type coeffs: list[int] | list[complex]
    :param numSlots: number of slots to be bootstrapped (0 = full packing)
    :type numSlots: int
    :param PIn: plaintext modulus of the RLWE input
    :type PIn: int
    :param POut: plaintext modulus of the RLWE output
    :type POut: int
    :param Bigq: ciphertext modulus of the RLWE scheme the input is converted from
    :type Bigq: int
    :param pubKey: public key (its element parameters define the modulus chain)
    :type pubKey: PublicKey
    :param dim1: baby-step dimensions for CoeffsToSlots and SlotsToCoeffs (0 = automatic)
    :type dim1: list[int]
    :param levelBudget: levels spent on CoeffsToSlots and SlotsToCoeffs (each in [1, log2(slots)])
    :type levelBudget: list[int]
    :param lvlsAfterBoot: number of levels remaining after functional bootstrapping
    :type lvlsAfterBoot: int
    :param depthLeveledComputation: depth reserved for a leveled computation between
                                    EvalFBTNoDecoding and EvalHomDecoding
    :type depthLeveledComputation: int
    :param order: order of the trigonometric Hermite interpolation (1, 2 or 3)
    :type order: int
)pbdoc";

const char* cc_EvalFBT_docs = R"pbdoc(
    Functional bootstrapping of a look-up table on a CKKS ciphertext imported from RLWE
    (SchemeletRLWEMP.ConvertRLWEToCKKS): modulus raise, CoeffsToSlots, complex exponential (or
    cosine for a Boolean function of order 1), trigonometric Hermite series, SlotsToCoeffs and
    scalings. Supported only in CKKS.

    :param ciphertext: input ciphertext holding the RLWE input in its coefficients
    :type ciphertext: Ciphertext
    :param coeffs: trigonometric Hermite interpolation coefficients of the look-up table
                   (complex, or integer for a Boolean function of order 1), scaled to
                   magnitude at most one
    :type coeffs: list[int] | list[complex]
    :param digitBitSize: bit size of the look-up table input (log2 of the input plaintext modulus)
    :type digitBitSize: int
    :param initialScaling: scale of the imported message (the RLWE ciphertext modulus of the input)
    :type initialScaling: int
    :param postScaling: integer the result is multiplied by after SlotsToCoeffs (typically the
                        scale the coefficients were divided by; values of at most 1 are ignored)
    :type postScaling: int
    :param levelToReduce: number of levels to drop before SlotsToCoeffs
    :type levelToReduce: int
    :param order: order of the trigonometric Hermite interpolation (1, 2 or 3)
    :type order: int
    :return: ciphertext holding the look-up table outputs in its coefficients, ready for
             SchemeletRLWEMP.ConvertCKKSToRLWE
    :rtype: Ciphertext
)pbdoc";

const char* cc_EvalFBTNoDecoding_docs = R"pbdoc(
    Functional bootstrapping of a look-up table without the final homomorphic decoding: the
    outputs stay in the slots so that a leveled computation can be applied before
    EvalHomDecoding. Supported only in CKKS.

    :param ciphertext: input ciphertext holding the RLWE input in its coefficients
    :type ciphertext: Ciphertext
    :param coeffs: trigonometric Hermite interpolation coefficients of the look-up table
    :type coeffs: list[int] | list[complex]
    :param digitBitSize: bit size of the look-up table input (log2 of the input plaintext modulus)
    :type digitBitSize: int
    :param initialScaling: scale of the imported message (the RLWE ciphertext modulus of the input)
    :type initialScaling: int
    :param order: order of the trigonometric Hermite interpolation (1, 2 or 3)
    :type order: int
    :return: ciphertext holding the look-up table outputs in its slots
    :rtype: Ciphertext
)pbdoc";

const char* cc_EvalHomDecoding_docs = R"pbdoc(
    Homomorphic decoding step of functional bootstrapping: drops levels if requested, applies
    SlotsToCoeffs, multiplies by postScaling and rescales to noise scale degree 1. Supported
    only in CKKS.

    :param ciphertext: ciphertext with the look-up table outputs in its slots
    :type ciphertext: Ciphertext
    :param postScaling: integer the result is multiplied by after SlotsToCoeffs (values of at
                        most 1 are ignored)
    :type postScaling: int
    :param levelToReduce: number of levels to drop before SlotsToCoeffs
    :type levelToReduce: int
    :return: ciphertext holding the outputs in its coefficients, at noise scale degree 1
    :rtype: Ciphertext
)pbdoc";

const char* cc_EvalMVBPrecompute_docs = R"pbdoc(
    Precomputes the complex-exponential powers for multi-value bootstrapping (modulus raise,
    CoeffsToSlots, complex exponential and its powers). Every look-up table later evaluated on
    the result (EvalMVB, EvalMVBNoDecoding) must be interpolated with the same shape (same
    plaintext modulus and order) as coeffs, since those determine which powers are computed.
    Supported only in CKKS.

    :param ciphertext: input ciphertext holding the RLWE input in its coefficients
    :type ciphertext: Ciphertext
    :param coeffs: trigonometric Hermite interpolation coefficients of one of the look-up tables
    :type coeffs: list[int] | list[complex]
    :param digitBitSize: bit size of the look-up table input (log2 of the input plaintext modulus)
    :type digitBitSize: int
    :param initialScaling: scale of the imported message (the RLWE ciphertext modulus of the input)
    :type initialScaling: int
    :param order: order of the trigonometric Hermite interpolation (1, 2 or 3)
    :type order: int
    :return: powers of the complex exponential
    :rtype: SeriesPowers
)pbdoc";

const char* cc_EvalMVB_docs = R"pbdoc(
    Multi-value bootstrapping: evaluates the trigonometric Hermite series of a look-up table
    on the powers from EvalMVBPrecompute and applies the homomorphic decoding. Supported only
    in CKKS.

    :param ciphertexts: powers of the complex exponential from EvalMVBPrecompute
    :type ciphertexts: SeriesPowers
    :param coeffs: trigonometric Hermite interpolation coefficients of the look-up table (same
                   shape as in EvalMVBPrecompute)
    :type coeffs: list[int] | list[complex]
    :param digitBitSize: bit size of the look-up table input (log2 of the input plaintext modulus)
    :type digitBitSize: int
    :param postScaling: integer the result is multiplied by after SlotsToCoeffs (values of at
                        most 1 are ignored)
    :type postScaling: int
    :param levelToReduce: number of levels to drop before SlotsToCoeffs
    :type levelToReduce: int
    :param order: order of the trigonometric Hermite interpolation (1, 2 or 3)
    :type order: int
    :return: ciphertext holding the look-up table outputs in its coefficients, at noise scale
             degree 1
    :rtype: Ciphertext
)pbdoc";

const char* cc_EvalMVBNoDecoding_docs = R"pbdoc(
    Multi-value bootstrapping without the final homomorphic decoding: the look-up table
    outputs stay in the slots so that a leveled computation can be applied before
    EvalHomDecoding. Supported only in CKKS.

    :param ciphertexts: powers of the complex exponential from EvalMVBPrecompute
    :type ciphertexts: SeriesPowers
    :param coeffs: trigonometric Hermite interpolation coefficients of the look-up table (same
                   shape as in EvalMVBPrecompute)
    :type coeffs: list[int] | list[complex]
    :param digitBitSize: bit size of the look-up table input (log2 of the input plaintext modulus)
    :type digitBitSize: int
    :param order: order of the trigonometric Hermite interpolation (1, 2 or 3)
    :type order: int
    :return: ciphertext holding the look-up table outputs in its slots
    :rtype: Ciphertext
)pbdoc";

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

const char* cc_EvalFEFuncBootstrapSetup_docs = R"pbdoc(
    Precomputes the encoding/decoding plaintexts for FE functional bootstrapping. Supported
    only in CKKS, with HYBRID key switching and FirstModSize == ScalingModSize + 1. Shares the
    bootstrapping precomputation slot for the given slot count with EvalBootstrapSetup and
    EvalFBTSetup, so a context can hold the precomputation for only one of them per slot count.

    :param levelBudget: levels spent on CoeffsToSlots and SlotsToCoeffs
    :type levelBudget: list[int]
    :param dim1: baby-step dimensions for the two linear transforms (0 = choose automatically)
    :type dim1: list[int]
    :param slots: number of slots to be bootstrapped (0 = full packing)
    :type slots: int
)pbdoc";

const char* cc_EvalFEFuncBootstrap_docs = R"pbdoc(
    Refreshes a ciphertext and evaluates a function on it in one pass, by evaluating the
    function's Fourier extension over the bootstrapped message. Supported only in CKKS.

    The message is embedded into half of the series period (t = m/2), so the input must lie in
    [-1/2, 1/2) and coefficients must be the Fourier extension of the target function over
    that domain. The result is 2*Re(c_0 + sum_{j>=1} c_j exp(2*Pi*i*j*t)) and is therefore
    always real-valued: with CKKSDataType COMPLEX the imaginary part of each input slot is
    discarded and the output slots have zero imaginary part. Use CKKSDataType REAL unless
    complex intermediates are needed elsewhere in the computation.

    :param ciphertext: input ciphertext, with slot values in [-1/2, 1/2)
    :type ciphertext: Ciphertext
    :param coefficients: Fourier coefficients c_j of the target function, c_0 first
    :type coefficients: list[complex]
    :return: refreshed ciphertext holding the function values
    :rtype: Ciphertext
)pbdoc";

const char* cc_EvalFEFuncBootstrapPrecompute_docs = R"pbdoc(
    Runs the function-independent part of FE functional bootstrapping and returns the powers
    of the complex exponential, so that several functions can be evaluated on one bootstrapped
    ciphertext. Supported only in CKKS.

    The refresh itself - SlotsToCoeffs, modulus raise, CoeffsToSlots and the complex
    exponential - happens here and dominates the cost; each subsequent
    EvalFEFuncBootstrapWithPrecomp only evaluates a series. The Paterson-Stockmeyer shape is
    fixed by coefficients, which must have degree at least 5, so pass the longest series of
    the family: every series later evaluated against these powers may have at most the degree
    of coefficients rounded up to the shape's capacity (EvalFEFuncBootstrapWithPrecomp reports
    the exact bound if it is exceeded). A series below degree 5 is evaluated straight from the
    power basis and is accepted as long as its degree does not exceed the number of powers the
    shape holds.

    :param ciphertext: input ciphertext, with slot values in [-1/2, 1/2)
    :type ciphertext: Ciphertext
    :param coefficients: Fourier coefficients of the longest series to be evaluated, c_0 first
    :type coefficients: list[complex]
    :return: powers of the complex exponential, to be passed to EvalFEFuncBootstrapWithPrecomp
    :rtype: SeriesPowers
)pbdoc";

const char* cc_EvalFEFuncBootstrapWithPrecomp_docs = R"pbdoc(
    Evaluates one function's Fourier series against powers from EvalFEFuncBootstrapPrecompute.
    Supported only in CKKS.

    :param powers: powers returned by EvalFEFuncBootstrapPrecompute
    :type powers: SeriesPowers
    :param coefficients: Fourier coefficients c_j of this function, c_0 first
    :type coefficients: list[complex]
    :return: refreshed ciphertext holding the function values
    :rtype: Ciphertext
)pbdoc";

const char* cc_ClearBootstrapPrecom_docs = R"pbdoc(
    Clear the CKKS bootstrap precomputations cached by this context's scheme.
)pbdoc";

const char* fbt_SeriesPowers_docs = R"pbdoc(
    Opaque holder for the powers of the complex exponential precomputed by
    EvalMVBPrecompute or EvalFEFuncBootstrapPrecompute.
)pbdoc";

const char* fbt_PolyVector_docs = R"pbdoc(
    Opaque holder for an RLWE ciphertext: the pair {b, a} of polynomials modulo a ciphertext
    modulus Q, as produced and consumed by SchemeletRLWEMP.
)pbdoc";

const char* fbt_PolyVector_len_docs = R"pbdoc(
    Number of polynomials in the RLWE ciphertext.

    :return: the number of polynomials
    :rtype: int
)pbdoc";

const char* fbt_PolyVector_Clone_docs = R"pbdoc(
    Returns a deep copy of the RLWE ciphertext.

    :return: the copy
    :rtype: PolyVector
)pbdoc";

const char* fbt_PolyVector_SwitchModulus_docs = R"pbdoc(
    Switches every polynomial of the RLWE ciphertext to the given modulus in place.

    :param modulus: the new modulus
    :type modulus: int
)pbdoc";

const char* fbt_PolyVector_sub_docs = R"pbdoc(
    Element-wise subtraction of two RLWE ciphertexts of the same size.

    :return: the difference
    :rtype: PolyVector
)pbdoc";

const char* fbt_GetMultiplicativeDepthByCoeffVector_docs = R"pbdoc(
    Gets the multiplicative depth of evaluating a series with the given coefficients with the
    Paterson-Stockmeyer algorithm, based on the table described in
    src/pke/examples/FUNCTION_EVALUATION.md of OpenFHE.

    :param vec: vector of coefficients
    :type vec: list[int] | list[complex]
    :param isNormalized: true if the vector is normalized
    :type isNormalized: bool
    :return: the multiplicative depth
    :rtype: int
)pbdoc";

const char* fbt_GetHermiteTrigCoefficients_docs = R"pbdoc(
    Calculates the intermediate trigonometric Hermite interpolation coefficients of a look-up
    table given as a Python function. These coefficients can be evaluated over ciphertexts
    encrypting exp(2*Pi*i*x) (e.g. by EvalFBT) to compute the function. The coefficients are
    divided by 2 to account for the fact that the real part of the evaluation needs to be
    taken to get the Hermite trigonometric interpolation result.

    :param func: the function to be approximated, mapping an integer to an integer
    :type func: Callable[[int], int]
    :param p: number of interpolation points (the plaintext modulus)
    :type p: int
    :param order: order of the Hermite interpolation (1 or 2)
    :type order: int
    :param scale: scaling factor the coefficients are divided by
    :type scale: int
    :return: the coefficients of the intermediate Hermite trigonometric interpolation
    :rtype: list[complex]
)pbdoc";

const char* fbt_SchemeletRLWEMP_docs = R"pbdoc(
    Helper ("schemelet") for RLWE ciphertexts with a message in the coefficients, used
    together with the CKKS functional bootstrapping (EvalFBT).

    An RLWE ciphertext is represented as a pair {b, a} of polynomials modulo a ciphertext
    modulus Q such that b + a*s = (Q/p)*m + e for the CKKS secret key s, a plaintext modulus p
    and an integer message vector m stored in the polynomial coefficients (BFV-style scaling).
    The static methods encrypt and decrypt such ciphertexts under the CKKS secret key with
    arbitrary Q and p, switch their modulus, and convert them to and from CKKS ciphertexts so
    that EvalFBT can evaluate a function on the encrypted values and return an exact RLWE
    ciphertext.
)pbdoc";

const char* schemelet_GetElementParams_docs = R"pbdoc(
    Returns the RNS element parameters of the secret key's crypto context with the towers of
    the given number of levels removed from the end. One level corresponds to one tower,
    except that under COMPOSITESCALINGAUTO and COMPOSITESCALINGMANUAL every level consists of
    compositeDegree towers and under FLEXIBLEAUTOEXT one extra tower is removed. The modulus
    of the result is the modulus Q' that EncryptCoeff() samples its encryption of zero over.

    :param privateKey: the CKKS secret key whose crypto context supplies the element parameters
    :type privateKey: PrivateKey
    :param level: number of levels to remove from the full parameters (0 keeps all towers)
    :type level: int
    :return: the reduced element parameters
    :rtype: ParmType
)pbdoc";

const char* schemelet_EncryptCoeff_docs = R"pbdoc(
    Encrypts a vector of integers as the coefficients of an RLWE ciphertext under the CKKS
    secret key. An RLWE encryption of zero is sampled over the modulus of elementParams,
    switched to Q, and the message scaled by Q/p is added. With N the ring dimension, the
    entries are placed at a stride of N/(2*len(input)); when the stride is greater than 1 the
    same values are repeated in the second half of the coefficient vector, and when the input
    has more than N/2 entries they are placed consecutively (at most N of them are used).

    :param input: the integer message; every entry is reduced modulo p as a signed value
    :type input: list[int]
    :param Q: ciphertext modulus of the returned RLWE ciphertext
    :type Q: int
    :param p: plaintext modulus
    :type p: int
    :param privateKey: the CKKS secret key
    :type privateKey: PrivateKey
    :param elementParams: RNS parameters whose modulus Q' the encryption of zero is generated
                          over (see GetElementParams())
    :type elementParams: ParmType
    :param bitReverse: if true, the input is permuted in bit-reversed order before encoding
                       (each half separately when the input has more than N/2 entries); this
                       matches the slot order of the CKKS conversions when rotations are
                       applied in the CKKS domain
    :type bitReverse: bool
    :return: the RLWE ciphertext as the pair {b, a} of polynomials modulo Q
    :rtype: PolyVector
)pbdoc";

const char* schemelet_DecryptCoeff_docs = R"pbdoc(
    Decrypts an RLWE ciphertext {b, a} modulo Q (as produced by EncryptCoeff() or
    ConvertCKKSToRLWE()) with the CKKS secret key. The ciphertext is switched to the modulus
    of elementParams, b + a*s is computed, switched back to Q and rounded to the plaintext
    modulus p, and the message coefficients are read at a stride of N/(2*numSlots) (N = ring
    dimension) as signed integers in (-p/2, p/2].

    :param input: the RLWE ciphertext {b, a} modulo Q
    :type input: PolyVector
    :param Q: ciphertext modulus of the input
    :type Q: int
    :param p: plaintext modulus
    :type p: int
    :param privateKey: the CKKS secret key
    :type privateKey: PrivateKey
    :param elementParams: RNS parameters used for the decryption (see GetElementParams())
    :type elementParams: ParmType
    :param numSlots: number of slots used in the CKKS computation; determines the stride
                     between message coefficients
    :type numSlots: int
    :param length: number of values to return (0 means numSlots)
    :type length: int
    :param bitReverse: if true, the bit-reversal permutation applied at encryption is undone
                       (each half separately when numSlots is less than length)
    :type bitReverse: bool
    :return: the decrypted integer values
    :rtype: list[int]
)pbdoc";

const char* schemelet_ModSwitch_docs = R"pbdoc(
    Switches an RLWE ciphertext {b, a} from modulus Q2 to modulus Q1 in place by scaling both
    polynomials by Q1/Q2 with rounding.

    :param input: the ciphertext polynomials, currently modulo Q2; replaced by the polynomials
                  modulo Q1
    :type input: PolyVector
    :param Q1: the target modulus
    :type Q1: int
    :param Q2: the current modulus
    :type Q2: int
)pbdoc";

const char* schemelet_ConvertRLWEToCKKS_docs = R"pbdoc(
    Embeds an RLWE ciphertext {b, a} modulo Bigq into a CKKS ciphertext so that EvalFBT can
    process it. A CKKS ciphertext with the requested number of slots is created at the given
    level by encrypting zero under the public key (this supplies the ciphertext metadata),
    and its two elements are replaced by the RLWE polynomials scaled and switched from Bigq
    to the CKKS modulus at that level. The level is adjusted for the scaling technique in the
    same way as in GetElementParams().

    :param cc: the CKKS crypto context
    :type cc: CryptoContext
    :param coeffs: the RLWE ciphertext {b, a}
    :type coeffs: PolyVector
    :param pubKey: CKKS public key used for the encryption of zero
    :type pubKey: PublicKey
    :param Bigq: modulus of the RLWE ciphertext
    :type Bigq: int
    :param slots: number of slots recorded in the CKKS ciphertext
    :type slots: int
    :param level: level of the resulting CKKS ciphertext
    :type level: int
    :return: a CKKS ciphertext whose elements are the modulus-switched RLWE polynomials
    :rtype: Ciphertext
)pbdoc";

const char* schemelet_ConvertCKKSToRLWE_docs = R"pbdoc(
    Extracts an RLWE ciphertext {b, a} modulo Q from a CKKS ciphertext: both elements are
    brought to coefficient representation, CRT-interpolated to polynomials over the CKKS
    modulus and scaled and switched to Q with rounding.

    :param ctxt: the CKKS ciphertext (two elements)
    :type ctxt: Ciphertext
    :param Q: the target modulus of the RLWE ciphertext
    :type Q: int
    :return: the pair {b, a} of polynomials modulo Q
    :rtype: PolyVector
)pbdoc";

const char* schemelet_GetQPrime_docs = R"pbdoc(
    Computes the product of the first lvls+1 RNS moduli q_0, ..., q_lvls of the public key's
    element parameters.

    :param pubKey: a CKKS public key supplying the RNS moduli
    :type pubKey: PublicKey
    :param lvls: number of moduli after q_0 to include in the product
    :type lvls: int
    :return: q_0 * q_1 * ... * q_lvls
    :rtype: int
)pbdoc";

const char* fbt_SchemeSwitchingDataSerializer_docs = R"pbdoc(
    Serializer for all the data needed by CKKS <-> FHEW scheme switching: the CKKS crypto
    context with its evaluation keys, the public key, the FHEW crypto context with its keys
    and the raw ciphertext.
)pbdoc";

const char* fbt_SchemeSwitchingDataSerializer_init_docs = R"pbdoc(
    Constructor collecting the objects to serialize. None is not accepted for any argument.

    :param cryptoContext: the CKKS crypto context (must have the FHEW context and switching
                          key for scheme switching set)
    :type cryptoContext: CryptoContext
    :param publicKey: the CKKS public key
    :type publicKey: PublicKey
    :param RAWCiphertext: the ciphertext to serialize
    :type RAWCiphertext: Ciphertext
)pbdoc";

const char* fbt_SetDataDirectory_docs = R"pbdoc(
    Sets the directory the serialized files are written to or read from. A trailing slash is
    removed; an empty string is rejected.

    :param dir: the data directory
    :type dir: str
)pbdoc";

const char* fbt_Serialize_docs = R"pbdoc(
    Writes all the scheme-switching data (crypto contexts, keys and the ciphertext) to the
    data directory.
)pbdoc";

const char* fbt_SchemeSwitchingDataDeserializer_docs = R"pbdoc(
    Deserializer for the data written by SchemeSwitchingDataSerializer: reads the CKKS crypto
    context with its evaluation keys, the public key, the FHEW crypto context with its keys
    and the raw ciphertext, available through the getters after Deserialize().
)pbdoc";

const char* fbt_getCryptoContext_docs = R"pbdoc(
    Getter for the deserialized CKKS crypto context.

    :return: the crypto context
    :rtype: CryptoContext
)pbdoc";

const char* fbt_getPublicKey_docs = R"pbdoc(
    Getter for the deserialized public key.

    :return: the public key
    :rtype: PublicKey
)pbdoc";

const char* fbt_getRAWCiphertext_docs = R"pbdoc(
    Getter for the deserialized ciphertext.

    :return: the ciphertext
    :rtype: Ciphertext
)pbdoc";

const char* fbt_Deserialize_docs = R"pbdoc(
    Reads all the scheme-switching data (crypto contexts, keys and the ciphertext) from the
    data directory and populates the getters.
)pbdoc";

#endif  // __FBT_DOCS_H__
