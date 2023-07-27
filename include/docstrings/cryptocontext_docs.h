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
    Parameters:
    ----------
        level (int): the level to set the key generation to
)pbdoc";

const char* cc_GetKeyGenLevel_docs = R"doc(
    Get the level used for key generation

    Returns:
        int: The level used for key generation
)doc";

const char* cc_GetRingDimension_docs = R"doc(
    Get the ring dimension used for this context

    Returns:
        int: The ring dimension
)doc";

const char* cc_Enable_docs = R"doc(
    Enable a particular feature for use with this CryptoContext

    Parameters:
    ----------
        feature (PKESchemeFeature): the feature that should be enabled. 
            The list of available features is defined in the PKESchemeFeature enum.
    
)doc";

const char* cc_KeyGen_docs = R"doc(
    Generate a public and private key pair

    Returns:
        KeyPair: a public/secret key pair
)doc";

const char* cc_EvalMultKeyGen_docs = R"doc(
    EvalMultKeyGen creates a key that can be used with the OpenFHE EvalMult operator the new evaluation key is stored in cryptocontext.

    Parameters:
    ----------
        privateKey (PrivateKey): the private key
)doc";

const char* cc_EvalMultKeysGen_docs = R"doc(
    EvalMultsKeyGen creates a vector evalmult keys that can be used with the OpenFHE EvalMult operator 1st key (for s^2) is used for multiplication of ciphertexts of depth 1 2nd key (for s^3) is used for multiplication of ciphertexts of depth 2, etc. a vector of new evaluation keys is stored in crytpocontext

    Parameters:
    ----------
        privateKey (PrivateKey): the private key
)doc";

const char* cc_EvalRotateKeyGen_docs = R"doc(
    EvalRotateKeyGen generates evaluation keys for a list of indices

    Parameters:
    ----------
        privateKey (PrivateKey): private key
        indexList (list): list of (integers) indices
        publicKey (PublicKey): public key (used in NTRU schemes)
)doc";

// MakeStringPlaintext
// const char* cc_MakeStringPlaintext_docs = R"pbdoc(
//     MakeStringPlaintext constructs a StringEncoding in this context

//     Parameters
//     ----------
//     str : str
//         the string to convert

//     Returns
//     --------
//     Plaintext
//         plaintext
// )pbdoc";

const char* cc_MakeStringPlaintext_docs = R"pbdoc(
    MakeStringPlaintext constructs a StringEncoding in this context

    :param str: the string to convert
    :type str: str
    :return: plaintext
)pbdoc";

//MakePackedPlaintext
const char* cc_MakePackedPlaintext_docs = R"doc(
    MakePackedPlaintext constructs a PackedEncoding in this context

    Parameters:
    ----------
        value (list): the vector (of integers) to convert
        depth (int): is the multiplicative depth to encode the plaintext at
        level (int): is the level to encode the plaintext at

    Returns:
    ----------
        Plaintext: plaintext
)doc";

//inline Plaintext MakeCoefPackedPlaintext(const std::vector<int64_t> &value, size_t depth = 1, uint32_t level = 0) const
const char* cc_MakeCoefPackedPlaintext_docs = R"doc(
    MakeCoefPackedPlaintext constructs a CoefPackedEncoding in this context

    Parameters:
    ----------
        value (list): the vector (of integers) to convert
        depth (int): is the multiplicative depth to encode the plaintext at
        level (int): is the level to encode the plaintext at

    Returns:
    ----------
        Plaintext: plaintext
)doc";
//MakeCKKSPackedPlaintext(const std::vector<std::complex<double>> &value, size_t depth = 1, uint32_t level = 0, const std::shared_ptr<ParmType> params = nullptr, usint slots = 0)
const char* cc_MakeCKKSPackedPlaintextComplex_docs = R"doc(
    COMPLEX ARITHMETIC IS NOT AVAILABLE STARTING WITH OPENFHE 1.10.6, AND THIS METHOD BE DEPRECATED. USE THE REAL-NUMBER METHOD INSTEAD. MakeCKKSPackedPlaintext constructs a CKKSPackedEncoding in this context from a vector of complex numbers

    Parameters:
    ----------
        value (list): input vector (of complex numbers)
        depth (int): depth used to encode the vector
        level (int): level at each the vector will get encrypted
        params (openfhe.ParmType): parameters to be used for the ciphertext (Only accepting params = None in this version)
        slots (int): number of slots

    Returns:
    ----------
        Plaintext: plaintext
)doc";

//MakeCKKSPlaintextReal
const char* cc_MakeCKKSPlaintextReal_docs = R"doc(
    MakeCKKSPlaintext constructs a CKKSPackedEncoding in this context from a vector of real numbers

    Parameters:
    ----------
        value (list): input vector (of floats)
        depth (int): depth used to encode the vector
        level (int): level at each the vector will get encrypted
        params (openfhe.ParmType): parameters to be used for the ciphertext (Only accepting params = None in this version)
        slots (int): number of slots

    Returns:
    ----------
        Plaintext: plaintext
)doc";

//EvalRotate
const char* cc_EvalRotate_docs = R"doc(
    EvalRotate rotates a ciphertext by a given index

    Parameters:
    ----------
        ciphertext (Ciphertext): the ciphertext to rotate
        index (int): the index of the rotation. Positive indices correspond to left rotations and negative indices correspond to right rotations.

    Returns:
    ----------
        Ciphertext: the rotated ciphertext
)doc";

//EvalFastRotationPreCompute
const char* cc_EvalFastRotationPreCompute_docs = R"doc(
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

    Parameters:
    ----------
        ciphertext (Ciphertext): the input ciphertext on which to do the precomputation (digit decomposition)

    Returns:
    ----------
        Ciphertext: the precomputed ciphertext created using the digit decomposition
)doc";

//EvalFastRotation
const char* cc_EvalFastRotation_docs = R"doc(
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

    Parameters:
    ----------
        ciphertext (Ciphertext):  the input ciphertext to perform the automorphism on
        index (int): the index of the rotation. Positive indices correspond to left rotations and negative indices correspond to right rotations.
        m (int): is the cyclotomic order
        digits (Ciphertext): the precomputed ciphertext created by EvalFastRotationPrecompute using the digit decomposition at the precomputation step
)doc";

//EvalFastRotationExt
const char* cc_EvalFastRotationExt_docs = R"doc(
    Only supported for hybrid key switching. Performs fast (hoisted) rotation and returns the results in the extended CRT basis P*Q

    Parameters:
    ----------
        ciphertext (Ciphertext): input ciphertext
        index (int): the rotation index
        digits (Ciphertext): the precomputed ciphertext created by EvalFastRotationPrecompute
        addFirst (bool): if true, the the first element c0 is also computed (otherwise ignored)
    
    Returns:
    ----------
        Ciphertext: resulting ciphertext
)doc";
//phertext<Element> EvalAtIndex(ConstCiphertext<Element> ciphertext, int32_t index) const
const char* cc_EvalAtIndex_docs = R"doc(
    Moves i-th slot to slot 0

    Parameters:
    ----------
        ciphertext (Ciphertext): the ciphertext
        i (int): the index
    
    Returns:
    ----------
        Ciphertext: resulting ciphertext
)doc";
//void EvalAtIndexKeyGen(const PrivateKey<Element> privateKey, const std::vector<int32_t> &indexList, const PublicKey<Element> publicKey = nullptr)
const char* cc_EvalAtIndexKeyGen_docs = R"doc(
    EvalAtIndexKeyGen generates evaluation keys for a list of indices

    Parameters:
    ----------
        privateKey (PrivateKey): the private key
        indexList (list): list of indices
        publicKey (PublicKey): the public key (used in NTRU schemes)
    
    Returns:
    ----------
        None
)doc";

//Encrypt
const char* cc_Encrypt_docs = R"doc(
    Encrypt a plaintext using a given public key

    Parameters:
    ----------
        plaintext (Plaintext): the plaintext to encrypt
        publicKey (PublicKey): the public key

    Returns:
    ----------
        Ciphertext: ciphertext (or null on failure)
)doc";

//Decrypt
const char* cc_Decrypt_docs = R"pbdoc(
Decrypt a single ciphertext into the appropriate plaintext

Parameters
----------
ciphertext : openfhe.Ciphertext
    ciphertext to decrypt.
privateKey : PrivateKey
    decryption key.

Returns
-------
openfhe.Plaintext
    decrypted plaintext.
)pbdoc";

// const char* cc_Decrypt_docs = R"pbdoc(
//     Decrypt a single ciphertext into the appropriate plaintext

//     :param ciphertext: ciphertext to decrypt
//     :type ciphertext: Ciphertext
//     :param privateKey: decryption key
//     :type privateKey: PrivateKey
//     :return: decrypted plaintext
//     :rtype: Plaintext
// )pbdoc";

//EvalAdd
const char* cc_EvalAdd_docs = R"doc(
    Add two ciphertexts

    Parameters:
    ----------
        ct1 (Ciphertext): first ciphertext
        ct2 (Ciphertext): second ciphertext

    Returns:
    ----------
        Ciphertext: resulting ciphertext
)doc";

//EvalAdd(ciphertext,double)
const char* cc_EvalAddfloat_docs = R"doc(
    EvalAdd - OpenFHE EvalAdd method for a ciphertext and constant

    Parameters:
    ----------
        ct (Ciphertext): ciphertext
        constant (float): constant to add

    Returns:
    ----------
        Ciphertext: new ciphertext for ciphertext + constant
)doc";

//EvalAddInPlace
const char* cc_EvalAddInPlace_docs = R"doc(
    EvalAdd - OpenFHE EvalAddInPlace method for a pair of ciphertexts

    Parameters:
    ----------
        ct1 (Ciphertext): Input/output ciphertext
        ct2 (Ciphertext): Input cipherext

    Returns:
    ----------
        ct1 contains ct1 + ct2
)doc";

//EvalAddInPlace(ciphertext,plaintext)
const char* cc_EvalAddInPlacePlaintext_docs = R"doc(
    EvalAdd - OpenFHE EvalAddInPlace method for a ciphertext and plaintext

    Parameters:
    ----------
        ct (Ciphertext): Input/output ciphertext
        pt (Plaintext): Input plaintext

    Returns:
    ----------
        ct contains ct + pt
)doc";

//EvalAddMutable
const char* cc_EvalAddMutable_docs = R"doc(
    EvalAdd - OpenFHE EvalAddMutable method for a pair of ciphertexts. This is a mutable version - input ciphertexts may get automatically rescaled, or level-reduced.

    Parameters:
    ----------
        ct1 (Ciphertext): first ciphertext
        ct2 (Ciphertext): second ciphertext

    Returns:
    ----------
        Ciphertext: new ciphertext for ct1 + ct2
)doc";

//EvalAddMutable(ciphertext,plaintext)
const char* cc_EvalAddMutablePlaintext_docs = R"doc(
    EvalAdd - OpenFHE EvalAddMutable method for a ciphertext and plaintext. This is a mutable version - input ciphertexts may get automatically rescaled, or level-reduced.

    Parameters:
    ----------
        ciphertext (Ciphertext): ciphertext
        plaintext (Plaintext): plaintext

    Returns:
    ----------
        Ciphertext: new ciphertext for ciphertext + plaintext
)doc";

//EvalAddMutableInPlace
const char* cc_EvalAddMutableInPlace_docs = R"doc(
    EvalAdd - Inplace version of EvalAddMutable

    Parameters:
    ----------
        ct1 (Ciphertext): Input/output ciphertext
        ct2 (Ciphertext): Input cipherext

    Returns:
    ----------
        ct1 contains ct1 + ct2
)doc";

//EvalSub
const char* cc_EvalSub_docs = R"doc(
    EvalSub - OpenFHE EvalSub method for a pair of ciphertexts

    Parameters:
    ----------
        ct1 (Ciphertext): first ciphertext
        ct2 (Ciphertext): second ciphertext

    Returns:
    ----------
        Ciphertext: new ciphertext for ct1 - ct2
)doc";

//EvalSub(ciphertext,double)
const char* cc_EvalSubfloat_docs = R"doc(
    EvalSub - OpenFHE EvalSub method for a ciphertext and constant

    Parameters:
    ----------
        ciphertext (Ciphertext): ciphertext
        constant (float): constant to subtract

    Returns:
    ----------
        Ciphertext: new ciphertext for ciphertext - constant
)doc";

//EvalSub(ciphertext,plaintext)
const char* cc_EvalSubPlaintext_docs = R"doc(
    EvalSub - OpenFHE EvalSub method for a ciphertext and plaintext

    Parameters:
    ----------
        ciphertext (Ciphertext): ciphertext
        plaintext (Plaintext): plaintext

    Returns:
    ----------
        Ciphertext: new ciphertext for ciphertext - plaintext
)doc";

//EvalSubInPlace
const char* cc_EvalSubInPlace_docs = R"doc(
    Inplace version of EvalSub for a pair of ciphertexts

    Parameters:
    ----------
        ct1 (Ciphertext): Input/output ciphertext
        ct2 (Ciphertext): Input cipherext

    Returns:
    ----------
        ct1 contains ct1 - ct2
)doc";

//EvalSubInPlace(ciphertext,double)
const char* cc_EvalSubInPlacefloat_docs = R"doc(
    Inplace version of EvalSub for a ciphertext and constant

    Parameters:
    ----------
        ciphertext (Ciphertext): Input/output ciphertext
        constant (float): constant to subtract

    Returns:
    ----------
        ciphertext contains ciphertext - constant
)doc";

//EvalSubMutable
const char* cc_EvalSubMutable_docs = R"doc(
    EvalSub - OpenFHE EvalSubMutable method for a pair of ciphertexts. This is a mutable version - input ciphertexts may get automatically rescaled, or level-reduced.

    Parameters:
    ----------
        ct1 (Ciphertext): first ciphertext
        ct2 (Ciphertext): second ciphertext

    Returns:
    ----------
        Ciphertext: new ciphertext for ct1 - ct2
)doc";

const char* cc_EvalSubMutableInPlace_docs = R"doc(
    EvalSub - Inplace variant for EvalSubMutable
)doc";
//EvalSubMutable(ciphertext,plaintext)
const char* cc_EvalSubMutablePlaintext_docs = R"doc(
    EvalSub - OpenFHE EvalSubMutable method for a ciphertext and plaintext. This is a mutable version - input ciphertexts may get automatically rescaled, or level-reduced.

    Parameters:
    ----------
        ciphertext (Ciphertext): 
        plaintext (Plaintext): 

    Returns:
    ----------
        Ciphertext: new ciphertext for ciphertext - plaintext
)doc";

//EvalMult
const char* cc_EvalMult_docs = R"doc(
    EvalMult - OpenFHE EvalMult method for a pair of ciphertexts - with key switching

    Parameters:
    ----------
        ct1 (Ciphertext): first ciphertext
        ct2 (Ciphertext): second ciphertext

    Returns:
    ----------
        Ciphertext: new ciphertext for ct1 * ct2
)doc";

//EvalMult(ciphertext,double)
const char* cc_EvalMultfloat_docs = R"doc(
    EvalMult - OpenFHE EvalMult method for a ciphertext and constant

    Parameters:
    ----------
        ciphertext (Ciphertext): the ciphertext
        constant (float): constant to multiply

    Returns:
    ----------
        Ciphertext: new ciphertext for ciphertext * constant
)doc";

//EvalMult(ciphertext,plaintext)
const char* cc_EvalMultPlaintext_docs = R"doc(
    EvalMult - OpenFHE EvalMult method for a ciphertext and plaintext

    Parameters:
    ----------
        ciphertext (Ciphertext): the ciphertext
        plaintext (Plaintext): the plaintext

    Returns:
    ----------
        Ciphertext: new ciphertext for ciphertext * plaintext
)doc";

//EvalMultMutable
const char* cc_EvalMultMutable_docs = R"doc(
    EvalMult - OpenFHE EvalMultMutable method for a pair of ciphertexts. This is a mutable version - input ciphertexts may get automatically rescaled, or level-reduced.

    Parameters:
    ----------
        ct1 (Ciphertext): first ciphertext
        ct2 (Ciphertext): second ciphertext

    Returns:
    ----------
        Ciphertext: new ciphertext for ct1 * ct2
)doc";

//EvalMultMutable(ciphertext,plaintext)
const char* cc_EvalMultMutablePlaintext_docs = R"doc(
    EvalMult - OpenFHE EvalMultMutable method for a ciphertext and plaintext. This is a mutable version - input ciphertexts may get automatically rescaled, or level-reduced.

    Parameters:
    ----------
        ciphertext (Ciphertext): the ciphertext
        plaintext (Plaintext): the plaintext

    Returns:
    ----------
        Ciphertext: new ciphertext for ciphertext * plaintext
)doc";

//EvalMultMutableInPlace
const char* cc_EvalMultMutableInPlace_docs = R"doc(
    EvalMult - OpenFHE EvalMult method for a pair of ciphertexts - with key switching This is a mutable version - input ciphertexts may get automatically rescaled, or level-reduced.

    Parameters:
    ----------
        ct1 (Ciphertext): Input/output ciphertext
        ct2 (Ciphertext): Input cipherext

    Returns:
    ----------
        ct1 contains ct1 * ct2
)doc";

//EvalSquare
const char* cc_EvalSquare_docs = R"doc(
    EvalSquare - OpenFHE EvalSquare method for a ciphertext

    Parameters:
    ----------
        ct (Ciphertext): the ciphertext to square

    Returns:
    ----------
        Ciphertext: new ciphertext for ct^2 = ct * ct
)doc";

//EvalSquareMutable
const char* cc_EvalSquareMutable_docs = R"doc(
    EvalSquare - OpenFHE EvalSquareMutable method for a ciphertext. This is a mutable version - input ciphertexts may get automatically rescaled, or level-reduced.

    Parameters:
    ----------
        ct (Ciphertext): the ciphertext to square

    Returns:
    ----------
        Ciphertext: new ciphertext for ct^2 = ct * ct
)doc";

//EvalSquareInPlace
const char* cc_EvalSquareInPlace_docs = R"doc(
    EvalSquare - OpenFHE EvalSquare method for a ciphertext. This is a mutable version - input ciphertexts may get automatically rescaled, or level-reduced.

    Parameters:
    ----------
        ct (Ciphertext): Input/output ciphertext

    Returns:
    ----------
        ct contains ct^2 = ct * ct
)doc";

//EvalMultNoRelin
const char* cc_EvalMultNoRelin_docs = R"doc(
    EvalMultNoRelin - OpenFHE EvalMult method for a pair of ciphertexts - no key switching (relinearization)

    Parameters:
    ----------
        ct1 (Ciphertext): first ciphertext
        ct2 (Ciphertext): second ciphertext

    Returns:
    ----------
        Ciphertext: new ciphertext for ct1 * ct2
)doc";

//Relinearize
const char* cc_Relinearize_docs = R"doc(
    Function for relinearization of a ciphertext.

    Parameters:
    ----------
        ct (Ciphertext): input ciphertext

    Returns:
    ----------
        Ciphertext: relienarized ciphertext
)doc";

//RelinearizeInPlace
const char* cc_RelinearizeInPlace_docs = R"doc(
    Function for inplace relinearization of a ciphertext.

    Parameters:
    ----------
        ct (Ciphertext): input/output ciphertext

    Returns:
    ----------
        ct contains relienarized ciphertext
)doc";

//EvalMultAndRelinearize
const char* cc_EvalMultAndRelinearize_docs = R"doc(
    Function for evaluating multiplication on ciphertext followed by relinearization operation. Currently it assumes that the input arguments have total depth smaller than the supported depth. Otherwise, it throws an error

    Parameters:
    ----------
        ct1 (Ciphertext): first input ciphertext
        ct2 (Ciphertext): second input ciphertext

    Returns:
    ----------
        Ciphertext: new ciphertext
)doc";

//EvalNegate
const char* cc_EvalNegate_docs = R"doc(
    EvalSub - OpenFHE Negate method for a ciphertext

    Parameters:
    ----------
        ct (Ciphertext): input ciphertext

    Returns:
    ----------
        Ciphertext: new ciphertext -ct
)doc";

//EvalNegateInPlace
const char* cc_EvalNegateInPlace_docs = R"doc(
    EvalSub - Inplace OpenFHE Negate method for a ciphertext

    Parameters:
    ----------
        ct (Ciphertext): input/output ciphertext

    Returns:
    ----------
        ct contains -ct
)doc";

//EvalLogistic((ConstCiphertext<Element> ciphertext, double a, double b, uint32_t degree)
// const char* cc_EvalLogistic_docs = R"doc(
//     Evaluate approximate logistic function 1/(1 + exp(-x)) on a ciphertext using the Chebyshev approximation.

//     Parameters:
//     ----------
//         ciphertext (Ciphertext): input ciphertext
//         a (float): lower bound of argument for which the coefficients were found
//         b (float): upper bound of argument for which the coefficients were found
//         degree (int): Desired degree of approximation

//     Returns:
//     ----------
//         Ciphertext: the result of polynomial evaluation
// )doc";

//EvalChebyshevSeries(ConstCiphertext<Element> ciphertext, const std::vector<double> &coefficients, double a, double b)
const char* cc_EvalChebyshevSeries_docs = R"doc(
    Method for evaluating Chebyshev polynomial interpolation; first the range [a,b] is mapped to [-1,1] using linear transformation 1 + 2 (x-a)/(b-a) If the degree of the polynomial is less than 5, use EvalChebyshevSeriesLinear, otherwise, use EvalChebyshevSeriesPS.

    Parameters:
    ----------
        ciphertext (Ciphertext): input ciphertext
        coefficients (list): is the list of coefficients in Chebyshev expansion
        a (float): lower bound of argument for which the coefficients were found
        b (float): upper bound of argument for which the coefficients were found

    Returns:
    ----------
        Ciphertext: the result of polynomial evaluation
)doc";

//EvalChebyshevSeriesLinear(ConstCiphertext<Element> ciphertext, const std::vector<double> &coefficients, double a, double b)
const char* cc_EvalChebyshevSeriesLinear_docs = R"doc(
    Evaluate Chebyshev polynomial of degree less than 5.

    Parameters:
    ----------
        ciphertext (Ciphertext): input ciphertext
        coefficients (list): is the list of coefficients in Chebyshev expansion
        a (float): lower bound of argument for which the coefficients were found
        b (float): upper bound of argument for which the coefficients were found

    Returns:
    ----------
        Ciphertext: the result of polynomial evaluation
)doc";

//EvalChebyshevSeriesPS(ConstCiphertext<Element> ciphertext, const std::vector<double> &coefficients, double a, double b)
const char* cc_EvalChebyshevSeriesPS_docs = R"doc(
    Evaluate Chebyshev polynomial of degree greater or equal to 5.

    Parameters:
    ----------
        ciphertext (Ciphertext): input ciphertext
        coefficients (list): is the list of coefficients in Chebyshev expansion
        a (float): lower bound of argument for which the coefficients were found
        b (float): upper bound of argument for which the coefficients were found

    Returns:
    ----------
        Ciphertext: the result of polynomial evaluation
)doc";

//EvalChebyshevFunction(std::function<double(double)> func, ConstCiphertext<Element> ciphertext, double a, double b, uint32_t degree)
const char* cc_EvalChebyshevFunction_docs = R"doc(
    Method for calculating Chebyshev evaluation on a ciphertext for a smooth input function over the range [a,b].

    Parameters:
    ----------
        func (function): is the function to be approximated
        ciphertext (Ciphertext): input ciphertext
        a (float): lower bound of argument for which the coefficients were found
        b (float): upper bound of argument for which the coefficients were found
        degree (int): Desired degree of approximation

    Returns:
    ----------
        Ciphertext: the coefficients of the Chebyshev approximation.
)doc";

//EvanSin(ciphertext,double,double,degree)
const char* cc_EvalSin_docs = R"doc(
    Evaluate approximate sine function on a ciphertext using the Chebyshev approximation.

    Parameters:
    ----------
        ciphertext (Ciphertext): input ciphertext
        a (float): lower bound of argument for which the coefficients were found
        b (float): upper bound of argument for which the coefficients were found
        degree (int): Desired degree of approximation

    Returns:
    ----------
        Ciphertext: the result of polynomial evaluation.
)doc";

//EvalCos(ciphertext,double,double,degree)
const char* cc_EvalCos_docs = R"doc(
    Evaluate approximate cosine function on a ciphertext using the Chebyshev approximation.

    Parameters:
    ----------
        ciphertext (Ciphertext): input ciphertext
        a (float): lower bound of argument for which the coefficients were found
        b (float): upper bound of argument for which the coefficients were found
        degree (int): Desired degree of approximation

    Returns:
    ----------
        Ciphertext: the result of polynomial evaluation.
)doc";

//EvalLogistic(ciphertext,double,double,degree)
const char* cc_EvalLogistic_docs = R"doc(
    Evaluate approximate logistic function 1/(1 + exp(-x)) on a ciphertext using the Chebyshev approximation.

    Parameters:
    ----------
        ciphertext (Ciphertext): input ciphertext
        a (float): lower bound of argument for which the coefficients were found
        b (float): upper bound of argument for which the coefficients were found
        degree (int): Desired degree of approximation

    Returns:
    ----------
        Ciphertext: the result of polynomial evaluation.
)doc";

//EvalDivide(ciphertext,double,double,degree)
const char* cc_EvalDivide_docs = R"doc(
    Evaluate approximate division function 1/x where x >= 1 on a ciphertext using the Chebyshev approximation.

    Parameters:
    ----------
        ciphertext (Ciphertext): input ciphertext
        a (float): lower bound of argument for which the coefficients were found
        b (float): upper bound of argument for which the coefficients were found
        degree (int): Desired degree of approximation

    Returns:
    ----------
        Ciphertext: the result of polynomial evaluation.
)doc";

//EvalSumKeyGen(const PrivateKey<Element> privateKey, const PublicKey<Element> publicKey = nullptr)
const char* cc_EvalSumKeyGen_docs = R"doc(
    EvalSumKeyGen generates the key map to be used by evalsum

    Parameters:
    ----------
        privateKey (PrivateKey): private key
        publicKey (PublicKey): public key (used in NTRU schemes)
    
    Returns:
    ----------
        None
)doc";

//EvalSumRowsKeyGen(const PrivateKey<Element> privateKey, const PublicKey<Element> publicKey = nullptr, usint rowSize = 0, usint subringDim = 0)
const char* cc_EvalSumRowsKeyGen_docs = R"doc(
    EvalSumRowsKeyGen generates the key map to be used by EvalSumRows

    Parameters:
    ----------
        privateKey (PrivateKey): private key
        publicKey (PublicKey): public key (used in NTRU schemes)
        rowSize (int): number of rows
        subringDim (int): dimension of the subring
    
    Returns:
    ----------
        dict: Evaluation key map, where the keys being integer indexes and values being EvalKey objects
)doc";

//EvalSumColsKeyGen(const PrivateKey<Element> privateKey, const PublicKey<Element> publicKey = nullptr)
const char* cc_EvalSumColsKeyGen_docs = R"doc(
    EvalSumColsKeyGen generates the key map to be used by EvalSumCols

    Parameters:
    ----------
        privateKey (PrivateKey): private key
        publicKey (PublicKey): public key (used in NTRU schemes)
    
    Returns:
    ----------
        dict: Evaluation key map, where the keys being integer indexes and values being EvalKey objects
)doc";

//Ciphertext<Element> EvalSumRows(ConstCiphertext<Element> ciphertext, usint rowSize, const std::map<usint, EvalKey<Element>> &evalSumKeyMap, usint subringDim = 0)
const char* cc_EvalSumRows_docs = R"doc(

    Parameters:
    ----------
        ciphertext (Ciphertext): input ciphertext
        rowSize (int): number of rows
        evalSumKeyMap (dict): evaluation key map, where the keys being integer indexes and values being EvalKey objects
        subringDim (int): dimension of the subring
    
    Returns:
    ----------
        Ciphertext: resulting ciphertext
)doc";

//Ciphertext<Element> EvalSumCols(ConstCiphertext<Element> ciphertext, usint rowSize, const std::map<usint, EvalKey<Element>> &evalSumKeyMap
const char* cc_EvalSumCols_docs = R"doc(

    Parameters:
    ----------
        ciphertext (Ciphertext): input ciphertext
        rowSize (int): number of rows
        evalSumKeyMap (dict): evaluation key map, where the keys being integer indexes and values being EvalKey objects
    
    Returns:
    ----------
        Ciphertext: resulting ciphertext
)doc";
//EvalInnerProduct(ciphertext,ciphertext,batchSize)
const char* cc_EvalInnerProduct_docs = R"doc(
    Evaluates inner product in batched encoding

    Parameters:
    ----------
        ciphertext1 (Ciphertext): first vector
        ciphertext2 (Ciphertext): second vector
        batchSize (int): size of the batch to be summed up

    Returns:
    ----------
        Ciphertext: resulting ciphertext
)doc";

//EvalInnerProduct(cipher,plain,batchsize)
const char* cc_EvalInnerProductPlaintext_docs = R"doc(
    Evaluates inner product in batched encoding

    Parameters:
    ----------
        ciphertext (Ciphertext): first vector - ciphertext
        plaintext (Plaintext): second vector - plaintext
        batchSize (int): size of the batch to be summed up

    Returns:
    ----------
        Ciphertext: resulting ciphertext
)doc";

//Ciphertext<Element> EvalMerge(const std::vector<Ciphertext<Element>> &ciphertextVec) const
const char* cc_EvalMerge_docs = R"doc(
    Merges multiple ciphertexts with encrypted results in slot 0 into a single ciphertext The slot assignment is done based on the order of ciphertexts in the vector

    Parameters:
    ----------
        ciphertextVec (list): vector of ciphertexts to be merged.

    Returns:
    ----------
        Ciphertext: resulting ciphertext
)doc";

//inline virtual Ciphertext<Element> EvalPoly(ConstCiphertext<Element> ciphertext, const std::vector<double> &coefficients) const
const char* cc_EvalPoly_docs = R"doc(
    Method for polynomial evaluation for polynomials represented as power series.

    Parameters:
    ----------
        ciphertext (Ciphertext): input ciphertext
        coefficients (list): is the vector of coefficients in the polynomial; the size of the vector is the degree of the polynomial + 1

    Returns:
    ----------
        Ciphertext: the result of polynomial evaluation.
)doc";

//inline Ciphertext<Element> EvalPolyLinear(ConstCiphertext<Element> ciphertext, const std::vector<double> &coefficients)
const char* cc_EvalPolyLinear_docs = R"doc(
    Method for polynomial evaluation for polynomials represented in the power series. This uses EvalPolyLinear, which uses a binary tree computation of the polynomial powers.

    Parameters:
    ----------
        ciphertext (Ciphertext): input ciphertext
        coefficients (list): is the vector of coefficients in the polynomial; the size of the vector is the degree of the polynomial

    Returns:
    ----------
        Ciphertext: the result of polynomial evaluation.
)doc";

//inline Ciphertext<Element> EvalPolyPS(ConstCiphertext<Element> ciphertext, const std::vector<double> &coefficients) const
const char* cc_EvalPolyPS_docs = R"doc(

    Parameters:
    ----------
        ciphertext (Ciphertext): input ciphertext
        coefficients (list): is the vector of coefficients in the polynomial; the size of the vector is the degree of the polynomial

    Returns:
    ----------
        Ciphertext: the result of polynomial evaluation.
)doc";

//Rescale(cipher)
const char* cc_Rescale_docs = R"doc(
    Rescale - An alias for OpenFHE ModReduce method. This is because ModReduce is called Rescale in CKKS.

    Parameters:
    ----------
        ciphertext (Ciphertext): ciphertext

    Returns:
    ----------
        Ciphertext: mod reduced ciphertext
)doc";

//void EvalBootstrapSetup(std::vector<uint32_t> levelBudget = {5, 4}, std::vector<uint32_t> dim1 = {0, 0}, uint32_t slots = 0, uint32_t correctionFactor = 0)
const char* cc_EvalBootstrapSetup_docs = R"doc(
    Bootstrap functionality: There are three methods that have to be called in this specific order:

    1. EvalBootstrapSetup: computes and encodes the coefficients for encoding and decoding and stores the necessary parameters

    2. EvalBootstrapKeyGen: computes and stores the keys for rotations and conjugation

    3. EvalBootstrap: refreshes the given ciphertext Sets all parameters for the linear method for the FFT-like method

    Parameters:
    ----------
        levelBudget (list):  vector of budgets for the amount of levels in encoding and decoding
        dim1 (list): vector of inner dimension in the baby-step giant-step routine for encoding and decodingl
        slots (int): number of slots to be bootstraped
        correctionFactor (int): alue to rescale message by to improve precision. If set to 0, we use the default logic. This value is only used when get_native_int()=64

    Returns:
    ----------
        None
)doc";

//void EvalBootstrapKeyGen(const PrivateKey<Element> privateKey, uint32_t slots)
const char* cc_EvalBootstrapKeyGen_docs = R"doc(
    Generates all automorphism keys for EvalBT. EvalBootstrapKeyGen uses the baby-step/giant-step strategy.

    Parameters:
    ----------
        privateKey (PrivateKey): private key.
        slots (int): number of slots to support permutations on.

    Returns:
    ----------
        None
)doc";

//Ciphertext<Element> EvalBootstrap(ConstCiphertext<Element> ciphertext, uint32_t numIterations = 1, uint32_t precision = 0)
const char* cc_EvalBootstrap_docs = R"doc(
    Defines the bootstrapping evaluation of ciphertext using either the FFT-like method or the linear method

    Parameters:
    ----------
        ciphertext (Ciphertext): the input ciphertext
        numIterations (int): number of iterations to run iterative bootstrapping (Meta-BTS). Increasing the iterations increases the precision of bootstrapping
        precision (int): precision of initial bootstrapping algorithm. This value is determined by the user experimentally by first running EvalBootstrap with numIterations = 1 and precision = 0 (unused).

    Returns:
    ----------
        Ciphertext: the refreshed ciphertext
)doc";

//inline std::shared_ptr<std::map<usint, EvalKey<Element>>> EvalAutomorphismKeyGen(const PrivateKey<Element> privateKey, const std::vector<usint> &indexLis
const char* cc_EvalAutomorphismKeyGen_docs = R"doc(
    Generate automophism keys for a given private key; Uses the private key for encryption

    Parameters:
    ----------
        privateKey (PrivateKey): private key.
        indexList (list): list of automorphism indices to be computed.

    Returns:
    ----------
        dict: returns the evaluation key
)doc";

//inline std::shared_ptr<std::map<usint, EvalKey<Element>>> EvalAutomorphismKeyGen(const PublicKey<Element> publicKey, const PrivateKey<Element> privateKey, const std::vector<usint> &indexList) const
const char* cc_EvalAutomorphismKeyGenPublic_docs = R"doc(
    Generate automophism keys for a given private key.

    Parameters:
    ----------
        publicKey (PublicKey): original public key.
        privateKey (PrivateKey): original private key.
        indexList (list): list of automorphism indices to be computed.

    Returns:
    ----------
        dict: returns the evaluation keys; index 0 of the vector corresponds to plaintext index 2, index 1 to plaintex index 3, etc.
)doc";

//inline usint FindAutomorphismIndex(const usint idx) const
const char* cc_FindAutomorphismIndex_docs = R"doc(
    Find the automorphism index for a given plaintext index

    Parameters:
    ----------
        idx (int): plaintext index

    Returns:
    ----------
        int: automorphism index
)doc";

//inline std::vector<usint> FindAutomorphismIndices(const std::vector<usint> idxList) const
const char* cc_FindAutomorphismIndices_docs = R"doc(
    Find the automorphism indices for a given list of plaintext indices

    Parameters:
    ----------
        idxList (list): list of plaintext indices

    Returns:
    ----------
        list: list of automorphism indices
)doc";

//ClearEvalMultKeys()
const char* cc_ClearEvalMultKeys_docs = R"doc(
    ClearEvalMultKeys - flush EvalMultKey cache
)doc";

//ClearEvalAutomorphismKeys()
const char* cc_ClearEvalAutomorphismKeys_docs = R"doc(
    ClearEvalAutomorphismKeys - flush EvalAutomorphismKey cache
)doc";

//static inline bool SerializeEvalAutomorphismKey(std::ostream &ser, const ST &sertype, std::string id = "")
const char* cc_SerializeEvalAutomorphismKey_docs = R"doc(
    SerializeEvalAutomorphismKey for a single EvalAuto key or all of the EvalAuto keys

    Parameters:
    ----------
        filename (str): output file
        sertype (SERJSON, SERBINARY): serialization type
        id (str): key to serialize; empty string means all keys

    Returns:
    ----------
        bool: true on success
)doc";

//SerializeEvalMultKey(filename,sertype,id)
const char* cc_SerializeEvalMultKey_docs = R"doc(
    SerializeEvalMultKey for a single EvalMult key or all of the EvalMult keys

    Parameters:
    ----------
        filename (str): output file
        sertype (SERJSON, SERBINARY): type of serialization
        id (str): for key to serialize - if empty string, serialize them all

    Returns:
    ----------
        bool: true on success
)doc";

//DeserializeEvalAutomorphismKey(filename,sertype)
const char* cc_DeserializeEvalAutomorphismKey_docs = R"doc(
    DeserializeEvalAutomorphismKey deserialize all keys in the serialization deserialized keys silently replace any existing matching keys deserialization will create CryptoContext if necessary

    Parameters:
    ----------
        filename (str): path for the file to deserialize from
        sertype (SERJSON, SERBINARY): type of serialization

    Returns:
    ----------
        bool: true on success
)doc";

//DeserializeEvalMultKey(filename,sertype)
const char* cc_DeserializeEvalMultKey_docs = R"doc(
    DeserializeEvalMultKey deserialize all keys in the serialization deserialized keys silently replace any existing matching keys deserialization will create CryptoContext if necessary

    Parameters:
    ----------
        filename (str): path for the file to deserialize from
        sertype (SERJSON, SERBINARY): type of serialization

    Returns:
    ----------
        bool: true on success
)doc";


#endif //CRYPTOCONTEXT_DOCSTRINGS_H
