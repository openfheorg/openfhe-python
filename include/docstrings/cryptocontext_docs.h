#ifndef CRYPTOCONTEXT_DOCSTRINGS_H
#define CRYPTOCONTEXT_DOCSTRINGS_H

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
const char* cc_MakeStringPlaintext_docs = R"doc(
    MakeStringPlaintext constructs a StringEncoding in this context

    Parameters:
    ----------
        str (str): the string to convert

    Returns:
    ----------
        Plaintext: plaintext
)doc";

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
const char* cc_Decrypt_docs = R"doc(
    Decrypt a single ciphertext into the appropriate plaintext

    Parameters:
    ----------
        ciphertext (Ciphertext): ciphertext to decrypt
        privateKey (PrivateKey): decryption key

    Returns:
    ----------
        Plaintext: decrypted plaintext
)doc";

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
        ct (Ciphertext): ciphertext
        pt (Plaintext): plaintext

    Returns:
    ----------
        Ciphertext: new ciphertext for ct + pt
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
        ct (Ciphertext): ciphertext
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
        Ciphertext: the result of polynomial evaluation
)doc";

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




#endif //CRYPTOCONTEXT_DOCSTRINGS_H