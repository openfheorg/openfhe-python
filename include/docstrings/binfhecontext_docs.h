#ifndef BINFHECONTEXT_DOCSTRINGS_H
#define BINFHECONTEXT_DOCSTRINGS_H

// GenerateBinFHEContext
const char* binfhe_GenerateBinFHEContext_parset_docs = R"doc(
    Creates a crypto context using predefined parameter sets. Recommended for most users.

    Parameters:
    ----------
    set : BINFHE_PARAMSET
        The parameter set: TOY, MEDIUM, STD128, STD192, STD256.
    method : BINFHE_METHOD
        The bootstrapping method (DM or CGGI).

    Returns:
    --------
    CryptoContext
        The created crypto context.
)doc";

// KeyGen
const char* binfhe_KeyGen_docs = R"doc(
    Generates a secret key for the main LWE scheme.

    Returns:
    --------
    LWEPrivateKey
        The secret key.
)doc";

// BTKeyGen
const char* binfhe_BTKeyGen_docs = R"doc(
    Generates bootstrapping keys.

    Parameters:
    -----------
    sk : LWEPrivateKey
        The secret key.
)doc";

// Encrypt
const char* binfhe_Encrypt_docs = R"doc(
    Encrypts a bit using a secret key (symmetric key encryption).

    Parameters:
    -----------
    sk : LWEPrivateKey
        The secret key.
    m : int
        The plaintext.
    output : BINFHE_OUTPUT
        FRESH to generate a fresh ciphertext, BOOTSTRAPPED to generate a refreshed ciphertext (default).
    p : int
        Plaintext modulus (default 4).
    mod : int
        Encrypt according to mod instead of m_q if mod != 0.

    Returns:
    --------
    LWECiphertext
        The ciphertext.
)doc";

// Decrypt
const char* binfhe_Decrypt_docs = R"doc(
    Decrypts a ciphertext using a secret key.

    Parameters:
    -----------
    sk : LWEPrivateKey
        The secret key.
    ct : LWECiphertext
        The ciphertext.
    p : int
        Plaintext modulus (default 4).

    Returns:
    --------
    int
        The plaintext.
)doc";

// EvalBinGate
const char* binfhe_EvalBinGate_docs = R"doc(
    Evaluates a binary gate (calls bootstrapping as a subroutine).

    Parameters:
    -----------
    gate : BINGATE
        The gate; can be AND, OR, NAND, NOR, XOR, or XNOR.
    ct1 : LWECiphertext
        First ciphertext.
    ct2 : LWECiphertext
        Second ciphertext.

    Returns:
    --------
    LWECiphertext
        The resulting ciphertext.
)doc";

// EvalNOT
const char* binfhe_EvalNOT_docs = R"doc(
    Evaluates the NOT gate.

    Parameters:
    -----------
    ct : LWECiphertext
        The input ciphertext.

    Returns:
    --------
    LWECiphertext
        The resulting ciphertext.
)doc";


#endif // BINFHECONTEXT_DOCSTRINGS_H
