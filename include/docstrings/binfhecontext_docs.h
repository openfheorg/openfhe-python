#ifndef BINFHECONTEXT_DOCSTRINGS_H
#define BINFHECONTEXT_DOCSTRINGS_H

// BinFHEContext Docs:
const char* binfhe_GenerateBinFHEContext_parset_docs = R"doc(
    Creates a crypto context using predefined parameters sets. Recommended for most users.

    Parameters:
    ----------
        set (BINFHE_PARAMSET): the parameter set: TOY, MEDIUM, STD128, STD192, STD256.
        method (BINFHE_METHOD):  the bootstrapping method (DM or CGGI).

    Returns:
    --------
        create the crypto context
)doc";

const char* binfhe_KeyGen_docs = R"doc(
    Generates a secret key for the main LWE scheme

    Returns:
    --------
        LWEPrivateKey: the secret key
)doc";

const char* binfhe_BTKeyGen_docs = R"doc(
    Generates bootstrapping keys

    Psrameters:
    -----------
        sk (LWEPrivateKey): secret key
)doc";

const char* binfhe_Encrypt_docs = R"doc(
    Encrypts a bit using a secret key (symmetric key encryption)

    Parameters:
    -----------
        sk (LWEPrivateKey): the secret key
        m (int): the plaintext
        output (BINFHE_OUTPUT):  FRESH to generate fresh ciphertext, BOOTSTRAPPED to generate a refreshed ciphertext (default)
        p (int): plaintext modulus (default 4)
        mod (int): Encrypt according to mod instead of m_q if mod != 0

    Returns:
    --------
        LWECiphertext: the ciphertext
)doc";

const char* binfhe_Decrypt_docs = R"doc(
    Encrypt according to mod instead of m_q if mod != 0

    Parameters:
    -----------
        sk (LWEPrivateKey): the secret key
        ct (LWECiphertext): the ciphertext
        p (int): plaintext modulus (default 4)

    Returns:
    --------
       int: the plaintext
)doc";

const char* binfhe_EvalBinGate_docs = R"doc(
    Evaluates a binary gate (calls bootstrapping as a subroutine)

    Parameters:
    -----------
        gate (BINGATE): the gate; can be AND, OR, NAND, NOR, XOR, or XNOR
        ct1 (LWECiphertext): first ciphertext
        ct2 (LWECiphertext): second ciphertext

    Returns:
    --------
        LWECiphertext: the resulting ciphertext
)doc";

const char* binfhe_EvalNOT_docs = R"doc(
    Evaluates NOT gate

    Parameters:
    -----------
        ct (LWECiphertext): the input ciphertext

    Returns:
    --------
        LWECiphertext: the resulting ciphertext
)doc";


#endif // BINFHECONTEXT_DOCSTRINGS_H
