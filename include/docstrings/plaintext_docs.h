#ifndef PLAINTEXT_DOCSTRINGS_H
#define PLAINTEXT_DOCSTRINGS_H

const char* ptx_GetScalingFactor_docs = R"doc(
    Get the scaling factor of the plaintext for CKKS-based plaintexts.

    Returns
    -------
        float: The scaling factor of the plaintext.
)doc";

const char* ptx_SetScalingFactor_docs = R"doc(
    Set the scaling factor of the plaintext for CKKS-based plaintexts.

    Parameters
    ----------
        sf (float): The scaling factor to set.
)doc";

const char* ptx_GetLength_docs = R"doc(
    Get method to return the length of the plaintext.

    Returns
    -------
        int: The length of the plaintext in terms of the number of bits.
)doc";

const char* ptx_GetSchemeID_docs = R"doc(
    Get the encryption technique of the plaintext for BFV-based plaintexts.

    Returns
    -------
        SCHEME: The scheme ID of the plaintext.
)doc";

const char* ptx_SetLength_docs = R"doc(
    resize the plaintext; only works for plaintexts that support a resizable vector (coefpacked)

    Parameters
    ----------
        newSize (int): -
)doc";

const char* ptx_IsEncoded_docs = R"doc(
    Check if the plaintext is encoded.

    Returns
    -------
        bool: True if the plaintext is encoded, False otherwise.
)doc";

const char* ptx_GetLogPrecision_docs = R"doc(
    Get the log of the plaintext precision.

    Returns
    -------
        float: The log of the plaintext precision.
)doc";

const char* ptx_Encode_docs = R"doc(
    Encode the plaintext into a polynomial

    Returns
    -------
        None
)doc";

const char* ptx_Decode_docs = R"doc(
    Decode the polynomial into a plaintext

    Returns
    -------
        None
)doc";

const char* ptx_GetCKKSPackedValue_docs = R"doc(
    Get the packed value of the plaintext for CKKS-based plaintexts.

    Returns
    -------
        List[complex]: The packed value of the plaintext.
)doc";

#endif // PLAINTEXT_DOCSTRINGS_H
