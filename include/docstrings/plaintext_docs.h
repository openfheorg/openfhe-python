#ifndef PLAINTEXT_DOCSTRINGS_H
#define PLAINTEXT_DOCSTRINGS_H

// GetScalingFactor
const char* ptx_GetScalingFactor_docs = R"doc(
    Get the scaling factor of the plaintext for CKKS-based plaintexts.

    :return: The scaling factor of the plaintext.
    :rtype: float
)doc";

// SetScalingFactor
const char* ptx_SetScalingFactor_docs = R"pbdoc(
    Set the scaling factor of the plaintext for CKKS-based plaintexts.

    :param sf: The scaling factor to set.
    :type sf: float
)pbdoc";

// GetLength
const char* ptx_GetLength_docs = R"pbdoc(
    Get method to return the length of the plaintext.

    :return: The length of the plaintext in terms of the number of bits.
    :rtype: int
)pbdoc";

// GetSchemeID
const char* ptx_GetSchemeID_docs = R"pbdoc(
    Get the encryption technique of the plaintext for BFV-based plaintexts.

    :return: The scheme ID of the plaintext.
    :rtype: SCHEME
)pbdoc";

// SetLength
const char* ptx_SetLength_docs = R"pbdoc(
    Resize the plaintext; only works for plaintexts that support a resizable vector (coefpacked).
    
    :param newSize: The new size of the plaintext.
    :type newSize: int
)pbdoc";

// IsEncoded
const char* ptx_IsEncoded_docs = R"pbdoc(
    Check if the plaintext is encoded.

    :return: True if the plaintext is encoded, False otherwise.
    :rtype: bool
)pbdoc";

// GetLogPrecision
const char* ptx_GetLogPrecision_docs = R"pbdoc(
    Get the log of the plaintext precision.

    :return: The log of the plaintext precision.
    :rtype: float
)pbdoc";

// Encode
const char* ptx_Encode_docs = R"pbdoc(
    Encode the plaintext into a polynomial.
)pbdoc";

// Decode
const char* ptx_Decode_docs = R"pbdoc(
    Decode the polynomial into a plaintext.
)pbdoc";

// GetCKKSPackedValue
const char* ptx_GetCKKSPackedValue_docs = R"pbdoc(
    Get the packed value of the plaintext for CKKS-based plaintexts.

    :return: The packed value of the plaintext.
    :rtype: List[complex]
)pbdoc";


#endif // PLAINTEXT_DOCSTRINGS_H
