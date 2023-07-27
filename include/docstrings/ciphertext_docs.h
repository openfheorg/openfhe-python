#ifndef CIPHERTEXT_DOCSTRINGS_H
#define CIPHERTEXT_DOCSTRINGS_H

// GetLevel
const char* ctx_GetLevel_docs = R"pbdoc(
    Get the number of scalings performed.

    :return: The level of the ciphertext.
    :rtype: int
)pbdoc";

// SetLevel
const char* ctx_SetLevel_docs = R"pbdoc(
    Set the number of scalings.

    :param level: The level to set.
    :type level: int
)pbdoc";

#endif // CIPHERTEXT_DOCSTRINGS_H
