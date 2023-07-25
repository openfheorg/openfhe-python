#ifndef CIPHERTEXT_DOCSTRINGS_H
#define CIPHERTEXT_DOCSTRINGS_H

const char* ctx_GetLevel_docs = R"doc(
    Get the number of scalings performed

    Returns
    -------
        int: The level of the ciphertext.
)doc";

const char* ctx_SetLevel_docs = R"doc(
    Set the number of scalings

    Parameters
    ----------
        level (int): The level to set.
)doc";
#endif // CIPHERTEXT_DOCSTRINGS_H
