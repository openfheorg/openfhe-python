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
#ifndef __SERIALIZATION_DOCS_H__
#define __SERIALIZATION_DOCS_H__

// Docstrings for the (de)serialization bindings in src/lib/pke/serialization.cpp.
// These constants have external linkage, so this header must be included by
// serialization.cpp only, like the other docstring headers.

const char* serial_SerializeEvalBootstrapKey_docs = R"pbdoc(
    Serialize the CKKS bootstrapping automorphism keys for the given key tag and slot count
    to a file.

    :param filename: path of the file to write
    :type filename: str
    :param sertype: serialization format (JSON or BINARY)
    :type sertype: SERJSON | SERBINARY
    :param cc: crypto context whose bootstrapping keys are serialized
    :type cc: CryptoContext
    :param keyTag: tag of the secret key the bootstrapping keys belong to
    :type keyTag: str
    :param slots: slot count whose bootstrapping keys are serialized
    :type slots: int
    :return: true on success; false if the file cannot be written (a message is printed)
    :rtype: bool
)pbdoc";

const char* serial_DeserializeEvalBootstrapKey_docs = R"pbdoc(
    Deserialize CKKS bootstrapping automorphism keys from a file and insert them into the
    static key cache for the given key tag and slot count, replacing any matching keys.

    :param filename: path of the file to read
    :type filename: str
    :param sertype: serialization format (JSON or BINARY)
    :type sertype: SERJSON | SERBINARY
    :param cc: crypto context the keys are loaded for
    :type cc: CryptoContext
    :param keyTag: tag of the secret key the bootstrapping keys belong to
    :type keyTag: str
    :param slots: slot count whose bootstrapping keys are loaded
    :type slots: int
    :return: true on success; false if the file cannot be read (a message is printed)
    :rtype: bool
)pbdoc";

const char* serial_DeserializeEvalBootstrapKeyIndex_docs = R"pbdoc(
    Deserialize only the CKKS bootstrapping automorphism keys with the given rotation indices
    from a file and insert them into the static key cache for the given key tag, replacing any
    matching keys.

    :param filename: path of the file to read
    :type filename: str
    :param sertype: serialization format (JSON or BINARY)
    :type sertype: SERJSON | SERBINARY
    :param keyTag: tag of the secret key the bootstrapping keys belong to
    :type keyTag: str
    :param indexList: automorphism indices of the keys to load
    :type indexList: list[int]
    :return: true on success; false if the file cannot be read (a message is printed)
    :rtype: bool
)pbdoc";

const char* serial_SerializeToFile_docs = R"pbdoc(
    Serialize an object (CryptoContext, PublicKey, PrivateKey, Ciphertext, EvalKey or
    EvalKeyMap) to a file in the given format.

    :param filename: path of the file to write
    :type filename: str
    :param obj: the object to serialize
    :param sertype: serialization format (JSON or BINARY)
    :type sertype: SERJSON | SERBINARY
    :return: true on success
    :rtype: bool
)pbdoc";

const char* serial_DeserializeCryptoContext_docs = R"pbdoc(
    Deserialize a CryptoContext from a file written by SerializeToFile.

    :param filename: path of the file to read
    :type filename: str
    :param sertype: serialization format the file was written in (JSON or BINARY)
    :type sertype: SERJSON | SERBINARY
    :return: the deserialized object and a success flag
    :rtype: tuple[CryptoContext, bool]
)pbdoc";

const char* serial_DeserializePublicKey_docs = R"pbdoc(
    Deserialize a PublicKey from a file written by SerializeToFile.

    :param filename: path of the file to read
    :type filename: str
    :param sertype: serialization format the file was written in (JSON or BINARY)
    :type sertype: SERJSON | SERBINARY
    :return: the deserialized object and a success flag
    :rtype: tuple[PublicKey, bool]
)pbdoc";

const char* serial_DeserializePrivateKey_docs = R"pbdoc(
    Deserialize a PrivateKey from a file written by SerializeToFile.

    :param filename: path of the file to read
    :type filename: str
    :param sertype: serialization format the file was written in (JSON or BINARY)
    :type sertype: SERJSON | SERBINARY
    :return: the deserialized object and a success flag
    :rtype: tuple[PrivateKey, bool]
)pbdoc";

const char* serial_DeserializeCiphertext_docs = R"pbdoc(
    Deserialize a Ciphertext from a file written by SerializeToFile.

    :param filename: path of the file to read
    :type filename: str
    :param sertype: serialization format the file was written in (JSON or BINARY)
    :type sertype: SERJSON | SERBINARY
    :return: the deserialized object and a success flag
    :rtype: tuple[Ciphertext, bool]
)pbdoc";

const char* serial_DeserializeEvalKey_docs = R"pbdoc(
    Deserialize an EvalKey from a file written by SerializeToFile.

    :param filename: path of the file to read
    :type filename: str
    :param sertype: serialization format the file was written in (JSON or BINARY)
    :type sertype: SERJSON | SERBINARY
    :return: the deserialized object and a success flag
    :rtype: tuple[EvalKey, bool]
)pbdoc";

const char* serial_DeserializeEvalKeyMap_docs = R"pbdoc(
    Deserialize an EvalKeyMap from a file written by SerializeToFile.

    :param filename: path of the file to read
    :type filename: str
    :param sertype: serialization format the file was written in (JSON or BINARY)
    :type sertype: SERJSON | SERBINARY
    :return: the deserialized object and a success flag
    :rtype: tuple[EvalKeyMap, bool]
)pbdoc";

const char* serial_Serialize_docs = R"pbdoc(
    Serialize an object (CryptoContext, PublicKey, PrivateKey, Ciphertext, EvalKey or
    EvalKeyMap) in the given format and return it as a str (JSON) or bytes (BINARY; an
    EvalKeyMap and a list of EvalKeys are returned as bytes in both formats).

    :param obj: the object to serialize
    :param sertype: serialization format (JSON or BINARY)
    :type sertype: SERJSON | SERBINARY
    :return: the serialized object
    :rtype: str | bytes
)pbdoc";

const char* serial_DeserializeCryptoContextString_docs = R"pbdoc(
    Deserialize a CryptoContext from a str (JSON) or bytes (BINARY) produced by Serialize.

    :param str: the serialized object
    :type str: str | bytes
    :param sertype: serialization format the data was written in (JSON or BINARY)
    :type sertype: SERJSON | SERBINARY
    :return: the deserialized object
    :rtype: CryptoContext
)pbdoc";

const char* serial_DeserializePublicKeyString_docs = R"pbdoc(
    Deserialize a PublicKey from a str (JSON) or bytes (BINARY) produced by Serialize.

    :param str: the serialized object
    :type str: str | bytes
    :param sertype: serialization format the data was written in (JSON or BINARY)
    :type sertype: SERJSON | SERBINARY
    :return: the deserialized object
    :rtype: PublicKey
)pbdoc";

const char* serial_DeserializePrivateKeyString_docs = R"pbdoc(
    Deserialize a PrivateKey from a str (JSON) or bytes (BINARY) produced by Serialize.

    :param str: the serialized object
    :type str: str | bytes
    :param sertype: serialization format the data was written in (JSON or BINARY)
    :type sertype: SERJSON | SERBINARY
    :return: the deserialized object
    :rtype: PrivateKey
)pbdoc";

const char* serial_DeserializeCiphertextString_docs = R"pbdoc(
    Deserialize a Ciphertext from a str (JSON) or bytes (BINARY) produced by Serialize.

    :param str: the serialized object
    :type str: str | bytes
    :param sertype: serialization format the data was written in (JSON or BINARY)
    :type sertype: SERJSON | SERBINARY
    :return: the deserialized object
    :rtype: Ciphertext
)pbdoc";

const char* serial_DeserializeEvalKeyString_docs = R"pbdoc(
    Deserialize an EvalKey from a str (JSON) or bytes (BINARY) produced by Serialize.

    :param str: the serialized object
    :type str: str | bytes
    :param sertype: serialization format the data was written in (JSON or BINARY)
    :type sertype: SERJSON | SERBINARY
    :return: the deserialized object
    :rtype: EvalKey
)pbdoc";

const char* serial_DeserializeEvalKeyMapString_docs = R"pbdoc(
    Deserialize an EvalKeyMap from bytes produced by Serialize (both formats return bytes for
    an EvalKeyMap).

    :param str: the serialized object
    :type str: bytes
    :param sertype: serialization format the data was written in (JSON or BINARY)
    :type sertype: SERJSON | SERBINARY
    :return: the deserialized object
    :rtype: EvalKeyMap
)pbdoc";

const char* serial_DeserializeEvalKeyMapVectorString_docs = R"pbdoc(
    Deserialize a list of EvalKeys from bytes produced by Serialize.

    :param str: the serialized object
    :type str: bytes
    :param sertype: serialization format the data was written in (BINARY)
    :type sertype: SERBINARY
    :return: the deserialized list of evaluation keys
    :rtype: list[EvalKey]
)pbdoc";

const char* serial_SerializeEvalMultKeyString_docs = R"pbdoc(
    Serialize the EvalMult keys for the given key tag (all EvalMult keys if the tag is empty)
    from the static key cache and return them as a str (JSON) or bytes (BINARY).

    :param sertype: serialization format (JSON or BINARY)
    :type sertype: SERJSON | SERBINARY
    :param keyTag: tag of the secret key whose EvalMult keys are serialized ("" for all)
    :type keyTag: str
    :return: the serialized keys
    :rtype: str | bytes
    :raises RuntimeError: if the serialization fails
)pbdoc";

const char* serial_DeserializeEvalMultKeyString_docs = R"pbdoc(
    Deserialize EvalMult keys from a str (JSON) or bytes (BINARY) produced by
    SerializeEvalMultKeyString and insert them into the static key cache, silently replacing
    any matching keys.

    :param data: the serialized keys
    :type data: str | bytes
    :param sertype: serialization format the data was written in (JSON or BINARY)
    :type sertype: SERJSON | SERBINARY
    :raises RuntimeError: if the deserialization fails
)pbdoc";

const char* serial_SerializeEvalAutomorphismKeyString_docs = R"pbdoc(
    Serialize the automorphism (rotation) keys for the given key tag (all automorphism keys if
    the tag is empty) from the static key cache and return them as a str (JSON) or bytes
    (BINARY).

    :param sertype: serialization format (JSON or BINARY)
    :type sertype: SERJSON | SERBINARY
    :param keyTag: tag of the secret key whose automorphism keys are serialized ("" for all)
    :type keyTag: str
    :return: the serialized keys
    :rtype: str | bytes
    :raises RuntimeError: if the serialization fails
)pbdoc";

const char* serial_DeserializeEvalAutomorphismKeyString_docs = R"pbdoc(
    Deserialize automorphism (rotation) keys from a str (JSON) or bytes (BINARY) produced by
    SerializeEvalAutomorphismKeyString and insert them into the static key cache, silently
    replacing any matching keys.

    :param data: the serialized keys
    :type data: str | bytes
    :param sertype: serialization format the data was written in (JSON or BINARY)
    :type sertype: SERJSON | SERBINARY
    :raises RuntimeError: if the deserialization fails
)pbdoc";

#endif  // __SERIALIZATION_DOCS_H__
