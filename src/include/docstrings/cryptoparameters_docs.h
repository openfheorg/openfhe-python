//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2023-2025, Duality Technologies Inc. and other contributors
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
#ifndef __CRYPTOPARAMETERS_DOCS_H__
#define __CRYPTOPARAMETERS_DOCS_H__

const char* ccparams_doc = R"doc(
    Crypto parameters for the BFV, BGV and CKKS scheme.

    :ivar SCHEME scheme: Scheme ID
    :ivar PlaintextModulus ptModulus: PlaintextModulus ptModulus is used in BGV/BFV type schemes and impacts noise growth
    :ivar int digitSize: digitSize is used in BV Key Switching only (KeySwitchTechnique = BV) and impacts noise growth
    :ivar float standardDeviation: standardDeviation is used for Gaussian error generation
    :ivar SecretKeyDist secretKeyDist: Secret key distribution: GAUSSIAN, UNIFORM_TERNARY, etc.
    :ivar int maxRelinSkDeg: Max relinearization degree of secret key polynomial (used for lazy relinearization)
    :ivar KeySwitchTechnique ksTech: key switching technique: BV or HYBRID currently
    :ivar ScalingTechnique scalTech: rescaling/modulus switching technique used in CKKS/BGV: FLEXIBLEAUTOEXT, FIXEDMANUL, FLEXIBLEAUTO, etc.
    :ivar int batchSize: max batch size of messages to be packed in encoding (number of slots)
    :ivar ProxyReEncryptionMode PREMode: PRE security mode
    :ivar MultipartyMode multipartyMode: Multiparty security mode in BFV/BGV
    :ivar ExecutionMode executionMode: Execution mode in CKKS
    :ivar DecryptionNoiseMode decryptionNoiseMode: Decryption noise mode in CKKS
    :ivar float noiseEstimate: Noise estimate in CKKS for NOISE_FLOODING_DECRYPT mode.
    :ivar float desiredPrecision: Desired precision for 128-bit CKKS. We use this value in NOISE_FLOODING_DECRYPT mode to determine the scaling factor.
    :ivar float statisticalSecurity: Statistical security of CKKS in NOISE_FLOODING_DECRYPT mode. This is the bound on the probability of success that any adversary can have. Specifically, they a probability of success of at most 2^(-statisticalSecurity).
    :ivar float numAdversarialQueries: This is the number of adversarial queries a user is expecting for their application, which we use to ensure security of CKKS in NOISE_FLOODING_DECRYPT mode.
    :ivar int thresholdNumOfParties: This is the number of parties in a threshold application, which is used for bound on the joint secret key
    :ivar int firstModSize: firstModSize and scalingModSize are used to calculate ciphertext modulus. The ciphertext modulus should be seen as: Q = q_0 * q_1 * ... * q_n * q' where q_0 is first prime, and it's number of bits is firstModSize other q_i have same number of bits and is equal to scalingModSize the prime q' is not explicitly given, but it is used internally in CKKS and BGV schemes (in *EXT scaling methods)
    :ivar int scalingModSize: firstModSize and scalingModSize are used to calculate ciphertext modulus. The ciphertext modulus should be seen as: Q = q_0 * q_1 * ... * q_n * q' where q_0 is first prime, and it's number of bits is firstModSize other q_i have same number of bits and is equal to scalingModSize the prime q' is not explicitly given, but it is used internally in CKKS and BGV schemes (in *EXT scaling methods)
    :ivar int numLargeDigits: see KeySwitchTechnique - number of digits in HYBRID key switching
    :ivar int multiplicativeDepth: multiplicative depth
    :ivar SecurityLevel securityLevel: security level: We use the values from the security standard  at http://homomorphicencryption.org/wp-content/uploads/2018/11/HomomorphicEncryptionStandardv1.1.pdf For given ring dimension and security level we have upper bound of possible highest modulus (Q for BV or P*Q for HYBRID)
    :ivar int ringDim: ring dimension N of the scheme : the ring is Z_Q[x] / (X^N+1)
    :ivar int evalAddCount: number of additions (used for setting noise in BGV and BFV)
    :ivar int keySwitchCount: number of key switching operations (used for setting noise in BGV and BFV)
    :ivar int multiHopModSize: size of moduli used for PRE in the provable HRA setting
    :ivar EncryptionTechnique encryptionTechnique: STANDARD or EXTENDED mode for BFV encryption
    :ivar MultiplicationTechnique multiplicationTechnique: multiplication method in BFV: BEHZ, HPS, etc.
    :ivar CKKSDataType ckksDataType: CKKS data type: real or complex. Noise flooding is only enabled for real values.
    :ivar uint32_t compositeDegree: parameter to support high-precision CKKS RNS with small word sizes
    :ivar uint32_t registerWordSize: parameter to support high-precision CKKS RNS with small word sizes
)doc";

const char* cc_GetScalingFactorReal_docs = R"pbdoc(
    Method to retrieve the scaling factor of level l. For FIXEDMANUAL scaling technique method always returns 2^p, where p corresponds to plaintext modulus

    :param l:  For FLEXIBLEAUTO scaling technique the level whose scaling factor we want to learn. Levels start from 0 (no scaling done - all towers) and go up to K-1, where K is the number of towers supported.
    :type l: int
    :return: the scaling factor.
    :rtype: float
)pbdoc";


#endif // __CRYPTOPARAMETERS_DOCS_H__
