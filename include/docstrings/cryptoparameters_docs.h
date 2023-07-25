#ifndef CRYPTOPARAMS_DOCSTRINGS_H
#define CRYPTOPARAMS_DOCSTRINGS_H

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
)doc";

#endif // CRYPTOPARAMS_DOCSTRINGS_H
