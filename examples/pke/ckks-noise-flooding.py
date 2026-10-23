#
# Please see CKKS_NOISE_FLOODING.md for technical details on CKKS noise flooding for the INDCPA^D scenario.
#
# Example for using CKKS with the experimental NOISE_FLOODING_DECRYPT mode. We do not recommend
# this mode for production yet. This experimental mode gives us equivalent security levels to
# BGV and BFV, but it requires the user to run all encrypted operations twice. The first iteration
# is a preliminary run to measure noise, and the second iteration is the actual run, which
# will input the noise as a parameter. We use the noise to enhance security within decryption.
#
# Note that a user can choose to run the first computation with NATIVE_SIZE = 64 to estimate noise,
# and the second computation with NATIVE_SIZE = 128, if they wish. This would require a
# different set of binaries: first, with NATIVE_SIZE = 64 and the second one with NATIVE_SIZE = 128.
# It can be considered as an optimization for the case when we need NATIVE_SIZE = 128.
#
# For NATIVE_SIZE=128, we automatically choose the scaling mod size and first mod size in the second iteration
# based on the input noise estimate. This means that we currently do not support bootstrapping in the
# NOISE_FLOODING_DECRYPT mode, since the scaling mod size and first mod size affect the noise estimate for
# bootstrapping. We plan to add support for bootstrapping in NOISE_FLOODING_DECRYPT mode in a future release.
#

from openfhe import *


def ckks_noise_flooding_demo():
    # ----------------------- Setup first CryptoContext -----------------------------
    # Phase 1 will be for noise estimation.
    # -------------------------------------------------------------------------------
    print("---------------------------------- PHASE 1: NOISE ESTIMATION ----------------------------------")
    parameters_noise_estimation = CCParamsCKKSRNS()
    # EXEC_NOISE_ESTIMATION indicates that the resulting plaintext will estimate the amount of noise in the computation.
    parameters_noise_estimation.SetExecutionMode(ExecutionMode.EXEC_NOISE_ESTIMATION)

    crypto_context_noise_estimation = get_crypto_context(parameters_noise_estimation)

    ring_dim = crypto_context_noise_estimation.GetRingDimension()
    print(f"CKKS scheme is using ring dimension {ring_dim}\n")

    # Key Generation
    key_pair_noise_estimation = crypto_context_noise_estimation.KeyGen()
    crypto_context_noise_estimation.EvalMultKeyGen(key_pair_noise_estimation.secretKey)

    # We run the encrypted computation the first time.
    noise_ciphertext = encrypted_computation(crypto_context_noise_estimation, key_pair_noise_estimation.publicKey)

    # Decrypt noise
    noise_plaintext = crypto_context_noise_estimation.Decrypt(key_pair_noise_estimation.secretKey, noise_ciphertext)
    noise = noise_plaintext.GetLogError()
    print(f"Noise \n\t{noise}")

    # ----------------------- Setup second CryptoContext -----------------------------
    # Phase 2 will be for the actual evaluation.
    # IMPORTANT: We must use a different public/private key pair here to achieve the
    # security guarantees for noise flooding.
    # -------------------------------------------------------------------------------
    print("---------------------------------- PHASE 2: EVALUATION ----------------------------------")
    parameters_evaluation = CCParamsCKKSRNS()
    # EXEC_EVALUATION indicates that we are in phase 2 of computation, and will obtain the actual result.
    parameters_evaluation.SetExecutionMode(ExecutionMode.EXEC_EVALUATION)
    # Here, we set the noise of our previous computation
    parameters_evaluation.SetNoiseEstimate(noise)

    # We can set our desired precision for 128-bit CKKS only. For NATIVE_SIZE=64, we ignore this parameter.
    parameters_evaluation.SetDesiredPrecision(25)

    # We can set the statistical security and number of adversarial queries, but we can also
    # leave these lines out, as we are setting them to the default values here.
    parameters_evaluation.SetStatisticalSecurity(30)
    parameters_evaluation.SetNumAdversarialQueries(1)

    # The remaining parameters must be the same as the first CryptoContext. Note that we can choose to run the
    # first computation with NATIVEINT = 64 to estimate noise, and the second computation with NATIVEINT = 128,
    # or vice versa, if we wish.
    crypto_context_evaluation = get_crypto_context(parameters_evaluation)

    # IMPORTANT: Generate new keys
    key_pair_evaluation = crypto_context_evaluation.KeyGen()
    crypto_context_evaluation.EvalMultKeyGen(key_pair_evaluation.secretKey)

    # We run the encrypted computation the second time.
    ciphertext_result = encrypted_computation(crypto_context_evaluation, key_pair_evaluation.publicKey)

    # Decrypt final result
    result = crypto_context_evaluation.Decrypt(key_pair_evaluation.secretKey, ciphertext_result)
    vec_size = 8
    result.SetLength(vec_size)
    print(f"Final output \n\t{result.GetCKKSPackedValue()}")

    expected_result = [1.01, 1.04, 0, 0, 1.25, 0, 0, 1.64]
    print(f"Expected result\n\t {expected_result}")


def get_crypto_context(parameters):
    # We recommend putting part of the CryptoContext inside a function because
    # you must make sure all parameters are the same, except EXECUTION_MODE and NOISE_ESTIMATE.

    # This demo is to illustrate how to use the security mode NOISE_FLOODING_DECRYPT to achieve enhanced security.
    parameters.SetDecryptionNoiseMode(DecryptionNoiseMode.NOISE_FLOODING_DECRYPT)

    # Specify main parameters
    parameters.SetSecretKeyDist(SecretKeyDist.UNIFORM_TERNARY)

    # Desired security level based on FHE standards. Note that this is different than NoiseDecryptionMode,
    # which also gives us enhanced security in CKKS when using NOISE_FLOODING_DECRYPT.
    # We must always use the same ring dimension in both iterations, so we set the security level to HEStd_NotSet,
    # and manually set the ring dimension.
    parameters.SetSecurityLevel(SecurityLevel.HEStd_NotSet)
    parameters.SetRingDim(1 << 16)

    rescale_tech = ScalingTechnique.FIXEDAUTO
    dcrt_bits = 59
    first_mod = 60

    parameters.SetScalingTechnique(rescale_tech)
    parameters.SetScalingModSize(dcrt_bits)
    parameters.SetFirstModSize(first_mod)

    # In this example, we perform two multiplications and an addition.
    parameters.SetMultiplicativeDepth(2)

    # Generate crypto context.
    crypto_context = GenCryptoContext(parameters)

    # Enable features that you wish to use.
    crypto_context.Enable(PKESchemeFeature.PKE)
    crypto_context.Enable(PKESchemeFeature.LEVELEDSHE)

    return crypto_context


def encrypted_computation(crypto_context, public_key):
    # We recommend putting the encrypted computation you wish to perform inside a function because
    # you have to perform it twice. In this example, we perform two multiplications and an addition.
    # The first iteration will return a ciphertext that contains a noise measurement.
    # The second iteration will return the actual encrypted computation.

    # Encoding and encryption of inputs
    # Generate random input
    vec1 = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8]
    vec2 = [1, 1, 0, 0, 1, 0, 0, 1]

    # Encoding as plaintexts and encrypt
    ptxt1 = crypto_context.MakeCKKSPackedPlaintext(vec1)
    ptxt2 = crypto_context.MakeCKKSPackedPlaintext(vec2)
    ciph1 = crypto_context.Encrypt(public_key, ptxt1)
    ciph2 = crypto_context.Encrypt(public_key, ptxt2)

    ciph_mult = crypto_context.EvalMult(ciph1, ciph2)
    ciph_mult2 = crypto_context.EvalMult(ciph_mult, ciph1)
    ciph_result = crypto_context.EvalAdd(ciph_mult2, ciph2)

    return ciph_result


def main():
    ckks_noise_flooding_demo()


if __name__ == "__main__":
    main()
