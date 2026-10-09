#
# Simple example for CKKS bootstrapping with composite scaling
#

from openfhe import *
import math


def main():
    simple_bootstrap_example()
    simple_bootstrap_stc_first_example()


def calculate_approximation_error(result, expected_result):
    # CalculateApproximationError() calculates the precision number (or approximation error).
    # The higher the precision, the less the error.
    # As recommended in footnote 23 of Security Guidelines for Implementing Homomorphic Encryption
    # (https://cic.iacr.org/p/1/4/26/pdf), precision bits are evaluated as the negative
    # base 2 logarithm of the average L1 norm between results from standard (cleartext) calculation
    # and those computed homomorphically.
    if len(result) != len(expected_result):
        raise Exception("Cannot compare vectors with different numbers of elements")

    # using the average
    acc_error = 0
    for i in range(len(result)):
        acc_error += abs(result[i] - expected_result[i])
    return abs(math.log2(acc_error / len(result)))


def simple_bootstrap_example():
    parameters = CCParamsCKKSRNS()

    # A. Specify main parameters
    # A1) Secret key distribution
    # SPARSE_ENCAPSULATED is recommended for CKKS bootstrapping (probability of failure below 2^-128).
    # UNIFORM_TERNARY, used here, is the distribution of the homomorphic encryption security guidelines;
    # its probability of failure is 2^-67 for N = 2^16 and 2^-27 for N = 2^17 with full packing.
    # SPARSE_TERNARY (original CKKS paper) is discouraged: about 2^-23 for N = 2^16.
    secret_key_dist = SecretKeyDist.UNIFORM_TERNARY
    parameters.SetSecretKeyDist(secret_key_dist)

    rescale_tech = ScalingTechnique.COMPOSITESCALINGAUTO
    dcrt_bits = 98
    first_mod = 100

    parameters.SetScalingModSize(dcrt_bits)
    parameters.SetScalingTechnique(rescale_tech)
    parameters.SetFirstModSize(first_mod)

    parameters.SetSecurityLevel(SecurityLevel.HEStd_NotSet)
    parameters.SetRingDim(1 << 12)

    register_word_size = 64
    parameters.SetRegisterWordSize(register_word_size)

    level_budget = [4, 4]

    levels_available_after_bootstrap = 10

    depth = levels_available_after_bootstrap + CryptoContext.GetBootstrapDepth(level_budget, secret_key_dist)

    print(f"levelBudget[0] = {level_budget[0]}")
    print(f"levelBudget[1] = {level_budget[1]}")
    print(f"secretKeyDist = {secret_key_dist}")
    print(f"depth = {depth}")

    parameters.SetMultiplicativeDepth(depth)

    cryptocontext = GenCryptoContext(parameters)
    cryptocontext.Enable(PKESchemeFeature.PKE)
    cryptocontext.Enable(PKESchemeFeature.KEYSWITCH)
    cryptocontext.Enable(PKESchemeFeature.LEVELEDSHE)
    cryptocontext.Enable(PKESchemeFeature.ADVANCEDSHE)
    cryptocontext.Enable(PKESchemeFeature.FHE)

    ring_dim = cryptocontext.GetRingDimension()
    # This is the maximum number of slots that can be used for full packing.
    num_slots = ring_dim // 2
    print(f"CKKS scheme is using ring dimension {ring_dim}\n")

    cryptocontext.EvalBootstrapSetup(level_budget)

    key_pair = cryptocontext.KeyGen()
    cryptocontext.EvalMultKeyGen(key_pair.secretKey)
    cryptocontext.EvalBootstrapKeyGen(key_pair.secretKey, num_slots)

    x = [0.25, 0.5, 0.75, 1.0, 2.0, 3.0, 4.0, 5.0]
    encoded_length = len(x)

    composite_degree = cryptocontext.GetCompositeDegree()

    ptxt = cryptocontext.MakeCKKSPackedPlaintext(x, 1, composite_degree * (depth - 1))

    print(f"Composite degree: {composite_degree} Bit length: {dcrt_bits / composite_degree} "
          f"Register size: {register_word_size}")

    ptxt.SetLength(encoded_length)
    print(f"Input: {ptxt}")

    ciph = cryptocontext.Encrypt(key_pair.publicKey, ptxt)

    print(f"Initial number of levels remaining: {depth - ciph.GetLevel() // composite_degree}")

    # Perform the bootstrapping operation. The goal is to increase the number of levels remaining
    # for HE computation.
    ciphertext_after = cryptocontext.EvalBootstrap(ciph, 1)

    print(f"Number of levels remaining after bootstrapping: "
          f"{depth - ciphertext_after.GetLevel() // composite_degree - (ciphertext_after.GetNoiseScaleDeg() - 1)}\n")

    print(f"Scaling factor after bootstrapping: {ciphertext_after.GetScalingFactor()}")

    print(f"Composite degree: {cryptocontext.GetCompositeDegree()}")
    print(f"Modulus bit length: {dcrt_bits / cryptocontext.GetCompositeDegree()}")
    print(f"Word register size: {register_word_size}")

    result = cryptocontext.Decrypt(ciphertext_after, key_pair.secretKey)
    result.SetLength(encoded_length)
    print(f"Output after bootstrapping \n\t{result}")

    actual_result = result.GetCKKSPackedValue()
    precision = calculate_approximation_error(actual_result, ptxt.GetCKKSPackedValue())
    print(f"Estimated precision: {precision}")


def simple_bootstrap_stc_first_example():
    parameters = CCParamsCKKSRNS()

    secret_key_dist = SecretKeyDist.UNIFORM_TERNARY
    parameters.SetSecretKeyDist(secret_key_dist)

    rescale_tech = ScalingTechnique.COMPOSITESCALINGAUTO
    dcrt_bits = 98
    first_mod = 100

    parameters.SetScalingModSize(dcrt_bits)
    parameters.SetScalingTechnique(rescale_tech)
    parameters.SetFirstModSize(first_mod)

    parameters.SetSecurityLevel(SecurityLevel.HEStd_NotSet)
    parameters.SetRingDim(1 << 12)

    register_word_size = 64
    parameters.SetRegisterWordSize(register_word_size)

    level_budget = [4, 4]

    # Note that the number of levels available after bootstrapping in the next bootstrapping call
    # will be levelsAvailableAfterBootstrap - 1 because an additional level
    # is used for scaling the ciphertext before next bootstrapping (in 64-bit CKKS bootstrapping)
    levels_available_after_bootstrap = 10 + level_budget[1]

    depth = levels_available_after_bootstrap + CryptoContext.GetBootstrapDepth([level_budget[0], 0], secret_key_dist)

    print(f"levelBudget[0] = {level_budget[0]}")
    print(f"levelBudget[1] = {level_budget[1]}")
    print(f"secretKeyDist = {secret_key_dist}")
    print(f"depth = {depth}")

    parameters.SetMultiplicativeDepth(depth)

    cryptocontext = GenCryptoContext(parameters)
    cryptocontext.Enable(PKESchemeFeature.PKE)
    cryptocontext.Enable(PKESchemeFeature.KEYSWITCH)
    cryptocontext.Enable(PKESchemeFeature.LEVELEDSHE)
    cryptocontext.Enable(PKESchemeFeature.ADVANCEDSHE)
    cryptocontext.Enable(PKESchemeFeature.FHE)

    ring_dim = cryptocontext.GetRingDimension()
    # This is the maximum number of slots that can be used for full packing.
    num_slots = ring_dim // 2
    print(f"CKKS scheme is using ring dimension {ring_dim}\n")

    cryptocontext.EvalBootstrapSetup(level_budget, [0, 0], num_slots, 0, True, True)

    key_pair = cryptocontext.KeyGen()
    cryptocontext.EvalMultKeyGen(key_pair.secretKey)
    cryptocontext.EvalBootstrapKeyGen(key_pair.secretKey, num_slots)

    x = [0.25, 0.5, 0.75, 1.0, 2.0, 3.0, 4.0, 5.0]
    encoded_length = len(x)

    composite_degree = cryptocontext.GetCompositeDegree()

    # We start with a depleted ciphertext that has used up all of its levels.
    ptxt = cryptocontext.MakeCKKSPackedPlaintext(x, 1, composite_degree * (depth - 1 - level_budget[1]))

    print(f"Composite degree: {composite_degree} Bit length: {dcrt_bits / composite_degree} "
          f"Register size: {register_word_size}")

    ptxt.SetLength(encoded_length)
    print(f"Input: {ptxt}")

    ciph = cryptocontext.Encrypt(key_pair.publicKey, ptxt)

    print(f"Initial number of levels remaining: {depth - ciph.GetLevel() // composite_degree}")

    # Perform the bootstrapping operation. The goal is to increase the number of levels remaining
    # for HE computation.
    ciphertext_after = cryptocontext.EvalBootstrap(ciph)

    print(f"Number of levels remaining after bootstrapping: "
          f"{depth - ciphertext_after.GetLevel() // composite_degree - (ciphertext_after.GetNoiseScaleDeg() - 1)}\n")

    print(f"Scaling factor after bootstrapping: {ciphertext_after.GetScalingFactor()}")

    print(f"Composite degree: {cryptocontext.GetCompositeDegree()}")
    print(f"Modulus bit length: {dcrt_bits / cryptocontext.GetCompositeDegree()}")
    print(f"Word register size: {register_word_size}")

    result = cryptocontext.Decrypt(ciphertext_after, key_pair.secretKey)
    result.SetLength(encoded_length)
    print(f"Output after bootstrapping \n\t{result}")

    actual_result = result.GetCKKSPackedValue()
    precision = calculate_approximation_error(actual_result, ptxt.GetCKKSPackedValue())
    print(f"Estimated precision: {precision}")


if __name__ == "__main__":
    main()
