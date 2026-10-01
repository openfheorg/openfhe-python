#
# Example for multiple iterations of CKKS bootstrapping with composite scaling
# to improve precision
#

from openfhe import *
import math
import random


def main():
    iterative_bootstrap_example()


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


def iterative_bootstrap_example():
    # Step 1: Set CryptoContext
    parameters = CCParamsCKKSRNS()
    secret_key_dist = SecretKeyDist.UNIFORM_TERNARY
    parameters.SetSecretKeyDist(secret_key_dist)
    parameters.SetSecurityLevel(SecurityLevel.HEStd_NotSet)
    parameters.SetRingDim(1 << 7)

    # All modes are supported for 64-bit CKKS bootstrapping.
    # For this configuration, 3 words per level will be used
    rescale_tech = ScalingTechnique.COMPOSITESCALINGAUTO
    dcrt_bits = 61
    first_mod = 66
    register_word_size = 27

    parameters.SetScalingModSize(dcrt_bits)
    parameters.SetScalingTechnique(rescale_tech)
    parameters.SetFirstModSize(first_mod)
    parameters.SetRegisterWordSize(register_word_size)

    # Here, we specify the number of iterations to run bootstrapping. Note that we currently only support 1 or 2 iterations.
    # Two iterations should give us approximately double the precision of one iteration.
    num_iterations = 2

    level_budget = [3, 3]
    bsgs_dim = [0, 0]

    levels_available_after_bootstrap = 10
    # Each extra iteration on top of 1 requires an extra level to be consumed.
    depth = levels_available_after_bootstrap + FHECKKSRNS.GetBootstrapDepth(level_budget, secret_key_dist) + (num_iterations - 1)
    parameters.SetMultiplicativeDepth(depth)

    # Generate crypto context.
    cryptocontext = GenCryptoContext(parameters)

    # Enable features that you wish to use. Note, we must enable FHE to use bootstrapping.
    cryptocontext.Enable(PKESchemeFeature.PKE)
    cryptocontext.Enable(PKESchemeFeature.KEYSWITCH)
    cryptocontext.Enable(PKESchemeFeature.LEVELEDSHE)
    cryptocontext.Enable(PKESchemeFeature.ADVANCEDSHE)
    cryptocontext.Enable(PKESchemeFeature.FHE)

    ring_dim = cryptocontext.GetRingDimension()
    print(f"CKKS scheme is using ring dimension {ring_dim}\n")

    composite_degree = cryptocontext.GetCompositeDegree()
    print(f"compositeDegree={composite_degree} modBitWidth={dcrt_bits / composite_degree} "
          f"targetHWArchWordSize={register_word_size}")

    # Step 2: Precomputations for bootstrapping
    # We use a full packing.
    num_slots = cryptocontext.GetCyclotomicOrder() // 4
    cryptocontext.EvalBootstrapSetup(level_budget, bsgs_dim, num_slots)

    # Step 3: Key Generation
    key_pair = cryptocontext.KeyGen()
    cryptocontext.EvalMultKeyGen(key_pair.secretKey)
    # Generate bootstrapping keys.
    cryptocontext.EvalBootstrapKeyGen(key_pair.secretKey, num_slots)

    # Step 4: Encoding and encryption of inputs
    # Generate random input
    x = [random.uniform(0.0, 1.0) for _ in range(num_slots)]

    # Encoding as plaintexts
    # We specify the number of slots as numSlots to achieve a performance improvement.
    # We use the other default values of depth 1, levels 0, and no params.
    # Alternatively, you can also set batch size as a parameter in the CryptoContext as follows:
    # parameters.SetBatchSize(numSlots);
    # Here, we assume all ciphertexts in the cryptoContext will have numSlots slots.
    # We start with a depleted ciphertext that has used up all of its levels.
    ptxt = cryptocontext.MakeCKKSPackedPlaintext(x, 1, composite_degree * (depth - 1), None, num_slots)
    ptxt.SetLength(num_slots)
    print(f"Input: {ptxt}")

    # Encrypt the encoded vectors
    ciph = cryptocontext.Encrypt(key_pair.publicKey, ptxt)

    # Step 5: Measure the precision of a single bootstrapping operation.
    ciphertext_after = cryptocontext.EvalBootstrap(ciph)

    result = cryptocontext.Decrypt(key_pair.secretKey, ciphertext_after)
    result.SetLength(num_slots)
    precision = math.floor(calculate_approximation_error(result.GetCKKSPackedValue(), ptxt.GetCKKSPackedValue()))
    print(f"Bootstrapping precision after 1 iteration: {precision}")

    # Set precision equal to empirically measured value after many test runs.
    precision = 19
    print(f"Precision input to algorithm: {precision}")

    # Step 6: Run bootstrapping with multiple iterations.
    ciphertext_two_iterations = cryptocontext.EvalBootstrap(ciph, num_iterations, precision)

    result_two_iterations = cryptocontext.Decrypt(key_pair.secretKey, ciphertext_two_iterations)
    result.SetLength(num_slots)
    actual_result = result_two_iterations.GetCKKSPackedValue()

    print(f"\nOutput after two iterations of bootstrapping: {actual_result}")
    precision_multiple_iterations = calculate_approximation_error(actual_result, ptxt.GetCKKSPackedValue())

    # Output the precision of bootstrapping after two iterations. It should be approximately double the original precision.
    print(f"\nBootstrapping precision after 2 iterations: {precision_multiple_iterations}")
    print(f"Number of levels remaining after 2 bootstrappings: "
          f"{depth - ciphertext_two_iterations.GetLevel() // composite_degree - (ciphertext_two_iterations.GetNoiseScaleDeg() - 1)}\n")


if __name__ == "__main__":
    main()
