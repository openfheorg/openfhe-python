from openfhe import *
import math
import random

def main():
    iterative_bootstrap_example()

def calculate_approximation_error(result,expected_result):
    if len(result) != len(expected_result):
        raise Exception("Cannot compare vectors with different numbers of elements")
    # using the infinity norm
    # error is abs of the difference of real parts
    max_error = max([abs(el1.real - el2.real) for (el1, el2) in zip(result, expected_result)])
    # return absolute value of log base2 of the error
    return abs(math.log(max_error,2))
def iterative_bootstrap_example():
    # Step 1: Set CryptoContext
    parameters = CCParamsCKKSRNS()
    secret_key_dist = SecretKeyDist.UNIFORM_TERNARY
    parameters.SetSecretKeyDist(secret_key_dist)
    parameters.SetSecurityLevel(SecurityLevel.HEStd_NotSet)
    parameters.SetRingDim(1 << 12)

    rescale_tech = ScalingTechnique.FLEXIBLEAUTO
    dcrt_bits = 59
    first_mod = 60

    parameters.SetScalingModSize(dcrt_bits)
    parameters.SetScalingTechnique(rescale_tech)
    parameters.SetFirstModSize(first_mod)

    # Here, we specify the number of iterations to run bootstrapping. 
    # Note that we currently only support 1 or 2 iterations.
    # Two iterations should give us approximately double the precision of one iteration.
    num_iterations = 2

    level_budget = [3, 3]
    # Each extra iteration on top of 1 requires an extra level to be consumed.
    approx_bootstrapp_depth = 8 + (num_iterations - 1)
    bsgs_dim = [0,0]

    levels_used_before_bootstrap = 10
    depth = levels_used_before_bootstrap + FHECKKSRNS.GetBootstrapDepth(approx_bootstrapp_depth, level_budget, secret_key_dist)
    parameters.SetMultiplicativeDepth(depth)

    # Generate crypto context
    cryptocontext = GenCryptoContext(parameters)

    # Enable features that you wish to use. Note, we must enable FHE to use bootstrapping.

    cryptocontext.Enable(PKESchemeFeature.PKE)
    cryptocontext.Enable(PKESchemeFeature.KEYSWITCH)
    cryptocontext.Enable(PKESchemeFeature.LEVELEDSHE)
    cryptocontext.Enable(PKESchemeFeature.ADVANCEDSHE)
    cryptocontext.Enable(PKESchemeFeature.FHE)

    ring_dim = cryptocontext.GetRingDimension()
    print(f"CKKS is using ring dimension {ring_dim}\n\n")

    # Step 2: Precomputations for bootstrapping
    # We use a sparse packing
    num_slots = 8
    cryptocontext.EvalBootstrapSetup(levelBudget, bsgs_dim, num_slots)

    # Step 3: Key generation
    keyPair = cryptocontext.KeyGen()
    cryptocontext.EvalMultKeyGen(keyPair.secretKey)
    # Generate bootstrapping keys.
    cryptocontext.EvalBootstrapKeyGen(keyPair.secretKey, num_slots)

    # Step 4: Encoding and encryption of inputs
    # Generate random input
    x = [random.uniform(0, 1) for i in range(num_slots)]

    """ Encoding as plaintexts
        We specify the number of slots as num_slots to achieve a performance improvement.
        We use the other default values of depth 1, levels 0, and no params.
        Alternatively, you can also set batch size as a parameter in the CryptoContext as follows:
        parameters.SetBatchSize(num_slots);
        Here, we assume all ciphertexts in the cryptoContext will have num_slots slots.
        We start with a depleted ciphertext that has used up all of its levels."""
    ptxt = cryptocontext.MakeCKKSPackedPlaintext(x, 1, depth -1,None,num_slots)

    # Encrypt the encoded vectors
    ciph = cryptocontext.Encrypt(keyPair.publicKey, ptxt)

    # Step 5: Measure the precision of a single bootstrapping operation.
    ciphertext_after = cryptocontext.EvalBootstrap(ciph)

    result = Decrypt(ciphertext_after,keyPair.secretKey)
    result.SetLength(num_slots)
    precision = calculate_approximation_error(result.GetCKKSPackedValue(),ptxt.GetCKKSPackedValue())
    print(f"Bootstrapping precision after 1 iteration: {precision} bits\n")

    # Set the precision equal to empirically measured value after many test runs.
    precision = 17
    print(f"Precision input to algorithm: {precision}\n")

    # Step 6: Run bootstrapping with multiple iterations
    ciphertext_two_iterations = cryptocontext.EvalBootstrap(ciph,num_iterations,precision)

    result_two_iterations = Decrypt(ciphertext_two_iterations,keyPair.secretKey)
    result_two_iterations.SetLength(num_slots)
    actual_result = result_two_iterations.GetCKKSPackedValue()

    print(f"Output after two interations of bootstrapping: {actual_result}\n")
    precision_multiple_iterations = calculate_approximation_error(actual_result,ptxt.GetCKKSPackedValue())

    print(f"Bootstrapping precision after 2 iterations: {precision_multiple_iterations} bits\n")
    print(f"Number of levels remaining after 2 bootstrappings: {depth - ciphertext_two_iterations.GetLevel()}\n")

if __name__ == "__main__":
    main()