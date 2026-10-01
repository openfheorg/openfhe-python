#
# Example for CKKS bootstrapping with sparse packing
#

from openfhe import *
import random


def main():
    # We run the example with 8 slots and ring dimension 4096 to illustrate how to run bootstrapping with a sparse plaintext.
    # Using a sparse plaintext and specifying the smaller number of slots gives a performance improvement (typically up to 3x).
    bootstrap_example(8)


def bootstrap_example(num_slots):
    # Step 1: Set CryptoContext
    parameters = CCParamsCKKSRNS()

    # A. Specify main parameters
    # A1) Secret key distribution
    # SPARSE_ENCAPSULATED is recommended for CKKS bootstrapping (probability of failure below 2^-128).
    # UNIFORM_TERNARY, used here, is the distribution of the homomorphic encryption security guidelines;
    # its probability of failure is 2^-67 for N = 2^16 and 2^-27 for N = 2^17 with full packing.
    # SPARSE_TERNARY (original CKKS paper) is discouraged: about 2^-23 for N = 2^16.
    secret_key_dist = SecretKeyDist.UNIFORM_TERNARY
    parameters.SetSecretKeyDist(secret_key_dist)

    # A2) Desired security level based on FHE standards.
    # In this example, we use the "NotSet" option, so the example can run more quickly with
    # a smaller ring dimension. Note that this should be used only in
    # non-production environments, or by experts who understand the security
    # implications of their choices. In production-like environments, we recommend using
    # HEStd_128_classic, HEStd_192_classic, or HEStd_256_classic for 128-bit, 192-bit,
    # or 256-bit security, respectively. If you choose one of these as your security level,
    # you do not need to set the ring dimension.
    parameters.SetSecurityLevel(SecurityLevel.HEStd_NotSet)
    parameters.SetRingDim(1 << 12)

    # A3) Key switching parameters.
    # By default, we use HYBRID key switching with a digit size of 3.
    # Choosing a larger digit size can reduce complexity, but the size of keys will increase.
    # Note that you can leave these lines of code out completely, since these are the default values.
    parameters.SetNumLargeDigits(3)
    parameters.SetKeySwitchTechnique(KeySwitchTechnique.HYBRID)

    # A4) Scaling parameters.
    # By default, we set the modulus sizes and rescaling technique to the following values
    # to obtain a good precision and performance tradeoff. We recommend keeping the parameters
    # below unless you are an FHE expert.
    if get_native_int() == 128:
        # Currently, only FIXEDMANUAL and FIXEDAUTO modes are supported for 128-bit CKKS bootstrapping.
        rescale_tech = ScalingTechnique.FIXEDAUTO
        dcrt_bits = 78
        first_mod = 89
    else:
        # All modes are supported for 64-bit CKKS bootstrapping.
        rescale_tech = ScalingTechnique.FLEXIBLEAUTO
        dcrt_bits = 59
        first_mod = 60

    parameters.SetScalingModSize(dcrt_bits)
    parameters.SetScalingTechnique(rescale_tech)
    parameters.SetFirstModSize(first_mod)

    # A4) Bootstrapping parameters.
    # We set a budget for the number of levels we can consume in bootstrapping for encoding and decoding, respectively.
    # Using larger numbers of levels reduces the complexity and number of rotation keys,
    # but increases the depth required for bootstrapping.
    # We must choose values smaller than ceil(log2(slots)). A level budget of {4, 4} is good for higher ring
    # dimensions (65536 and higher).
    level_budget = [3, 3]

    # We give the user the option of configuring values for an optimization algorithm in bootstrapping.
    # Here, we specify the giant step for the baby-step-giant-step algorithm in linear transforms
    # for encoding and decoding, respectively. Either choose this to be a power of 2
    # or an exact divisor of the number of slots. Setting it to have the default value of {0, 0} allows OpenFHE to choose
    # the values automatically.
    bsgs_dim = [0, 0]

    # A5) Multiplicative depth.
    # The goal of bootstrapping is to increase the number of available levels we have, or in other words,
    # to dynamically increase the multiplicative depth. However, the bootstrapping procedure itself
    # needs to consume a few levels to run. We compute the number of bootstrapping levels required
    # using GetBootstrapDepth, and add it to levelsAvailableAfterBootstrap to set our initial multiplicative
    # depth.
    levels_available_after_bootstrap = 10
    depth = levels_available_after_bootstrap + FHECKKSRNS.GetBootstrapDepth(level_budget, secret_key_dist)
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

    # Step 2: Precomputations for bootstrapping
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
    ptxt = cryptocontext.MakeCKKSPackedPlaintext(x, 1, depth - 1, None, num_slots)
    ptxt.SetLength(num_slots)
    print(f"Input: {ptxt}")

    # Encrypt the encoded vectors
    ciph = cryptocontext.Encrypt(key_pair.publicKey, ptxt)

    print(f"Initial number of levels remaining: {depth - ciph.GetLevel()}")

    # Step 5: Perform the bootstrapping operation. The goal is to increase the number of levels remaining
    # for HE computation.
    ciphertext_after = cryptocontext.EvalBootstrap(ciph)

    print(f"Number of levels remaining after bootstrapping: {depth - ciphertext_after.GetLevel()}\n")

    # Step 7: Decryption and output
    result = cryptocontext.Decrypt(key_pair.secretKey, ciphertext_after)
    result.SetLength(num_slots)
    print(f"Output after bootstrapping \n\t{result}")


if __name__ == "__main__":
    main()
