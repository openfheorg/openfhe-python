from openfhe import *

def main():
    simple_bootstrap_example()

def simple_bootstrap_example():
    parameters = CCParamsCKKSRNS()

    secret_key_dist = SecretKeyDist.UNIFORM_TERNARY
    parameters.SetSecretKeyDist(secret_key_dist)

    parameters.SetSecurityLevel(SecurityLevel.HEStd_NotSet)
    parameters.SetRingDim(1<<12)

    rescale_tech = ScalingTechnique.FLEXIBLEAUTO
    dcrt_bits = 59
    first_mod = 60
    
    parameters.SetScalingModSize(dcrt_bits)
    parameters.SetScalingTechnique(rescale_tech)
    parameters.SetFirstModSize(first_mod)

    level_budget = [4, 4]
    approx_bootstrapp_depth = 8

    levels_used_before_bootstrap = 10

    depth = levels_used_before_bootstrap + FHECKKSRNS.GetBootstrapDepth(approx_bootstrapp_depth, level_budget, secret_key_dist)

    parameters.SetMultiplicativeDepth(depth)

    cryptocontext = GenCryptoContext(parameters)
    cryptocontext.Enable(PKESchemeFeature.PKE)
    cryptocontext.Enable(PKESchemeFeature.KEYSWITCH)
    cryptocontext.Enable(PKESchemeFeature.LEVELEDSHE)
    cryptocontext.Enable(PKESchemeFeature.ADVANCEDSHE)
    cryptocontext.Enable(PKESchemeFeature.FHE)

    ring_dim = cryptocontext.GetRingDimension()
    # This is the mazimum number of slots that can be used full packing.

    num_slots = int(ring_dim / 2)
    print(f"CKKS is using ring dimension {ring_dim}")

    cryptocontext.EvalBootstrapSetup(level_budget)

    key_pair = cryptocontext.KeyGen()
    cryptocontext.EvalMultKeyGen(key_pair.secretKey)
    cryptocontext.EvalBootstrapKeyGen(key_pair.secretKey, num_slots)

    x = [0.25, 0.5, 0.75, 1.0, 2.0, 3.0, 4.0, 5.0]
    encoded_length = len(x)

    ptxt = cryptocontext.MakeCKKSPackedPlaintext(x)
    ptxt.SetLength(encoded_length)

    print(f"Input: {x}")

    ciph = cryptocontext.Encrypt(key_pair.publicKey, ptxt)

    print(f"Initial number of levels remaining: {ciph.GetLevel()}")

    ciphertext_after = cryptocontext.EvalBootstrap(ciph)

    print(f"Number of levels remaining after bootstrapping: {ciphertext_after.GetLevel()}")

    result = Decrypt(ciphertext_after,key_pair.secretKey)
    result.SetLength(encoded_length)
    print(f"Output after bootstrapping: {result}")

if __name__ == '__main__':
    main()