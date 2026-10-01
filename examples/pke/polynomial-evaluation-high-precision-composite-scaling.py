#
# Example of polynomial evaluation using CKKS with composite scaling.
#
# Note: unlike the C++ version of this example, the moduli chain of the public key
# and the average scale approximation error are not printed here because the Python
# bindings do not expose the DCRTPoly element parameters (GetPublicElements,
# GetNumOfElements, etc.).
#

from openfhe import *
import sys
import time


def main(args=[]):
    # Parameters for d=4
    # first_mod_size     = 106
    # scaling_mod_size   = 104
    # register_word_size = 32
    # Parameters for d=3
    first_mod_size = 96
    scaling_mod_size = 80
    register_word_size = 32

    print("\n======EXAMPLE FOR EVALPOLY========\n")

    mult_depth = 6

    if len(args) > 0:
        argc_count = 0
        while argc_count < len(args):
            param_value = int(args[argc_count])
            if argc_count == 0:
                first_mod_size = param_value
                print(f"Setting First Mod Size: {first_mod_size}")
            elif argc_count == 1:
                scaling_mod_size = param_value
                print(f"Setting Scaling Mod Size: {scaling_mod_size}")
            elif argc_count == 2:
                register_word_size = param_value
                print(f"Setting Register Word Size: {register_word_size}")
            elif argc_count == 3:
                mult_depth = param_value
                print(f"Setting Multiplicative Depth: {mult_depth}")
            else:
                print("Invalid option")
            argc_count += 1

        print("Completed reading input parameters!")
    else:
        print("Using default parameters")
        print(f"First Mod Size: {first_mod_size}")
        print(f"Scaling Mod Size: {scaling_mod_size}")
        print(f"Register Word Size: {register_word_size}")
        print(f"Multiplicative Depth: {mult_depth}")
        print(f"Usage: {sys.argv[0]} [firstModSize] [scalingModSize] [registerWordSize] [multDepth]")

    parameters = CCParamsCKKSRNS()
    parameters.SetMultiplicativeDepth(mult_depth)
    parameters.SetFirstModSize(first_mod_size)
    parameters.SetScalingModSize(scaling_mod_size)

    parameters.SetRegisterWordSize(register_word_size)
    parameters.SetScalingTechnique(ScalingTechnique.COMPOSITESCALINGAUTO)

    cc = GenCryptoContext(parameters)
    cc.Enable(PKESchemeFeature.PKE)
    cc.Enable(PKESchemeFeature.KEYSWITCH)
    cc.Enable(PKESchemeFeature.LEVELEDSHE)
    cc.Enable(PKESchemeFeature.ADVANCEDSHE)

    composite_degree = cc.GetCompositeDegree()

    print("-----------------------------------------------------------------")
    print(f"Composite Degree: {composite_degree}")
    print(f"Prime Moduli Size: {scaling_mod_size / composite_degree}")
    print(f"Register Word Size: {register_word_size}")
    print("-----------------------------------------------------------------")

    input = [0.5, 0.7, 0.9, 0.95, 0.93]

    encoded_length = len(input)

    coefficients1 = [0.15, 0.75, 0, 1.25, 0, 0, 1, 0, 1, 2, 0, 1, 0, 0, 0, 0, 1]
    coefficients2 = [1, 2, 3, 4, 5, -1, -2, -3, -4, -5,
                     0.1, 0.2, 0.3, 0.4, 0.5, -0.1, -0.2, -0.3, -0.4, -0.5,
                     0.1, 0.2, 0.3, 0.4, 0.5, -0.1, -0.2, -0.3, -0.4, -0.5]

    plaintext1 = cc.MakeCKKSPackedPlaintext(input)

    key_pair = cc.KeyGen()

    print("Generating evaluation key for homomorphic multiplication...", end="")
    cc.EvalMultKeyGen(key_pair.secretKey)
    print("Completed.")

    ciphertext1 = cc.Encrypt(key_pair.publicKey, plaintext1)

    t = time.time()
    result = cc.EvalPoly(ciphertext1, coefficients1)
    time_eval_poly1 = (time.time() - t) * 1000

    t = time.time()
    result2 = cc.EvalPoly(ciphertext1, coefficients2)
    time_eval_poly2 = (time.time() - t) * 1000

    plaintext_dec = cc.Decrypt(key_pair.secretKey, result)
    plaintext_dec.SetLength(encoded_length)

    plaintext_dec2 = cc.Decrypt(key_pair.secretKey, result2)
    plaintext_dec2.SetLength(encoded_length)

    print(f"\n Original Plaintext #1: \n{plaintext1}")

    print(f"\n Result of evaluating a polynomial with coefficients {coefficients1} \n{plaintext_dec}")

    print("\n Expected result: (0.70519107, 1.38285078, 3.97211180, 5.60215665, 4.86357575) ")

    print(f"\n Evaluation time: {time_eval_poly1:.4f} ms")

    print(f"\n Result of evaluating a polynomial with coefficients {coefficients2} \n{plaintext_dec2}")

    print("\n Expected result: (3.4515092326, 5.3752765397, 4.8993108833, 3.2495023573, 4.0485229982) ")

    print(f"\n Evaluation time: {time_eval_poly2:.4f} ms")


if __name__ == "__main__":
    main(sys.argv[1:])
