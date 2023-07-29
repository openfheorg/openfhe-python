from openfhe import *
import math

def main():
    eval_logistic_example()
    eval_function_example()

def eval_logistic_example():
    print("--------------------------------- EVAL LOGISTIC FUNCTION ---------------------------------\n")
    parameters = CCParamsCKKSRNS()
    parameters.SetSecurityLevel(SecurityLevel.HEStd_NotSet)
    parameters.SetRingDim(1 << 10)

    scaling_mod_size = 59
    first_mod_size = 60

    parameters.SetScalingModSize(scaling_mod_size)
    parameters.SetFirstModSize(first_mod_size)

    poly_degree = 16
    mult_depth = 6

    parameters.SetMultiplicativeDepth(mult_depth)
    cc = GenCryptoContext(parameters)
    cc.Enable(PKESchemeFeature.PKE)
    cc.Enable(PKESchemeFeature.KEYSWITCH)
    cc.Enable(PKESchemeFeature.LEVELEDSHE)
    cc.Enable(PKESchemeFeature.ADVANCEDSHE)

    key_pair = cc.KeyGen()
    cc.EvalMultKeyGen(key_pair.secretKey)

    input = [-4, -3, -2, -1, 0, 1, 2, 3, 4]
    encoded_length = len(input)
    plaintext = cc.MakeCKKSPackedPlaintext(input)
    ciphertext = cc.Encrypt(key_pair.publicKey, plaintext)

    lower_bound = -4
    upper_bound = 4
    result = cc.EvalLogistic(ciphertext, lower_bound, upper_bound, poly_degree)

    plaintext_dec = cc.Decrypt(result, key_pair.secretKey)
    plaintext_dec.SetLength(encoded_length)

    expected_output = [0.0179885, 0.0474289, 0.119205, 0.268936, 0.5, 0.731064, 0.880795, 0.952571, 0.982011]
    print(f"Expected output\n\t {expected_output}\n")

    final_result = plaintext_dec.GetCKKSPackedValue()
    print(f"Actual output\n\t {final_result}\n")

def eval_function_example():
    print("--------------------------------- EVAL SQUARE ROOT FUNCTION ---------------------------------\n")
    parameters = CCParamsCKKSRNS()
    parameters.SetSecurityLevel(SecurityLevel.HEStd_NotSet)
    parameters.SetRingDim(1 << 10)

    if get_native_int() == 128:
        scaling_mod_size = 78
        first_mod_size = 89
    else:
        scaling_mod_size = 50
        first_mod_size = 60

    parameters.SetScalingModSize(scaling_mod_size)
    parameters.SetFirstModSize(first_mod_size)

    poly_degree = 50
    mult_depth = 7

    parameters.SetMultiplicativeDepth(mult_depth)
    cc = GenCryptoContext(parameters)
    cc.Enable(PKESchemeFeature.PKE)
    cc.Enable(PKESchemeFeature.KEYSWITCH)
    cc.Enable(PKESchemeFeature.LEVELEDSHE)
    cc.Enable(PKESchemeFeature.ADVANCEDSHE)

    key_pair = cc.KeyGen()
    cc.EvalMultKeyGen(key_pair.secretKey)

    input = [1, 2, 3, 4, 5, 6, 7, 8, 9]
    encoded_length = len(input)
    plaintext = cc.MakeCKKSPackedPlaintext(input)
    ciphertext = cc.Encrypt(key_pair.publicKey, plaintext)

    lower_bound = 0
    upper_bound = 10
    result = cc.EvalChebyshevFunction(math.sqrt,ciphertext, lower_bound, upper_bound, poly_degree)

    plaintext_dec = cc.Decrypt(result, key_pair.secretKey)
    plaintext_dec.SetLength(encoded_length)

    expected_output = [1, 1.414213, 1.732050, 2, 2.236067, 2.449489, 2.645751, 2.828427, 3]
    print(f"Expected output\n\t {expected_output}\n")

    final_result = plaintext_dec.GetCKKSPackedValue()
    print(f"Actual output\n\t {final_result}\n")
if __name__ == "__main__":
    main()