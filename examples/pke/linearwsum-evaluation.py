#
# Example of linear weighted sum evaluation using CKKS.
#

from openfhe import *
import time


def main():
    print("\n======EXAMPLE FOR EVAL LINEAR WEIGHTED SUM========\n")

    parameters = CCParamsCKKSRNS()
    parameters.SetMultiplicativeDepth(1)
    parameters.SetScalingModSize(50)
    parameters.SetBatchSize(8)
    parameters.SetSecurityLevel(SecurityLevel.HEStd_NotSet)
    parameters.SetRingDim(2048)
    parameters.SetScalingTechnique(ScalingTechnique.FLEXIBLEAUTO)
    parameters.SetFirstModSize(60)

    cc = GenCryptoContext(parameters)
    cc.Enable(PKESchemeFeature.PKE)
    cc.Enable(PKESchemeFeature.KEYSWITCH)
    cc.Enable(PKESchemeFeature.LEVELEDSHE)
    cc.Enable(PKESchemeFeature.ADVANCEDSHE)

    input = [
        [0.5, 0.7, 0.9, 0.95, 0.93, 1.3],
        [1.2, 1.7, -0.9, 0.85, -0.63, 2],
        [0.5, 0, 1.9, 2.95, -3.93, 3.3],
        [1.5, 0.7, 1.9, 2.95, -3.78, 3.3],
        [0.5, 2.7, 1.9, 0.0, -3.43, 1.3],
        [0.5, 0.7, -1.9, 2.95, 1.96, 0.0],
        [0.0, 0.0, 1.0, 0.0, 0.0, 0.0],
    ]

    encoded_length = len(input)

    coefficients = [0.15, 0.75, 1.25, 1, 0, 0.5, 0.5]

    key_pair = cc.KeyGen()

    print("Generating evaluation key for homomorphic multiplication...", end="")
    cc.EvalMultKeyGen(key_pair.secretKey)
    print("Completed.")

    ciphertext_vec = []
    for i in range(encoded_length):
        plaintext = cc.MakeCKKSPackedPlaintext(input[i])
        ciphertext_vec.append(cc.Encrypt(key_pair.publicKey, plaintext))

    t = time.time()
    result = cc.EvalLinearWSum(ciphertext_vec, coefficients)
    time_eval_linear_wsum = (time.time() - t) * 1000

    unenc_ip = []
    for i in range(len(input[0])):
        x = 0
        for j in range(encoded_length):
            x += input[j][i] * coefficients[j]
        unenc_ip.append(x)

    plaintext_dec = cc.Decrypt(key_pair.secretKey, result)
    plaintext_dec.SetLength(encoded_length)

    print(f"\n Result of evaluating a linear weighted sum with coefficients {coefficients} \n")
    print(plaintext_dec)

    print(f"\n Expected result: {unenc_ip}")

    print(f"\n Evaluation time: {time_eval_linear_wsum:.4f} ms")


if __name__ == "__main__":
    main()
