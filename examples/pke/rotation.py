#
# Example of vector rotation.
# This code shows how the EvalRotate and EvalMerge operations work
#

from openfhe import *


def main():
    print("\nThis code shows how the EvalRotate and EvalMerge operations work "
          "for different cyclotomic rings (both power-of-two and cyclic).\n")

    print("\n========== BFVrns.EvalRotate - Power-of-Two Cyclotomics ===========")
    bfvrns_eval_rotate_2n()

    print("\n========== CKKS.EvalRotate - Power-of-Two Cyclotomics ===========")
    ckks_eval_rotate_2n()

    print("\n========== BFVrns.EvalMerge - Power-of-Two Cyclotomics ===========")
    bfvrns_eval_merge_2n()


def bfvrns_eval_rotate_2n():
    parameters = CCParamsBFVRNS()
    parameters.SetPlaintextModulus(65537)
    parameters.SetMaxRelinSkDeg(3)

    cc = GenCryptoContext(parameters)
    # enable features that you wish to use
    cc.Enable(PKESchemeFeature.PKE)
    cc.Enable(PKESchemeFeature.KEYSWITCH)
    cc.Enable(PKESchemeFeature.LEVELEDSHE)

    n = cc.GetCyclotomicOrder() // 2

    # Initialize the public key containers.
    kp = cc.KeyGen()

    index_list = [2, 3, 4, 5, 6, 7, 8, 9, 10, -n + 2, -n + 3, n - 1, n - 2, -1, -2, -3, -4, -5]

    cc.EvalRotateKeyGen(kp.secretKey, index_list)

    vector_of_ints = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
    vector_of_ints += [0] * (n - len(vector_of_ints))
    vector_of_ints[n - 1] = n
    vector_of_ints[n - 2] = n - 1
    vector_of_ints[n - 3] = n - 2

    int_array = cc.MakePackedPlaintext(vector_of_ints)

    ciphertext = cc.Encrypt(kp.publicKey, int_array)

    for i in range(18):
        permuted_ciphertext = cc.EvalRotate(ciphertext, index_list[i])

        int_array_new = cc.Decrypt(kp.secretKey, permuted_ciphertext)
        int_array_new.SetLength(10)

        print(f"Automorphed array - at index {index_list[i]}: {int_array_new}")


def ckks_eval_rotate_2n():
    parameters = CCParamsCKKSRNS()
    parameters.SetMultiplicativeDepth(2)
    parameters.SetScalingModSize(40)

    cc = GenCryptoContext(parameters)
    cc.Enable(PKESchemeFeature.PKE)
    cc.Enable(PKESchemeFeature.KEYSWITCH)
    cc.Enable(PKESchemeFeature.LEVELEDSHE)

    cycl_order = cc.GetCyclotomicOrder()

    # Initialize the public key containers.
    kp = cc.KeyGen()

    n = cycl_order // 4
    index_list = [2, 3, 4, 5, 6, 7, 8, 9, 10, -n + 2, -n + 3, n - 1, n - 2, -1, -2, -3, -4, -5]

    cc.EvalRotateKeyGen(kp.secretKey, index_list)

    vector_of_ints = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
    vector_of_ints += [0] * (n - len(vector_of_ints))
    vector_of_ints[n - 1] = n
    vector_of_ints[n - 2] = n - 1
    vector_of_ints[n - 3] = n - 2

    int_array = cc.MakeCKKSPackedPlaintext(vector_of_ints)

    ciphertext = cc.Encrypt(kp.publicKey, int_array)

    for i in range(18):
        permuted_ciphertext = cc.EvalRotate(ciphertext, index_list[i])

        int_array_new = cc.Decrypt(kp.secretKey, permuted_ciphertext)
        int_array_new.SetLength(10)

        print(f"Automorphed array - at index {index_list[i]}: {int_array_new}")


def bfvrns_eval_merge_2n():
    parameters = CCParamsBFVRNS()
    parameters.SetPlaintextModulus(65537)
    parameters.SetMultiplicativeDepth(2)
    parameters.SetMaxRelinSkDeg(3)

    cc = GenCryptoContext(parameters)
    # enable features that you wish to use
    cc.Enable(PKESchemeFeature.PKE)
    cc.Enable(PKESchemeFeature.KEYSWITCH)
    cc.Enable(PKESchemeFeature.LEVELEDSHE)
    cc.Enable(PKESchemeFeature.ADVANCEDSHE)

    # Initialize the public key containers.
    kp = cc.KeyGen()

    index_list = [-1, -2, -3, -4, -5]

    cc.EvalRotateKeyGen(kp.secretKey, index_list)

    ciphertexts = []

    vector_of_ints1 = [32, 2, 3, 4, 5, 6, 7, 8, 9, 10]
    int_array1 = cc.MakePackedPlaintext(vector_of_ints1)
    ciphertexts.append(cc.Encrypt(kp.publicKey, int_array1))

    vector_of_ints2 = [2, 2, 3, 4, 5, 6, 7, 8, 9, 10]
    int_array2 = cc.MakePackedPlaintext(vector_of_ints2)
    ciphertexts.append(cc.Encrypt(kp.publicKey, int_array2))

    vector_of_ints3 = [4, 2, 3, 4, 5, 6, 7, 8, 9, 10]
    int_array3 = cc.MakePackedPlaintext(vector_of_ints3)
    ciphertexts.append(cc.Encrypt(kp.publicKey, int_array3))

    vector_of_ints4 = [8, 2, 3, 4, 5, 6, 7, 8, 9, 10]
    int_array4 = cc.MakePackedPlaintext(vector_of_ints4)
    ciphertexts.append(cc.Encrypt(kp.publicKey, int_array4))

    vector_of_ints5 = [16, 2, 3, 4, 5, 6, 7, 8, 9, 10]
    int_array5 = cc.MakePackedPlaintext(vector_of_ints5)
    ciphertexts.append(cc.Encrypt(kp.publicKey, int_array5))

    print(f"Input ciphertext {int_array1}")
    print(f"Input ciphertext {int_array2}")
    print(f"Input ciphertext {int_array3}")
    print(f"Input ciphertext {int_array4}")
    print(f"Input ciphertext {int_array5}")

    merged_ciphertext = cc.EvalMerge(ciphertexts)

    int_array_new = cc.Decrypt(kp.secretKey, merged_ciphertext)
    int_array_new.SetLength(10)

    print(f"\nMerged ciphertext {int_array_new}")


if __name__ == "__main__":
    main()
