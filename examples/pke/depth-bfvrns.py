#
# Example of a computation circuit of depth 3.
# BFVrns demo for a homomorphic multiplication of depth 6 and three different
# approaches for depth-3 multiplications
#

from openfhe import *
import math
import time


def main():
    ############################################################
    # Set-up of parameters
    ############################################################

    print("\nThis code demonstrates the use of the BFVrns scheme for homomorphic multiplication. ")
    print("This code shows how to auto-generate parameters during run-time based on desired plaintext moduli and security levels. ")
    print("In this demonstration we use three input plaintext and show how to both add them together and multiply them together. ")

    parameters = CCParamsBFVRNS()
    parameters.SetPlaintextModulus(536903681)
    parameters.SetMultiplicativeDepth(3)
    parameters.SetMaxRelinSkDeg(3)

    crypto_context = GenCryptoContext(parameters)
    # enable features that you wish to use
    crypto_context.Enable(PKESchemeFeature.PKE)
    crypto_context.Enable(PKESchemeFeature.KEYSWITCH)
    crypto_context.Enable(PKESchemeFeature.LEVELEDSHE)
    crypto_context.Enable(PKESchemeFeature.ADVANCEDSHE)

    print(f"\np = {crypto_context.GetPlaintextModulus()}")
    print(f"n = {crypto_context.GetCyclotomicOrder() // 2}")
    print(f"log2 q = {math.log2(crypto_context.GetModulus())}")

    ############################################################
    # Perform Key Generation Operation
    ############################################################

    print("\nRunning key generation (used for source data)...")

    t = time.time()
    key_pair = crypto_context.KeyGen()
    processing_time = (time.time() - t) * 1000
    print(f"Key generation time: {processing_time}ms")

    print("Running key generation for homomorphic multiplication evaluation keys...")

    t = time.time()
    crypto_context.EvalMultKeysGen(key_pair.secretKey)
    processing_time = (time.time() - t) * 1000
    print(f"Key generation time for homomorphic multiplication evaluation keys: {processing_time}ms")

    ############################################################
    # Encode source data
    ############################################################

    vector_of_ints1 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]
    plaintext1 = crypto_context.MakePackedPlaintext(vector_of_ints1)

    vector_of_ints2 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]
    plaintext2 = crypto_context.MakePackedPlaintext(vector_of_ints2)

    vector_of_ints3 = [2, 1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]
    plaintext3 = crypto_context.MakePackedPlaintext(vector_of_ints3)

    vector_of_ints4 = [2, 1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]
    plaintext4 = crypto_context.MakePackedPlaintext(vector_of_ints4)

    vector_of_ints5 = [3, 2, 1, 4, 5, 6, 7, 8, 9, 10, 11, 12]
    plaintext5 = crypto_context.MakePackedPlaintext(vector_of_ints5)

    vector_of_ints6 = [3, 2, 1, 4, 5, 6, 7, 8, 9, 10, 11, 12]
    plaintext6 = crypto_context.MakePackedPlaintext(vector_of_ints6)

    vector_of_ints7 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]
    plaintext7 = crypto_context.MakePackedPlaintext(vector_of_ints7)

    print(f"\nOriginal Plaintext #1: \n{plaintext1}")
    print(f"\nOriginal Plaintext #2: \n{plaintext2}")
    print(f"\nOriginal Plaintext #3: \n{plaintext3}")
    print(f"\nOriginal Plaintext #4: \n{plaintext4}")
    print(f"\nOriginal Plaintext #5: \n{plaintext5}")
    print(f"\nOriginal Plaintext #6: \n{plaintext6}")
    print(f"\nOriginal Plaintext #7: \n{plaintext7}")

    ############################################################
    # Encryption
    ############################################################

    print("\nRunning encryption of all plaintexts... ", end="")

    ciphertexts = []

    t = time.time()
    ciphertexts.append(crypto_context.Encrypt(key_pair.publicKey, plaintext1))
    ciphertexts.append(crypto_context.Encrypt(key_pair.publicKey, plaintext2))
    ciphertexts.append(crypto_context.Encrypt(key_pair.publicKey, plaintext3))
    ciphertexts.append(crypto_context.Encrypt(key_pair.publicKey, plaintext4))
    ciphertexts.append(crypto_context.Encrypt(key_pair.publicKey, plaintext5))
    ciphertexts.append(crypto_context.Encrypt(key_pair.publicKey, plaintext6))
    ciphertexts.append(crypto_context.Encrypt(key_pair.publicKey, plaintext7))
    processing_time = (time.time() - t) * 1000

    print("Completed\n")
    print(f"\nAverage encryption time: {processing_time / 7}ms")

    ############################################################
    # Homomorphic multiplication of 2 ciphertexts
    ############################################################

    t = time.time()
    ciphertext_mult = crypto_context.EvalMult(ciphertexts[0], ciphertexts[1])
    processing_time = (time.time() - t) * 1000
    print(f"\nTotal time of multiplying 2 ciphertexts using EvalMult w/ relinearization: {processing_time}ms")

    t = time.time()
    plaintext_dec_mult = crypto_context.Decrypt(key_pair.secretKey, ciphertext_mult)
    processing_time = (time.time() - t) * 1000
    print(f"\nDecryption time: {processing_time}ms")

    plaintext_dec_mult.SetLength(plaintext1.GetLength())

    print("\nResult of homomorphic multiplication of ciphertexts #1 and #2: ")
    print(plaintext_dec_mult)

    ############################################################
    # Homomorphic multiplication of 7 ciphertexts
    ############################################################

    print("\nRunning a binary-tree multiplication of 7 ciphertexts...", end="")

    t = time.time()
    ciphertext_mult7 = crypto_context.EvalMultMany(ciphertexts)
    processing_time = (time.time() - t) * 1000

    print("Completed\n")
    print(f"\nTotal time of multiplying 7 ciphertexts using EvalMultMany: {processing_time}ms")

    plaintext_dec_mult7 = crypto_context.Decrypt(key_pair.secretKey, ciphertext_mult7)
    plaintext_dec_mult7.SetLength(plaintext1.GetLength())

    print("\nResult of 6 homomorphic multiplications: ")
    print(plaintext_dec_mult7)

    ############################################################
    # Homomorphic multiplication of 3 ciphertexts where relinearization is done
    # at the end
    ############################################################

    print("\nRunning a depth-3 multiplication w/o relinearization until the very end...", end="")

    t = time.time()
    ciphertext_mult12 = crypto_context.EvalMultNoRelin(ciphertexts[0], ciphertexts[1])
    processing_time = (time.time() - t) * 1000

    print("Completed\n")
    print(f"Time of multiplying 2 ciphertexts w/o relinearization: {processing_time}ms")

    ciphertext_mult123 = crypto_context.EvalMultAndRelinearize(ciphertext_mult12, ciphertexts[2])

    plaintext_dec_mult123 = crypto_context.Decrypt(key_pair.secretKey, ciphertext_mult123)
    plaintext_dec_mult123.SetLength(plaintext1.GetLength())

    print("\nResult of 3 homomorphic multiplications: ")
    print(plaintext_dec_mult123)

    ############################################################
    # Homomorphic multiplication of 3 ciphertexts w/o any relinearization
    ############################################################

    print("\nRunning a depth-3 multiplication w/o relinearization...", end="")

    ciphertext_mult12 = crypto_context.EvalMultNoRelin(ciphertexts[0], ciphertexts[1])
    ciphertext_mult123 = crypto_context.EvalMultNoRelin(ciphertext_mult12, ciphertexts[2])

    print("Completed\n")

    plaintext_dec_mult123 = crypto_context.Decrypt(key_pair.secretKey, ciphertext_mult123)
    plaintext_dec_mult123.SetLength(plaintext1.GetLength())

    print("\nResult of 3 homomorphic multiplications: ")
    print(plaintext_dec_mult123)

    ############################################################
    # Homomorphic multiplication of 3 ciphertexts w/ relinearization after each
    # multiplication
    ############################################################

    print("\nRunning a depth-3 multiplication w/ relinearization after each multiplication...", end="")

    t = time.time()
    ciphertext_mult12 = crypto_context.EvalMult(ciphertexts[0], ciphertexts[1])
    processing_time = (time.time() - t) * 1000

    print("Completed\n")
    print(f"Time of multiplying 2 ciphertexts w/ relinearization: {processing_time}ms")

    ciphertext_mult123 = crypto_context.EvalMult(ciphertext_mult12, ciphertexts[2])

    plaintext_dec_mult123 = crypto_context.Decrypt(key_pair.secretKey, ciphertext_mult123)
    plaintext_dec_mult123.SetLength(plaintext1.GetLength())

    print("\nResult of 3 homomorphic multiplications: ")
    print(plaintext_dec_mult123)


if __name__ == "__main__":
    main()
