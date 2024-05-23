# Initial Settings
from openfhe import *

# import openfhe.PKESchemeFeature as Feature


def main():
    # Sample Program: Step 1: Set CryptoContext
    parameters = CCParamsBFVRNS()
    parameters.SetPlaintextModulus(65537)
    parameters.SetMultiplicativeDepth(2)

    crypto_context = GenCryptoContext(parameters)
    # Enable features that you wish to use
    crypto_context.Enable(PKESchemeFeature.PKE)
    crypto_context.Enable(PKESchemeFeature.KEYSWITCH)
    crypto_context.Enable(PKESchemeFeature.LEVELEDSHE)

    # Sample Program: Step 2: Key Generation

    # Generate a public/private key pair
    key_pair = crypto_context.KeyGen()

    # Generate the relinearization key
    crypto_context.EvalMultKeyGen(key_pair.secretKey)

    # Generate the rotation evaluation keys
    crypto_context.EvalRotateKeyGen(key_pair.secretKey, [1, 2, -1, -2])

    # Sample Program: Step 3: Encryption

    # First plaintext vector is encoded
    vector_of_ints1 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]
    plaintext1 = crypto_context.MakePackedPlaintext(vector_of_ints1)

    # Second plaintext vector is encoded
    vector_of_ints2 = [3, 2, 1, 4, 5, 6, 7, 8, 9, 10, 11, 12]
    plaintext2 = crypto_context.MakePackedPlaintext(vector_of_ints2)

    # Third plaintext vector is encoded
    vector_of_ints3 = [1, 2, 5, 2, 5, 6, 7, 8, 9, 10, 11, 12]
    plaintext3 = crypto_context.MakePackedPlaintext(vector_of_ints3)

    # The encoded vectors are encrypted
    ciphertext1 = crypto_context.Encrypt(key_pair.publicKey, plaintext1)
    ciphertext2 = crypto_context.Encrypt(key_pair.publicKey, plaintext2)
    ciphertext3 = crypto_context.Encrypt(key_pair.publicKey, plaintext3)

    #  Sample Program: Step 4: Evaluation

    # Homomorphic additions
    ciphertext_add12 = crypto_context.EvalAdd(ciphertext1, ciphertext2)
    ciphertext_add_result = crypto_context.EvalAdd(ciphertext_add12, ciphertext3)

    # Homomorphic Multiplication
    ciphertext_mult12 = crypto_context.EvalMult(ciphertext1, ciphertext2)
    ciphertext_mult_result = crypto_context.EvalMult(ciphertext_mult12, ciphertext3)

    # Homomorphic Rotations
    ciphertext_rot1 = crypto_context.EvalRotate(ciphertext1, 1)
    ciphertext_rot2 = crypto_context.EvalRotate(ciphertext1, 2)
    ciphertext_rot3 = crypto_context.EvalRotate(ciphertext1, -1)
    ciphertext_rot4 = crypto_context.EvalRotate(ciphertext1, -2)

    # Sample Program: Step 5: Decryption

    # Decrypt the result of additions
    plaintext_add_result = crypto_context.Decrypt(
        ciphertext_add_result, key_pair.secretKey
    )

    # Decrypt the result of multiplications
    plaintext_mult_result = crypto_context.Decrypt(
        ciphertext_mult_result, key_pair.secretKey
    )

    # Decrypt the result of rotations
    plaintextRot1 = crypto_context.Decrypt(ciphertext_rot1, key_pair.secretKey)
    plaintextRot2 = crypto_context.Decrypt(ciphertext_rot2, key_pair.secretKey)
    plaintextRot3 = crypto_context.Decrypt(ciphertext_rot3, key_pair.secretKey)
    plaintextRot4 = crypto_context.Decrypt(ciphertext_rot4, key_pair.secretKey)

    plaintextRot1.SetLength(len(vector_of_ints1))
    plaintextRot2.SetLength(len(vector_of_ints1))
    plaintextRot3.SetLength(len(vector_of_ints1))
    plaintextRot4.SetLength(len(vector_of_ints1))

    print("Plaintext #1: " + str(plaintext1))
    print("Plaintext #2: " + str(plaintext2))
    print("Plaintext #3: " + str(plaintext3))

    # Output Results
    print("\nResults of homomorphic computations")
    print("#1 + #2 + #3 = " + str(plaintext_add_result))
    print("#1 * #2 * #3 = " + str(plaintext_mult_result))
    print("Left rotation of #1 by 1 = " + str(plaintextRot1))
    print("Left rotation of #1 by 2 = " + str(plaintextRot2))
    print("Right rotation of #1 by 1 = " + str(plaintextRot3))
    print("Right rotation of #1 by 2 = " + str(plaintextRot4))


if __name__ == "__main__":
    main()
