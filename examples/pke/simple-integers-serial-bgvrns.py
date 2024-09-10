# Initial Settings
from openfhe import *
import tempfile
import os

# import openfhe.PKESchemeFeature as Feature

datafolder = "demoData"


def main_action():
    serType = BINARY  # BINARY or JSON
    print(
        "This program requres the subdirectory `"
        + datafolder
        + "' to exist, otherwise you will get an error writing serializations."
    )

    # Sample Program: Step 1: Set CryptoContext
    parameters = CCParamsBGVRNS()
    parameters.SetPlaintextModulus(65537)
    parameters.SetMultiplicativeDepth(2)

    cryptoContext = GenCryptoContext(parameters)
    # Enable features that you wish to use
    cryptoContext.Enable(PKESchemeFeature.PKE)
    cryptoContext.Enable(PKESchemeFeature.KEYSWITCH)
    cryptoContext.Enable(PKESchemeFeature.LEVELEDSHE)

    # Serialize cryptocontext
    if not SerializeToFile(datafolder + "/cryptocontext.txt", cryptoContext, serType):
        raise Exception(
            "Error writing serialization of the crypto context to cryptocontext.txt"
        )
    print("The cryptocontext has been serialized.")

    # Sample Program: Step 2: Key Generation

    # Generate a public/private key pair
    keypair = cryptoContext.KeyGen()
    print("The keypair has been generated.")

    # Serialize the public key
    if not SerializeToFile(datafolder + "/key-public.txt", keypair.publicKey, serType):
        raise Exception(
            "Error writing serialization of the public key to key-public.txt"
        )
    print("The public key has been serialized.")

    # Serialize the secret key
    if not SerializeToFile(datafolder + "/key-private.txt", keypair.secretKey, serType):
        raise Exception(
            "Error writing serialization of the secret key to key-private.txt"
        )
    print("The secret key has been serialized.")

    # Generate the relinearization key
    cryptoContext.EvalMultKeyGen(keypair.secretKey)
    print("The relinearization key has been generated.")

    # Serialize the relinearization key
    if not cryptoContext.SerializeEvalMultKey(
        datafolder + "/key-eval-mult.txt", serType
    ):
        raise Exception(
            'Error writing serialization of the eval mult keys to "key-eval-mult.txt"'
        )
    print("The relinearization key has been serialized.")

    # Generate the rotation evaluation keys
    cryptoContext.EvalRotateKeyGen(keypair.secretKey, [1, 2, -1, -2])
    print("The rotation evaluation keys have been generated.")

    # Serialize the rotation evaluation keys
    if not cryptoContext.SerializeEvalAutomorphismKey(
        datafolder + "/key-eval-rot.txt", serType
    ):
        raise Exception(
            'Error writing serialization of the eval rotate keys to "key-eval-rot.txt"'
        )
    print("The rotation evaluation keys have been serialized.")

    # Sample Program: Step 3: Encryption

    # First plaintext vector is encoded
    vectorOfInts1 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]
    plaintext1 = cryptoContext.MakePackedPlaintext(vectorOfInts1)

    # Second plaintext vector is encoded
    vectorOfInts2 = [3, 2, 1, 4, 5, 6, 7, 8, 9, 10, 11, 12]
    plaintext2 = cryptoContext.MakePackedPlaintext(vectorOfInts2)

    # Third plaintext vector is encoded
    vectorOfInts3 = [1, 2, 5, 2, 5, 6, 7, 8, 9, 10, 11, 12]
    plaintext3 = cryptoContext.MakePackedPlaintext(vectorOfInts3)

    # The encoded vectors are encrypted
    ciphertext1 = cryptoContext.Encrypt(keypair.publicKey, plaintext1)
    ciphertext2 = cryptoContext.Encrypt(keypair.publicKey, plaintext2)
    ciphertext3 = cryptoContext.Encrypt(keypair.publicKey, plaintext3)
    print("The plaintexts have been encrypted.")

    if not SerializeToFile(datafolder + "/ciphertext1.txt", ciphertext1, serType):
        raise Exception(
            "Error writing serialization of ciphertext 1 to ciphertext1.txt"
        )
    print("The first ciphertext has been serialized.")

    if not SerializeToFile(datafolder + "/ciphertext2.txt", ciphertext2, serType):
        raise Exception("Error writing serialization of ciphertext2 to ciphertext2.txt")
    print("The second ciphertext has been serialized.")

    if not SerializeToFile(datafolder + "/ciphertext3.txt", ciphertext3, serType):
        raise Exception("Error writing serialization of ciphertext3 to ciphertext3.txt")
    print("The third ciphertext has been serialized.")

    # Sample Program: Step 4: Evaluation

    # OpenFHE maintains an internal map of CryptoContext objects which are
    # indexed by a tag and the tag is applied to both the CryptoContext and some
    # of the keys. When deserializing a context, OpenFHE checks for the tag and
    # if it finds it in the CryptoContext map, it will return the stored version.
    # Hence, we need to clear the context and clear the keys.
    ClearEvalMultKeys()
    cryptoContext.ClearEvalAutomorphismKeys()
    ReleaseAllContexts()

    # Deserialize the crypto context

    cc, res = DeserializeCryptoContext(datafolder + "/cryptocontext.txt", serType)
    if not res:
        raise Exception(
            "Error reading serialization of the crypto context from cryptocontext.txt"
        )
    print("The cryptocontext has been deserialized.")

    # Deserialize the public key
    pk, res = DeserializePublicKey(datafolder + "/key-public.txt", serType)

    if not res:
        raise Exception(
            "Error reading serialization of the public key from key-public.txt"
        )
    print("The public key has been deserialized.")

    if not cc.DeserializeEvalMultKey(datafolder + "/key-eval-mult.txt", serType):
        raise Exception("Could not deserialize the eval mult key file")

    print("The relinearization key has been deserialized.")

    if not cc.DeserializeEvalAutomorphismKey(datafolder + "/key-eval-rot.txt", serType):
        raise Exception("Could not deserialize the eval rotation key file")

    print("Deserialized the eval rotation keys.")

    # Deserialize the ciphertexts
    ct1, res = DeserializeCiphertext(datafolder + "/ciphertext1.txt", serType)

    if not res:
        raise Exception("Could not read the ciphertext")
    print("The first ciphertext has been deserialized.")

    ct2, res = DeserializeCiphertext(datafolder + "/ciphertext2.txt", serType)

    if not res:
        raise Exception("Could not read the ciphertext")
    print("The second ciphertext has been deserialized.")

    ct3, res = DeserializeCiphertext(datafolder + "/ciphertext3.txt", serType)
    if not res:
        raise Exception("Could not read the ciphertext")
    print("The third ciphertext has been deserialized.")

    # Homomorphic addition

    ciphertextAdd12 = cc.EvalAdd(ct1, ct2)
    ciphertextAddResult = cc.EvalAdd(ciphertextAdd12, ct3)

    # Homomorphic multiplication
    ciphertextMult12 = cc.EvalMult(ct1, ct2)
    ciphertextMultResult = cc.EvalMult(ciphertextMult12, ct3)

    # Homomorphic rotation
    ciphertextRot1 = cc.EvalRotate(ct1, 1)
    ciphertextRot2 = cc.EvalRotate(ct2, 2)
    ciphertextRot3 = cc.EvalRotate(ct3, -1)
    ciphertextRot4 = cc.EvalRotate(ct3, -2)

    # Sample Program: Step 5: Decryption

    sk, res = DeserializePrivateKey(datafolder + "/key-private.txt", serType)
    if not res:
        raise Exception("Could not read secret key")
    print("The secret key has been deserialized.")

    # Decrypt the result of additions
    plaintextAddResult = cc.Decrypt(sk, ciphertextAddResult)

    # Decrypt the result of multiplications
    plaintextMultResult = cc.Decrypt(sk, ciphertextMultResult)

    # Decrypt the result of rotations
    plaintextRot1 = cc.Decrypt(sk, ciphertextRot1)
    plaintextRot2 = cc.Decrypt(sk, ciphertextRot2)
    plaintextRot3 = cc.Decrypt(sk, ciphertextRot3)
    plaintextRot4 = cc.Decrypt(sk, ciphertextRot4)

    # Shows only the same number of elements as in the original plaintext vector
    # By default it will show all coefficients in the BFV-encoded polynomial
    plaintextRot1.SetLength(len(vectorOfInts1))
    plaintextRot2.SetLength(len(vectorOfInts1))
    plaintextRot3.SetLength(len(vectorOfInts1))
    plaintextRot4.SetLength(len(vectorOfInts1))

    # Output results
    print("\nResults of homomorphic computations")
    print("#1 + #2 + #3: " + str(plaintextAddResult))
    print("#1 * #2 * #3: " + str(plaintextMultResult))
    print("Left rotation of #1 by 1: " + str(plaintextRot1))
    print("Left rotation of #1 by 2: " + str(plaintextRot2))
    print("Right rotation of #1 by 1: " + str(plaintextRot3))
    print("Right rotation of #1 by 2: " + str(plaintextRot4))


def main():
    global datafolder
    with tempfile.TemporaryDirectory() as td:
        datafolder = td + "/" + datafolder
        os.mkdir(datafolder)
        main_action()


if __name__ == "__main__":
    main()
