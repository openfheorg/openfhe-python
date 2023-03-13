# Initial Settings
from openfhe import *
# import openfhe.PKESchemeFeature as Feature


# Sample Program: Step 1: Set CryptoContext
parameters = CCParamsBFVRNS()
parameters.SetPlaintextModulus(65537)
parameters.SetMultiplicativeDepth(2)

cryptoContext = GenCryptoContext(parameters)
# Enable features that you wish to use
cryptoContext.Enable(PKESchemeFeature.PKE)
cryptoContext.Enable(PKESchemeFeature.KEYSWITCH)
cryptoContext.Enable(PKESchemeFeature.LEVELEDSHE)

# Sample Program: Step 2: Key Generation

# Generate a public/private key pair
keypair = cryptoContext.KeyGen()

# Generate the relinearization key
cryptoContext.EvalMultKeyGen(keypair.secretKey)

# Generate the rotation evaluation keys
cryptoContext.EvalRotateKeyGen(keypair.secretKey, [1, 2, -1, -2])

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

#  Sample Program: Step 4: Evaluation

# Homomorphic additions
ciphertextAdd12 = cryptoContext.EvalAdd(ciphertext1, ciphertext2)
ciphertextAddResult = cryptoContext.EvalAdd(ciphertextAdd12, ciphertext3)

# Homomorphic Multiplication
ciphertextMult12 = cryptoContext.EvalMult(ciphertext1, ciphertext2)
ciphertextMultResult = cryptoContext.EvalMult(ciphertextMult12, ciphertext3)

# Homomorphic Rotations
ciphertextRot1 = cryptoContext.EvalRotate(ciphertext1, 1)
ciphertextRot2 = cryptoContext.EvalRotate(ciphertext1, 2)
ciphertextRot3 = cryptoContext.EvalRotate(ciphertext1, -1)
ciphertextRot4 = cryptoContext.EvalRotate(ciphertext1, -2)

# Sample Program: Step 5: Decryption

# Decrypt the result of additions
plaintextAddResult = Decrypt(ciphertextAddResult,keypair.secretKey)

# Decrypt the result of multiplications
plaintextMultResult = Decrypt(ciphertextMultResult,keypair.secretKey)

# Decrypt the result of rotations
plaintextRot1 = Decrypt(ciphertextRot1,keypair.secretKey)
plaintextRot2 = Decrypt(ciphertextRot2,keypair.secretKey)
plaintextRot3 = Decrypt(ciphertextRot3,keypair.secretKey)
plaintextRot4 = Decrypt(ciphertextRot4,keypair.secretKey)


plaintextRot1.SetLength(len(vectorOfInts1))
plaintextRot2.SetLength(len(vectorOfInts1))
plaintextRot3.SetLength(len(vectorOfInts1))
plaintextRot4.SetLength(len(vectorOfInts1))

print("Plaintext #1: " + str(plaintext1))
print("Plaintext #2: " + str(plaintext2))
print("Plaintext #3: " + str(plaintext3))

# Output Results
print("\nResults of homomorphic computations")
print("#1 + #2 + #3 = " + str(plaintextAddResult))
print("#1 * #2 * #3 = " + str(plaintextMultResult))
print("Left rotation of #1 by 1 = " + str(plaintextRot1))
print("Left rotation of #1 by 2 = " + str(plaintextRot2))
print("Right rotation of #1 by 1 = " + str(plaintextRot3))
print("Right rotation of #1 by 2 = " + str(plaintextRot4))