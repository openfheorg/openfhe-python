# Initial Setting
from openfhe import *
# import openfhe.PKESchemeFeature as Feature
# Creating the parameters object
parameters = CCParamsBFVRNS()

# Printing Default Multip. Depth and Plaintext Modulus
print("Default BFV Plaintext Modulus = " + str(parameters.GetPlaintextModulus()))
print("Default BFV Multiplicative Depth = " + str(parameters.GetMultiplicativeDepth()))

# Setting different values
parameters.SetPlaintextModulus(65537)
parameters.SetMultiplicativeDepth(2)

# Getting new values
print("New BFV Plaintext Modulus = " + str(parameters.GetPlaintextModulus()))
print("New BFV Multiplicative Depth = " + str(parameters.GetMultiplicativeDepth()))

cryptoContext = GenCryptoContext(parameters)

cryptoContext.SetKeyGenLevel(2)
print(cryptoContext.GetKeyGenLevel())
print(PKESchemeFeature.__members__)
cryptoContext.Enable(PKESchemeFeature.PKE)
cryptoContext.Enable(PKESchemeFeature.KEYSWITCH)
cryptoContext.Enable(PKESchemeFeature.LEVELEDSHE)

keypair = cryptoContext.KeyGen()
print("Public Key: " + str(keypair.publicKey))

cryptoContext.EvalMultKeyGen(keypair.secretKey)
cryptoContext.EvalRotateKeyGen(keypair.secretKey, [1, 2, -1, -2]);

vectorOfInts1 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]
vectorOfInts2 = [3, 2, 1, 4, 5, 6, 7, 8, 9, 10, 11, 12]
vectorOfInts3 = [1, 2, 5, 2, 5, 6, 7, 8, 9, 10, 11, 12]
plaintext1 = cryptoContext.MakePackedPlaintext(vectorOfInts1)
plaintext2 = cryptoContext.MakePackedPlaintext(vectorOfInts2)
plaintext3 = cryptoContext.MakePackedPlaintext(vectorOfInts3)



ciphertext1 = cryptoContext.Encrypt(keypair.publicKey, plaintext1)
ciphertextRot1 = cryptoContext.EvalRotate(ciphertext1, 1)