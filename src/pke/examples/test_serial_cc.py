# Initial Settings
from openfhe import *
# import openfhe.PKESchemeFeature as Feature

datafolder = 'demoData'

print("This program requres the subdirectory `" + datafolder + "' to exist, otherwise you will get an error writing serializations.")

# Sample Program: Step 1: Set CryptoContext
parameters = CCParamsBFVRNS()
parameters.SetPlaintextModulus(65537)
parameters.SetMultiplicativeDepth(2)

cryptoContext = GenCryptoContext(parameters)
# Enable features that you wish to use
cryptoContext.Enable(PKESchemeFeature.PKE)
cryptoContext.Enable(PKESchemeFeature.KEYSWITCH)
cryptoContext.Enable(PKESchemeFeature.LEVELEDSHE)

keypair = cryptoContext.KeyGen()
vectorOfInts1 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]
plaintext1 = cryptoContext.MakePackedPlaintext(vectorOfInts1)
ciphertext1 = cryptoContext.Encrypt(keypair.publicKey, plaintext1)

# Serialize cryptocontext
if not SerializeToFile(datafolder + "/cryptocontext.json", cryptoContext, JSON):
   raise Exception("Error writing serialization of the crypto context to cryptocontext.json")
print("The cryptocontext has been serialized.")
# Serialize Ciphertext
if not SerializeToFile(datafolder + "/ciphertext1.json", ciphertext1, JSON):
   raise Exception("Error writing serialization of the ciphertext to ciphertext1.json")

cryptoContext.ClearEvalMultKeys()
cryptoContext.ClearEvalAutomorphismKeys()
ReleaseAllContexts()
# Deserialize the crypto context
#cc = CryptoContext()

res, cc = DeserializeFromFiletuple(datafolder + "/cryptocontext.json", JSON)
if not res:
   raise Exception("Error reading serialization of the crypto context from cryptocontext.txt")
# cc = DeserializeFromFile2(datafolder + "/cryptocontext.json", JSON)
# print("The cryptocontext has been deserialized.")
# Serialize cryptocontext again
if not SerializeToFile(datafolder + "/cryptocontext2.json", cc, JSON):
   raise Exception("Error writing serialization of the crypto context to cryptocontext.json")
print("The cryptocontext has been serialized.")

ct1 = Ciphertext()
# Deserialize the ciphertext
if not DeserializeFromFile(datafolder + "/ciphertext1.json", ct1, JSON):
   raise Exception("Error reading serialization of the ciphertext from ciphertext1.txt")

# Serialize the ciphertext again
if not SerializeToFile(datafolder + "/ciphertext12.json", ct1, JSON):
   raise Exception("Error writing serialization of the ciphertext to ciphertext2.json")



