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

# Serialize cryptocontext
if not SerializeToFile(datafolder + "/cryptocontext.txt", cryptoContext, BINARY):
   raise Exception("Error writing serialization of the crypto context to cryptocontext.txt")

print("The cryptocontext has been serialized.")

# Sample Program: Step 2: Key Generation

# Generate a public/private key pair
keypair = cryptoContext.KeyGen()

print("The keypair has been generated.")

# Serialize the public key
if not SerializeToFile(datafolder + "/key-public.txt", keypair.publicKey, BINARY):
   raise Exception("Error writing serialization of the public key to key-public.txt")

print("The public key has been serialized.")

# Serialize the secret key
if not SerializeToFile(datafolder + "/key-secret.txt", keypair.secretKey, BINARY):
   raise Exception("Error writing serialization of the secret key to key-secret.txt")

print("The secret key has been serialized.")

# Generate the relinearization key
cryptoContext.EvalMultKeyGen(keypair.secretKey)

print("The relinearization key has been generated.")

# Serialize the relinearization key

if not cryptoContext.SerializeEvalMultKey(datafolder + "/key-relin.txt",BINARY):
   raise Exception("Error writing serialization of the eval mult keys to \"key-eval-mult.txt\"")

print("The relinearization key has been serialized.")




