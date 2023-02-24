# Initial Setting
from openfhe import *

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