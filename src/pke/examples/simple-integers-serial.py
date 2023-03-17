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

if not SerializeToFile(datafolder + "/cryptocontext.txt", cryptoContext, JSON):
   raise Exception("Error writing serialization of the crypto context to cryptocontext.txt")


