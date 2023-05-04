from openfhe import *
import math

def main():
    EvalLogisticExample()
    EvalFunctionExample()

def EvalLogisticExample():
    print("--------------------------------- EVAL LOGISTIC FUNCTION ---------------------------------\n")
    parameters = CCParamsCKKSRNS()
    parameters.SetSecurityLevel(SecurityLevel.HEStd_NotSet)
    parameters.SetRingDim(1 << 10)

    scalingModSize = 59
    firstModSize = 60

    parameters.SetScalingModSize(scalingModSize)
    parameters.SetFirstModSize(firstModSize)

    polyDegree = 16
    multDepth = 6

    parameters.SetMultiplicativeDepth(multDepth)
    cc = GenCryptoContext(parameters)
    cc.Enable(PKESchemeFeature.PKE)
    cc.Enable(PKESchemeFeature.KEYSWITCH)
    cc.Enable(PKESchemeFeature.LEVELEDSHE)
    cc.Enable(PKESchemeFeature.ADVANCEDSHE)

    keyPair = cc.KeyGen()
    cc.EvalMultKeyGen(keyPair.secretKey)

    input = [-4, -3, -2, -1, 0, 1, 2, 3, 4]
    encodedLength = len(input)
    plaintext = cc.MakeCKKSPackedPlaintext(input)
    ciphertext = cc.Encrypt(keyPair.publicKey, plaintext)

    lowerBound = -4
    upperBound = 4
    result = cc.EvalLogistic(ciphertext, lowerBound, upperBound, polyDegree)

    plaitextDec = Decrypt(result, keyPair.secretKey)
    plaitextDec.SetLength(encodedLength)

    expectedOutput = [0.0179885, 0.0474289, 0.119205, 0.268936, 0.5, 0.731064, 0.880795, 0.952571, 0.982011]
    print(f"Expected output\n\t {expectedOutput}\n")

    finalResult = plaitextDec.GetCKKSPackedValue()
    print(f"Actual output\n\t {finalResult}\n")

def EvalFunctionExample():
    print("--------------------------------- EVAL SQUARE ROOT FUNCTION ---------------------------------\n")
    parameters = CCParamsCKKSRNS()
    parameters.SetSecurityLevel(SecurityLevel.HEStd_NotSet)
    parameters.SetRingDim(1 << 10)

    scalingModSize = 59
    firstModSize = 60

    parameters.SetScalingModSize(scalingModSize)
    parameters.SetFirstModSize(firstModSize)

    polyDegree = 50
    multDepth = 7

    parameters.SetMultiplicativeDepth(multDepth)
    cc = GenCryptoContext(parameters)
    cc.Enable(PKESchemeFeature.PKE)
    cc.Enable(PKESchemeFeature.KEYSWITCH)
    cc.Enable(PKESchemeFeature.LEVELEDSHE)
    cc.Enable(PKESchemeFeature.ADVANCEDSHE)

    keyPair = cc.KeyGen()
    cc.EvalMultKeyGen(keyPair.secretKey)

    input = [1, 2, 3, 4, 5, 6, 7, 8, 9]
    encodedLength = len(input)
    plaintext = cc.MakeCKKSPackedPlaintext(input)
    ciphertext = cc.Encrypt(keyPair.publicKey, plaintext)

    lowerBound = 1
    upperBound = 9
    result = cc.EvalChebyshevFunction(math.sqrt,ciphertext, lowerBound, upperBound, polyDegree)

    plaintextDec = Decrypt(result, keyPair.secretKey)
    plaintextDec.SetLength(encodedLength)

    expectedOutput = [1, 1.414213, 1.732050, 2, 2.236067, 2.449489, 2.645751, 2.828427, 3]
    print(f"Expected output\n\t {expectedOutput}\n")

    finalResult = plaintextDec.GetCKKSPackedValue()
    print(f"Actual output\n\t {finalResult}\n")
if __name__ == "__main__":
    main()