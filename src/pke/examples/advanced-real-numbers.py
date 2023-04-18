from openfhe import *

def AutmaticRescaleDemo(scalTech):
    if(scalTech == ScalingTechnique.FLEXIBLEAUTO):
        print("\n\n\n===== FlexibleAutoDemo =============\n") 
    else:
         print("\n\n\n===== FixedAutoDemo =============\n")

    batchSize = 8
    parameters = CCParamsCKKSRNS()
    parameters.SetMultiplicativeDepth(5)
    parameters.SetScalingModSize(50)
    parameters.SetScalingTechnique(scalTech)
    parameters.SetBatchSize(batchSize)

    cc = GenCryptoContext(parameters)

    print(f"CKKS scheme is using ring dimension {cc.GetRingDimension()}\n")

    cc.Enable(PKESchemeFeature.PKE)
    cc.Enable(PKESchemeFeature.KEYSWITCH)
    cc.Enable(PKESchemeFeature.LEVELEDSHE)

    keys = cc.KeyGen()
    cc.EvalMultKeyGen(keys.secretKey)

    # Input
    x = [1.0, 1.01, 1.02, 1.03, 1.04, 1.05, 1.06, 1.07]
    ptxt = cc.MakeCKKSPackedPlaintext(x)

    print(f"Input x: {ptxt}")

    c = cc.Encrypt(keys.publicKey,ptxt)

    # Computing f(x) = x^18 + x^9 + 1
    #
    # In the following we compute f(x) with a computation
    # that has a multiplicative depth of 5.
    #
    # The result is correct, even though there is no call to
    # the Rescale() operation.

    c2 = cc.EvalMult(c, c)                       # x^2
    c4 = cc.EvalMult(c2, c2)                     # x^4
    c8 = cc.EvalMult(c4, c4)                     # x^8
    c16 = cc.EvalMult(c8, c8)                    # x^16
    c9 = cc.EvalMult(c8, c)                      # x^9
    c18 = cc.EvalMult(c16, c2)                   # x^18
    cRes = cc.EvalAdd(cc.EvalAdd(c18, c9), 1.0)  # Final result

    result = Decrypt(cRes,keys.secretKey)
    print("x^18 + x^9 + 1 = ", result)
    result.SetLength(batchSize)
    print(f"Result: {result}")


AutmaticRescaleDemo(ScalingTechnique.FLEXIBLEAUTO)