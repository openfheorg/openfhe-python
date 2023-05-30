from openfhe import *
import time # to enable TIC-TOC timing measurements

def AutomaticRescaleDemo(scalTech):
    if(scalTech == ScalingTechnique.FLEXIBLEAUTO):
        print("\n\n\n ===== FlexibleAutoDemo =============\n") 
    else:
         print("\n\n\n ===== FixedAutoDemo =============\n")

    batchSize = 8
    parameters = CCParamsCKKSRNS()
    parameters.SetMultiplicativeDepth(6)
    parameters.SetScalingModSize(90)
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

    # Computing f(x) = x^18 + x^9 + d
    #
    # In the following we compute f(x) with a computation
    # that has a multiplicative depth of 5.
    #
    # The result is correct, even though there is no call to
    # the Rescale() operation.

    c2 = cc.EvalMult(c, c)                        # x^2
    c4 = cc.EvalMult(c2, c2)                      # x^4
    c8 = cc.EvalMult(c4, c4)                      # x^8
    c16 = cc.EvalMult(c8, c8)                     # x^16
    c9 = cc.EvalMult(c8, c)                       # x^9
    c18 = cc.EvalMult(c16, c2)                    # x^18
    cRes1 = cc.EvalAdd(cc.EvalAdd(c18, c9), 1.0)  # Final result 1
    cRes2 = cc.EvalSub(cc.EvalAdd(c18,c9), 1.0)   # Final result 2
    cRes3 = cc.EvalMult(cc.EvalAdd(c18,c9), 0.5)  # Final result 3

    result1 = Decrypt(cRes1,keys.secretKey)
    result.SetLength(batchSize)
    print("x^18 + x^9 + 1 = ", result)
    
    result2 = Decrypt(cRes2,keys.secretKey)
    result.SetLength(batchSize)
    print("x^18 + x^9 - 1 = ", result)

    result3 = Decrypt(cRes3,keys.secretKey)
    result.SetLength(batchSize)
    print("0.5 * (x^18 + x^9) = ", result)


def ManualRescaleDemo(ScalingTechnique):
    print("\n\n\n ===== FixedManualDemo =============\n")
    
    batchSize = 8
    parameters = CCParamsCKKSRNS()
    parameters.SetMultiplicativeDepth(5)
    parameters.SetScalingModSize(90)
    parameters.SetBatchSize(batchSize)

    cc = GenCryptoContext(parameters)

    print(f"CKKS scheme is using ring dimension {cc.GetRingDimension()}\n")
    
    cc.Enable(PKESchemeFeature.PKE)
    cc.Enable(PKESchemeFeature.KEYSWITCH)
    cc.Enable(PKESchemeFeature.LEVELEDSHE)

    keys = cc.KeyGen()
    cc.EvalMultKeyGen(keys.secretKey)

    # Input
    x = [1.0, 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7]
    ptxt = cc.MakeCKKSPackedPlaintext(x)

    print(f"Input x: {ptxt}")

    c = cc.Encrypt(keys.publicKey,ptxt)

    # Computing f(x) = x^18 + x^9 + 1
    #
    # Compare the following with the corresponding code
    # for FIXEDAUTO. Here we need to track the depth of ciphertexts
    # and call Rescale whenever needed. In this instance it's still
    # not hard to do so, but this can be quite tedious in other
    # complicated computations. (e.g. in bootstrapping)
    #
    #

    # x^2
    c2_depth2 = cc.EvalMult(c, c)
    c2_depth1 = cc.Rescale(c2_depth2)
    # x^4
    c4_depth2 = cc.EvalMult(c2_depth1, c2_depth1)
    c4_depth1 = cc.Rescale(c4_depth2)
    # x^8
    c8_depth2 = cc.EvalMult(c4_depth1, c4_depth1)
    c8_depth1 = cc.Rescale(c8_depth2)
    # x^16
    c16_depth2 = cc.EvalMult(c8_depth1, c8_depth1)
    c16_depth1 = cc.Rescale(c16_depth2)
    # x^9
    c9_depth2 = cc.EvalMult(c8_depth1, c)
    # x^18
    c18_depth2 = cc.EvalMult(c16_depth1, c2_depth1)
    # Final result
    cRes_depth2 = cc.EvalAdd(cc.EvalAdd(c18_depth2, c9_depth2), 1.0)
    cRes_depth1 = cc.Rescale(cRes_depth2)

    result = Decrypt(cRes_depth1,keys.secretKey)
    result.SetLength(batchSize)
    print("x^18 + x^9 + 1 = ", result)

def HybridKeySwitchingDemo1():
    
    print("\n\n\n ===== HybridKeySwitchingDemo1 ============= \n")
    dnum = 2
    batchSize = 8
    parameters = CCParamsCKKSRNS()
    parameters.SetMultiplicativeDepth(5)
    parameters.SetScalingModSize(90)
    parameters.SetBatchSize(batchSize)
    parameters.SetScalingTechnique(ScalingTechnique.FIXEDAUTO)
    parameters.SetNumLargeDigits(dnum)

    cc = GenCryptoContext(parameters)

    print(f"CKKS scheme is using ring dimension {cc.GetRingDimension()}\n")

    print(f"- Using HYBRID key switching with {dnum} digits\n")

    cc.Enable(PKESchemeFeature.PKE)
    cc.Enable(PKESchemeFeature.KEYSWITCH)
    cc.Enable(PKESchemeFeature.LEVELEDSHE)

    keys = cc.KeyGen()
    cc.EvalRotateKeyGen(keys.secretKey,[1,-2])

    # Input
    x = [1.0, 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7]
    ptxt = cc.MakeCKKSPackedPlaintext(x)

    print(f"Input x: {ptxt}")

    c = cc.Encrypt(keys.publicKey,ptxt)

    t = time.time()
    cRot1 = cc.EvalRotate(c,1)
    cRot2 = cc.EvalRotate(cRot1,-2)
    time2digits = time.time() - t

    result = Decrypt(cRot2,keys.secretKey)
    result.SetLength(batchSize)
    print(f"x rotate by -1 = {result}")
    print(f" - 2 rotations with HYBRID (2 digits) took {time2digits*1000} ms")


def HybridKeySwitchingDemo2():
    print("\n\n\n ===== HybridKeySwitchingDemo2 =============\n")
    dnum = 3
    batchSize = 8
    parameters = CCParamsCKKSRNS()
    parameters.SetMultiplicativeDepth(5)
    parameters.SetScalingModSize(90)
    parameters.SetBatchSize(batchSize)
    parameters.SetScalingTechnique(ScalingTechnique.FIXEDAUTO)
    parameters.SetNumLargeDigits(dnum)

    cc = GenCryptoContext(parameters)

    # Compare the ring dimension in this demo to the one in the previous
    print(f"CKKS scheme is using ring dimension {cc.GetRingDimension()}\n")

    print(f"- Using HYBRID key switching with {dnum} digits\n")

    cc.Enable(PKESchemeFeature.PKE)
    cc.Enable(PKESchemeFeature.KEYSWITCH)
    cc.Enable(PKESchemeFeature.LEVELEDSHE)

    keys = cc.KeyGen()
    cc.EvalRotateKeyGen(keys.secretKey,[1,-2])

    # Input
    x = [1.0, 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7]
    ptxt = cc.MakeCKKSPackedPlaintext(x)

    print(f"Input x: {ptxt}")

    c = cc.Encrypt(keys.publicKey,ptxt)

    t = time.time()
    cRot1 = cc.EvalRotate(c,1)
    cRot2 = cc.EvalRotate(cRot1,-2)
    time3digits = time.time() - t
    # The runtime here is smaller than the previous demo

    result = Decrypt(cRot2,keys.secretKey)
    result.SetLength(batchSize)
    print(f"x rotate by -1 = {result}")
    print(f" - 2 rotations with HYBRID (3 digits) took {time3digits*1000} ms")

def FastRotationDemo1():
    print("\n\n\n ===== FastRotationDemo1 =============\n")
    batchSize = 8
    parameters = CCParamsCKKSRNS()
    parameters.SetMultiplicativeDepth(1)
    parameters.SetScalingModSize(90)
    parameters.SetBatchSize(batchSize)

    cc = GenCryptoContext(parameters)

    N = cc.GetRingDimension()
    print(f"CKKS scheme is using ring dimension {N}\n")

    cc.Enable(PKESchemeFeature.PKE)
    cc.Enable(PKESchemeFeature.KEYSWITCH)
    cc.Enable(PKESchemeFeature.LEVELEDSHE)

    keys = cc.KeyGen()
    cc.EvalRotateKeyGen(keys.secretKey,[1,2,3,4,5,6,7])

    # Input
    x = [0, 0, 0, 0, 0, 0, 0, 1]
    ptxt = cc.MakeCKKSPackedPlaintext(x)

    print(f"Input x: {ptxt}")

    c = cc.Encrypt(keys.publicKey,ptxt)

    # First, we perform 7 regular (non-hoisted) rotations
    # and measure the runtime
    t = time.time()
    cRot1 = cc.EvalRotate(c,1)
    cRot2 = cc.EvalRotate(c,2)
    cRot3 = cc.EvalRotate(c,3)
    cRot4 = cc.EvalRotate(c,4)
    cRot5 = cc.EvalRotate(c,5)
    cRot6 = cc.EvalRotate(c,6)
    cRot7 = cc.EvalRotate(c,7)
    timeNoHoisting = time.time() - t

    cResNoHoist = c + cRot1 + cRot2 + cRot3 + cRot4 + cRot5 + cRot6 + cRot7

    # M is the cyclotomic order and we need it to call EvalFastRotation
    M = 2*N

    # Then, we perform 7 rotations with hoisting.
    t = time.time()
    cPrecomp = cc.EvalFastRotationPrecompute(c)
    cRot1 = cc.EvalFastRotation(c, 1, M, cPrecomp)
    cRot2 = cc.EvalFastRotation(c, 2, M, cPrecomp)
    cRot3 = cc.EvalFastRotation(c, 3, M, cPrecomp)
    cRot4 = cc.EvalFastRotation(c, 4, M, cPrecomp)
    cRot5 = cc.EvalFastRotation(c, 5, M, cPrecomp)
    cRot6 = cc.EvalFastRotation(c, 6, M, cPrecomp)
    cRot7 = cc.EvalFastRotation(c, 7, M, cPrecomp)
    timeHoisting = time.time() - t
    # The time with hoisting should be faster than without hoisting.

    cResHoist = c + cRot1 + cRot2 + cRot3 + cRot4 + cRot5 + cRot6 + cRot7
    
    result = Decrypt(cResNoHoist,keys.secretKey)
    result.SetLength(batchSize)
    print(f"Result without hoisting: {result}")
    print(f" - 7 rotations without hoisting took {timeNoHoisting*1000} ms")

    
    result = Decrypt(cResHoist,keys.secretKey)
    result.SetLength(batchSize)
    print(f"Result with hoisting: {result}")
    print(f" - 7 rotations with hoisting took {timeHoisting*1000} ms")




def FastRotationDemo2():
    print("\n\n\n ===== FastRotationDemo2 =============\n")

    batchSize = 8

    parameters = CCParamsCKKSRNS()
    parameters.SetMultiplicativeDepth(1)
    parameters.SetScalingModSize(90)
    parameters.SetBatchSize(batchSize)
    parameters.SetScalingTechnique(ScalingTechnique.FIXEDAUTO)
    parameters.SetKeySwitchTechnique(KeySwitchTechnique.BV)

    digitSize = 3
    firstModSize = 100
    parameters.SetFirstModSize(firstModSize)
    parameters.SetDigitSize(digitSize)

    cc = GenCryptoContext(parameters)

    N = cc.GetRingDimension()
    print(f"CKKS scheme is using ring dimension {N}\n")

    cc.Enable(PKESchemeFeature.PKE)
    cc.Enable(PKESchemeFeature.KEYSWITCH)
    cc.Enable(PKESchemeFeature.LEVELEDSHE)

    keys = cc.KeyGen()
    cc.EvalRotateKeyGen(keys.secretKey,[1,2,3,4,5,6,7])

    # Input
    x = [0, 0, 0, 0, 0, 0, 0, 1]
    ptxt = cc.MakeCKKSPackedPlaintext(x)

    print(f"Input x: {ptxt}")

    c = cc.Encrypt(keys.publicKey,ptxt)

    # First, we perform 7 regular (non-hoisted) rotations
    # and measure the runtime
    t = time.time()
    cRot1 = cc.EvalRotate(c,1)
    cRot2 = cc.EvalRotate(c,2)
    cRot3 = cc.EvalRotate(c,3)
    cRot4 = cc.EvalRotate(c,4)
    cRot5 = cc.EvalRotate(c,5)
    cRot6 = cc.EvalRotate(c,6)
    cRot7 = cc.EvalRotate(c,7)
    timeNoHoisting = time.time() - t

    cResNoHoist = c + cRot1 + cRot2 + cRot3 + cRot4 + cRot5 + cRot6 + cRot7

    # M is the cyclotomic order and we need it to call EvalFastRotation
    M = 2*N

    # Then, we perform 7 rotations with hoisting.
    t = time.time()
    cPrecomp = cc.EvalFastRotationPrecompute(c)
    cRot1 = cc.EvalFastRotation(c, 1, M, cPrecomp)
    cRot2 = cc.EvalFastRotation(c, 2, M, cPrecomp)
    cRot3 = cc.EvalFastRotation(c, 3, M, cPrecomp)
    cRot4 = cc.EvalFastRotation(c, 4, M, cPrecomp)
    cRot5 = cc.EvalFastRotation(c, 5, M, cPrecomp)
    cRot6 = cc.EvalFastRotation(c, 6, M, cPrecomp)
    cRot7 = cc.EvalFastRotation(c, 7, M, cPrecomp)
    timeHoisting = time.time() - t
    # The time with hoisting should be faster than without hoisting.
    # Also, the benefits from hoisting should be more pronounced in this
    # case because we're using BV. Of course, we also observe less
    # accurate results than when using HYBRID, because of using
    # digitSize = 10 (Users can decrease digitSize to see the accuracy
    # increase, and performance decrease).

    cResHoist = c + cRot1 + cRot2 + cRot3 + cRot4 + cRot5 + cRot6 + cRot7

    result = Decrypt(cResNoHoist,keys.secretKey)
    result.SetLength(batchSize)
    print(f"Result without hoisting: {result}")
    print(f" - 7 rotations without hoisting took {timeNoHoisting*1000} ms")

    result = Decrypt(cResHoist,keys.secretKey)
    result.SetLength(batchSize)
    print(f"Result with hoisting: {result}")
    print(f" - 7 rotations with hoisting took {timeHoisting*1000} ms")


def main():
    if get_native_int() == 128:
        AutomaticRescaleDemo(ScalingTechnique.FIXEDAUTO)
        # Note that FLEXIBLEAUTO is not supported for 128-bit CKKS
        ManualRescaleDemo(ScalingTechnique.FIXEDMANUAL)
        HybridKeySwitchingDemo1()
        HybridKeySwitchingDemo2()
        FastRotationDemo1()
        FastRotationDemo2()
    else:
        print("This demo only runs for 128-bit CKKS.\n")

if __name__ == "__main__":
    main()

