from openfhe import *
import time # to enable TIC-TOC timing measurements
 
def automatic_rescale_demo(scal_tech):
    if(scal_tech == ScalingTechnique.FLEXIBLEAUTO):
        print("\n\n\n ===== FlexibleAutoDemo =============\n") 
    else:
         print("\n\n\n ===== FixedAutoDemo =============\n")

    batch_size = 8
    parameters = CCParamsCKKSRNS()
    parameters.SetMultiplicativeDepth(6)
    parameters.SetScalingModSize(89)
    parameters.SetScalingTechnique(scal_tech)
    parameters.SetBatchSize(batch_size)

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
    c_res1 = cc.EvalAdd(cc.EvalAdd(c18, c9), 1.0)  # Final result 1
    c_res2 = cc.EvalSub(cc.EvalAdd(c18,c9), 1.0)   # Final result 2
    c_res3 = cc.EvalMult(cc.EvalAdd(c18,c9), 0.5)  # Final result 3

    result1 = cc.Decrypt(c_res1,keys.secretKey)
    result1.SetLength(batch_size)
    print("x^18 + x^9 + 1 = ", result1)
    
    result2 = cc.Decrypt(c_res2,keys.secretKey)
    result2.SetLength(batch_size)
    print("x^18 + x^9 - 1 = ", result2)

    result3 = cc.Decrypt(c_res3,keys.secretKey)
    result3.SetLength(batch_size)
    print("0.5 * (x^18 + x^9) = ", result3)


def manual_rescale_demo(scal_tech):
    print("\n\n\n ===== FixedManualDemo =============\n")
    
    batch_size = 8
    parameters = CCParamsCKKSRNS()
    parameters.SetMultiplicativeDepth(5)
    parameters.SetScalingModSize(89)
    parameters.SetBatchSize(batch_size)

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
    c_res_depth2 = cc.EvalAdd(cc.EvalAdd(c18_depth2, c9_depth2), 1.0)
    c_res_depth1 = cc.Rescale(c_res_depth2)

    result = cc.Decrypt(c_res_depth1,keys.secretKey)
    result.SetLength(batch_size)
    print("x^18 + x^9 + 1 = ", result)

def hybrid_key_switching_demo1():
    
    print("\n\n\n ===== hybrid_key_switching_demo1 ============= \n")
    dnum = 2
    batch_size = 8
    parameters = CCParamsCKKSRNS()
    parameters.SetMultiplicativeDepth(5)
    parameters.SetScalingModSize(89)
    parameters.SetBatchSize(batch_size)
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
    c_rot1 = cc.EvalRotate(c,1)
    c_rot2 = cc.EvalRotate(c_rot1,-2)
    time2digits = time.time() - t

    result = cc.Decrypt(c_rot2,keys.secretKey)
    result.SetLength(batch_size)
    print(f"x rotate by -1 = {result}")
    print(f" - 2 rotations with HYBRID (2 digits) took {time2digits*1000} ms")


def hybrid_key_switching_demo2():
    print("\n\n\n ===== hybrid_key_switching_demo2 =============\n")
    dnum = 3
    batch_size = 8
    parameters = CCParamsCKKSRNS()
    parameters.SetMultiplicativeDepth(5)
    parameters.SetScalingModSize(89)
    parameters.SetBatchSize(batch_size)
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
    c_rot1 = cc.EvalRotate(c,1)
    c_rot2 = cc.EvalRotate(c_rot1,-2)
    time3digits = time.time() - t
    # The runtime here is smaller than the previous demo

    result = cc.Decrypt(c_rot2,keys.secretKey)
    result.SetLength(batch_size)
    print(f"x rotate by -1 = {result}")
    print(f" - 2 rotations with HYBRID (3 digits) took {time3digits*1000} ms")

def fast_rotation_demo1():
    print("\n\n\n ===== fast_rotation_demo1 =============\n")
    batch_size = 8
    parameters = CCParamsCKKSRNS()
    parameters.SetMultiplicativeDepth(1)
    parameters.SetScalingModSize(89)
    parameters.SetBatchSize(batch_size)

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
    c_rot1 = cc.EvalRotate(c,1)
    c_rot2 = cc.EvalRotate(c,2)
    c_rot3 = cc.EvalRotate(c,3)
    c_rot4 = cc.EvalRotate(c,4)
    c_rot5 = cc.EvalRotate(c,5)
    c_rot6 = cc.EvalRotate(c,6)
    c_rot7 = cc.EvalRotate(c,7)
    time_no_hoisting = time.time() - t

    c_res_no_hoist = c + c_rot1 + c_rot2 + c_rot3 + c_rot4 + c_rot5 + c_rot6 + c_rot7

    # M is the cyclotomic order and we need it to call EvalFastRotation
    M = 2*N

    # Then, we perform 7 rotations with hoisting.
    t = time.time()
    c_precomp = cc.EvalFastRotationPrecompute(c)
    c_rot1 = cc.EvalFastRotation(c, 1, M, c_precomp)
    c_rot2 = cc.EvalFastRotation(c, 2, M, c_precomp)
    c_rot3 = cc.EvalFastRotation(c, 3, M, c_precomp)
    c_rot4 = cc.EvalFastRotation(c, 4, M, c_precomp)
    c_rot5 = cc.EvalFastRotation(c, 5, M, c_precomp)
    c_rot6 = cc.EvalFastRotation(c, 6, M, c_precomp)
    c_rot7 = cc.EvalFastRotation(c, 7, M, c_precomp)
    time_hoisting = time.time() - t
    # The time with hoisting should be faster than without hoisting.

    c_res_hoist = c + c_rot1 + c_rot2 + c_rot3 + c_rot4 + c_rot5 + c_rot6 + c_rot7
    
    result = cc.Decrypt(c_res_no_hoist,keys.secretKey)
    result.SetLength(batch_size)
    print(f"Result without hoisting: {result}")
    print(f" - 7 rotations without hoisting took {time_no_hoisting*1000} ms")

    
    result = cc.Decrypt(c_res_hoist,keys.secretKey)
    result.SetLength(batch_size)
    print(f"Result with hoisting: {result}")
    print(f" - 7 rotations with hoisting took {time_hoisting*1000} ms")




def fast_rotation_demo2():
    print("\n\n\n ===== fast_rotation_demo2 =============\n")

    batch_size = 8

    parameters = CCParamsCKKSRNS()
    parameters.SetMultiplicativeDepth(1)
    parameters.SetScalingModSize(89)
    parameters.SetBatchSize(batch_size)
    parameters.SetScalingTechnique(ScalingTechnique.FIXEDAUTO)
    parameters.SetKeySwitchTechnique(KeySwitchTechnique.BV)

    digit_size = 10
    first_mod_size = 100
    parameters.SetFirstModSize(first_mod_size)
    parameters.SetDigitSize(digit_size)

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
    c_rot1 = cc.EvalRotate(c,1)
    c_rot2 = cc.EvalRotate(c,2)
    c_rot3 = cc.EvalRotate(c,3)
    c_rot4 = cc.EvalRotate(c,4)
    c_rot5 = cc.EvalRotate(c,5)
    c_rot6 = cc.EvalRotate(c,6)
    c_rot7 = cc.EvalRotate(c,7)
    time_no_hoisting = time.time() - t

    c_res_no_hoist = c + c_rot1 + c_rot2 + c_rot3 + c_rot4 + c_rot5 + c_rot6 + c_rot7

    # M is the cyclotomic order and we need it to call EvalFastRotation
    M = 2*N

    # Then, we perform 7 rotations with hoisting.
    t = time.time()
    c_precomp = cc.EvalFastRotationPrecompute(c)
    c_rot1 = cc.EvalFastRotation(c, 1, M, c_precomp)
    c_rot2 = cc.EvalFastRotation(c, 2, M, c_precomp)
    c_rot3 = cc.EvalFastRotation(c, 3, M, c_precomp)
    c_rot4 = cc.EvalFastRotation(c, 4, M, c_precomp)
    c_rot5 = cc.EvalFastRotation(c, 5, M, c_precomp)
    c_rot6 = cc.EvalFastRotation(c, 6, M, c_precomp)
    c_rot7 = cc.EvalFastRotation(c, 7, M, c_precomp)
    time_hoisting = time.time() - t
    # The time with hoisting should be faster than without hoisting.
    # Also, the benefits from hoisting should be more pronounced in this
    # case because we're using BV. Of course, we also observe less
    # accurate results than when using HYBRID, because of using
    # digitSize = 10 (Users can decrease digitSize to see the accuracy
    # increase, and performance decrease).

    c_res_hoist = c + c_rot1 + c_rot2 + c_rot3 + c_rot4 + c_rot5 + c_rot6 + c_rot7

    result = cc.Decrypt(c_res_no_hoist,keys.secretKey)
    result.SetLength(batch_size)
    print(f"Result without hoisting: {result}")
    print(f" - 7 rotations without hoisting took {time_no_hoisting*1000} ms")

    result = cc.Decrypt(c_res_hoist,keys.secretKey)
    result.SetLength(batch_size)
    print(f"Result with hoisting: {result}")
    print(f" - 7 rotations with hoisting took {time_hoisting*1000} ms")


def main():
    if get_native_int() == 128:
        automatic_rescale_demo(ScalingTechnique.FIXEDAUTO)
        # Note that FLEXIBLEAUTO is not supported for 128-bit CKKS
        manual_rescale_demo(ScalingTechnique.FIXEDMANUAL)
        hybrid_key_switching_demo1()
        hybrid_key_switching_demo2()
        fast_rotation_demo1()
        fast_rotation_demo2()
    else:
        print("This demo only runs for 128-bit CKKS.\nIf you want to test it please reinstall the OpenFHE C++ with the flag -DNATIVE_SIZE=128, then reinstall OpenFHE-Python.")

if __name__ == "__main__":
    main()

