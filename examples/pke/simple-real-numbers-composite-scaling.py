from openfhe import *
import sys


def main():
    # Defaults (same as C++)
    multDepth = 2
    firstModSize = 90
    scaleModSize = 73
    batchSize = 8
    registerWordSize = 32

    # Parse CLI args like the C++ demo:
    #   script.py [firstModSize] [scalingModSize] [registerWordSize] [multDepth]
    argv = sys.argv
    if len(argv) > 1:
        argcCount = 1
        while argcCount < len(argv):
            paramValue = int(argv[argcCount])
            if argcCount == 1:
                firstModSize = paramValue
                print(f"Setting First Mod Size: {firstModSize}")
            elif argcCount == 2:
                scaleModSize = paramValue
                print(f"Setting Scaling Mod Size: {scaleModSize}")
            elif argcCount == 3:
                registerWordSize = paramValue
                print(f"Setting Register Word Size: {registerWordSize}")
            elif argcCount == 4:
                multDepth = paramValue
                print(f"Setting Multiplicative Depth: {multDepth}")
            else:
                print("Invalid option")
            argcCount += 1
            print(f"argcCount: {argcCount}")
        print("Complete !")
    else:
        print("Using default parameters")
        print(f"First Mod Size: {firstModSize}")
        print(f"Scaling Mod Size: {scaleModSize}")
        print(f"Register Word Size: {registerWordSize}")
        print(f"Multiplicative Depth: {multDepth}")
        print(f"Usage: {argv[0]} [firstModSize] [scalingModSize] [registerWordSize] [multDepth]")

    # Step 1: Setup CryptoContext (CKKS)
    parameters = CCParamsCKKSRNS()
    parameters.SetMultiplicativeDepth(multDepth)
    parameters.SetFirstModSize(firstModSize)
    parameters.SetScalingModSize(scaleModSize)
    parameters.SetBatchSize(batchSize)
    parameters.SetSecurityLevel(SecurityLevel.HEStd_NotSet)
    parameters.SetRingDim(1 << 12)

    parameters.SetScalingTechnique(ScalingTechnique.COMPOSITESCALINGAUTO)
    parameters.SetRegisterWordSize(registerWordSize)

    cc = GenCryptoContext(parameters)

    # If your Python bindings expose CryptoParametersCKKSRNS, you may be able to do:
    # cryptoParams = cc.GetCryptoParameters()
    # print("Composite Degree:", cryptoParams.GetCompositeDegree())
    # but not all builds expose this cleanly; the C++ demo prints it mainly for info.

    # Enable features
    cc.Enable(PKE)
    cc.Enable(KEYSWITCH)
    cc.Enable(LEVELEDSHE)

    print(f"CKKS scheme is using ring dimension {cc.GetRingDimension()}\n")

    # Step 2: Key Generation
    keys = cc.KeyGen()
    cc.EvalMultKeyGen(keys.secretKey)
    cc.EvalRotateKeyGen(keys.secretKey, [1, -2])

    # Step 3: Encoding and encryption of inputs
    x1 = [0.25, 0.5, 0.75, 1.0, 2.0, 3.0, 4.0, 5.0]
    x2 = [5.0, 4.0, 3.0, 2.0, 1.0, 0.75, 0.5, 0.25]

    ptxt1 = cc.MakeCKKSPackedPlaintext(x1)
    ptxt2 = cc.MakeCKKSPackedPlaintext(x2)

    print(f"Input x1: {ptxt1}")
    print(f"Input x2: {ptxt2}")

    c1 = cc.Encrypt(keys.publicKey, ptxt1)
    c2 = cc.Encrypt(keys.publicKey, ptxt2)

    # Step 4: Evaluation
    cAdd = cc.EvalAdd(c1, c2)
    cSub = cc.EvalSub(c1, c2)
    cScalar = cc.EvalMult(c1, 4.0)
    cMul = cc.EvalMult(c1, c2)
    cRot1 = cc.EvalRotate(c1, 1)
    cRot2 = cc.EvalRotate(c1, -2)

    # Step 5: Decryption and output
    print("\nResults of homomorphic computations:\n")

    result = cc.Decrypt(keys.secretKey, c1)
    result.SetLength(batchSize)
    print(f"x1 = {result}", end="")
    print(f"Estimated precision in bits: {result.GetLogPrecision()}")

    result = cc.Decrypt(keys.secretKey, cAdd)
    result.SetLength(batchSize)
    print(f"x1 + x2 = {result}", end="")
    print(f"Estimated precision in bits: {result.GetLogPrecision()}")

    result = cc.Decrypt(keys.secretKey, cSub)
    result.SetLength(batchSize)
    print(f"x1 - x2 = {result}")

    result = cc.Decrypt(keys.secretKey, cScalar)
    result.SetLength(batchSize)
    print(f"4 * x1 = {result}")

    result = cc.Decrypt(keys.secretKey, cMul)
    result.SetLength(batchSize)
    print(f"x1 * x2 = {result}")

    result = cc.Decrypt(keys.secretKey, cRot1)
    result.SetLength(batchSize)
    print("\nIn rotations, very small outputs (~10^-10 here) correspond to 0's:")
    print(f"x1 rotate by 1 = {result}")

    result = cc.Decrypt(keys.secretKey, cRot2)
    result.SetLength(batchSize)
    print(f"x1 rotate by -2 = {result}")

    # Testing EvalSub ciphertext - double
    cSubDouble = cc.EvalSub(c1, 0.5)
    print(f"c1 noise degree = {c1.GetNoiseScaleDeg()}")
    print(f"c1 scaling factor = {c1.GetScalingFactor()}")

    # Testing EvalAdd ciphertext + negative double
    cAddNegDouble = cc.EvalAdd(c1, -0.5)

    result = cc.Decrypt(keys.secretKey, cSubDouble)
    result.SetLength(batchSize)
    print(f"x1 - 0.5 = {result}")

    result = cc.Decrypt(keys.secretKey, cAddNegDouble)
    result.SetLength(batchSize)
    print(f"x1 + (-0.5) = {result}")


if __name__ == "__main__":
    main()
