#
# Simple examples for CKKS in the COMPOSITESCALINGMANUAL mode, with the register
# word size and composite degree set explicitly
#

from openfhe import *
import sys


def main(args=[]):
    # Step 1: Setup CryptoContext

    # A. Specify main parameters
    # A1) Multiplicative depth: the maximum possible depth of a given
    # multiplication, but not the total number of multiplications supported by
    # the scheme.
    multDepth = 2

    # A2) Bit-length of scaling factor.
    firstModSize = 96
    scaleModSize = 95

    # A3) Number of plaintext slots used in the ciphertext.
    batchSize = 8

    # The word size in bits of the target hardware architecture.
    registerWordSize = 27

    # This example features the usage of COMPOSITESCALINGMANUAL scaling technique usage.
    # Internally, it works the same way as COMPOSITESCALINGAUTO. The only difference is that
    # it allows the user/developer to manually set the composite degree value d without any restrictions.
    # Use it in practice to explore different combinations of parameters (registerWordSize, scalingModSize,
    # and compositeDegree) that might be suitable to the target application/workload and hardware but it is
    # typically assumed to be a faulty selection in COMPOSITESCALINGAUTO. Note that there is no guarantee it
    # will work. It solely increases the degrees of freedom in COMPOSITESCALING usage that can be manipulated
    # by the user/developer.
    scalTech = ScalingTechnique.COMPOSITESCALINGMANUAL

    # Desired and manually-set composite degree d in [2,3,4].
    compositeDegree = 4

    # Parse CLI args like the C++ demo:
    #   script.py [firstModSize] [scalingModSize] [registerWordSize] [compositeDegree] [multDepth]
    if len(args) > 0:
        argcCount = 0
        while argcCount < len(args):
            paramValue = int(args[argcCount])
            if argcCount == 0:
                firstModSize = paramValue
                print(f"Setting First Mod Size: {firstModSize}")
            elif argcCount == 1:
                scaleModSize = paramValue
                print(f"Setting Scaling Mod Size: {scaleModSize}")
            elif argcCount == 2:
                registerWordSize = paramValue
                print(f"Setting Register Word Size: {registerWordSize}")
            elif argcCount == 3:
                compositeDegree = paramValue
                print(f"Setting Composite Degree: {compositeDegree}")
            elif argcCount == 4:
                multDepth = paramValue
                print(f"Setting Multiplicative Depth: {multDepth}")
            else:
                print("Invalid option")
            argcCount += 1
            print(f"argcCount: {argcCount + 1}")
        print("Complete !")
    else:
        print("Using default parameters")
        print(f"First Mod Size: {firstModSize}")
        print(f"Scaling Mod Size: {scaleModSize}")
        print(f"Register Word Size: {registerWordSize}")
        print(f"Composite Degree: {compositeDegree}")
        print(f"Multiplicative Depth: {multDepth}")
        print(f"Usage: {sys.argv[0]} [firstModSize] [scalingModSize] [registerWordSize] [compositeDegree] [multDepth]")

    # A4) Desired security level based on FHE standards.
    parameters = CCParamsCKKSRNS()
    parameters.SetMultiplicativeDepth(multDepth)
    parameters.SetFirstModSize(firstModSize)
    parameters.SetScalingModSize(scaleModSize)
    parameters.SetBatchSize(batchSize)
    parameters.SetSecurityLevel(SecurityLevel.HEStd_NotSet)
    parameters.SetRingDim(1 << 12)

    parameters.SetScalingTechnique(scalTech)
    parameters.SetRegisterWordSize(registerWordSize)
    parameters.SetCompositeDegree(compositeDegree)

    cc = GenCryptoContext(parameters)
    print(f"Composite Degree: {cc.GetCompositeDegree()}")
    print(f"Prime Modulus Size: {scaleModSize / cc.GetCompositeDegree()}")
    print(f"Register Word Size: {registerWordSize}")

    # Enable the features that you wish to use
    cc.Enable(PKESchemeFeature.PKE)
    cc.Enable(PKESchemeFeature.KEYSWITCH)
    cc.Enable(PKESchemeFeature.LEVELEDSHE)
    print(f"CKKS scheme is using ring dimension {cc.GetRingDimension()}\n")

    # B. Step 2: Key Generation
    # B1) Generate encryption keys.
    keys = cc.KeyGen()

    # B2) Generate the relinearization key
    cc.EvalMultKeyGen(keys.secretKey)

    # B3) Generate the rotation keys
    cc.EvalRotateKeyGen(keys.secretKey, [1, -2])

    # Step 3: Encoding and encryption of inputs

    # Inputs
    x1 = [0.25, 0.5, 0.75, 1.0, 2.0, 3.0, 4.0, 5.0]
    x2 = [5.0, 4.0, 3.0, 2.0, 1.0, 0.75, 0.5, 0.25]

    # Encoding as plaintexts
    ptxt1 = cc.MakeCKKSPackedPlaintext(x1)
    ptxt2 = cc.MakeCKKSPackedPlaintext(x2)

    print(f"Input x1: {ptxt1}")
    print(f"Input x2: {ptxt2}")

    # Encrypt the encoded vectors
    c1 = cc.Encrypt(keys.publicKey, ptxt1)
    c2 = cc.Encrypt(keys.publicKey, ptxt2)

    # Step 4: Evaluation

    # Homomorphic addition
    cAdd = cc.EvalAdd(c1, c2)

    # Homomorphic subtraction
    cSub = cc.EvalSub(c1, c2)

    # Homomorphic scalar multiplication
    cScalar = cc.EvalMult(c1, 4.0)

    # Homomorphic multiplication
    cMul = cc.EvalMult(c1, c2)

    # Homomorphic rotations
    cRot1 = cc.EvalRotate(c1, 1)
    cRot2 = cc.EvalRotate(c1, -2)

    # Step 5: Decryption and output
    print("\nResults of homomorphic computations: ")

    result = cc.Decrypt(keys.secretKey, c1)
    result.SetLength(batchSize)
    print(f"x1 = {result}", end="")
    print(f"Estimated precision in bits: {result.GetLogPrecision()}")

    # Decrypt the result of addition
    result = cc.Decrypt(keys.secretKey, cAdd)
    result.SetLength(batchSize)
    print(f"x1 + x2 = {result}", end="")
    print(f"Estimated precision in bits: {result.GetLogPrecision()}")

    # Decrypt the result of subtraction
    result = cc.Decrypt(keys.secretKey, cSub)
    result.SetLength(batchSize)
    print(f"x1 - x2 = {result}")

    # Decrypt the result of scalar multiplication
    result = cc.Decrypt(keys.secretKey, cScalar)
    result.SetLength(batchSize)
    print(f"4 * x1 = {result}")

    # Decrypt the result of multiplication
    result = cc.Decrypt(keys.secretKey, cMul)
    result.SetLength(batchSize)
    print(f"x1 * x2 = {result}")

    # Decrypt the result of rotations
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

    # Decrypt the result of subtraction
    result = cc.Decrypt(keys.secretKey, cSubDouble)
    result.SetLength(batchSize)
    print(f"x1 - 0.5 = {result}")

    # Decrypt the result of addition
    result = cc.Decrypt(keys.secretKey, cAddNegDouble)
    result.SetLength(batchSize)
    print(f"x1 + (-0.5) = {result}")


if __name__ == "__main__":
    main(sys.argv[1:])
