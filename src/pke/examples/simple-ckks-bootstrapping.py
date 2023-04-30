from openfhe import *

def main(nativeint=64):
    SimpleBootstrapExample(nativeint)

def SimpleBootstrapExample(nativeint):
    parameters = CCParamsCKKSRNS()

    secretKeyDist = SecretKeyDist.UNIFORM_TERNARY
    parameters.SetSecretKeyDist(secretKeyDist)

    parameters.SetSecurityLevel(SecurityLevel.HEStd_NotSet)
    parameters.SetRingDim(1<<12)

    if nativeint==128:
        rescaleTech = ScalingTechnique.FIXEDAUTO
        dcrtBits = 78
        firstMod = 89
    else:
        rescaleTech = ScalingTechnique.FLEXIBLEAUTO
        dcrtBits = 59
        firstMod = 60
    
    parameters.SetScalingModSize(dcrtBits)
    parameters.SetScalingTechnique(rescaleTech)
    parameters.SetFirstModSize(firstMod)

    levelBudget = [4, 4]
    approxBootstrappDepth = 8

    levelsUsedBeforeBootstrap = 10

    depth = levelsUsedBeforeBootstrap + FHECKKSRNS.GetBootstrapDepth(approxBootstrappDepth, levelBudget, secretKeyDist)

    parameters.SetMultiplicativeDepth(depth)

    cryptocontext = GenCryptoContext(parameters)
    cryptocontext.Enable(PKESchemeFeature.PKE)
    cryptocontext.Enable(PKESchemeFeature.KEYSWITCH)
    cryptocontext.Enable(PKESchemeFeature.LEVELEDSHE)
    cryptocontext.Enable(PKESchemeFeature.ADVANCEDSHE)
    cryptocontext.Enable(PKESchemeFeature.FHE)

    ringDim = cryptocontext.GetRingDimension()
    # This is the mazimum number of slots that can be used full packing.

    numSlots = int(ringDim / 2)
    print(f"CKKS is using ring dimension {ringDim}")

    cryptocontext.EvalBootstrapSetup(levelBudget)

    keyPair = cryptocontext.KeyGen()
    cryptocontext.EvalMultKeyGen(keyPair.secretKey)
    cryptocontext.EvalBootstrapKeyGen(keyPair.secretKey, numSlots)

    x = [0.25, 0.5, 0.75, 1.0, 2.0, 3.0, 4.0, 5.0]
    encodedLength = len(x)

    ptxt = cryptocontext.MakeCKKSPackedPlaintext(x)
    ptxt.SetLength(encodedLength)

    print(f"Input: {x}")

    ciph = cryptocontext.Encrypt(keyPair.publicKey, ptxt)

    print(f"Initial number of levels remaining: {ciph.GetLevel()}")

    ciphertextAfter = cryptocontext.EvalBootstrap(ciph)

    print(f"Number of levels remaining after bootstrapping: {ciphertextAfter.GetLevel()}")

    result = Decrypt(ciphertextAfter,keyPair.secretKey)
    result.SetLength(encodedLength)
    print(f"Output after bootstrapping: {result}")

if __name__ == '__main__':
    main(64)