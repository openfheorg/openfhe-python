from openfhe import *

def main(nativeint=128):
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
    print(depth)
    parameters.SetMultiplicativeDepth(depth)

    cryptocontext = GenCryptoContext(parameters)
    cryptocontext.Enable(PKESchemeFeature.PKE)
    cryptocontext.Enable(PKESchemeFeature.KEYSWITCH)
    #cryptocontext.Enable()

if __name__ == '__main__':
    main()