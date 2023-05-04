from openfhe import *
import math
import random

def main():
    IterativeBootstrapExample()

def CalculateApproximationError(result,expectedResult):
    if len(result) != len(expectedResult):
        raise Exception("Cannot compare vectors with different numbers of elements")
    # using the infinity norm
    maxError = 0
    for i in range(len(result)):
        # error is abs of the difference of real parts
        error = abs(result[i].real - expectedResult[i].real)
        if error > maxError:
            maxError = error
    # resturn absolute value of log base2 of the error
    return abs(math.log(maxError,2))
def IterativeBootstrapExample():
    # Step 1: Set CryptoContext
    parameters = CCParamsCKKSRNS()
    secretKeyDist = SecretKeyDist.UNIFORM_TERNARY
    parameters.SetSecretKeyDist(secretKeyDist)
    parameters.SetSecurityLevel(SecurityLevel.HEStd_NotSet)
    parameters.SetRingDim(1 << 12)

    rescaleTech = ScalingTechnique.FLEXIBLEAUTO
    dcrtBits = 59
    firstMod = 60

    parameters.SetScalingModSize(dcrtBits)
    parameters.SetScalingTechnique(rescaleTech)
    parameters.SetFirstModSize(firstMod)

    # Here, we specify the number of iterations to run bootstrapping. 
    # Note that we currently only support 1 or 2 iterations.
    # Two iterations should give us approximately double the precision of one iteration.
    numIterations = 2

    levelBudget = [3, 3]
    # Each extra iteration on top of 1 requires an extra level to be consumed.
    approxBootstrappDepth = 8 + (numIterations - 1)
    bsgsDim = [0,0]

    levelsUsedBeforeBootstrap = 10
    depth = levelsUsedBeforeBootstrap + FHECKKSRNS.GetBootstrapDepth(approxBootstrappDepth, levelBudget, secretKeyDist)
    parameters.SetMultiplicativeDepth(depth)

    # Generate crypto context
    cryptocontext = GenCryptoContext(parameters)

    # Enable features that you wish to use. Note, we must enable FHE to use bootstrapping.

    cryptocontext.Enable(PKESchemeFeature.PKE)
    cryptocontext.Enable(PKESchemeFeature.KEYSWITCH)
    cryptocontext.Enable(PKESchemeFeature.LEVELEDSHE)
    cryptocontext.Enable(PKESchemeFeature.ADVANCEDSHE)
    cryptocontext.Enable(PKESchemeFeature.FHE)

    ringDim = cryptocontext.GetRingDimension()
    print(f"CKKS is using ring dimension {ringDim}\n\n")

    # Step 2: Precomputations for bootstrapping
    # We use a sparse packing
    numSlots = 8
    cryptocontext.EvalBootstrapSetup(levelBudget, bsgsDim, numSlots)

    # Step 3: Key generation
    keyPair = cryptocontext.KeyGen()
    cryptocontext.EvalMultKeyGen(keyPair.secretKey)
    # Generate bootstrapping keys.
    cryptocontext.EvalBootstrapKeyGen(keyPair.secretKey, numSlots)

    # Step 4: Encoding and encryption of inputs
    # Generate random input
    x = []
    for i in range(numSlots):
        x.append(random.uniform(0, 1))

    """ Encoding as plaintexts
        We specify the number of slots as numSlots to achieve a performance improvement.
        We use the other default values of depth 1, levels 0, and no params.
        Alternatively, you can also set batch size as a parameter in the CryptoContext as follows:
        parameters.SetBatchSize(numSlots);
        Here, we assume all ciphertexts in the cryptoContext will have numSlots slots.
        We start with a depleted ciphertext that has used up all of its levels."""
    ptxt = cryptocontext.MakeCKKSPackedPlaintext(x, 1, depth -1,None,numSlots)

    # Encrypt the encoded vectors
    ciph = cryptocontext.Encrypt(keyPair.publicKey, ptxt)

    # Step 5: Measure the precision of a single bootstrapping operation.
    ciphertextAfter = cryptocontext.EvalBootstrap(ciph)

    result = Decrypt(ciphertextAfter,keyPair.secretKey)
    result.SetLength(numSlots)
    precision = CalculateApproximationError(result.GetCKKSPackedValue(),ptxt.GetCKKSPackedValue())
    print(f"Bootstrapping precision after 1 iteration: {precision} bits\n")

    # Set the precision equal to empirically measured value after many test runs.
    precision = 17
    print(f"Precision input to algorithm: {precision}\n")

    # Step 6: Run bootstrapping with multiple iterations
    ciphertextTwoIterations = cryptocontext.EvalBootstrap(ciph,numIterations,precision)

    resultTwoIterations = Decrypt(ciphertextTwoIterations,keyPair.secretKey)
    resultTwoIterations.SetLength(numSlots)
    actualResult = resultTwoIterations.GetCKKSPackedValue()

    print(f"Output after two interations of bootstrapping: {actualResult}\n")
    precisionMultipleIterations = CalculateApproximationError(actualResult,ptxt.GetCKKSPackedValue())

    print(f"Bootstrapping precision after 2 iterations: {precisionMultipleIterations} bits\n")
    print(f"Number of levels remaining after 2 bootstrappings: {depth - ciphertextTwoIterations.GetLevel()}\n")

if __name__ == "__main__":
    main()