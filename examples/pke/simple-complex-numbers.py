from openfhe import *


def SimpleComplexNumbers():
    print("\n================= Simple Operations on Complex Numbers =====================")

    # Step 1: Setup CryptoContext
    multDepth = 1
    scaleModSize = 50
    batchSize = 8
    ckksDataType = CKKSDataType.COMPLEX

    parameters = CCParamsCKKSRNS()
    parameters.SetMultiplicativeDepth(multDepth)
    parameters.SetScalingModSize(scaleModSize)
    parameters.SetBatchSize(batchSize)
    parameters.SetCKKSDataType(ckksDataType)

    cc = GenCryptoContext(parameters)

    cc.Enable(PKE)
    cc.Enable(KEYSWITCH)
    cc.Enable(LEVELEDSHE)
    print(f"CKKS scheme is using ring dimension {cc.GetRingDimension()}\n")

    # Step 2: Key Generation
    keys = cc.KeyGen()
    cc.EvalMultKeyGen(keys.secretKey)
    cc.EvalRotateKeyGen(keys.secretKey, [1, -2])

    # Conjugation key: automorphism with index 2N-1
    indexConj = 2 * cc.GetRingDimension() - 1
    cc.EvalAutomorphismKeyGen(keys.secretKey, [indexConj])

    # Step 3: Encoding and encryption of inputs
    x1 = [0.25 + 0.25j, 0.5 + 0.5j, 0.75 + 0.75j, 1.0 + 1.0j,
          2.0 + 2.0j,  3.0 + 3.0j, 4.0 + 4.0j,   5.0 + 5.0j]
    x2 = [5.0 - 5.0j, 4.0 - 4.0j, 3.0 - 3.0j, 2.0 - 2.0j,
          1.0 - 1.0j, 0.75 - 0.75j, 0.5 - 0.5j, 0.25 - 0.25j]

    constComplex = 1.0 - 2.0j
    constComplex2 = 1.0 + 0.5j

    ptxt1 = cc.MakeCKKSPackedPlaintext(x1)
    ptxt2 = cc.MakeCKKSPackedPlaintext(x2)

    print(f"Input x1: {ptxt1}", end="")
    print(f"Input x2: {ptxt2}", end="")

    c1 = cc.Encrypt(keys.publicKey, ptxt1)
    c2 = cc.Encrypt(keys.publicKey, ptxt2)

    # Step 4: Evaluation
    cAdd = cc.EvalAdd(c1, c2)
    cSub = cc.EvalSub(c1, c2)
    cScalar = cc.EvalMult(c1, 4.0)
    cMul = cc.EvalMult(c1, c2)
    cRot1 = cc.EvalRotate(c1, 1)
    cRot2 = cc.EvalRotate(c1, -2)

    # Conjugation (automorphism)
    evalConjKeyMap = cc.GetEvalAutomorphismKeyMap(c1.GetKeyTag())
    cConj1 = cc.EvalAutomorphism(c1, indexConj, evalConjKeyMap)

    # Multiply by a complex constant
    cMulC = cc.EvalMult(c1, constComplex)

    # Additions by complex constants
    cAddC = cc.EvalAdd(c2, constComplex)
    cc.EvalAddInPlace(cAddC, constComplex2)

    # Subtractions by complex constants
    cSubC = cc.EvalSub(c2, constComplex)
    cc.EvalSubInPlace(cSubC, constComplex2)

    # Step 5: Decryption and output
    print("\nDecrypted complex inputs:\n")
    result = cc.Decrypt(keys.secretKey, c1)
    result.SetLength(batchSize)
    print(f"x1 = {result}", end="")

    result = cc.Decrypt(keys.secretKey, c2)
    result.SetLength(batchSize)
    print(f"x2 = {result}", end="")

    print("\nResults of homomorphic computations:\n")

    result = cc.Decrypt(keys.secretKey, cAdd)
    result.SetLength(batchSize)
    print(f"x1 + x2 = {result}", end="")

    result = cc.Decrypt(keys.secretKey, cSub)
    result.SetLength(batchSize)
    print(f"x1 - x2 = {result}", end="")

    result = cc.Decrypt(keys.secretKey, cScalar)
    result.SetLength(batchSize)
    print(f"4 * x1 = {result}", end="")

    result = cc.Decrypt(keys.secretKey, cMul)
    result.SetLength(batchSize)
    print(f"x1 * x2 = {result}", end="")

    result = cc.Decrypt(keys.secretKey, cRot1)
    result.SetLength(batchSize)
    print("\nIn rotations, very small outputs (~10^-10 here) correspond to 0's:")
    print(f"x1 rotated by 1 = {result}", end="")

    result = cc.Decrypt(keys.secretKey, cRot2)
    result.SetLength(batchSize)
    print(f"x1 rotated by -2 = {result}", end="")

    result = cc.Decrypt(keys.secretKey, cConj1)
    result.SetLength(batchSize)
    print(f"x1 conjugated = {result}", end="")

    result = cc.Decrypt(keys.secretKey, cMulC)
    result.SetLength(batchSize)
    print(f"x1 * (1 - 2i) = {result}", end="")

    result = cc.Decrypt(keys.secretKey, cAddC)
    result.SetLength(batchSize)
    print(f"x2 + (1 - 2i) + (1 + 0.5i) = {result}", end="")

    result = cc.Decrypt(keys.secretKey, cSubC)
    result.SetLength(batchSize)
    print(f"x2 - (1 - 2i) - (1 + 0.5i) = {result}", end="")


def _fill_to_length(vec, n, fill_value=0):
    # C++ Fill<T>(x, numSlots) behavior for demos is usually "pad with zeros"
    if len(vec) >= n:
        return vec[:n]
    return vec + [fill_value] * (n - len(vec))


def SimpleBootstrappingComplex():
    print("\n================= Bootstrapping Complex Numbers =====================")

    parameters = CCParamsCKKSRNS()

    secretKeyDist = SecretKeyDist.UNIFORM_TERNARY
    parameters.SetSecretKeyDist(secretKeyDist)

    parameters.SetSecurityLevel(SecurityLevel.HEStd_NotSet)
    ringDim = 1 << 6
    parameters.SetRingDim(ringDim)

    # In your C++ demo this depends on NATIVEINT. Here we pick the common 64-bit path.
    rescaleTech = ScalingTechnique.FLEXIBLEAUTO
    dcrtBits = 59
    firstMod = 60

    parameters.SetScalingModSize(dcrtBits)
    parameters.SetScalingTechnique(rescaleTech)
    parameters.SetFirstModSize(firstMod)

    parameters.SetCKKSDataType(CKKSDataType.COMPLEX)

    numSlots = ringDim // 2
    # parameters.SetBatchSize(numSlots)  # intentionally not set in the C++ demo

    levelBudget = [2, 2]
    levelsAvailableAfterBootstrap = 10
    depth = levelsAvailableAfterBootstrap + FHECKKSRNS.GetBootstrapDepth(levelBudget, secretKeyDist)
    parameters.SetMultiplicativeDepth(depth)

    cryptoContext = GenCryptoContext(parameters)
    cryptoContext.Enable(PKE)
    cryptoContext.Enable(KEYSWITCH)
    cryptoContext.Enable(LEVELEDSHE)
    cryptoContext.Enable(ADVANCEDSHE)
    cryptoContext.Enable(FHE)

    print(f"CKKS scheme is using ring dimension {ringDim} and number of slots {numSlots}\n")

    cryptoContext.EvalBootstrapSetup(levelBudget, [0, 0], numSlots)

    keyPair = cryptoContext.KeyGen()
    cryptoContext.EvalMultKeyGen(keyPair.secretKey)
    cryptoContext.EvalBootstrapKeyGen(keyPair.secretKey, numSlots)

    x = [0.25 + 0.25j, 0.5 - 0.5j, 0.75 + 0.75j, 1.0 - 1.0j,
         2.0 + 2.0j,  3.0 - 3.0j, 4.0 + 4.0j,  5.0 - 5.0j]
    x = _fill_to_length(x, numSlots, 0.0 + 0.0j)
    encodedLength = len(x)

    # depleted ciphertext: level = depth-1
    ptxt = cryptoContext.MakeCKKSPackedPlaintext(x, 1, depth - 1, None, numSlots)
    ptxt.SetLength(encodedLength)
    print(f"Input: {ptxt}")

    ciph = cryptoContext.Encrypt(keyPair.publicKey, ptxt)

    print(f"Initial number of levels remaining: {depth - ciph.GetLevel()}")

    ciphertextAfter = cryptoContext.EvalBootstrap(ciph)

    levels_after = depth - ciphertextAfter.GetLevel() - (ciphertextAfter.GetNoiseScaleDeg() - 1)
    print(f"Number of levels remaining after bootstrapping: {levels_after}\n")

    result = cryptoContext.Decrypt(keyPair.secretKey, ciphertextAfter)
    result.SetLength(encodedLength)
    print(f"Output after bootstrapping:\n\t{result}", end="")


def SimpleBootstrappingStCFirstComplex():
    print("\n================= Bootstrapping Complex Numbers with StC Transformation First =====================")

    parameters = CCParamsCKKSRNS()

    secretKeyDist = SecretKeyDist.UNIFORM_TERNARY
    parameters.SetSecretKeyDist(secretKeyDist)

    parameters.SetSecurityLevel(SecurityLevel.HEStd_NotSet)
    ringDim = 1 << 6
    parameters.SetRingDim(ringDim)

    # Common 64-bit path
    rescaleTech = ScalingTechnique.FLEXIBLEAUTO
    dcrtBits = 59
    firstMod = 60

    parameters.SetScalingModSize(dcrtBits)
    parameters.SetScalingTechnique(rescaleTech)
    parameters.SetFirstModSize(firstMod)

    parameters.SetCKKSDataType(CKKSDataType.COMPLEX)

    numSlots = ringDim // 2
    # parameters.SetBatchSize(numSlots)  # intentionally not set in the C++ demo

    levelBudget = [2, 2]

    levelsAvailableAfterBootstrap = 10 + levelBudget[1]
    depth = levelsAvailableAfterBootstrap + FHECKKSRNS.GetBootstrapDepth([levelBudget[0], 0], secretKeyDist)
    parameters.SetMultiplicativeDepth(depth)

    cryptoContext = GenCryptoContext(parameters)
    cryptoContext.Enable(PKE)
    cryptoContext.Enable(KEYSWITCH)
    cryptoContext.Enable(LEVELEDSHE)
    cryptoContext.Enable(ADVANCEDSHE)
    cryptoContext.Enable(FHE)

    print(f"CKKS scheme is using ring dimension {ringDim} and number of slots {numSlots} with depth {depth}\n")

    cryptoContext.EvalBootstrapSetup(levelBudget, [0, 0], numSlots, 0, True, True)

    keyPair = cryptoContext.KeyGen()
    cryptoContext.EvalMultKeyGen(keyPair.secretKey)
    cryptoContext.EvalBootstrapKeyGen(keyPair.secretKey, numSlots)

    x = [0.25 + 0.25j, 0.5 - 0.5j, 0.75 + 0.75j, 1.0 - 1.0j,
         2.0 + 2.0j,  3.0 - 3.0j, 4.0 + 4.0j,  5.0 - 5.0j]
    x = _fill_to_length(x, numSlots, 0.0 + 0.0j)
    encodedLength = len(x)

    # depleted ciphertext: level = depth - 1 - levelBudget[1]
    ptxt = cryptoContext.MakeCKKSPackedPlaintext(x, 1, depth - 1 - levelBudget[1], None, numSlots)
    ptxt.SetLength(encodedLength)
    print(f"Input: {ptxt}")

    ciph = cryptoContext.Encrypt(keyPair.publicKey, ptxt)

    print(f"Initial number of levels remaining: {depth - ciph.GetLevel()}")

    ciphertextAfter = cryptoContext.EvalBootstrap(ciph)

    levels_after = depth - ciphertextAfter.GetLevel() - (ciphertextAfter.GetNoiseScaleDeg() - 1)
    print(f"Number of levels remaining after bootstrapping: {levels_after}\n")

    result = cryptoContext.Decrypt(keyPair.secretKey, ciphertextAfter)

    # C++: result->SetLength(2 * encodedLength);
    result.SetLength(2 * encodedLength)
    print(f"Output after bootstrapping:\n\t{result}", end="")


def main():
    SimpleComplexNumbers()
    SimpleBootstrappingComplex()
    SimpleBootstrappingStCFirstComplex()


if __name__ == "__main__":
    main()
