from openfhe import *

def main():
    print("Interactive (3P) Bootstrapping Ciphertext [Chebyshev] (TCKKS) started ...")

    # Same test with different rescaling techniques in CKKS
    TCKKSCollectiveBoot(FIXEDMANUAL)
    TCKKSCollectiveBoot(FIXEDAUTO)
    if get_native_int()!=128:
        TCKKSCollectiveBoot(FLEXIBLEAUTO)
        TCKKSCollectiveBoot(FLEXIBLEAUTOEXT)

    print("Interactive (3P) Bootstrapping Ciphertext [Chebyshev] (TCKKS) terminated gracefully!")



def checkApproximateEquality(a, b, vectorSize, epsilon):
    allTrue = [1] * vectorSize
    tmp = [abs(a[i] - b[i]) <= epsilon for i in range(vectorSize)]
    if tmp != allTrue:
        print("IntMPBoot - Ctxt Chebyshev Failed:")
        print(f"- is diff <= eps?: {tmp}")
    else:
        print("SUCCESSFUL Bootstrapping!")

def TCKKSCollectiveBoot(scaleTech):
    if scaleTech not in [FIXEDMANUAL, FIXEDAUTO, FLEXIBLEAUTO, FLEXIBLEAUTOEXT]:
        errMsg = "ERROR: Scaling technique is not supported!"
        raise Exception(errMsg)

    parameters = CCParamsCKKSRNS()

    secretKeyDist = UNIFORM_TERNARY
    parameters.SetSecretKeyDist(secretKeyDist)

    parameters.SetSecurityLevel(HEStd_128_classic)

    dcrtBits = 50
    firstMod = 60

    parameters.SetScalingModSize(dcrtBits)
    parameters.SetScalingTechnique(scaleTech)
    parameters.SetFirstModSize(firstMod)

    multiplicativeDepth = 10  # Adjust according to your requirements
    parameters.SetMultiplicativeDepth(multiplicativeDepth)
    parameters.SetKeySwitchTechnique(HYBRID)

    batchSize = 16  # Adjust batch size if needed
    parameters.SetBatchSize(batchSize)

    compressionLevel = COMPRESSION_LEVEL.COMPACT  # or COMPRESSION_LEVEL.SLACK
    parameters.SetInteractiveBootCompressionLevel(compressionLevel)

    cryptoContext = GenCryptoContext(parameters)
    cryptoContext.Enable(PKE)
    cryptoContext.Enable(KEYSWITCH)
    cryptoContext.Enable(LEVELEDSHE)
    cryptoContext.Enable(ADVANCEDSHE)
    cryptoContext.Enable(MULTIPARTY)

    ringDim = cryptoContext.GetRingDimension()
    maxNumSlots = ringDim // 2

    print(f"TCKKS scheme is using ring dimension {ringDim}")
    print(f"TCKKS scheme number of slots         {batchSize}")
    print(f"TCKKS scheme max number of slots     {maxNumSlots}")
    print(f"TCKKS example with Scaling Technique {scaleTech}")

    numParties = 3

    print("\n===========================IntMPBoot protocol parameters===========================\n")
    print(f"number of parties: {numParties}\n")
    print("===============================================================\n")

    # Round 1 (party A)
    kp1 = cryptoContext.KeyGen()

    # Generate evalmult key part for A
    evalMultKey = cryptoContext.KeySwitchGen(kp1.secretKey, kp1.secretKey)

    # Generate evalsum key part for A
    cryptoContext.EvalSumKeyGen(kp1.secretKey)
    evalSumKeys = cryptoContext.GetEvalSumKeyMap(kp1.secretKey.GetKeyTag())

    # Round 2 (party B)
    kp2 = cryptoContext.MultipartyKeyGen(kp1.publicKey)
    evalMultKey2 = cryptoContext.MultiKeySwitchGen(kp2.secretKey, kp2.secretKey, evalMultKey)
    evalMultAB = cryptoContext.MultiAddEvalKeys(evalMultKey, evalMultKey2, kp2.publicKey.GetKeyTag())
    evalMultBAB = cryptoContext.MultiMultEvalKey(kp2.secretKey, evalMultAB, kp2.publicKey.GetKeyTag())
    evalSumKeysB = cryptoContext.MultiEvalSumKeyGen(kp2.secretKey, evalSumKeys, kp2.publicKey.GetKeyTag())
    evalSumKeysJoin = cryptoContext.MultiAddEvalSumKeys(evalSumKeys, evalSumKeysB, kp2.publicKey.GetKeyTag())
    cryptoContext.InsertEvalSumKey(evalSumKeysJoin)
    evalMultAAB = cryptoContext.MultiMultEvalKey(kp1.secretKey, evalMultAB, kp2.publicKey.GetKeyTag())
    evalMultFinal = cryptoContext.MultiAddEvalMultKeys(evalMultAAB, evalMultBAB, evalMultAB.GetKeyTag())
    cryptoContext.InsertEvalMultKey([evalMultFinal])

    # Round 3 (party C) - Lead Party (who encrypts and finalizes the bootstrapping protocol)
    kp3 = cryptoContext.MultipartyKeyGen(kp2.publicKey)
    evalMultKey3 = cryptoContext.MultiKeySwitchGen(kp3.secretKey, kp3.secretKey, evalMultKey)
    evalMultABC = cryptoContext.MultiAddEvalKeys(evalMultAB, evalMultKey3, kp3.publicKey.GetKeyTag())
    evalMultBABC = cryptoContext.MultiMultEvalKey(kp2.secretKey, evalMultABC, kp3.publicKey.GetKeyTag())
    evalMultAABC = cryptoContext.MultiMultEvalKey(kp1.secretKey, evalMultABC, kp3.publicKey.GetKeyTag())
    evalMultCABC = cryptoContext.MultiMultEvalKey(kp3.secretKey, evalMultABC, kp3.publicKey.GetKeyTag())
    evalMultABABC = cryptoContext.MultiAddEvalMultKeys(evalMultBABC, evalMultAABC, evalMultBABC.GetKeyTag())
    evalMultFinal2 = cryptoContext.MultiAddEvalMultKeys(evalMultABABC, evalMultCABC, evalMultCABC.GetKeyTag())
    cryptoContext.InsertEvalMultKey([evalMultFinal2])

    if not kp1.good():
        print("Key generation failed!")
        exit(1)
    if not kp2.good():
        print("Key generation failed!")
        exit(1)
    if not kp3.good():
        print("Key generation failed!")
        exit(1)

    # END of Key Generation

    input = [-4.0, -3.0, -2.0, -1.0, 0.0, 1.0, 2.0, 3.0, 4.0]

    # Chebyshev coefficients
    coefficients = [1.0, 0.558971, 0.0, -0.0943712, 0.0, 0.0215023, 0.0, -0.00505348, 0.0, 0.00119324,
                    0.0, -0.000281928, 0.0, 0.0000664347, 0.0, -0.0000148709]
    # Input range
    a = -4
    b = 4

    pt1 = cryptoContext.MakeCKKSPackedPlaintext(input)
    encodedLength = len(input)

    ct1 = cryptoContext.Encrypt(kp3.publicKey, pt1)

    ct1 = cryptoContext.EvalChebyshevSeries(ct1, coefficients, a, b)

    # INTERACTIVE BOOTSTRAPPING STARTS

    ct1 = cryptoContext.IntMPBootAdjustScale(ct1)

    # Leading party (party B) generates a Common Random Poly (crp) at max coefficient modulus (QNumPrime).
    # a is sampled at random uniformly from R_{Q}
    crp = cryptoContext.IntMPBootRandomElementGen(kp3.publicKey)
    # Each party generates its own shares: maskedDecryptionShare and reEncryptionShare
    # (h_{0,i}, h_{1,i}) = (masked decryption share, re-encryption share)
    
    # extract c1 - element-wise
    c1 = ct1.Clone()
    c1.RemoveElement(0)
    sharesPair0 = cryptoContext.IntMPBootDecrypt(kp1.secretKey, c1, crp)
    sharesPair1 = cryptoContext.IntMPBootDecrypt(kp2.secretKey, c1, crp)
    sharesPair2 = cryptoContext.IntMPBootDecrypt(kp3.secretKey, c1, crp)

    sharesPairVec = [sharesPair0, sharesPair1, sharesPair2]

    # Party B finalizes the protocol by aggregating the shares and reEncrypting the results
    aggregatedSharesPair = cryptoContext.IntMPBootAdd(sharesPairVec)
    ciphertextOutput = cryptoContext.IntMPBootEncrypt(kp3.publicKey, aggregatedSharesPair, crp, ct1)

    # INTERACTIVE BOOTSTRAPPING ENDS

    # distributed decryption

    ciphertextPartial1 = cryptoContext.MultipartyDecryptMain([ciphertextOutput], kp1.secretKey)
    ciphertextPartial2 = cryptoContext.MultipartyDecryptMain([ciphertextOutput], kp2.secretKey)
    ciphertextPartial3 = cryptoContext.MultipartyDecryptLead([ciphertextOutput], kp3.secretKey)
    partialCiphertextVec = [ciphertextPartial1[0], ciphertextPartial2[0], ciphertextPartial3[0]]

    plaintextMultiparty = cryptoContext.MultipartyDecryptFusion(partialCiphertextVec)
    plaintextMultiparty.SetLength(encodedLength)

    # Ground truth result
    result = [0.0179885, 0.0474289, 0.119205, 0.268936, 0.5, 0.731064, 0.880795, 0.952571, 0.982011]
    plaintextResult = cryptoContext.MakeCKKSPackedPlaintext(result)

    print("Ground Truth:")
    print("\t", plaintextResult.GetCKKSPackedValue())
    print("Computed Result:")
    print("\t", plaintextMultiparty.GetCKKSPackedValue())

    checkApproximateEquality(plaintextResult.GetCKKSPackedValue(), plaintextMultiparty.GetCKKSPackedValue(), encodedLength, 0.0001)

    print("\n============================ INTERACTIVE DECRYPTION ENDED ============================")

    print(f"\nTCKKSCollectiveBoot FHE example with rescaling technique: {scaleTech} Completed!")

if __name__ == "__main__":
    main()
