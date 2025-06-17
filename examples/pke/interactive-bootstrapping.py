from openfhe import *


def main():
    # the scaling technigue can be changed to FIXEDMANUAL, FIXEDAUTO, or FLEXIBLEAUTOEXT
    ThresholdFHE(FLEXIBLEAUTO)
    Chebyshev(FLEXIBLEAUTO)

def ThresholdFHE(scaleTech):
    # if scaleTech not in [FIXEDMANUAL, FIXEDAUTO, FLEXIBLEAUTOEXT]:
    #     errMsg = "ERROR: Scaling technique is not supported!"
    #     raise Exception(errMsg)

    print(f"Threshold FHE example with Scaling Technique {scaleTech}")

    parameters = CCParamsCKKSRNS()
    # 1 extra level needs to be added for FIXED* modes (2 extra levels for FLEXIBLE* modes) to the multiplicative depth
    # to support 2-party interactive bootstrapping
    depth = 7
    parameters.SetMultiplicativeDepth(depth)
    parameters.SetScalingModSize(50)
    parameters.SetBatchSize(16)
    parameters.SetScalingTechnique(scaleTech)

    cc = GenCryptoContext(parameters)
    cc.Enable(PKE)
    cc.Enable(LEVELEDSHE)
    cc.Enable(ADVANCEDSHE)
    cc.Enable(MULTIPARTY)

    #############################################################
    # Perform Key Generation Operation
    #############################################################

    print("Running key generation (used for source data)...")
    print("Round 1 (party A) started.")

    kp1 = cc.KeyGen()
    evalMultKey = cc.KeySwitchGen(kp1.secretKey, kp1.secretKey)

    print("Round 1 of key generation completed.")
    #############################################################
    print("Round 2 (party B) started.")
    print("Joint public key for (s_a + s_b) is generated...")
    kp2 = cc.MultipartyKeyGen(kp1.publicKey)

    input = [-0.9, -0.8, -0.6, -0.4, -0.2, 0., 0.2, 0.4, 0.6, 0.8, 0.9]

    # This plaintext only has 3 RNS limbs, the minimum needed to perform 2-party interactive bootstrapping for FLEXIBLEAUTO
    plaintext1 = cc.MakeCKKSPackedPlaintext(input, 1, depth - 2)
    ciphertext1 = cc.Encrypt(kp2.publicKey, plaintext1)

    # INTERACTIVE BOOTSTRAPPING STARTS

    # under the hood it reduces to two towers
    ciphertext1 = cc.IntBootAdjustScale(ciphertext1)
    print("IntBootAdjustScale Succeeded")

    # masked decryption on the server: c0 = b + a*s0
    ciphertextOutput1 = cc.IntBootDecrypt(kp1.secretKey, ciphertext1)
    print("IntBootDecrypt on Server Succeeded")

    ciphertext2 = ciphertext1.Clone()
    ciphertext2.SetElements([ciphertext2.GetElements()[1]])

    # masked decryption on the client: c1 = a*s1
    ciphertextOutput2 = cc.IntBootDecrypt(kp2.secretKey, ciphertext2)
    print("IntBootDecrypt on Client Succeeded")

    # Encryption of masked decryption c1 = a*s1
    ciphertextOutput2 = cc.IntBootEncrypt(kp2.publicKey, ciphertextOutput2)
    print("IntBootEncrypt on Client Succeeded")

    # Compute Enc(c1) + c0
    ciphertextOutput = cc.IntBootAdd(ciphertextOutput2, ciphertextOutput1)
    print("IntBootAdd on Server Succeeded")

    # INTERACTIVE BOOTSTRAPPING ENDS

    # distributed decryption
    ciphertextPartial1 = cc.MultipartyDecryptLead([ciphertextOutput], kp1.secretKey)
    ciphertextPartial2 = cc.MultipartyDecryptMain([ciphertextOutput], kp2.secretKey)

    partialCiphertextVec = [ciphertextPartial1[0], ciphertextPartial2[0]]
    plaintextMultiparty = cc.MultipartyDecryptFusion(partialCiphertextVec)

    plaintextMultiparty.SetLength(len(input))

    print(f"Original plaintext \n\t {plaintext1.GetCKKSPackedValue()}")
    print(f"Result after bootstrapping \n\t {plaintextMultiparty.GetCKKSPackedValue()}")

def Chebyshev(scaleTech):
#     if scaleTech not in [FIXEDMANUAL, FIXEDAUTO, FLEXIBLEAUTOEXT]:
#         errMsg = "ERROR: Scaling technique is not supported!"
#         raise Exception(errMsg)

    print(f"Threshold FHE example with Scaling Technique {scaleTech}")
    
    parameters = CCParamsCKKSRNS()
    # 1 extra level needs to be added for FIXED* modes (2 extra levels for FLEXIBLE* modes) to the multiplicative depth
    # to support 2-party interactive bootstrapping
    parameters.SetMultiplicativeDepth(8)
    parameters.SetScalingModSize(50)
    parameters.SetBatchSize(16)
    parameters.SetScalingTechnique(scaleTech)

    cc = GenCryptoContext(parameters)
    # enable features that you wish to use
    cc.Enable(PKE)
    cc.Enable(LEVELEDSHE)
    cc.Enable(ADVANCEDSHE)
    cc.Enable(MULTIPARTY)

    ############################################################
    # Perform Key Generation Operation
    ############################################################

    print("Running key generation (used for source data)...")
    print("Round 1 (party A) started.")

    kp1 = cc.KeyGen()

    evalMultKey = cc.KeySwitchGen(kp1.secretKey, kp1.secretKey)
    cc.EvalSumKeyGen(kp1.secretKey)
    evalSumKeys = cc.GetEvalSumKeyMap(kp1.secretKey.GetKeyTag())

    print("Round 1 of key generation completed.")
    ############################################################
    print("Round 2 (party B) started.")
    print("Joint public key for (s_a + s_b) is generated...")
    kp2 = cc.MultipartyKeyGen(kp1.publicKey)

    evalMultKey2 = cc.MultiKeySwitchGen(kp2.secretKey, kp2.secretKey, evalMultKey)

    print("Joint evaluation multiplication key for (s_a + s_b) is generated...")
    evalMultAB = cc.MultiAddEvalKeys(evalMultKey, evalMultKey2, kp2.publicKey.GetKeyTag())

    print("Joint evaluation multiplication key (s_a + s_b) is transformed into s_b*(s_a + s_b)...")
    evalMultBAB = cc.MultiMultEvalKey(kp2.secretKey, evalMultAB, kp2.publicKey.GetKeyTag())

    evalSumKeysB = cc.MultiEvalSumKeyGen(kp2.secretKey, evalSumKeys, kp2.publicKey.GetKeyTag())

    print("Joint evaluation summation key for (s_a + s_b) is generated...")
    evalSumKeysJoin = cc.MultiAddEvalSumKeys(evalSumKeys, evalSumKeysB, kp2.publicKey.GetKeyTag())

    cc.InsertEvalSumKey(evalSumKeysJoin)

    print("Round 2 of key generation completed.")

    print("Round 3 (party A) started.")
    print("Joint key (s_a + s_b) is transformed into s_a*(s_a + s_b)...")
    evalMultAAB = cc.MultiMultEvalKey(kp1.secretKey, evalMultAB, kp2.publicKey.GetKeyTag())

    print("Computing the final evaluation multiplication key for (s_a + s_b)*(s_a + s_b)...")
    evalMultFinal = cc.MultiAddEvalMultKeys(evalMultAAB, evalMultBAB, evalMultAB.GetKeyTag())

    cc.InsertEvalMultKey([evalMultFinal])

    print("Round 3 of key generation completed.")

    input = [-4.0, -3.0, -2.0, -1.0, 0.0, 1.0, 2.0, 3.0, 4.0]

    coefficients = [1.0, 0.558971, 0.0, -0.0943712, 0.0, 0.0215023, 0.0, -0.00505348, 0.0, 0.00119324,
                    0.0, -0.000281928, 0.0, 0.0000664347, 0.0, -0.0000148709]

    a = -4
    b = 4

    plaintext1 = cc.MakeCKKSPackedPlaintext(input)

    ciphertext1 = cc.Encrypt(kp2.publicKey, plaintext1)

    # The Chebyshev series interpolation requires 6 levels
    ciphertext1 = cc.EvalChebyshevSeries(ciphertext1, coefficients, a, b)
    print("Ran Chebyshev interpolation")

    # INTERACTIVE BOOTSTRAPPING STARTS

    ciphertext1 = cc.IntBootAdjustScale(ciphertext1)
    print("IntBootAdjustScale Succeeded")

    # masked decryption on the server: c0 = b + a*s0
    ciphertextOutput1 = cc.IntBootDecrypt(kp1.secretKey, ciphertext1)
    print("IntBootDecrypt on Server Succeeded")

    ciphertext2 = ciphertext1.Clone()
    ciphertext2.SetElements([ciphertext2.GetElements()[1]])

    # masked decryption on the client: c1 = a*s1
    ciphertextOutput2 = cc.IntBootDecrypt(kp2.secretKey, ciphertext2)
    print("IntBootDecrypt on Client Succeeded")

    # Encryption of masked decryption c1 = a*s1
    ciphertextOutput2 = cc.IntBootEncrypt(kp2.publicKey, ciphertextOutput2)
    print("IntBootEncrypt on Client Succeeded")

    # Compute Enc(c1) + c0
    ciphertextOutput = cc.IntBootAdd(ciphertextOutput2, ciphertextOutput1)
    print("IntBootAdd on Server Succeeded")

    # INTERACTIVE BOOTSTRAPPING ENDS

    # distributed decryption

    ciphertextPartial1 = cc.MultipartyDecryptLead([ciphertextOutput], kp1.secretKey)

    ciphertextPartial2 = cc.MultipartyDecryptMain([ciphertextOutput], kp2.secretKey)

    partialCiphertextVec = [ciphertextPartial1[0], ciphertextPartial2[0]]
    plaintextMultiparty = cc.MultipartyDecryptFusion(partialCiphertextVec)

    plaintextMultiparty.SetLength(len(input))

    print(f"\n Original Plaintext #1: \n {plaintext1}")

    print(f"\n Results of evaluating the polynomial with coefficients {coefficients} \n")
    print(f"\n Ciphertext result: {plaintextMultiparty}")

    print("\n Plaintext result: ( 0.0179885, 0.0474289, 0.119205, 0.268936, 0.5, 0.731064, 0.880795, 0.952571, 0.982011 ) \n")

    print("\n Exact result: ( 0.0179862, 0.0474259, 0.119203, 0.268941, 0.5, 0.731059, 0.880797, 0.952574, 0.982014 ) \n")

    print("\n Another round of Chebyshev interpolation after interactive bootstrapping: \n")

    ciphertextOutput = cc.EvalChebyshevSeries(ciphertextOutput, coefficients, a, b)
    print("Ran Chebyshev interpolation")

    # distributed decryption

    ciphertextPartial1 = cc.MultipartyDecryptLead([ciphertextOutput], kp1.secretKey)

    ciphertextPartial2 = cc.MultipartyDecryptMain([ciphertextOutput], kp2.secretKey)

    partialCiphertextVec = [ciphertextPartial1[0], ciphertextPartial2[0]]
    plaintextMultiparty = cc.MultipartyDecryptFusion(partialCiphertextVec)

    plaintextMultiparty.SetLength(len(input))

    print(f"\n Ciphertext result: {plaintextMultiparty}")

    print("\n Plaintext result: ( 0.504497, 0.511855, 0.529766, 0.566832, 0.622459, 0.675039, 0.706987, 0.721632, 0.727508 )")


if __name__ == "__main__":
    main()
