from openfhe import *
from math import log2

def main():
    print("\n=================RUNNING FOR BFVrns======================\n")
    RunBFVrns()

def RunBFVrns():
    plaintextModulus = 65537
    sigma = 3.2
    securityLevel = SecurityLevel.HEStd_128_classic

    batchSize = 16
    multDepth = 4
    digitSize = 30
    dcrtBits = 60

    parameters = CCParamsBFVRNS()
    parameters.SetPlaintextModulus(plaintextModulus)
    parameters.SetSecurityLevel(securityLevel)
    parameters.SetStandardDeviation(sigma)
    parameters.SetSecretKeyDist(UNIFORM_TERNARY)
    parameters.SetMultiplicativeDepth(multDepth)
    parameters.SetBatchSize(batchSize)
    parameters.SetDigitSize(digitSize)
    parameters.SetScalingModSize(dcrtBits)
    parameters.SetThresholdNumOfParties(5)
    parameters.SetMultiplicationTechnique(HPSPOVERQLEVELED)

    cc = GenCryptoContext(parameters)
    # Enable features you wish to use
    cc.Enable(PKE)
    cc.Enable(KEYSWITCH)
    cc.Enable(LEVELEDSHE)
    cc.Enable(ADVANCEDSHE)
    cc.Enable(MULTIPARTY)

    ##########################################################
    # Set-up of parameters
    ##########################################################

    # Output the generated parameters
    print(f"p = {cc.GetPlaintextModulus()}")
    print(f"n = {cc.GetCyclotomicOrder() / 2}")
    print(f"log2 q = {log2(cc.GetModulus())}")

    ############################################################
    ## Perform Key Generation Operation
    ############################################################

    print("Running key generation (used for source data)...")

    # Round 1 (party A)

    print("Round 1 (party A) started.")

    kp1 = cc.KeyGen()
    kp2 = cc.MultipartyKeyGen(kp1.publicKey)
    kp3 = cc.MultipartyKeyGen(kp2.publicKey)
    kp4 = cc.MultipartyKeyGen(kp3.publicKey)
    kp5 = cc.MultipartyKeyGen(kp4.publicKey)

    # Generate evalmult key part for A
    evalMultKey = cc.KeySwitchGen(kp1.secretKey, kp1.secretKey)
    evalMultKey2 = cc.MultiKeySwitchGen(kp2.secretKey, kp2.secretKey, evalMultKey)
    evalMultKey3 = cc.MultiKeySwitchGen(kp3.secretKey, kp3.secretKey, evalMultKey)
    evalMultKey4 = cc.MultiKeySwitchGen(kp4.secretKey, kp4.secretKey, evalMultKey)
    evalMultKey5 = cc.MultiKeySwitchGen(kp5.secretKey, kp5.secretKey, evalMultKey)

    evalMultAB = cc.MultiAddEvalKeys(evalMultKey, evalMultKey2, kp2.publicKey.GetKeyTag())
    evalMultABC = cc.MultiAddEvalKeys(evalMultAB, evalMultKey3, kp3.publicKey.GetKeyTag())
    evalMultABCD = cc.MultiAddEvalKeys(evalMultABC, evalMultKey4, kp4.publicKey.GetKeyTag())
    evalMultABCDE = cc.MultiAddEvalKeys(evalMultABCD, evalMultKey5, kp5.publicKey.GetKeyTag())

    evalMultEABCDE = cc.MultiMultEvalKey(kp5.secretKey, evalMultABCDE, kp5.publicKey.GetKeyTag())
    evalMultDABCDE = cc.MultiMultEvalKey(kp4.secretKey, evalMultABCDE, kp5.publicKey.GetKeyTag())
    evalMultCABCDE = cc.MultiMultEvalKey(kp3.secretKey, evalMultABCDE, kp5.publicKey.GetKeyTag())
    evalMultBABCDE = cc.MultiMultEvalKey(kp2.secretKey, evalMultABCDE, kp5.publicKey.GetKeyTag())
    evalMultAABCDE = cc.MultiMultEvalKey(kp1.secretKey, evalMultABCDE, kp5.publicKey.GetKeyTag())

    evalMultDEABCDE = cc.MultiAddEvalMultKeys(evalMultEABCDE, evalMultDABCDE, evalMultEABCDE.GetKeyTag())
    evalMultCDEABCDE = cc.MultiAddEvalMultKeys(evalMultCABCDE, evalMultDEABCDE, evalMultCABCDE.GetKeyTag())
    evalMultBCDEABCDE = cc.MultiAddEvalMultKeys(evalMultBABCDE, evalMultCDEABCDE, evalMultBABCDE.GetKeyTag())

    evalMultFinal = cc.MultiAddEvalMultKeys(evalMultAABCDE, evalMultBCDEABCDE, kp5.publicKey.GetKeyTag())
    cc.InsertEvalMultKey([evalMultFinal])

    print("Round 1 of key generation completed.")

    ############################################################
    ## EvalSum Key Generation
    ############################################################

    print("Running evalsum key generation (used for source data)...")

    # Generate evalsum key part for A
    cc.EvalSumKeyGen(kp1.secretKey)
    evalSumKeys = cc.GetEvalSumKeyMap(kp1.secretKey.GetKeyTag())

    evalSumKeysB = cc.MultiEvalSumKeyGen(kp2.secretKey, evalSumKeys, kp2.publicKey.GetKeyTag())
    evalSumKeysC = cc.MultiEvalSumKeyGen(kp3.secretKey, evalSumKeys, kp3.publicKey.GetKeyTag())
    evalSumKeysD = cc.MultiEvalSumKeyGen(kp4.secretKey, evalSumKeys, kp4.publicKey.GetKeyTag())
    evalSumKeysE = cc.MultiEvalSumKeyGen(kp5.secretKey, evalSumKeys, kp5.publicKey.GetKeyTag())

    evalSumKeysAB = cc.MultiAddEvalSumKeys(evalSumKeys, evalSumKeysB, kp2.publicKey.GetKeyTag())
    evalSumKeysABC = cc.MultiAddEvalSumKeys(evalSumKeysC, evalSumKeysAB, kp3.publicKey.GetKeyTag())
    evalSumKeysABCD = cc.MultiAddEvalSumKeys(evalSumKeysABC, evalSumKeysD, kp4.publicKey.GetKeyTag())

    evalSumKeysJoin = cc.MultiAddEvalSumKeys(evalSumKeysE, evalSumKeysABCD, kp5.publicKey.GetKeyTag())
    cc.InsertEvalSumKey(evalSumKeysJoin)

    print("Evalsum key generation completed.")

    ############################################################
    ## Encode source data
    ############################################################

    vectorOfInts1 = [1, 2, 3, 4, 5, 6, 5, 4, 3, 2, 1, 0]
    vectorOfInts2 = [1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0]
    vectorOfInts3 = [2, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0]

    plaintext1 = cc.MakePackedPlaintext(vectorOfInts1)
    plaintext2 = cc.MakePackedPlaintext(vectorOfInts2)
    plaintext3 = cc.MakePackedPlaintext(vectorOfInts3)

    ############################################################
    ## Encryption
    ############################################################

    ciphertext1 = cc.Encrypt(kp5.publicKey, plaintext1)
    ciphertext2 = cc.Encrypt(kp5.publicKey, plaintext2)
    ciphertext3 = cc.Encrypt(kp5.publicKey, plaintext3)

    ############################################################
    ## Homomorphic Operations
    ############################################################

    ciphertextAdd12 = cc.EvalAdd(ciphertext1, ciphertext2)
    ciphertextAdd123 = cc.EvalAdd(ciphertextAdd12, ciphertext3)

    ciphertextMult1 = cc.EvalMult(ciphertext1, ciphertext1)
    ciphertextMult2 = cc.EvalMult(ciphertextMult1, ciphertext1)
    ciphertextMult3 = cc.EvalMult(ciphertextMult2, ciphertext1)
    ciphertextMult = cc.EvalMult(ciphertextMult3, ciphertext1)

    ciphertextEvalSum = cc.EvalSum(ciphertext3, batchSize)

    ############################################################
    ## Decryption after Accumulation Operation on Encrypted Data with Multiparty
    ############################################################

    # Distributed decryption
    # partial decryption by party A
    ciphertextPartial1 = cc.MultipartyDecryptLead([ciphertextAdd123], kp1.secretKey)

    # partial decryption by party B
    ciphertextPartial2 = cc.MultipartyDecryptMain([ciphertextAdd123], kp2.secretKey)

    # partial decryption by party C
    ciphertextPartial3 = cc.MultipartyDecryptMain([ciphertextAdd123], kp3.secretKey)

    # partial decryption by party D
    ciphertextPartial4 = cc.MultipartyDecryptMain([ciphertextAdd123], kp4.secretKey)

    # partial decryption by party E
    ciphertextPartial5 = cc.MultipartyDecryptMain([ciphertextAdd123], kp5.secretKey)

    partialCiphertextVec = [ciphertextPartial1[0], ciphertextPartial2[0], ciphertextPartial3[0],
                            ciphertextPartial4[0], ciphertextPartial5[0]]

    plaintextMultipartyNew = cc.MultipartyDecryptFusion(partialCiphertextVec)

    print("\n Original Plaintext: \n")
    print(plaintext1)
    print(plaintext2)
    print(plaintext3)

    plaintextMultipartyNew.SetLength(plaintext1.GetLength())

    print("\n Resulting Fused Plaintext: \n")
    print(plaintextMultipartyNew)

    print("\n")

    ciphertextPartial1 = cc.MultipartyDecryptLead([ciphertextMult], kp1.secretKey)
    ciphertextPartial2 = cc.MultipartyDecryptMain([ciphertextMult], kp2.secretKey)
    ciphertextPartial3 = cc.MultipartyDecryptMain([ciphertextMult], kp3.secretKey)
    ciphertextPartial4 = cc.MultipartyDecryptMain([ciphertextMult], kp4.secretKey)
    ciphertextPartial5 = cc.MultipartyDecryptMain([ciphertextMult], kp5.secretKey)

    partialCiphertextVecMult = [ciphertextPartial1[0], ciphertextPartial2[0], ciphertextPartial3[0],
                                ciphertextPartial4[0], ciphertextPartial5[0]]

    plaintextMultipartyMult = cc.MultipartyDecryptFusion(partialCiphertextVecMult)

    plaintextMultipartyMult.SetLength(plaintext1.GetLength())

    print("\n Resulting Fused Plaintext after Multiplication of plaintexts 1 and 3: \n")
    print(plaintextMultipartyMult)

    print("\n")

    ciphertextPartial1 = cc.MultipartyDecryptLead([ciphertextEvalSum], kp1.secretKey)
    ciphertextPartial2 = cc.MultipartyDecryptMain([ciphertextEvalSum], kp2.secretKey)
    ciphertextPartial3 = cc.MultipartyDecryptMain([ciphertextEvalSum], kp3.secretKey)
    ciphertextPartial4 = cc.MultipartyDecryptMain([ciphertextEvalSum], kp4.secretKey)
    ciphertextPartial5 = cc.MultipartyDecryptMain([ciphertextEvalSum], kp5.secretKey)

    partialCiphertextVecEvalSum = [ciphertextPartial1[0], ciphertextPartial2[0], ciphertextPartial3[0],
                                   ciphertextPartial4[0], ciphertextPartial5[0]]

    plaintextMultipartyEvalSum = cc.MultipartyDecryptFusion(partialCiphertextVecEvalSum)

    plaintextMultipartyEvalSum.SetLength(plaintext1.GetLength())

    print("\n Fused result after the Summation of ciphertext 3: \n")
    print(plaintextMultipartyEvalSum)

if __name__ == "__main__":
    main()
