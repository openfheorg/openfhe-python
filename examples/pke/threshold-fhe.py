from openfhe import *
from math import log2

def main():
    print("\n=================RUNNING FOR BGVrns - Additive =====================")

    RunBGVrnsAdditive()

    print("\n=================RUNNING FOR BFVrns=====================")

    RunBFVrns()

    print("\n=================RUNNING FOR CKKS=====================")

    RunCKKS()

def RunBGVrnsAdditive():
    parameters = CCParamsBGVRNS()
    parameters.SetPlaintextModulus(65537)

    # NOISE_FLOODING_MULTIPARTY adds extra noise to the ciphertext before decrypting
    # and is most secure mode of threshold FHE for BFV and BGV.
    parameters.SetMultipartyMode(NOISE_FLOODING_MULTIPARTY)

    cc = GenCryptoContext(parameters)
    # Enable Features you wish to use
    cc.Enable(PKE)
    cc.Enable(KEYSWITCH)
    cc.Enable(LEVELEDSHE)
    cc.Enable(ADVANCEDSHE)
    cc.Enable(MULTIPARTY)

    ##########################################################
    # Set-up of parameters
    ##########################################################

    # Print out the parameters
    print(f"p = {parameters.GetPlaintextModulus()}")
    # TODO (Oliveira, R.) - Find a workaround for printing out the following parameters
    # print(f"n = {parameters.GetElementParams().GetCyclotomicOrder()/2}")
    # print(f"lo2 q = {log2(parameters.GetElementParams().GetModulus().ConvertToDouble())}")

    ############################################################
    ## Perform Key Generation Operation
    ############################################################

    print("Running key generation (used for source data)...")

    # generate the public key for first share
    kp1 = cc.KeyGen()
    # generate the public key for two shares
    kp2 = cc.MultipartyKeyGen(kp1.publicKey)
    # generate the public key for all three secret shares
    kp3 = cc.MultipartyKeyGen(kp2.publicKey)

    if not kp1.good():
        print("Key generation failed!")
        return 1
    if not kp2.good():
        print("Key generation failed!")
        return 1
    if not kp3.good():
        print("Key generation failed!")
        return 1
    
    ############################################################
    ## Encode source data
    ############################################################

    vectorOfInts1 = [1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0]
    vectorOfInts2 = [1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0]
    vectorOfInts3 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0]

    plaintext1 = cc.MakePackedPlaintext(vectorOfInts1)
    plaintext2 = cc.MakePackedPlaintext(vectorOfInts2)
    plaintext3 = cc.MakePackedPlaintext(vectorOfInts3)

    ############################################################
    ## Encryption
    ############################################################
    ciphertext1 = cc.Encrypt(kp3.publicKey, plaintext1)
    ciphertext2 = cc.Encrypt(kp3.publicKey, plaintext2)
    ciphertext3 = cc.Encrypt(kp3.publicKey, plaintext3)

    ############################################################
    ## EvalAdd Operation on Re-Encrypted Data
    ############################################################

    ciphertextAdd12 = cc.EvalAdd(ciphertext1, ciphertext2)
    ciphertextAdd123 = cc.EvalAdd(ciphertextAdd12, ciphertext3)

    ############################################################
    ## Decryption after Accumulation Operation on Encrypted Data with Multiparty
    ############################################################

    # partial decryption by first party
    ciphertextPartial1 = cc.MultipartyDecryptLead([ciphertextAdd123], kp1.secretKey)

    # partial decryption by second party
    ciphertextPartial2 = cc.MultipartyDecryptMain([ciphertextAdd123], kp2.secretKey)

    # partial decryption by third party
    ciphertextPartial3 = cc.MultipartyDecryptMain([ciphertextAdd123], kp3.secretKey)

    partialCiphertextVec = []
    partialCiphertextVec.append(ciphertextPartial1[0])
    partialCiphertextVec.append(ciphertextPartial2[0])
    partialCiphertextVec.append(ciphertextPartial3[0])

    # partial decryption are combined together
    plaintextMultipartyNew = cc.MultipartyDecryptFusion(partialCiphertextVec)

    print("\n Original Plaintext: \n")
    print(plaintext1)
    print(plaintext2)
    print(plaintext3)

    plaintextMultipartyNew.SetLength(plaintext1.GetLength())

    print("\n Resulting Fused Plaintext adding 3 ciphertexts: \n")
    print(plaintextMultipartyNew)

    print("\n")


def RunBFVrns():
    pass

def RunCKKS():
    pass

if __name__ == '__main__':
    main()

