from openfhe import *

#
# A utility class defining a party that is involved in the collective bootstrapping protocol
#
class Party:
    def __init__(self, id, sharesPair, kpShard):
        self.id = id
        self.sharesPair = sharesPair
        self.kpShard = kpShard
    def __init__(self):
        self.id = None
        self.sharesPair = None
        self.kpShard = None
    def __str__(self):
        return f"Party {self.id}"

def main():
    print( "Interactive Multi-Party Bootstrapping Ciphertext (TCKKS) started ...\n")

    # Same test with different rescaling techniques in CKKS
    TCKKSCollectiveBoot(FIXEDMANUAL)
    TCKKSCollectiveBoot(FIXEDAUTO)
    if get_native_int()!=128:
        TCKKSCollectiveBoot(FLEXIBLEAUTO)
        TCKKSCollectiveBoot(FLEXIBLEAUTOEXT)

    print("Interactive Multi-Party Bootstrapping Ciphertext (TCKKS) terminated gracefully!\n")

# Demonstrate interactive multi-party bootstrapping for 3 parties
# We follow Protocol 5 in https://eprint.iacr.org/2020/304, "Multiparty
# Homomorphic Encryption from Ring-Learning-With-Errors"

def TCKKSCollectiveBoot(scaleTech):
    if scaleTech != FIXEDMANUAL and scaleTech != FIXEDAUTO and scaleTech != FLEXIBLEAUTO and scaleTech != FLEXIBLEAUTOEXT:
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

    multiplicativeDepth = 7
    parameters.SetMultiplicativeDepth(multiplicativeDepth)
    parameters.SetKeySwitchTechnique(HYBRID)

    batchSize = 4
    parameters.SetBatchSize(batchSize)

    compressionLevel = COMPRESSION_LEVEL.SLACK
    parameters.SetInteractiveBootCompressionLevel(compressionLevel)

    cryptoContext = GenCryptoContext(parameters)
    cryptoContext.Enable(PKE)
    cryptoContext.Enable(KEYSWITCH)
    cryptoContext.Enable(LEVELEDSHE)
    cryptoContext.Enable(ADVANCEDSHE)
    cryptoContext.Enable(MULTIPARTY)

    ringDim = cryptoContext.GetRingDimension()
    maxNumSlots = ringDim / 2

    print(f"TCKKS scheme is using ring dimension {ringDim}")
    print(f"TCKKS scheme number of slots         {maxNumSlots}")
    print(f"TCKKS scheme max number of slots     {maxNumSlots}")
    print(f"TCKKS example with Scaling Technique {scaleTech}")

    numParties = 3

    print("\n===========================IntMPBoot protocol parameters===========================\n")
    print(f"number of parties: {numParties}\n")
    print("===============================================================\n")

    # List to store parties objects
    parties = [Party()]*numParties

    print("Running key generation (used for source data)...\n")

    for i in range(numParties):
        #define id of parties[i] as i
        parties[i].id = i
        print(f"Party {parties[i].id} started.")
        if i == 0:
            parties[i].kpShard = cryptoContext.KeyGen()
        else:
            parties[i].kpShard = cryptoContext.MultipartyKeyGen(parties[0].kpShard.publicKey)
        print(f"Party {i} key generation completed.\n")
    
    print("Joint public key for (s_0 + s_1 + ... + s_n) is generated...")

    # Assert everything is good
    for i in range(numParties):
        if not parties[i].kpShard.good():
            print(f"Key generation failed for party {i}!\n")
            return 1

    # Generate collective public key
    secretKeys = []
    for i in range(numParties):
        secretKeys.append(parties[i].kpShard.secretKey)
    kpMultiparty = cryptoContext.MultipartyKeyGen(secretKeys)

    # Prepare input vector
    msg1 = [-0.9, -0.8, 0.2, 0.4]
    ptxt1 = cryptoContext.MakeCKKSPackedPlaintext(msg1)

    # Encryption
    inCtxt = cryptoContext.Encrypt(kpMultiparty.publicKey, ptxt1)
    
    print("Compressing ctxt to the smallest possible number of towers!\n")
    inCtxt = cryptoContext.IntMPBootAdjustScale(inCtxt)

    print("\n============================ INTERACTIVE BOOTSTRAPPING STARTS ============================\n")
    
    #Leading party (P0) generates a Common Random Poly (a) at max coefficient modulus (QNumPrime).
    # a is sampled at random uniformly from R_{Q}
    a = cryptoContext.IntMPBootRandomElementGen(parties[0].kpShard.publicKey)
    print("Common Random Poly (a) has been generated with coefficient modulus Q\n")

    # Each party generates its own shares: maskedDecryptionShare and reEncryptionShare
    sharePairVec = []

    # Make a copy of input ciphertext and remove the first element (c0), we only
    # c1 for IntMPBootDecrypt
    c1 = inCtxt.Clone()
    c1.RemoveElement(0)

    for i in range(numParties):
        print(f"Party {i} started its part in Collective Bootstrapping Protocol.\n")
        parties[i].sharesPair = cryptoContext.IntMPBootDecrypt(parties[i].kpShard.secretKey, c1, a)
        sharePairVec.append(parties[i].sharesPair)
    
    # P0 finalizes the protocol by aggregating the shares and reEncrypting the results
    aggregatedSharesPair = cryptoContext.IntMPBootAdd(sharePairVec);
    # Make sure you provide the non-striped ciphertext (inCtxt) in IntMPBootEncrypt
    outCtxt = cryptoContext.IntMPBootEncrypt(parties[0].kpShard.publicKey, aggregatedSharesPair, a, inCtxt)

    # INTERACTIVE BOOTSTRAPPING ENDS
    print("\n============================ INTERACTIVE BOOTSTRAPPING ENDED ============================\n")

    # Distributed Decryption
    print("\n============================ INTERACTIVE DECRYPTION STARTED ============================ \n")

    partialCiphertextVec = []
    print("Party 0 started its part in the collective decryption protocol\n")
    partialCiphertextVec.append(cryptoContext.MultipartyDecryptLead([outCtxt], parties[0].kpShard.secretKey)[0])

    for i in range(1, numParties):
        print(f"Party {i} started its part in the collective decryption protocol\n")
        partialCiphertextVec.append(cryptoContext.MultipartyDecryptMain([outCtxt], parties[i].kpShard.secretKey)[0])

    # Checking the results
    print("MultipartyDecryptFusion ...\n")
    plaintextMultiparty = cryptoContext.MultipartyDecryptFusion(partialCiphertextVec)
    plaintextMultiparty.SetLength(len(msg1))

    # transform to python:
    print(f"Original plaintext \n\t {ptxt1.GetCKKSPackedValue()}\n")
    print(f"Result after bootstrapping \n\t {plaintextMultiparty.GetCKKSPackedValue()}\n")

    print("\n============================ INTERACTIVE DECRYPTION ENDED ============================\n")      

if __name__ == "__main__":
    main()
