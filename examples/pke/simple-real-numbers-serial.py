from openfhe import *
import os
from pathlib import Path
import tempfile

# NOTE:
# If running locally, you may want to replace the "hardcoded" datafolder with
# the datafolder location below which gets the current working directory

# Save-Load locations for keys
datafolder = "demoData"
ccLocation = "/cryptocontext.txt"
pubKeyLocation = "/key_pub.txt"  # Pub key
multKeyLocation = "/key_mult.txt"  # relinearization key
rotKeyLocation = "/key_rot.txt"  # automorphism / rotation key

# Save-load locations for RAW ciphertexts
cipherOneLocation = "/ciphertext1.txt"
cipherTwoLocation = "/ciphertext2.txt"

# Save-load locations for evaluated ciphertexts
cipherMultLocation = "/ciphertextMult.txt"
cipherAddLocation = "/ciphertextAdd.txt"
cipherRotLocation = "/ciphertextRot.txt"
cipherRotNegLocation = "/ciphertextRotNegLocation.txt"
clientVectorLocation = "/clientVectorFromClient.txt"


# Demarcate - Visual separator between the sections of code
def demarcate(msg):
    print("**************************************************\n")
    print(msg)
    print("**************************************************\n")


"""
serverSetupAndWrite(multDepth, scaleModSize, batchSize)
    simulates a server at startup where we generate a cryptocontext and keys.
    then, we generate some data (akin to loading raw data on an enclave)
    before encrypting the data
    :param multDepth: multiplication depth
    :param scaleModSize: number of bits to use in the scale factor (not the
    scale factor itself)
    :param batchSize: batch size to use
    :return Tuple<cryptoContext, keyPair>
"""


def serverSetupAndWrite(multDepth, scaleModSize, batchSize):

    parameters = CCParamsCKKSRNS()
    parameters.SetMultiplicativeDepth(multDepth)
    parameters.SetScalingModSize(scaleModSize)
    parameters.SetBatchSize(batchSize)

    serverCC = GenCryptoContext(parameters)

    serverCC.Enable(PKE)
    serverCC.Enable(KEYSWITCH)
    serverCC.Enable(LEVELEDSHE)

    print("Cryptocontext generated")

    serverKP = serverCC.KeyGen()
    print("Keypair generated")

    serverCC.EvalMultKeyGen(serverKP.secretKey)
    print("Eval Mult Keys/ Relinearization keys have been generated")

    serverCC.EvalRotateKeyGen(serverKP.secretKey, [1, 2, -1, -2])
    print("Rotation keys generated")

    vec1 = [1.0, 2.0, 3.0, 4.0]
    vec2 = [12.5, 13.5, 14.5, 15.5]
    vec3 = [10.5, 11.5, 12.5, 13.5]
    print("\nDisplaying first data vector: ")
    print(vec1)
    print("\n")

    serverP1 = serverCC.MakeCKKSPackedPlaintext(vec1)
    serverP2 = serverCC.MakeCKKSPackedPlaintext(vec2)
    serverP3 = serverCC.MakeCKKSPackedPlaintext(vec3)

    print("Plaintext version of first vector: " + str(serverP1))

    print("Plaintexts have been generated from complex-double vectors")

    serverC1 = serverCC.Encrypt(serverKP.publicKey, serverP1)
    serverC2 = serverCC.Encrypt(serverKP.publicKey, serverP2)
    serverC3 = serverCC.Encrypt(serverKP.publicKey, serverP3)

    print("Ciphertexts have been generated from plaintexts")

    ###
    #    Part 2:
    #    We serialize the following:
    #      Cryptocontext
    #      Public key
    #      relinearization (eval mult keys)
    #      rotation keys
    #      Some of the ciphertext
    #
    #      We serialize all of them to files
    ###
    demarcate("Part 2: Data Serialization (server)")

    if not SerializeToFile(datafolder + ccLocation, serverCC, BINARY):
        raise Exception("Exception writing cryptocontext to cryptocontext.txt")
    print("Cryptocontext serialized")

    if not SerializeToFile(datafolder + pubKeyLocation, serverKP.publicKey, BINARY):
        raise Exception("Exception writing public key to pubkey.txt")
    print("Public key has been serialized")

    if not serverCC.SerializeEvalMultKey(datafolder + multKeyLocation, BINARY):
        raise Exception("Error writing eval mult keys")
    print("EvalMult/ relinearization keys have been serialized")

    if not serverCC.SerializeEvalAutomorphismKey(datafolder + rotKeyLocation, BINARY):
        raise Exception("Error writing rotation keys")
    print("Rotation keys have been serialized")

    if not SerializeToFile(datafolder + cipherOneLocation, serverC1, BINARY):
        raise Exception("Error writing ciphertext 1")

    if not SerializeToFile(datafolder + cipherTwoLocation, serverC2, BINARY):
        raise Exception("Error writing ciphertext 2")

    return (serverCC, serverKP, len(vec1))


###
# clientProcess
#  - deserialize data from a file which simulates receiving data from a server
# after making a request
#  - we then process the data by doing operations (multiplication, addition,
# rotation, etc)
#  - !! We also create an object and encrypt it in this function before sending
# it off to the server to be decrypted
###


def clientProcess():
    # clientCC = CryptoContext()
    # clientCC.ClearEvalAutomorphismKeys()
    ReleaseAllContexts()
    ClearEvalMultKeys()

    clientCC, res = DeserializeCryptoContext(datafolder + ccLocation, BINARY)
    if not res:
        raise Exception(
            f"I cannot deserialize the cryptocontext from {datafolder+ccLocation}"
        )

    print("Client CC deserialized")

    # clientKP = KeyPair()
    # We do NOT have a secret key. The client
    # should not have access to this
    clientPuclicKey, res = DeserializePublicKey(datafolder + pubKeyLocation, BINARY)
    if not res:
        raise Exception(
            f"I cannot deserialize the public key from {datafolder+pubKeyLocation}"
        )
    print("Client KP deserialized\n")

    if not clientCC.DeserializeEvalMultKey(datafolder + multKeyLocation, BINARY):
        raise Exception(
            f"Cannot deserialize eval mult keys from {datafolder+multKeyLocation}"
        )
    print("Deserialized eval mult keys\n")

    if not clientCC.DeserializeEvalAutomorphismKey(datafolder + rotKeyLocation, BINARY):
        raise Exception(
            f"Cannot deserialize eval automorphism keys from {datafolder+rotKeyLocation}"
        )

    clientC1, res = DeserializeCiphertext(datafolder + cipherOneLocation, BINARY)
    if not res:
        raise Exception(
            f"Cannot deserialize the ciphertext from {datafolder+cipherOneLocation}"
        )
    print("Deserialized ciphertext 1\n")

    clientC2, res = DeserializeCiphertext(datafolder + cipherTwoLocation, BINARY)
    if not res:
        raise Exception(
            f"Cannot deserialize the ciphertext from {datafolder+cipherTwoLocation}"
        )
    print("Deserialized ciphertext 2\n")

    clientCiphertextMult = clientCC.EvalMult(clientC1, clientC2)
    clientCiphertextAdd = clientCC.EvalAdd(clientC1, clientC2)
    clientCiphertextRot = clientCC.EvalRotate(clientC1, 1)
    clientCiphertextRotNeg = clientCC.EvalRotate(clientC1, -1)

    # Now, we want to simulate a client who is encrypting data for the server to
    # decrypt. E.g weights of a machine learning algorithm
    demarcate("Part 3.5: Client Serialization of data that has been operated on")

    clientVector1 = [1.0, 2.0, 3.0, 4.0]
    clientPlaintext1 = clientCC.MakeCKKSPackedPlaintext(clientVector1)
    clientInitializedEncryption = clientCC.Encrypt(clientPuclicKey, clientPlaintext1)
    SerializeToFile(datafolder + cipherMultLocation, clientCiphertextMult, BINARY)
    SerializeToFile(datafolder + cipherAddLocation, clientCiphertextAdd, BINARY)
    SerializeToFile(datafolder + cipherRotLocation, clientCiphertextRot, BINARY)
    SerializeToFile(datafolder + cipherRotNegLocation, clientCiphertextRotNeg, BINARY)
    SerializeToFile(
        datafolder + clientVectorLocation, clientInitializedEncryption, BINARY
    )

    print("Serialized all ciphertexts from client\n")


###
#  serverVerification
#  - deserialize data from the client.
#  - Verify that the results are as we expect
# @param cc cryptocontext that was previously generated
# @param kp keypair that was previously generated
# @param vectorSize vector size of the vectors supplied
# @return
#  5-tuple of the plaintexts of various operations
##
def serverVerification(cc, kp, vectorSize):

    serverCiphertextFromClient_Mult, res = DeserializeCiphertext(
        datafolder + cipherMultLocation, BINARY
    )
    serverCiphertextFromClient_Add, res = DeserializeCiphertext(
        datafolder + cipherAddLocation, BINARY
    )
    serverCiphertextFromClient_Rot, res = DeserializeCiphertext(
        datafolder + cipherRotLocation, BINARY
    )
    serverCiphertextFromClient_RotNeg, res = DeserializeCiphertext(
        datafolder + cipherRotNegLocation, BINARY
    )
    serverCiphertextFromClient_Vec, res = DeserializeCiphertext(
        datafolder + clientVectorLocation, BINARY
    )
    print("Deserialized all data from client on server\n")

    print("Part 5: Correctness Verification")

    serverPlaintextFromClient_Mult = cc.Decrypt(
        kp.secretKey, serverCiphertextFromClient_Mult
    )
    serverPlaintextFromClient_Add = cc.Decrypt(
        kp.secretKey, serverCiphertextFromClient_Add
    )
    serverPlaintextFromClient_Rot = cc.Decrypt(
        kp.secretKey, serverCiphertextFromClient_Rot
    )
    serverPlaintextFromClient_RotNeg = cc.Decrypt(
        kp.secretKey, serverCiphertextFromClient_RotNeg
    )
    serverPlaintextFromClient_Vec = cc.Decrypt(
        kp.secretKey, serverCiphertextFromClient_Vec
    )

    serverPlaintextFromClient_Mult.SetLength(vectorSize)
    serverPlaintextFromClient_Add.SetLength(vectorSize)
    serverPlaintextFromClient_Vec.SetLength(vectorSize)
    serverPlaintextFromClient_Rot.SetLength(vectorSize + 1)
    serverPlaintextFromClient_RotNeg.SetLength(vectorSize + 1)

    return (
        serverPlaintextFromClient_Mult,
        serverPlaintextFromClient_Add,
        serverPlaintextFromClient_Vec,
        serverPlaintextFromClient_Rot,
        serverPlaintextFromClient_RotNeg,
    )


def main():
    global datafolder
    with tempfile.TemporaryDirectory() as td:
        datafolder = td + "/" + datafolder
        os.makedirs(datafolder)
        main_action()


def main_action():
    print(
        f"This program requires the subdirectory `{datafolder}' to exist, otherwise you will get\n an error writing serializations."
    )

    # Set main params
    multDepth = 5
    scaleModSize = 40
    batchSize = 32

    cryptoContextIdx = 0
    keyPairIdx = 1
    vectorSizeIdx = 2

    cipherMultResIdx = 0
    cipherAddResIdx = 1
    cipherVecResIdx = 2
    cipherRotResIdx = 3
    cipherRotNegResIdx = 4

    demarcate(
        "Part 1: Cryptocontext generation, key generation, data encryption \n(server)"
    )

    tupleCryptoContext_KeyPair = serverSetupAndWrite(multDepth, scaleModSize, batchSize)
    cc = tupleCryptoContext_KeyPair[cryptoContextIdx]
    kp = tupleCryptoContext_KeyPair[keyPairIdx]
    vectorSize = tupleCryptoContext_KeyPair[vectorSizeIdx]

    demarcate("Part 3: Client deserialize all data")
    clientProcess()

    demarcate("Part 4: Server deserialization of data from client. ")

    tupleRes = serverVerification(cc, kp, vectorSize)
    multRes = tupleRes[cipherMultResIdx]
    addRes = tupleRes[cipherAddResIdx]
    vecRes = tupleRes[cipherVecResIdx]
    rotRes = tupleRes[cipherRotResIdx]
    rotNegRes = tupleRes[cipherRotNegResIdx]

    # vec1: [1,2,3,4]
    # vec2: [12.5, 13.5, 14.5, 15.5]

    print(multRes)  # EXPECT: 12.5, 27.0, 43.5, 62
    print(addRes)  # EXPECT: 13.5, 15.5, 17.5, 19.5
    print(vecRes)  # EXPECT:  [1,2,3,4]

    print("Displaying 5 elements of a 4-element vector to illustrate rotation")
    print(rotRes)  # EXPECT: [2, 3, 4, noise, noise]
    print(rotNegRes)  # EXPECT: [noise, 1, 2, 3, 4]


if __name__ == "__main__":
    main()
