#
# Scheme switching serialization in a simple context. The goal of this is to show a simple setup for scheme switching
# serialization before progressing into the next logical step - serialization and communication across
# 2 separate entities
#

from openfhe import *
import math
import os
import tempfile

# Save-Load locations for keys
datafolder = "demoData"

# Save-load locations for evaluated ciphertext
cipher_argmin_location = "/ciphertextArgmin.txt"


def demarcate(msg):
    # Visual separator between the sections of code
    print("*" * 49 + "\n")
    print(msg)
    print("*" * 49 + "\n")


def server_verification(cc, kp, vector_size):
    # - deserialize data from the client.
    # - Verify that the results are as we expect
    server_ciphertext_from_client_argmin, res = DeserializeCiphertext(datafolder + cipher_argmin_location, BINARY)
    print("Deserialized all data from client on server\n")

    demarcate("Part 5: Correctness verification")

    server_plaintext_from_client_argmin = cc.Decrypt(kp.secretKey, server_ciphertext_from_client_argmin)
    server_plaintext_from_client_argmin.SetLength(vector_size)

    return server_plaintext_from_client_argmin


def server_setup_and_write(ring_dim, batch_size, mult_depth, scale_mod_size, first_mod_size, log_q_lwe, one_hot):
    # - simulates a server at startup where we generate a cryptocontext and keys.
    # - then, we generate some data (akin to loading raw data on an enclave)
    #   before encrypting the data
    sl = SecurityLevel.HEStd_NotSet
    sl_bin = TOY

    parameters = CCParamsCKKSRNS()
    parameters.SetMultiplicativeDepth(mult_depth)
    parameters.SetSecurityLevel(sl)
    parameters.SetRingDim(ring_dim)
    parameters.SetBatchSize(batch_size)
    parameters.SetScalingModSize(scale_mod_size)
    parameters.SetFirstModSize(first_mod_size)
    # 128-bit CKKS supports only the FIXED* scaling techniques; keep the library default there
    if get_native_int() != 128:
        parameters.SetScalingTechnique(ScalingTechnique.FLEXIBLEAUTO)

    server_cc = GenCryptoContext(parameters)

    # Enable the features that you wish to use
    server_cc.Enable(PKESchemeFeature.PKE)
    server_cc.Enable(PKESchemeFeature.KEYSWITCH)
    server_cc.Enable(PKESchemeFeature.LEVELEDSHE)
    server_cc.Enable(PKESchemeFeature.ADVANCEDSHE)
    server_cc.Enable(PKESchemeFeature.FHE)
    server_cc.Enable(PKESchemeFeature.SCHEMESWITCH)

    print("Cryptocontext generated")

    server_kp = server_cc.KeyGen()
    print("Keypair generated")

    params = SchSwchParams()
    params.SetSecurityLevelCKKS(sl)
    params.SetSecurityLevelFHEW(sl_bin)
    params.SetCtxtModSizeFHEWLargePrec(log_q_lwe)
    params.SetNumSlotsCKKS(batch_size)
    params.SetNumValues(batch_size)
    params.SetComputeArgmin(True)
    params.SetOneHotEncoding(one_hot)
    private_key_fhew = server_cc.EvalSchemeSwitchingSetup(params)

    server_cc.EvalSchemeSwitchingKeyGen(server_kp, private_key_fhew)

    vec = [1.0, 2.0, 3.0, 4.0]
    print(f"\nDisplaying data vector: {vec}\n")

    server_p = server_cc.MakeCKKSPackedPlaintext(vec)

    print(f"Plaintext version of vector: {server_p}")
    print("Plaintexts have been generated from complex-double vectors")

    server_c = server_cc.Encrypt(server_kp.publicKey, server_p)

    print("Ciphertext have been generated from Plaintext")

    # Part 2:
    # We serialize the following:
    #   Cryptocontext
    #   Public key
    #   relinearization (eval mult keys)
    #   rotation keys
    #   binfhe cryptocontext
    #   binfhe bootstrapping keys
    #   Some of the ciphertext
    #
    # We serialize all of them to files
    demarcate("Scheme Switching Part 2: Data Serialization (server)")

    serializer = SchemeSwitchingDataSerializer(server_cc, server_kp.publicKey, server_c)
    serializer.SetDataDirectory(datafolder)
    serializer.Serialize()

    return server_cc, server_kp, len(vec)


def client_process(modulus_lwe):
    # - deserialize data from a file which simulates receiving data from a server
    #   after making a request
    # - we then process the data
    ClearEvalMultKeys()
    ClearEvalSumKeys()
    CryptoContext.ClearEvalAutomorphismKeys()
    ReleaseAllContexts()

    deserializer = SchemeSwitchingDataDeserializer()
    deserializer.SetDataDirectory(datafolder)
    deserializer.Deserialize()

    client_cc = deserializer.getCryptoContext()
    client_public_key = deserializer.getPublicKey()
    client_bin_cc = client_cc.GetBinCCForSchemeSwitch()
    client_c = deserializer.getRAWCiphertext()

    # Scale the inputs to ensure their difference is correctly represented after switching to FHEW
    scale_sign = 512.0
    beta = client_bin_cc.GetBeta()
    p_lwe = modulus_lwe // (2 * beta)  # Large precision

    client_cc.EvalCompareSwitchPrecompute(p_lwe, scale_sign, False)

    print("Done with precomputations\n")

    # Compute on the ciphertext
    client_ciphertext_argmin = client_cc.EvalMinSchemeSwitching(client_c, client_public_key, client_c.GetSlots(),
                                                                client_c.GetSlots(), 0, 1)

    print("Done with argmin computation\n")

    # Now, we want to simulate a client who is encrypting data for the server to
    # decrypt. E.g weights of a machine learning algorithm
    demarcate("Part 3.5: Client Serialization of data that has been operated on")

    SerializeToFile(datafolder + cipher_argmin_location, client_ciphertext_argmin[1], BINARY)

    print("Serialized ciphertext from client\n")


def main_action():
    # Set main params
    ring_dim = 64
    batch_size = 4
    mult_depth = 13 + int(math.log2(batch_size))
    log_q_cc_lwe = 25
    one_hot = True
    scale_mod_size = 50
    first_mod_size = 60

    demarcate("Scheme switching Part 1: Cryptocontext generation, key generation, data encryption (server)")

    cc, kp, vector_size = server_setup_and_write(ring_dim, batch_size, mult_depth, scale_mod_size, first_mod_size,
                                                 log_q_cc_lwe, one_hot)

    demarcate("Scheme switching Part 3: Client deserialize all data")

    client_process(1 << log_q_cc_lwe)

    demarcate("Scheme switching Part 4: Server deserialization of data from client. ")

    argmin_res = server_verification(cc, kp, vector_size)

    # vec1: {1,2,3,4}
    print(argmin_res)  # EXPECT: 1.0, 0.0, 0.0, 0.0


def main():
    global datafolder
    with tempfile.TemporaryDirectory() as td:
        datafolder = td + "/" + datafolder
        os.mkdir(datafolder)
        main_action()


if __name__ == "__main__":
    main()
