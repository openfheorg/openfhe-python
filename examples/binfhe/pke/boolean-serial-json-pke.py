#
# Example for FHEW with JSON serialization and public key encryption
#

from openfhe import *
import os
import tempfile

# path where files will be written to
datafolder = "demoData"


def main_action():
    # Generating the crypto context
    cc1 = BinFHEContext()
    cc1.GenerateBinFHEContext(TOY)

    print("Generating keys.")

    # Generating the secret key
    sk1 = cc1.KeyGen()

    # Generate the bootstrapping keys and public key
    cc1.BTKeyGen(sk1, PUB_ENCRYPT)

    print("Done generating all keys.")

    pk1 = cc1.GetPublicKey()

    # Encryption for a ciphertext that will be serialized
    ct1 = cc1.Encrypt(pk1, 1)

    # CODE FOR SERIALIZATION

    # Serializing key-independent crypto context
    if not SerializeToFile(datafolder + "/cryptoContext.txt", cc1, JSON):
        raise Exception("Error serializing the cryptocontext")
    print("The cryptocontext has been serialized.")

    # Serializing refreshing and key switching keys (needed for bootstrapping)
    if not SerializeToFile(datafolder + "/btKey.txt", cc1.GetBTKey(), JSON):
        raise Exception("Error serializing the bootstrapping keys")
    print("The bootstrapping keys have been serialized.")

    # Serializing secret key
    if not SerializeToFile(datafolder + "/sk1.txt", sk1, JSON):
        raise Exception("Error serializing sk1")
    print("The secret key sk1 key been serialized.")

    # Serializing public key
    if not SerializeToFile(datafolder + "/pk1.txt", pk1, JSON):
        raise Exception("Error serializing pk1")
    print("The public key pk1 key been serialized.")

    # Serializing a ciphertext
    if not SerializeToFile(datafolder + "/ct1.txt", ct1, JSON):
        raise Exception("Error serializing ct1")
    print("A ciphertext has been serialized.")

    # CODE FOR DESERIALIZATION

    # Deserializing the cryptocontext
    cc, res = DeserializeBinFHECryptoContext(datafolder + "/cryptoContext.txt", JSON)
    if not res:
        raise Exception("Could not deserialize the cryptocontext")
    print("The cryptocontext has been deserialized.")

    # deserializing the refreshing and switching keys (for bootstrapping)
    bt_key, res = DeserializeBinFHEBTKey(datafolder + "/btKey.txt", JSON)
    if not res:
        raise Exception("Could not deserialize the bootstrapping keys")
    print("The bootstrapping keys have been deserialized.")

    # Loading the keys in the cryptocontext
    cc.BTKeyLoad(bt_key)

    # Deserializing the secret key
    sk, res = DeserializeLWEPrivateKey(datafolder + "/sk1.txt", JSON)
    if not res:
        raise Exception("Could not deserialize the secret key")
    print("The secret key has been deserialized.")

    # Deserializing the public key
    pk, res = DeserializeLWEPublicKey(datafolder + "/pk1.txt", JSON)
    if not res:
        raise Exception("Could not deserialize the public key")
    print("The public key has been deserialized.")

    # Deserializing a previously serialized ciphertext
    ct, res = DeserializeLWECiphertext(datafolder + "/ct1.txt", JSON)
    if not res:
        raise Exception("Could not deserialize the ciphertext")
    print("The ciphertext has been deserialized.")

    # OPERATIONS WITH DESERIALIZED KEYS AND CIPHERTEXTS

    ct2 = cc.Encrypt(pk, 1)

    print("Running the computation")

    ct_result = cc.EvalBinGate(AND, ct, ct2)

    print("The computation has completed")

    result = cc.Decrypt(sk, ct_result)

    print(f"result of 1 AND 1 = {result}")


def main():
    global datafolder
    with tempfile.TemporaryDirectory() as td:
        datafolder = td + "/" + datafolder
        os.mkdir(datafolder)
        main_action()


if __name__ == "__main__":
    main()
