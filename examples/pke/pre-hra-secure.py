#
# Example of HRA-secure Proxy Re-Encryption with 13 hops.
#

from openfhe import *
import math
import random
import time


def run_demo_pre():
    # Generate parameters.
    print("setting up the HRA-secure BGV PRE cryptosystem")
    t = time.time()

    plaintext_modulus = 2  # can encode shorts

    num_hops = 13

    parameters = CCParamsBGVRNS()
    parameters.SetPlaintextModulus(plaintext_modulus)
    parameters.SetScalingTechnique(ScalingTechnique.FIXEDMANUAL)
    parameters.SetPRENumHops(num_hops)
    parameters.SetStatisticalSecurity(40)
    parameters.SetNumAdversarialQueries(1048576)
    parameters.SetRingDim(32768)
    parameters.SetPREMode(ProxyReEncryptionMode.NOISE_FLOODING_HRA)
    parameters.SetKeySwitchTechnique(KeySwitchTechnique.HYBRID)
    parameters.SetMultiplicativeDepth(0)

    cc = GenCryptoContext(parameters)
    print(f"\nParam generation time: \t{(time.time() - t) * 1000} ms")

    # Turn on features
    cc.Enable(PKESchemeFeature.PKE)
    cc.Enable(PKESchemeFeature.KEYSWITCH)
    cc.Enable(PKESchemeFeature.LEVELEDSHE)
    cc.Enable(PKESchemeFeature.PRE)

    print(f"p = {cc.GetPlaintextModulus()}")
    print(f"n = {cc.GetCyclotomicOrder() // 2}")
    print(f"log2 q = {math.log2(cc.GetModulus())}")

    ringsize = cc.GetRingDimension()
    print(f"Alice can encrypt {ringsize // 8} bytes of data")

    ############################################################
    # Perform Key Generation Operation
    ############################################################

    print("\nRunning Alice key generation (used for source data)...")

    t = time.time()
    key_pair1 = cc.KeyGen()
    print(f"Key generation time: \t{(time.time() - t) * 1000} ms")

    ############################################################
    # Encode source data
    ############################################################

    nshort = ringsize

    v_shorts = [random.randint(0, plaintext_modulus - 1) for _ in range(nshort)]

    pt = cc.MakeCoefPackedPlaintext(v_shorts)

    ############################################################
    # Encryption
    ############################################################

    t = time.time()
    ct1 = cc.Encrypt(key_pair1.publicKey, pt)
    print(f"Encryption time: \t{(time.time() - t) * 1000} ms")

    ############################################################
    # Decryption of Ciphertext
    ############################################################

    t = time.time()
    pt_dec1 = cc.Decrypt(key_pair1.secretKey, ct1)
    print(f"Decryption time: \t{(time.time() - t) * 1000} ms")

    pt_dec1.SetLength(pt.GetLength())

    ############################################################
    # Perform Key Generation Operation
    ############################################################

    key_pair_vector = []
    reencryption_key_vector = []

    print(f"Generating keys for {num_hops} parties")

    for i in range(num_hops):
        t = time.time()
        key_pair_vector.append(cc.KeyGen())
        t1 = (time.time() - t) * 1000
        if i == 1:
            print(f"Key generation time: \t{t1} ms")

        ############################################################
        # Perform the proxy re-encryption key generation operation.
        # This generates the keys which are used to perform the key switching.
        ############################################################
        if i == 0:
            reencryption_key_vector.append(cc.ReKeyGen(key_pair1.secretKey, key_pair_vector[i].publicKey))
        else:
            t = time.time()
            reencryption_key_vector.append(cc.ReKeyGen(key_pair_vector[i - 1].secretKey, key_pair_vector[i].publicKey))
            t1 = (time.time() - t) * 1000
            if i == 1:
                print(f"Re-encryption key generation time: \t{t1} ms")

    ############################################################
    # Re-Encryption
    ############################################################
    good = True
    for i in range(num_hops):
        t = time.time()
        ct1 = cc.ReEncrypt(ct1, reencryption_key_vector[i])
        t1 = (time.time() - t) * 1000
        print(f"Re-Encryption time at hop {i + 1}\t{t1} ms")

        if i < num_hops - 1:
            cc.ModReduceInPlace(ct1)

        ############################################################
        # Decryption of Ciphertext
        ############################################################

        t = time.time()
        pt_dec2 = cc.Decrypt(key_pair_vector[i].secretKey, ct1)
        t1 = (time.time() - t) * 1000
        print(f"Decryption time: \t{t1} ms")

        pt_dec2.SetLength(pt.GetLength())

        unpacked0 = pt.GetCoefPackedValue()
        unpacked1 = pt_dec1.GetCoefPackedValue()
        unpacked2 = pt_dec2.GetCoefPackedValue()

        # note that OpenFHE assumes that plaintext is in the range of -p/2..p/2
        # to recover 0...q simply add q if the unpacked value is negative
        unpacked1 = [v + plaintext_modulus if v < 0 else v for v in unpacked1]
        unpacked2 = [v + plaintext_modulus if v < 0 else v for v in unpacked2]

        # compare all the results for correctness
        for j in range(pt.GetLength()):
            if unpacked0[j] != unpacked1[j] or unpacked0[j] != unpacked2[j]:
                good = False

        if good:
            print("PRE passes")
        else:
            print("PRE fails")

    ############################################################
    # Done
    ############################################################

    print("Execution Completed.")

    return good


def main():
    passed = run_demo_pre()
    if not passed:  # there could be an error
        raise Exception("PRE failed")


if __name__ == "__main__":
    main()
