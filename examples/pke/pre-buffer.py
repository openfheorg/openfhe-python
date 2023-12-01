import time
import random
from math import log2
from openfhe import *

def main():
    passed = run_demo_pre()

    if not passed: # there could be an error
        return 1
    return 0 # successful return

def run_demo_pre():
    # Generate parameters.
    print("setting up BFV RNS crypto system")
    start_time = time.time()
    plaintextModulus = 65537  # can encode shorts

    parameters = CCParamsBFVRNS()
    parameters.SetPlaintextModulus(plaintextModulus)
    parameters.SetScalingModSize(60)

    cc = GenCryptoContext(parameters)
    print(f"\nParam generation time: {time.time() - start_time} ms")

    # Turn on features
    cc.Enable(PKE)
    cc.Enable(KEYSWITCH)
    cc.Enable(LEVELEDSHE)
    cc.Enable(PRE)

    print(f"p = {cc.GetPlaintextModulus()}")
    print(f"n = {cc.GetCyclotomicOrder()/2}")
    print(f"log2 q = {log2(cc.GetModulus())}")
    print(f"r = {cc.GetDigitSize()}")

    ringsize = cc.GetRingDimension()
    print(f"Alice can encrypt {ringsize * 2} bytes of data")

    # Perform Key Generation Operation

    print("\nRunning Alice key generation (used for source data)...")
    start_time = time.time()
    keyPair1 = cc.KeyGen()
    print(f"Key generation time: {time.time() - start_time} ms")

    if not keyPair1.good():
        print("Alice Key generation failed!")
        return False

    # Encode source data
    nshort = ringsize
    vShorts = [random.randint(0, 65536) for _ in range(nshort)]
    pt = cc.MakePackedPlaintext(vShorts)

    # Encryption
    start_time = time.time()
    ct1 = cc.Encrypt(keyPair1.publicKey, pt)
    print(f"Encryption time: {time.time() - start_time} ms")

    # Decryption of Ciphertext
    start_time = time.time()
    ptDec1 = cc.Decrypt(keyPair1.secretKey, ct1)
    print(f"Decryption time: {time.time() - start_time} ms")

    ptDec1.SetLength(pt.GetLength())

    # Perform Key Generation Operation
    print("Bob Running key generation ...")
    start_time = time.time()
    keyPair2 = cc.KeyGen()
    print(f"Key generation time: {time.time() - start_time} ms")

    if not keyPair2.good():
        print("Bob Key generation failed!")
        return False
    
    # Perform the proxy re-encryption key generation operation.
    # This generates the keys which are used to perform the key switching.

    print("\nGenerating proxy re-encryption key...")
    start_time = time.time()
    reencryptionKey12 = cc.ReKeyGen(keyPair1.secretKey, keyPair2.publicKey)
    print(f"Key generation time: {time.time() - start_time} ms")

    # Re-Encryption
    start_time = time.time()
    ct2 = cc.ReEncrypt(ct1, reencryptionKey12)
    print(f"Re-Encryption time: {time.time() - start_time} ms")

    # Decryption of Ciphertext
    start_time = time.time()
    ptDec2 = cc.Decrypt(keyPair2.secretKey, ct2)
    print(f"Decryption time: {time.time() - start_time} ms")

    ptDec2.SetLength(pt.GetLength())

    unpacked0 = pt.GetPackedValue()
    unpacked1 = ptDec1.GetPackedValue()
    unpacked2 = ptDec2.GetPackedValue()
    good = True

    # note that OpenFHE assumes that plaintext is in the range of -p/2..p/2
    # to recover 0...q simply add q if the unpacked value is negative
    for j in range(pt.GetLength()):
        if unpacked1[j] < 0:
            unpacked1[j] += plaintextModulus
        if unpacked2[j] < 0:
            unpacked2[j] += plaintextModulus

    # compare all the results for correctness
    for j in range(pt.GetLength()):
        if (unpacked0[j] != unpacked1[j]) or (unpacked0[j] != unpacked2[j]):
            print(f"{j}, {unpacked0[j]}, {unpacked1[j]}, {unpacked2[j]}")
            good = False

    if good:
        print("PRE passes")
    else:
        print("PRE fails")

    print("Execution Completed.")

    return good

if __name__ == "__main__":
    main()
