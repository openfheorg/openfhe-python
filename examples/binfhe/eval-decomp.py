from openfhe import *
import math

## Sample Program: Step 1: Set CryptoContext

cc = BinFHEContext()

# Set the ciphertext modulus to be 1 << 23
# Note that normally we do not use this way to obtain the input ciphertext.
# Instead, we assume that an LWE ciphertext with large ciphertext
# modulus is already provided (e.g., by extracting from a CKKS ciphertext).
# However, we do not provide such a step in this example.
# Therefore, we use a brute force way to create a large LWE ciphertext.
logQ = 23
cc.GenerateBinFHEContext(STD128, False, logQ, 0, GINX, False)

Q = 1 << logQ

q = 4096                                            # q
factor = 1 << int(logQ - math.log2(q))              # Q/q
P = cc.GetMaxPlaintextSpace() * factor              # Obtain the maximum plaintext space

## Sample Program: Step 2: Key Generation
# Generate the secret key
sk = cc.KeyGen()

print("Generating the bootstrapping keys...")

# Generate the bootstrapping keys (refresh and switching keys)
cc.BTKeyGen(sk)

print("Completed the key generation.")

## Sample Program: Step 3: Encryption
ct1 = cc.Encrypt(sk, P // 2 + 1, LARGE_DIM, P, Q)
print(f"Encrypted value: {P // 2 + 1}")

## Sample Program: Step 4: Evaluation
# Decompose the large ciphertext into small ciphertexts that fit in q
decomp = cc.EvalDecomp(ct1)

## Sample Program: Step 5: Decryption
p = cc.GetMaxPlaintextSpace()
print("Decomposed value: ", end="")
for i in range(len(decomp)):
    ct = decomp[i]
    if i == len(decomp) - 1:
        # after every evalfloor, the least significant digit is dropped so
        # the last modulus is computed as log p = (log P) mod (log GetMaxPlaintextSpace)
        logp = (P - 1).bit_length() % (p - 1).bit_length()
        p = 1 << logp
    result = cc.Decrypt(sk, ct, p)
    print(f"({result} * {cc.GetMaxPlaintextSpace()}^{i})", end="")
    if i != len(decomp) - 1:
        print(" + ", end="")
print()
