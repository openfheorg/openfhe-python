from openfhe import *

## Sample Program: Step 1: Set CryptoContext

cc = BinFHEContext()
cc.GenerateBinFHEContext(STD128, False)

## Sample Program: Step 2: Key Generation

# Generate the secret key
sk = cc.KeyGen()

print("Generating the bootstrapping keys...")

# Generate the bootstrapping keys (refresh, switching and public keys)
cc.BTKeyGen(sk, PUB_ENCRYPT)

print("Completed the key generation.")

## Sample Program: Step 3: Encryption

# Obtain the maximum plaintext space
# With the default parameter, p = 8
p = cc.GetMaxPlaintextSpace()

# Number of bits to round down
bits = 1
input = 6
print(f"Homomorphically round down the input by {bits} bits.")

pk = cc.GetPublicKey()

ct1 = cc.Encrypt(pk, input % p, SMALL_DIM, p)

## Sample Program: Step 4: Evaluation
ct_rounded = cc.EvalFloor(ct1, bits)

## Sample Program: Step 5: Decryption
result = cc.Decrypt(sk, ct_rounded, p // (1 << bits))

print(f"Input: {input}. Expected: {input >> bits}. Evaluated = {result}")
