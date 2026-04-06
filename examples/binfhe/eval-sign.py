from openfhe import *
from math import log2

## Sample Program: Step 1: Set CryptoContext

cc = BinFHEContext()

"""
Set the ciphertext modulus to be 1 << 17
Note that normally we do not use this way to obtain the input ciphertext.
Instead, we assume that an LWE ciphertext with large ciphertext
modulus is already provided (e.g., by extracting from a CKKS ciphertext).
However, we do not provide such a step in this example.
Therefore, we use a brute force way to create a large LWE ciphertext.
"""
logQ = 17
cc.GenerateBinFHEContext(STD128, False, logQ, method=BINFHE_METHOD.GINX, timeOptimization=False)

Q = 1 << logQ

q      = 4096
factor = 1 << int(logQ - log2(q))
p      = cc.GetMaxPlaintextSpace() * factor

## Sample Program: Step 2: Key Generation
# Generate the secret key
sk = cc.KeyGen()

print("Generating the bootstrapping keys...")

# Generate the bootstrapping keys (refresh and switching keys)
cc.BTKeyGen(sk)

print("Completed the key generation...")

## Sample Program: Step 3: Extract the MSB and decrypt to check the result
# Note that we check for 8 different numbers
for i in range(8):
    # We first encrypt with large Q
    ct1 = cc.Encrypt(sk, int(p // 2 + i - 3), output=BINFHE_OUTPUT.LARGE_DIM, p=p, mod=Q)

    # Get the MSB
    ct1 = cc.EvalSign(ct1)

    result = cc.Decrypt(sk, ct1, 2)

    print(f"Input :{i}. Expected sign :{int(i >= 3)}. Evaluated sign: {result}")
