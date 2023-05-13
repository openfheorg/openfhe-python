from openfhe import *

## Sample Program: Step 1: Set CryptoContext

cc = BinFHEContext()

"""
STD128 is the security level of 128 bits of security based on LWE Estimator
and HE standard. Other common options are TOY, MEDIUM, STD192, and STD256.
MEDIUM corresponds to the level of more than 100 bits for both quantum and
classical computer attacks
"""
cc.GenerateBinFHEContext(STD128,GINX)

## Sample Program: Step 2: Key Generation

# Generate the secret key
sk = cc.KeyGen()

print("Generating the bootstrapping keys...\n")

# Generate the bootstrapping keys (refresh and switching keys)
cc.BTKeyGen(sk)

# Sample Program: Step 3: Encryption
"""
Encrypt two ciphertexts representing Boolean True (1).
By default, freshly encrypted ciphertexts are bootstrapped.
If you wish to get a fresh encryption without bootstrapping, write
ct1 = cc.Encrypt(sk, 1, FRESH)
"""
ct1 = cc.Encrypt(sk, 1)
ct2 = cc.Encrypt(sk, 1)

# Sample Program: Step 4: Evaluation
