from openfhe import *

## Sample Program: Step 1: Set CryptoContext

cc = BinFHEContext()

"""
STD128 is the security level of 128 bits of security based on LWE Estimator
and HE standard. Other common options are TOY, MEDIUM, STD192, and STD256.
MEDIUM corresponds to the level of more than 100 bits for both quantum and
classical computer attacks. The second argument is the bootstrapping method
(AP or GINX). The default method is GINX. Here we explicitly set AP. GINX
typically provides better performance: the bootstrapping key is much
smaller in GINX (by 20x) while the runtime is roughly the same.
"""
cc.GenerateBinFHEContext(STD128,AP)

## Sample Program: Step 2: Key Generation

# Generate the secret key
sk = cc.KeyGen()

print("Generating the bootstrapping keys...\n")

# Generate the bootstrapping keys (refresh and switching keys)
cc.BTKeyGen(sk)

print("Completed the key generation.\n")
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

# Compute (1 AND 1) = 1; Other binary gate options are OR, NAND, and NOR
ctAND1 = cc.EvalBinGate(AND, ct1, ct2)

# Compute (NOT 1) = 0
ct2Not = cc.EvalNOT(ct2)

# Compute (1 AND (NOT 1)) = 0
ctAND2 = cc.EvalBinGate(AND, ct2Not, ct1)

# Compute OR of the result in ctAND1 and ctAND2
ctResult = cc.EvalBinGate(OR, ctAND1, ctAND2)

# Sample Program: Step 5: Decryption

result = cc.Decrypt(sk, ctResult)

print(f"Result of encrypted computation of (1 AND 1) OR (1 AND (NOT 1)) = {result}")

