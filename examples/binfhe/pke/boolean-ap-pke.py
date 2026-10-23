from openfhe import *

## Sample Program: Step 1: Set CryptoContext

cc = BinFHEContext()

# STD128 is the security level of 128 bits of security based on LWE Estimator
# and HE standard. Other common options are TOY, MEDIUM, STD192, and STD256.
# MEDIUM corresponds to the level of more than 100 bits for both quantum and
# classical computer attacks. The second argument is the bootstrapping method
# (AP or GINX). The default method is GINX. Here we explicitly set AP. GINX
# typically provides better performance: the bootstrapping key is much
# smaller in GINX (by 20x) while the runtime is roughly the same.
cc.GenerateBinFHEContext(STD128, AP)

## Sample Program: Step 2: Key Generation

# Generate the secret key
sk = cc.KeyGen()

print("Generating the bootstrapping keys...")

# Generate the bootstrapping keys (refresh, switching and public keys)
# Public keys are generated when the keygenMode is set to PUB_ENCRYPT
cc.BTKeyGen(sk, PUB_ENCRYPT)

pk = cc.GetPublicKey()
print("Completed the key generation.")

## Sample Program: Step 3: Encryption

# Encrypt two ciphertexts representing Boolean True (1)
ct1 = cc.Encrypt(pk, 1)
ct2 = cc.Encrypt(pk, 1)

## Sample Program: Step 4: Evaluation

# Compute (1 AND 1) = 1; Other binary gate options are OR, NAND, and NOR
ct_and1 = cc.EvalBinGate(AND, ct1, ct2)

# Compute (NOT 1) = 0
ct2_not = cc.EvalNOT(ct2)

# Compute (1 AND (NOT 1)) = 0
ct_and2 = cc.EvalBinGate(AND, ct2_not, ct1)

# Computes OR of the results in ct_and1 and ct_and2 = 1
ct_result = cc.EvalBinGate(OR, ct_and1, ct_and2)

## Sample Program: Step 5: Decryption

result = cc.Decrypt(sk, ct_result)

print(f"Result of encrypted computation of (1 AND 1) OR (1 AND (NOT 1)) = {result}")
