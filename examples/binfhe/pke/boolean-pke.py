from openfhe import *

## Sample Program: Step 1: Set CryptoContext

cc = BinFHEContext()

# STD128 is the security level of 128 bits of security based on LWE Estimator
# and HE standard. Other common options are TOY, MEDIUM, STD192, and STD256.
# MEDIUM corresponds to the level of more than 100 bits for both quantum and
# classical computer attacks.
cc.GenerateBinFHEContext(STD128)

# verifying public key encrypt and decrypt without bootstrap
# Generate the secret, public key pair
kp = cc.KeyGenPair()

# LARGE_DIM specifies the dimension of the output ciphertext
ctp = cc.Encrypt(kp.publicKey, 1, LARGE_DIM)

# decryption check before computation
result = cc.Decrypt(kp.secretKey, ctp)
print(f"Result of encrypted ciphertext of 1 = {result}")

## Sample Program: Step 2: Key Generation

# Generate the secret key
sk = cc.KeyGen()

print("Generating the bootstrapping keys...")

# Generate the bootstrapping keys (refresh, switching and public keys)
cc.BTKeyGen(sk, PUB_ENCRYPT)

print("Completed the key generation.")

## Sample Program: Step 3: Encryption

# Encrypt two ciphertexts representing Boolean True (1).
# By default, freshly encrypted ciphertexts are bootstrapped.
# If you wish to get a fresh encryption without bootstrapping, write
# ct1 = cc.Encrypt(sk, 1, LARGE_DIM)
ct1 = cc.Encrypt(cc.GetPublicKey(), 1)
ct2 = cc.Encrypt(cc.GetPublicKey(), 1)

# decryption check before computation
result = cc.Decrypt(sk, ct1)
print(f"Result of encrypted ciphertext of 1 = {result}")

## Sample Program: Step 4: Evaluation

# Compute (1 AND 1) = 1; Other binary gate options are OR, NAND, and NOR
ct_and1 = cc.EvalBinGate(AND, ct1, ct2)

result1 = cc.Decrypt(sk, ct_and1)
print(f"Result of encrypted computation of (1 AND 1) = {result1}")

# Compute (NOT 1) = 0
ct2_not = cc.EvalNOT(ct2)

result = cc.Decrypt(sk, ct2_not)
print(f"Result of encrypted computation of (NOT 1) = {result}")

# Compute (1 AND (NOT 1)) = 0
ct_and2 = cc.EvalBinGate(AND, ct2_not, ct1)

result = cc.Decrypt(sk, ct_and2)
print(f"Result of encrypted computation of (1 AND (NOT 1)) = {result}")

# Computes OR of the results in ct_and1 and ct_and2 = 1
ct_result = cc.EvalBinGate(OR, ct_and1, ct_and2)

## Sample Program: Step 5: Decryption
result = cc.Decrypt(sk, ct_result)
print(f"Result of encrypted computation of (1 AND 1) OR (1 AND (NOT 1)) = {result}")
