from openfhe import *

## Sample Program: Step 1: Set CryptoContext

cc = BinFHEContext()
cc.GenerateBinFHEContext(STD128_4, GINX)

## Sample Program: Step 2: Key Generation
# Generate the secret key
sk = cc.KeyGen()

print("Generating the bootstrapping keys...")

# Generate the bootstrapping keys (refresh and switching keys)
cc.BTKeyGen(sk)

print("Completed the key generation.")

## Sample Program: Step 3: Encryption
# Encrypt several ciphertexts representing Boolean True (1) or False (0).
# plaintext modulus is set higher than 4 to 2 * num_of_inputs
p = 6
ct1_3input = cc.Encrypt(sk, 1, SMALL_DIM, p)
ct2_3input = cc.Encrypt(sk, 1, SMALL_DIM, p)
ct3_3input = cc.Encrypt(sk, 0, SMALL_DIM, p)

# 1, 1, 0
ct123 = [ct1_3input, ct2_3input, ct3_3input]

# 1, 1, 0
ct_and3 = cc.EvalBinGate(AND3, ct123)

# 1, 1, 0
ct_or3 = cc.EvalBinGate(OR3, ct123)

## Sample Program: Step 5: Decryption
result = cc.Decrypt(sk, ct_and3, p)
if result != 0:
    raise Exception("Decryption failure")
print(f"Result of encrypted computation of AND(1, 1, 0) = {result}")

result = cc.Decrypt(sk, ct_or3, p)
if result != 1:
    raise Exception("Decryption failure")
print(f"Result of encrypted computation of OR(1, 1, 0) = {result}")

# majority gate and cmux for 3 input does not need higher plaintext modulus
p = 4
ct1_3input_p4 = cc.Encrypt(sk, 1, SMALL_DIM, p)
ct2_3input_p4 = cc.Encrypt(sk, 1, SMALL_DIM, p)
ct3_3input_p4 = cc.Encrypt(sk, 0, SMALL_DIM, p)
ct4_3input_p4 = cc.Encrypt(sk, 0, SMALL_DIM, p)

# 1, 1, 0
ct123_p4 = [ct1_3input_p4, ct2_3input_p4, ct3_3input_p4]

# 1, 0, 0
ct134_p4 = [ct1_3input_p4, ct3_3input_p4, ct4_3input_p4]

# 1, 0, 1
ct132_p4 = [ct1_3input_p4, ct3_3input_p4, ct2_3input_p4]

# 1, 1, 0
ct_majority = cc.EvalBinGate(MAJORITY, ct123_p4)

# 1, 0, 1
ct_cmux0 = cc.EvalBinGate(CMUX, ct132_p4)

# 1, 0, 0
ct_cmux1 = cc.EvalBinGate(CMUX, ct134_p4)

result = cc.Decrypt(sk, ct_majority)
if result != 1:
    raise Exception("Decryption failure")
print(f"Result of encrypted computation of Majority(1, 1, 0) = {result}")

result = cc.Decrypt(sk, ct_cmux1)
if result != 1:
    raise Exception("Decryption failure")
print(f"Result of encrypted computation of CMUX(1, 0, 0) = {result}")

result = cc.Decrypt(sk, ct_cmux0)
if result != 0:
    raise Exception("Decryption failure")
print(f"Result of encrypted computation of CMUX(1, 0, 1) = {result}")

# for 4 input gates
p = 8
ct1_4input = cc.Encrypt(sk, 1, SMALL_DIM, p)
ct2_4input = cc.Encrypt(sk, 0, SMALL_DIM, p)
ct3_4input = cc.Encrypt(sk, 0, SMALL_DIM, p)
ct4_4input = cc.Encrypt(sk, 0, SMALL_DIM, p)

# 1, 0, 0, 0
ct1234 = [ct1_4input, ct2_4input, ct3_4input, ct4_4input]

## Sample Program: Step 4: Evaluation

# 1, 0, 0, 0
ct_and4 = cc.EvalBinGate(AND4, ct1234)

# 1, 0, 0, 0
ct_or4 = cc.EvalBinGate(OR4, ct1234)

## Sample Program: Step 5: Decryption
result = cc.Decrypt(sk, ct_and4, p)
if result != 0:
    raise Exception("Decryption failure")
print(f"Result of encrypted computation of AND(1, 0, 0, 0) = {result}")

result = cc.Decrypt(sk, ct_or4, p)
if result != 1:
    raise Exception("Decryption failure")
print(f"Result of encrypted computation of OR(1, 0, 0, 0) = {result}")
