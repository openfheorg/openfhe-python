from openfhe import *

# Sample Program: Step 1: Set CryptoContext
cc = BinFHEContext()

print("Generate cryptocontext\n")

"""
STD128 is the security level of 128 bits of security based on LWE Estimator
and HE standard. Other common options are TOY, MEDIUM, STD192, and STD256. MEDIUM 
corresponds to the level of more than 100 bits for both quantum and
classical computer attacks
"""

cc.GenerateBinFHEContext(STD128)
print("Finished generating cryptocontext\n")

# Sample Program: Step 2: Key Generation

# Generate the secret key
sk = cc.KeyGen()

print("Generating the bootstrapping keys...\n")

# Generate the bootstrapping keys (refresh and switching keys)
cc.BTKeyGen(sk)

print("Completed the key generation.\n\n")

# Sample Program: Step 3: Encryption

# Encrypt two ciphertexts representing Boolean True (1).
ct10 = cc.Encrypt(sk, 1)
ct11 = cc.Encrypt(sk, 1)
# Encrypt two ciphertexts representing Boolean False (0).
ct00 = cc.Encrypt(sk, 0)
ct01 = cc.Encrypt(sk, 0)

# Sample Program: Step 4: Evaluation of NAND gates

ctNAND1 = cc.EvalBinGate(NAND, ct10, ct11)
ctNAND2 = cc.EvalBinGate(NAND, ct10, ct01)
ctNAND3 = cc.EvalBinGate(NAND, ct00, ct01)
ctNAND4 = cc.EvalBinGate(NAND, ct00, ct11)

result = cc.Decrypt(sk, ctNAND1)
print(f"1 NAND 1 = {result}")

result = cc.Decrypt(sk, ctNAND2)
print(f"1 NAND 0 = {result}")

result = cc.Decrypt(sk, ctNAND3)
print(f"0 NAND 0 = {result}")

result = cc.Decrypt(sk, ctNAND4)
print(f"0 NAND 1 = {result}")

# Sample Program: Step 5: Evaluation of AND gates

ctAND1 = cc.EvalBinGate(AND, ct10, ct11)
ctAND2 = cc.EvalBinGate(AND, ct10, ct01)
ctAND3 = cc.EvalBinGate(AND, ct00, ct01)
ctAND4 = cc.EvalBinGate(AND, ct00, ct11)

result = cc.Decrypt(sk, ctAND1)
print(f"1 AND 1 = {result}")

result = cc.Decrypt(sk, ctAND2)
print(f"1 AND 0 = {result}")

result = cc.Decrypt(sk, ctAND3)
print(f"0 AND 0 = {result}")

result = cc.Decrypt(sk, ctAND4)
print(f"0 AND 1 = {result}")

# Sample Program: Step 6: Evaluation of OR gates

ctOR1 = cc.EvalBinGate(OR, ct10, ct11)
ctOR2 = cc.EvalBinGate(OR, ct10, ct01)
ctOR3 = cc.EvalBinGate(OR, ct00, ct01)
ctOR4 = cc.EvalBinGate(OR, ct00, ct11)

result = cc.Decrypt(sk, ctOR1)
print(f"1 OR 1 = {result}")

result = cc.Decrypt(sk, ctOR2)
print(f"1 OR 0 = {result}")

result = cc.Decrypt(sk, ctOR3)
print(f"0 OR 0 = {result}")

result = cc.Decrypt(sk, ctOR4)
print(f"0 OR 1 = {result}")

# Sample Program: Step 7: Evaluation of NOR gates

ctNOR1 = cc.EvalBinGate(NOR, ct10, ct11)
ctNOR2 = cc.EvalBinGate(NOR, ct10, ct01)
ctNOR3 = cc.EvalBinGate(NOR, ct00, ct01)
ctNOR4 = cc.EvalBinGate(NOR, ct00, ct11)

result = cc.Decrypt(sk, ctNOR1)
print(f"1 NOR 1 = {result}")

result = cc.Decrypt(sk, ctNOR2)
print(f"1 NOR 0 = {result}")

result = cc.Decrypt(sk, ctNOR3)
print(f"0 NOR 0 = {result}")

result = cc.Decrypt(sk, ctNOR4)
print(f"0 NOR 1 = {result}")

# Sample Program: Step 8: Evaluation of XOR gates

ctXOR1 = cc.EvalBinGate(XOR, ct10, ct11)
ctXOR2 = cc.EvalBinGate(XOR, ct10, ct01)
ctXOR3 = cc.EvalBinGate(XOR, ct00, ct01)
ctXOR4 = cc.EvalBinGate(XOR, ct00, ct11)

result = cc.Decrypt(sk, ctXOR1)
print(f"1 XOR 1 = {result}")

result = cc.Decrypt(sk, ctXOR2)
print(f"1 XOR 0 = {result}")

result = cc.Decrypt(sk, ctXOR3)
print(f"0 XOR 0 = {result}")

result = cc.Decrypt(sk, ctXOR4)
print(f"0 XOR 1 = {result}")

# Sample Program: Step 9: Evaluation of XNOR gates

ctXNOR1 = cc.EvalBinGate(XNOR, ct10, ct11)
ctXNOR2 = cc.EvalBinGate(XNOR, ct10, ct01)
ctXNOR3 = cc.EvalBinGate(XNOR, ct00, ct01)
ctXNOR4 = cc.EvalBinGate(XNOR, ct00, ct11)

result = cc.Decrypt(sk, ctXNOR1)
print(f"1 XNOR 1 = {result}")

result = cc.Decrypt(sk, ctXNOR2)
print(f"1 XNOR 0 = {result}")

result = cc.Decrypt(sk, ctXNOR3)
print(f"0 XNOR 0 = {result}")

result = cc.Decrypt(sk, ctXNOR4)
print(f"0 XNOR 1 = {result}")

# Sample Program: Step 90: Evaluation of NOR gates
# using XOR_FAT (1 boostrap but the probability of failure is higher)

ctNOR1_FAST = cc.EvalBinGate(XOR_FAST, ct10, ct11)
ctNOR2_FAST = cc.EvalBinGate(XOR_FAST, ct10, ct01)
ctNOR3_FAST = cc.EvalBinGate(XOR_FAST, ct00, ct01)
ctNOR4_FAST = cc.EvalBinGate(XOR_FAST, ct00, ct11)

result = cc.Decrypt(sk, ctNOR1_FAST)
print(f"1 XOR_FAST 1 = {result}")

result = cc.Decrypt(sk, ctNOR2_FAST)
print(f"1 XOR_FAST 0 = {result}")

result = cc.Decrypt(sk, ctNOR3_FAST)
print(f"0 XOR_FAST 0 = {result}")

result = cc.Decrypt(sk, ctNOR4_FAST)
print(f"0 XOR_FAST 1 = {result}")

# Sample Program: Step 10: Evaluation of XNOR gates
# using XNOR_FAT (1 boostrap but the probability of failure is higher)

ctXNOR1_FAST = cc.EvalBinGate(XNOR_FAST, ct10, ct11)
ctXNOR2_FAST = cc.EvalBinGate(XNOR_FAST, ct10, ct01)
ctXNOR3_FAST = cc.EvalBinGate(XNOR_FAST, ct00, ct01)
ctXNOR4_FAST = cc.EvalBinGate(XNOR_FAST, ct00, ct11)

result = cc.Decrypt(sk, ctXNOR1_FAST)
print(f"1 XNOR_FAST 1 = {result}")

result = cc.Decrypt(sk, ctXNOR2_FAST)
print(f"1 XNOR_FAST 0 = {result}")

result = cc.Decrypt(sk, ctXNOR3_FAST)
print(f"0 XNOR_FAST 0 = {result}")

result = cc.Decrypt(sk, ctXNOR4_FAST)
print(f"0 XNOR_FAST 1 = {result}")






