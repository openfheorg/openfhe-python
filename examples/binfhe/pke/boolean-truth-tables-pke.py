from openfhe import *
import sys

## Sample Program: Step 1: Set CryptoContext

cc = BinFHEContext()

print("Generate cryptocontext", file=sys.stderr)

# STD128 is the security level of 128 bits of security based on LWE Estimator
# and HE standard. Other options are TOY, MEDIUM, STD192, and STD256. MEDIUM
# corresponds to the level of more than 100 bits for both quantum and
# classical computer attacks.
cc.GenerateBinFHEContext(STD128)

print("Finished generating cryptocontext", file=sys.stderr)

## Sample Program: Step 2: Key Generation

# Generate the secret key
sk = cc.KeyGen()

print("Generating the bootstrapping keys...")

# Generate the bootstrapping keys (refresh, switching and public keys)
cc.BTKeyGen(sk, PUB_ENCRYPT)

pk = cc.GetPublicKey()

print("Completed the key generation.\n")

## Sample Program: Step 3: Encryption

# Encrypt two ciphertexts representing Boolean True (1)
ct10 = cc.Encrypt(pk, 1)
ct11 = cc.Encrypt(pk, 1)

# Encrypt two ciphertexts representing Boolean False (0)
ct00 = cc.Encrypt(pk, 0)
ct01 = cc.Encrypt(pk, 0)

## Sample Program: Step 4: Evaluation of NAND gates

ct_nand1 = cc.EvalBinGate(NAND, ct10, ct11)
ct_nand2 = cc.EvalBinGate(NAND, ct10, ct01)
ct_nand3 = cc.EvalBinGate(NAND, ct00, ct01)
ct_nand4 = cc.EvalBinGate(NAND, ct00, ct11)

print(f"1 NAND 1 = {cc.Decrypt(sk, ct_nand1)}")
print(f"1 NAND 0 = {cc.Decrypt(sk, ct_nand2)}")
print(f"0 NAND 0 = {cc.Decrypt(sk, ct_nand3)}")
print(f"0 NAND 1 = {cc.Decrypt(sk, ct_nand4)}\n")

## Sample Program: Step 5: Evaluation of AND gates

ct_and1 = cc.EvalBinGate(AND, ct10, ct11)
ct_and2 = cc.EvalBinGate(AND, ct10, ct01)
ct_and3 = cc.EvalBinGate(AND, ct00, ct01)
ct_and4 = cc.EvalBinGate(AND, ct00, ct11)

print(f"1 AND 1 = {cc.Decrypt(sk, ct_and1)}")
print(f"1 AND 0 = {cc.Decrypt(sk, ct_and2)}")
print(f"0 AND 0 = {cc.Decrypt(sk, ct_and3)}")
print(f"0 AND 1 = {cc.Decrypt(sk, ct_and4)}\n")

## Sample Program: Step 6: Evaluation of OR gates

ct_or1 = cc.EvalBinGate(OR, ct10, ct11)
ct_or2 = cc.EvalBinGate(OR, ct10, ct01)
ct_or3 = cc.EvalBinGate(OR, ct00, ct01)
ct_or4 = cc.EvalBinGate(OR, ct00, ct11)

print(f"1 OR 1 = {cc.Decrypt(sk, ct_or1)}")
print(f"1 OR 0 = {cc.Decrypt(sk, ct_or2)}")
print(f"0 OR 0 = {cc.Decrypt(sk, ct_or3)}")
print(f"0 OR 1 = {cc.Decrypt(sk, ct_or4)}\n")

## Sample Program: Step 7: Evaluation of NOR gates

ct_nor1 = cc.EvalBinGate(NOR, ct10, ct11)
ct_nor2 = cc.EvalBinGate(NOR, ct10, ct01)
ct_nor3 = cc.EvalBinGate(NOR, ct00, ct01)
ct_nor4 = cc.EvalBinGate(NOR, ct00, ct11)

print(f"1 NOR 1 = {cc.Decrypt(sk, ct_nor1)}")
print(f"1 NOR 0 = {cc.Decrypt(sk, ct_nor2)}")
print(f"0 NOR 0 = {cc.Decrypt(sk, ct_nor3)}")
print(f"0 NOR 1 = {cc.Decrypt(sk, ct_nor4)}\n")

## Sample Program: Step 8: Evaluation of XOR gates

ct_xor1 = cc.EvalBinGate(XOR, ct10, ct11)
ct_xor2 = cc.EvalBinGate(XOR, ct10, ct01)
ct_xor3 = cc.EvalBinGate(XOR, ct00, ct01)
ct_xor4 = cc.EvalBinGate(XOR, ct00, ct11)

print(f"1 XOR 1 = {cc.Decrypt(sk, ct_xor1)}")
print(f"1 XOR 0 = {cc.Decrypt(sk, ct_xor2)}")
print(f"0 XOR 0 = {cc.Decrypt(sk, ct_xor3)}")
print(f"0 XOR 1 = {cc.Decrypt(sk, ct_xor4)}\n")

## Sample Program: Step 9: Evaluation of XNOR gates

ct_xnor1 = cc.EvalBinGate(XNOR, ct10, ct11)
ct_xnor2 = cc.EvalBinGate(XNOR, ct10, ct01)
ct_xnor3 = cc.EvalBinGate(XNOR, ct00, ct01)
ct_xnor4 = cc.EvalBinGate(XNOR, ct00, ct11)

print(f"1 XNOR 1 = {cc.Decrypt(sk, ct_xnor1)}")
print(f"1 XNOR 0 = {cc.Decrypt(sk, ct_xnor2)}")
print(f"0 XNOR 0 = {cc.Decrypt(sk, ct_xnor3)}")
print(f"0 XNOR 1 = {cc.Decrypt(sk, ct_xnor4)}\n")
