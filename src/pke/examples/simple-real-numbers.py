from openfhe import *

multDepth = 1
scaleModSize = 50
batchSize = 8

parameters = CCParamsCKKSRNS()
parameters.SetMultiplicativeDepth(multDepth)
parameters.SetScalingModSize(scaleModSize)
parameters.SetBatchSize(batchSize)

cc = GenCryptoContext(parameters)
cc.Enable(PKESchemeFeature.PKE)
cc.Enable(PKESchemeFeature.KEYSWITCH)
cc.Enable(PKESchemeFeature.LEVELEDSHE)

print("The CKKS scheme is using ring dimension: " + str(cc.GetRingDimension()))

keys = cc.KeyGen()
cc.EvalMultKeyGen(keys.secretKey)
cc.EvalRotateKeyGen(keys.secretKey, [1, -2])

x1 = [0.25, 0.5, 0.75, 1.0, 2.0, 3.0, 4.0, 5.0]
x2 = [5.0, 4.0, 3.0, 2.0, 1.0, 0.75, 0.5, 0.25]

cc.Test_Member_Function('test')
ptx1 = cc.MakeCKKSPackedPlaintext5(x1)
ptx2 = cc.MakeCKKSPackedPlaintext5(x2)

print("Input x1: " + str(ptx1))
print("Input x2: " + str(ptx2))

# Encrypt the encoded vectors
c1 = cc.Encrypt(keys.publicKey, ptx1)
c2 = cc.Encrypt(keys.publicKey, ptx2)

# Step 4: Evaluation
# Homomorphic additions
cAdd = cc.EvalAdd(c1, c2)
# Homomorphic Subtraction
cSub = cc.EvalSub(c1, c2)
# Homomorphic Multiplication
cMult = cc.EvalMult(c1, c2)
# Homomorphic Rotations
cRot1 = cc.EvalRotate(c1, 1)
cRot2 = cc.EvalRotate(c1, -2)

# Step 5: Decryption and output
# Decrypt the result of additions
ptAdd = Decrypt(cAdd,keys.secretKey)

# We set the precision to 8 decimal digits for a nicer output.
# If you want to see the error/noise introduced by CKKS, bump it up
# to 15 and it should become visible.

precision = 8
print("Results of homomorphic computations:")
result = Decrypt(c1, keys.secretKey)
result.SetLength(batchSize)
print("x1 = " + str(result))
print("Estimated precision in bits: " + str(result.GetLogPrecision()))



