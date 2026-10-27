from openfhe import *

## Sample Program: Step 1: Set CryptoContext

cc = BinFHEContext()
cc.GenerateBinFHEContext(STD128, True, 12)

## Sample Program: Step 2: Key Generation

# Generate the secret key
sk = cc.KeyGen()

print("Generating the bootstrapping keys...")

# Generate the bootstrapping keys (refresh, switching and public keys)
cc.BTKeyGen(sk, PUB_ENCRYPT)

pk = cc.GetPublicKey()

print("Completed the key generation.")

## Sample Program: Step 3: Create the to-be-evaluated function and obtain its corresponding LUT
p = cc.GetMaxPlaintextSpace()  # Obtain the maximum plaintext space

# Initialize Function f(x) = x^3 % p
def fp(m, p1):
    if m < p1:
        return m**3 % p1
    else:
        return (m - p1 // 2)**3 % p1

# Generate LUT from function f(x)
lut = cc.GenerateLUTviaFunction(fp, p)
print(f"Evaluate x^3%{p}.")

## Sample Program: Step 4: evaluate f(x) homomorphically and decrypt
# Note that we check for all the possible plaintexts.
for i in range(p):
    ct1 = cc.Encrypt(pk, i % p, SMALL_DIM, p)

    ct_cube = cc.EvalFunc(ct1, lut)

    result = cc.Decrypt(sk, ct_cube, p)

    print(f"Input: {i}. Expected: {fp(i, p)}. Evaluated = {result}")
