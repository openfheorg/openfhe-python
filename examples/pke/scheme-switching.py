from openfhe import *
from math import *

def main():
    SwitchCKKSToFHEW()
    SwitchFHEWtoCKKS()
    FloorViaSchemeSwitching()
    # FuncViaSchemeSwitching()
    # PolyViaSchemeSwitching()
    ComparisonViaSchemeSwitching()
    ArgminViaSchemeSwitching()
    ArgminViaSchemeSwitchingAlt()
    # ArgminViaSchemeSwitchingUnit()
    ArgminViaSchemeSwitchingAltUnit()

def SwitchCKKSToFHEW():

    # Example of switching a packed ciphertext from CKKS to multiple FHEW ciphertexts.
    print("\n-----SwitchCKKSToFHEW-----\n")

    # Step 1: Setup CryptoContext for CKKS

    # Specify main parameters
    multDepth    = 3
    firstModSize = 60
    scaleModSize = 50
    ringDim      = 4096
    sl      = HEStd_NotSet
    slBin = TOY
    logQ_ccLWE   = 25
    # slots = ringDim / 2  # Uncomment for fully-packed
    slots     = 16  # sparsely-packed
    batchSize = slots

    parameters = CCParamsCKKSRNS()

    parameters.SetMultiplicativeDepth(multDepth)
    parameters.SetFirstModSize(firstModSize)
    parameters.SetScalingModSize(scaleModSize)
    parameters.SetScalingTechnique(FIXEDMANUAL)
    parameters.SetSecurityLevel(sl)
    parameters.SetRingDim(ringDim)
    parameters.SetBatchSize(batchSize)

    cc = GenCryptoContext(parameters)

    # Enable the features that you wish to use
    cc.Enable(PKE)
    cc.Enable(KEYSWITCH)
    cc.Enable(LEVELEDSHE)
    cc.Enable(SCHEMESWITCH)

    print(f"CKKS scheme is using ring dimension {cc.GetRingDimension()},")
    print(f"number of slots {slots}, and supports a multiplicative depth of {multDepth}\n")

    # Generate encryption keys
    keys = cc.KeyGen()

    # Step 2: Prepare the FHEW cryptocontext and keys for FHEW and scheme switching
    FHEWparams     = cc.EvalCKKStoFHEWSetup(sl, slBin, False, logQ_ccLWE, False, slots)
    ccLWE          = FHEWparams[0]
    privateKeyFHEW = FHEWparams[1]
    cc.EvalCKKStoFHEWKeyGen(keys, privateKeyFHEW)

    print(f"FHEW scheme is using a lattice parameter {ccLWE.Getn()},")
    print(f"logQ {logQ_ccLWE},")
    print(f"and modulus q {ccLWE.Getq()}\n")

    #  Compute the scaling factor to decrypt correctly in FHEW; the LWE mod switch is performed on the ciphertext at the last level
    modulus_CKKS_from = cc.GetModulusCKKS()

    pLWE1 = ccLWE.GetMaxPlaintextSpace() # Small precision
    modulus_LWE  = 1 << logQ_ccLWE
    beta = ccLWE.GetBeta()
    pLWE2 = modulus_LWE / (2*beta) # Large precision

    scFactor = cc.GetScalingFactorReal(0)
    # if (cc.GetScalingTechnique() == FLEXIBLEAUTOEXT):
    #     scFactor = cc.GetScalingFactorReal(1)
    scale1 = modulus_CKKS_from / (scFactor * pLWE1)
    scale2 = modulus_CKKS_from / (scFactor * pLWE2)

    # Perform the precomputation for switching
    cc.EvalCKKStoFHEWPrecompute(scale1)

    # Step 3: Encoding and encryption of inputs
    # Inputs
    x1 = [0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0]
    x2 = [0.0, 271.1, 30000.0, pLWE2-2]
    encodedLength1 = len(x1)
    encodedLength2 = len(x2)

    # Encoding as plaintexts
    ptxt1 = cc.MakeCKKSPackedPlaintext(x1, 1, 0)
    ptxt2 = cc.MakeCKKSPackedPlaintext(x2, 1, 0)

    # Encrypt the encoded vectors
    c1 = cc.Encrypt(keys.publicKey, ptxt1)
    c2 = cc.Encrypt(keys.publicKey, ptxt2)

    # Step 4: Scheme Switching from CKKS to FHEW
    cTemp = cc.EvalCKKStoFHEW(c1, encodedLength1)

    print(f"\n---Decrypting switched ciphertext with small precision (plaintext modulus {pLWE1}) ---\n")
    
    x1Int = [round(x) % pLWE1 for x in x1]

    ptxt1.SetLength(encodedLength1)
    print(f"Input x1: {ptxt1.GetRealPackedValue()}; which rounds to {x1Int}")
    print("FHEW Decryption")

    for i in range(len(cTemp)):
        result = ccLWE.Decrypt(privateKeyFHEW, cTemp[i], pLWE1)
        print(result, end=" ")
    print("\n")

    # B: Second scheme switching case

    # Perform the precomputation for switching
    cc.EvalCKKStoFHEWPrecompute(scale2)
    
    # Transform the ciphertext from CKKS to FHEW (only for the number of inputs given)
    cTemp2 = cc.EvalCKKStoFHEW(c2, encodedLength2)

    print(f"\n---Decrypting switched ciphertext with large precision (plaintext modulus {pLWE2}) ---\n")
    ptxt2.SetLength(encodedLength2)
    print(f"Input x2: {ptxt2.GetRealPackedValue()}")
    print("FHEW Decryption")

    for i in range(len(cTemp2)):
        result = ccLWE.Decrypt(privateKeyFHEW, cTemp2[i], int(pLWE2))
        print(result, end=" ")
    print("\n")

    # C: Decompose the FHEW ciphertexts in smaller digits
    print(f"Decomposed values for digit size of {pLWE1}:")
    # Generate the bootstrapping keys (refresh and switching keys)
    ccLWE.BTKeyGen(privateKeyFHEW)

    for j in range(len(cTemp2)):
        # Decompose the large ciphertext into small ciphertexts that fit in q
        decomp = ccLWE.EvalDecomp(cTemp2[j])

        # Decryption
        p = ccLWE.GetMaxPlaintextSpace()
        for i in range(len(decomp)):
            ct = decomp[i]
            if i == len(decomp) - 1:
                p = int(pLWE2 / (pLWE1 ** floor(log(pLWE2)/log(pLWE1))))
                # The last digit should be up to P / p^floor(log_p(P))
            resultDecomp = ccLWE.Decrypt(privateKeyFHEW, ct, p)
            print(f"( {resultDecomp} * {pLWE1} ^ {i} )") 
            if i != len(decomp) - 1:
                print("+", end=" ")
        print("\n")

def SwitchFHEWtoCKKS():
    pass

def FloorViaSchemeSwitching():
    pass

def FuncViaSchemeSwitching():
    pass

def PolyViaSchemeSwitching():
    pass

def ComparisonViaSchemeSwitching():
    pass

def ArgminViaSchemeSwitching():
    pass

def ArgminViaSchemeSwitchingAlt():
    pass

def ArgminViaSchemeSwitchingUnit():
    pass

def ArgminViaSchemeSwitchingAltUnit():
    pass

if __name__ == "__main__":
    main()
