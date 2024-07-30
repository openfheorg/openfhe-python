from openfhe import *
from math import *

def main():
    SwitchCKKSToFHEW()
    SwitchFHEWtoCKKS()
    FloorViaSchemeSwitching()
    FuncViaSchemeSwitching()
    PolyViaSchemeSwitching()
    ComparisonViaSchemeSwitching()
    ArgminViaSchemeSwitching()
    ArgminViaSchemeSwitchingAlt()
    ArgminViaSchemeSwitchingUnit()
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
    # FHEWparams     = cc.EvalCKKStoFHEWSetup(sl, slBin, False, logQ_ccLWE, False, slots)    
    params = SchSwchParams()
    params.SetSecurityLevelCKKS(sl)
    params.SetSecurityLevelFHEW(slBin)
    params.SetCtxtModSizeFHEWLargePrec(logQ_ccLWE)
    params.SetNumSlotsCKKS(slots)
    
    privateKeyFHEW = cc.EvalCKKStoFHEWSetup(params)
    ccLWE = cc.GetBinCCForSchemeSwitch()
    
    # ccLWE          = FHEWparams[0]
    # privateKeyFHEW = FHEWparams[1]
    cc.EvalCKKStoFHEWKeyGen(keys, privateKeyFHEW)

    print(f"FHEW scheme is using a lattice parameter {ccLWE.Getn()},")
    print(f"logQ {logQ_ccLWE},")
    print(f"and modulus q {ccLWE.Getq()}\n")

    #  Compute the scaling factor to decrypt correctly in FHEW; the LWE mod switch is performed on the ciphertext at the last level
    pLWE1 = ccLWE.GetMaxPlaintextSpace() # Small precision
    modulus_LWE  = 1 << logQ_ccLWE
    beta = ccLWE.GetBeta()
    pLWE2 = modulus_LWE / (2*beta) # Large precision

    scale1 = 1 / pLWE1
    scale2 = 1 / pLWE2

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
    print("\n-----SwitchFHEWtoCKKS-----\n")
    print("Output precision is only wrt the operations in CKKS after switching back.\n")

    # Step 1: Setup CryptoContext for CKKS to be switched into

    #  A. Specify main parameters
    scTech = FIXEDAUTO
    multDepth = 3 + 9 + 1 
    # for r = 3 in FHEWtoCKKS, Chebyshev max depth allowed is 9, 1 more level for postscaling
    if scTech == FLEXIBLEAUTOEXT:
        multDepth += 1
    scaleModSize = 50
    ringDim = 8192
    sl = HEStd_NotSet #  If this is not HEStd_NotSet, ensure ringDim is compatible
    logQ_ccLWE = 28

    # slots = ringDim/2; # Uncomment for fully-packed
    slots = 16 # sparsely-packed
    batchSize = slots

    parameters = CCParamsCKKSRNS()
    parameters.SetMultiplicativeDepth(multDepth)
    parameters.SetScalingModSize(scaleModSize)
    parameters.SetScalingTechnique(scTech)
    parameters.SetSecurityLevel(sl)
    parameters.SetRingDim(ringDim)
    parameters.SetBatchSize(batchSize)

    cc = GenCryptoContext(parameters)

    # Enable the features that you wish to use
    cc.Enable(PKE)
    cc.Enable(KEYSWITCH)
    cc.Enable(LEVELEDSHE)
    cc.Enable(ADVANCEDSHE)
    cc.Enable(SCHEMESWITCH)

    print(f"CKKS scheme is using ring dimension {cc.GetRingDimension()},\n number of slots {slots}, and suports a multiplicative depth of {multDepth}\n")

    # Generate encryption keys
    keys = cc.KeyGen()

    # Step 2: Prepare the FHEW cryptocontext and keys for FHEW and scheme switching
    ccLWE = BinFHEContext()
    ccLWE.GenerateBinFHEContext(TOY, False, logQ_ccLWE, 0, GINX, False)

    # LWE private key
    lwesk = ccLWE.KeyGen()

    print(f"FHEW scheme is using lattice parameter {ccLWE.Getn()},\n logQ {logQ_ccLWE},\n and modulus q {ccLWE.Getq()}\n")

    # Step 3. Precompute the necessary keys and information for switching from FHEW to CKKS
    cc.EvalFHEWtoCKKSSetup(ccLWE, slots, logQ_ccLWE)

    cc.EvalFHEWtoCKKSKeyGen(keys, lwesk)

    # Step 4: Encoding and encryption of inputs
    # For correct CKKS decryption, the messages have to be much smaller than the FHEW plaintext modulus!
    pLWE1 = ccLWE.GetMaxPlaintextSpace() # Small precision
    pLWE2 = 256 # Medium precision
    modulus_LWE = 1 << logQ_ccLWE
    beta = ccLWE.GetBeta()
    pLWE3 = int(modulus_LWE / (2 * beta)) # Large precision
    x1 = [1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0]
    x2 = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
    if len(x1) < slots:
        zeros = [0] * (slots - len(x1))
        x1.extend(zeros)
        x2.extend(zeros)

    # Encrypt
    # Encrypted under small plaintext modulus p = 4 and ciphertext modulus:
    ctxtsLWE1 = [ccLWE.Encrypt(lwesk, x1[i]) for i in range(slots)]
    # Encrypted under larger plaintext modulus p = 16 but small ciphertext modulus:
    ctxtsLWE2 = [ccLWE.Encrypt(lwesk, x1[i], FRESH, pLWE1) for i in range(slots)]
    # Encrypted under larger plaintext modulus and large ciphertext modulus:
    ctxtsLWE3 = [ccLWE.Encrypt(lwesk, x2[i], FRESH, pLWE2, modulus_LWE) for i in range(slots)]
    # Encrypted under large plaintext modulus and large ciphertext modulus:
    ctxtsLWE4 = [ccLWE.Encrypt(lwesk, x2[i], FRESH, pLWE3, modulus_LWE) for i in range(slots)]

    # Step 5. Perform the scheme switching
    cTemp = cc.EvalFHEWtoCKKS(ctxtsLWE1, slots, slots)

    print(f"\n---Input x1: {x1} encrypted under p = 4 and Q = {ctxtsLWE1[0].GetModulus()} ---")

    # Step 6. Decrypt
    plaintextDec = cc.Decrypt(keys.secretKey, cTemp)
    plaintextDec.SetLength(slots)
    print(f"Switched CKKS decryption 1: {plaintextDec}")

    # Step 5'. Perform the scheme switching
    cTemp = cc.EvalFHEWtoCKKS(ctxtsLWE2, slots, slots, pLWE1, 0, pLWE1)

    print(f"\n---Input x1: {x1} encrypted under p = {pLWE1} and Q = {ctxtsLWE2[0].GetModulus()} ---")

    # Step 6'. Decrypt
    plaintextDec = cc.Decrypt(keys.secretKey, cTemp)
    plaintextDec.SetLength(slots)
    print(f"Switched CKKS decryption 2: {plaintextDec}")

    # Step 5''. Perform the scheme switching
    cTemp = cc.EvalFHEWtoCKKS(ctxtsLWE3, slots, slots, pLWE2, 0, pLWE2)

    print(f"\n---Input x2: {x2} encrypted under p = {pLWE2} and Q = {ctxtsLWE3[0].GetModulus()} ---")

    # Step 6''. Decrypt
    plaintextDec = cc.Decrypt(keys.secretKey, cTemp)
    plaintextDec.SetLength(slots)
    print(f"Switched CKKS decryption 3: {plaintextDec}")

    # Step 5'''. Perform the scheme switching
    cTemp2 = cc.EvalFHEWtoCKKS(ctxtsLWE4, slots, slots, pLWE3, 0, pLWE3)

    print(f"\n---Input x2: {x2} encrypted under p = {pLWE3} and Q = {ctxtsLWE4[0].GetModulus()} ---")

    # Step 6'''. Decrypt
    plaintextDec = cc.Decrypt(keys.secretKey, cTemp2)
    plaintextDec.SetLength(slots)
    print(f"Switched CKKS decryption 4: {plaintextDec}")

def FloorViaSchemeSwitching():
    print("\n-----FloorViaSchemeSwitching-----\n")
    print("Output precision is only wrt the operations in CKKS after switching back.\n")

    # Step 1: Setup CryptoContext for CKKS
    scTech = FIXEDAUTO
    multDepth = 3 + 9 + 1  # for r = 3 in FHEWtoCKKS, Chebyshev max depth allowed is 9, 1 more level for postscaling
    if scTech == FLEXIBLEAUTOEXT:
        multDepth += 1

    scaleModSize = 50
    ringDim = 8192
    sl = HEStd_NotSet
    slBin = TOY
    logQ_ccLWE = 23
    slots = 16  # sparsely-packed
    batchSize = slots

    parameters = CCParamsCKKSRNS()
    parameters.SetMultiplicativeDepth(multDepth)
    parameters.SetScalingModSize(scaleModSize)
    parameters.SetScalingTechnique(scTech)
    parameters.SetSecurityLevel(sl)
    parameters.SetRingDim(ringDim)
    parameters.SetBatchSize(batchSize)

    cc = GenCryptoContext(parameters)

    # Enable the features that you wish to use
    cc.Enable(PKE)
    cc.Enable(KEYSWITCH)
    cc.Enable(LEVELEDSHE)
    cc.Enable(ADVANCEDSHE)
    cc.Enable(SCHEMESWITCH)

    print(f"CKKS scheme is using ring dimension {cc.GetRingDimension()},\n number of slots {slots}, and suports a multiplicative depth of {multDepth}\n")

    # Generate encryption keys.
    keys = cc.KeyGen()
    
    # Step 2: Prepare the FHEW cryptocontext and keys for FHEW and scheme switching
    params = SchSwchParams()
    params.SetSecurityLevelCKKS(sl)
    params.SetSecurityLevelFHEW(slBin)
    params.SetCtxtModSizeFHEWLargePrec(logQ_ccLWE)
    params.SetNumSlotsCKKS(slots)
    params.SetNumValues(slots)
    
    privateKeyFHEW = cc.EvalSchemeSwitchingSetup(params)
    ccLWE = cc.GetBinCCForSchemeSwitch()

    cc.EvalSchemeSwitchingKeyGen(keys, privateKeyFHEW)

    # Generate bootstrapping key for EvalFloor
    ccLWE.BTKeyGen(privateKeyFHEW)

    print(f"FHEW scheme is using lattice parameter {ccLWE.Getn()},\n logQ {logQ_ccLWE},\n and modulus q {ccLWE.Getq()}\n")

    # Set the scaling factor to be able to decrypt; the LWE mod switch is performed on the ciphertext at the last level
    modulus_CKKS_from = cc.GetModulusCKKS()

    modulus_LWE = 1 << logQ_ccLWE
    beta = ccLWE.GetBeta()
    pLWE = int(modulus_LWE / (2 * beta))  # Large precision

    scaleCF = 1.0 / pLWE

    cc.EvalCKKStoFHEWPrecompute(scaleCF)

    # Step 3: Encoding and encryption of inputs
    # Inputs
    x1 = [0.0, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0, 11.0, 12.0, 13.0, 14.0, 15.0]

    # Encoding as plaintexts
    ptxt1 = cc.MakeCKKSPackedPlaintext(x1, 1, 0, None)#, None)

    # Encrypt the encoded vectors
    c1 = cc.Encrypt(keys.publicKey, ptxt1)

    # Step 4: Scheme switching from CKKS to FHEW
    cTemp = cc.EvalCKKStoFHEW(c1, slots)
    
    # Step 5: Evaluate the floor function
    bits = 2

    cFloor = [ccLWE.EvalFloor(cTemp[i], bits) for i in range(len(cTemp))]

    print(f"Input x1: {ptxt1.GetRealPackedValue()}")
    print(f"Expected result for EvalFloor with {bits} bits: ", end="")
    for i in range(slots):
        print(int(ptxt1.GetRealPackedValue()[i]) >> bits, end=" ")
    
    print(f"\nFHEW decryption p = {pLWE}/(1 << bits) = {pLWE // (1 << bits)}: ", end="")
    for i in range(len(cFloor)):
        pFloor = ccLWE.Decrypt(privateKeyFHEW, cFloor[i], pLWE // (1 << bits))
        print(pFloor, end=" ")
    print("\n")

    # Step 6: Scheme switching from FHEW to CKKS
    cTemp2 = cc.EvalFHEWtoCKKS(cFloor, slots, slots, pLWE // (1 << bits), 0, pLWE / (1 << bits))

    plaintextDec2 = cc.Decrypt(keys.secretKey, cTemp2)
    plaintextDec2.SetLength(slots)
    print(f"Switched floor decryption modulus_LWE mod {pLWE // (1 << bits)}: {plaintextDec2}")

def FuncViaSchemeSwitching():
    print("\n-----FuncViaSchemeSwitching-----\n")
    print("Output precision is only wrt the operations in CKKS after switching back.\n")

    # Step 1: Setup CryptoContext for CKKS
    multDepth = 9 + 3 + 2  # 1 for CKKS to FHEW, 14 for FHEW to CKKS
    scaleModSize = 50
    ringDim = 2048
    sl = HEStd_NotSet
    slBin = TOY
    logQ_ccLWE = 25
    arbFunc = True
    slots = 8  # sparsely-packed
    batchSize = slots

    parameters = CCParamsCKKSRNS()
    parameters.SetMultiplicativeDepth(multDepth)
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
    cc.Enable(ADVANCEDSHE)
    cc.Enable(SCHEMESWITCH)

    print(f"CKKS scheme is using ring dimension {cc.GetRingDimension()},\n and number of slots {slots}\n")

    # Generate encryption keys.
    keys = cc.KeyGen()

    # Step 2: Prepare the FHEW cryptocontext and keys for FHEW and scheme switching
    params = SchSwchParams()
    params.SetSecurityLevelCKKS(sl)
    params.SetSecurityLevelFHEW(slBin)
    params.SetArbitraryFunctionEvaluation(True)
    params.SetCtxtModSizeFHEWLargePrec(logQ_ccLWE)
    params.SetNumSlotsCKKS(slots)
    params.SetNumValues(slots)
    
    privateKeyFHEW = cc.EvalSchemeSwitchingSetup(params)
    ccLWE = cc.GetBinCCForSchemeSwitch()

    cc.EvalSchemeSwitchingKeyGen(keys, privateKeyFHEW)

    # Generate the bootstrapping keys for EvalFunc in FHEW
    ccLWE.BTKeyGen(privateKeyFHEW)

    print(f"FHEW scheme is using lattice parameter {ccLWE.Getn()},\n logQ {logQ_ccLWE},\n and modulus q {ccLWE.Getq()}\n")

    # Set the scaling factor to be able to decrypt; the LWE mod switch is performed on the ciphertext at the last level
    pLWE = ccLWE.GetMaxPlaintextSpace()  # Small precision because GenerateLUTviaFunction needs p < q
    scaleCF = 1.0 / pLWE

    cc.EvalCKKStoFHEWPrecompute(scaleCF)

    # Step 3: Initialize the function
    # Initialize Function f(x) = x^3 + 2x + 1 % p
    def fp(m, p1):
        if m < p1:
            return (m * m * m + 2 * m * m + 1) % p1
        else:
            return ((m - p1 / 2) * (m - p1 / 2) * (m - p1 / 2) + 2 * (m - p1 / 2) * (m - p1 / 2) + 1) % p1

    # Generate LUT from function f(x)
    lut = ccLWE.GenerateLUTviaFunction(fp, pLWE)
    
    # Step 4: Encoding and encryption of inputs
    # Inputs
    x1 = [0.0, 0.3, 2.0, 4.0, 5.0, 6.0, 7.0, 8.0]

    # Encoding as plaintexts
    ptxt1 = cc.MakeCKKSPackedPlaintext(x1, 1, 0, None)

    # Encrypt the encoded vectors
    c1 = cc.Encrypt(keys.publicKey, ptxt1)

    # Step 5: Scheme switching from CKKS to FHEW
    cTemp = cc.EvalCKKStoFHEW(c1, slots)

    print(f"Input x1: {ptxt1.GetRealPackedValue()}")
    print("FHEW decryption: ", end="")
    for i in range(len(cTemp)):
        result = ccLWE.Decrypt(privateKeyFHEW, cTemp[i], pLWE)
        print(result, end=" ")

    # Step 6: Evaluate the function
    cFunc = [ccLWE.EvalFunc(cTemp[i], lut) for i in range(len(cTemp))]

    print("\nExpected result x^3 + 2*x + 1 mod p: ", end="")
    for i in range(slots):
        print(fp(int(x1[i]) % pLWE, pLWE), end=" ")

    print(f"\nFHEW decryption mod {pLWE}: ", end="")
    for i in range(len(cFunc)):
        pFunc = ccLWE.Decrypt(privateKeyFHEW, cFunc[i], pLWE)
        print(pFunc, end=" ")
    print("\n")

    # Step 7: Scheme switching from FHEW to CKKS
    cTemp2 = cc.EvalFHEWtoCKKS(cFunc, slots, slots, pLWE, 0, pLWE)

    plaintextDec2 = cc.Decrypt(keys.secretKey, cTemp2)
    plaintextDec2.SetLength(slots)
    print(f"\nSwitched decryption modulus_LWE mod {pLWE}\nworks only for messages << p: {plaintextDec2}")

    # Transform through arcsine
    cTemp2 = cc.EvalFHEWtoCKKS(cFunc, slots, slots, 4, 0, 2)

    plaintextDec2 = cc.Decrypt(keys.secretKey, cTemp2)
    plaintextDec2.SetLength(slots)

    print("Arcsin(switched result) * p/2pi gives the correct result if messages are < p/4: ", end="")
    for i in range(slots):
        x = max(min(plaintextDec2.GetRealPackedValue()[i], 1.0), -1.0)
        print(asin(x) * pLWE / (2 * pi), end=" ")
    print()
    

def PolyViaSchemeSwitching():
    print("\n-----PolyViaSchemeSwitching-----\n")

    # Step 1: Setup CryptoContext for CKKS to be switched into

    # A. Specify main parameters
    scTech = FIXEDAUTO
    multDepth = 3 + 9 + 1 + 2  # for r = 3 in FHEWtoCKKS, Chebyshev max depth allowed is 9, 1 more level for postscaling, 3 levels for functionality
    if scTech == FLEXIBLEAUTOEXT:
        multDepth += 1
    scaleModSize = 50
    ringDim = 2048
    sl = HEStd_NotSet
    slBin = TOY
    logQ_ccLWE = 25

    slots = 16  # sparsely-packed
    batchSize = slots

    # Create encryption parameters
    parameters = CCParamsCKKSRNS()
    parameters.SetMultiplicativeDepth(multDepth)
    parameters.SetScalingModSize(scaleModSize)
    parameters.SetScalingTechnique(scTech)
    parameters.SetSecurityLevel(sl)
    parameters.SetRingDim(ringDim)
    parameters.SetBatchSize(batchSize)

    cc = GenCryptoContext(parameters)

    # Enable the features that you wish to use
    cc.Enable(PKE)
    cc.Enable(KEYSWITCH)
    cc.Enable(LEVELEDSHE)
    cc.Enable(ADVANCEDSHE)
    cc.Enable(SCHEMESWITCH)

    print(f"CKKS scheme is using ring dimension {cc.GetRingDimension()},\n number of slots {slots}, and suports a multiplicative depth of {multDepth}\n")

    # Generate encryption keys
    keys = cc.KeyGen()

    # Step 2: Prepare the FHEW cryptocontext and keys for FHEW and scheme switching
    params = SchSwchParams()
    params.SetSecurityLevelCKKS(sl)
    params.SetSecurityLevelFHEW(slBin)
    params.SetCtxtModSizeFHEWLargePrec(logQ_ccLWE)
    params.SetNumSlotsCKKS(slots)
    params.SetNumValues(slots)
    
    privateKeyFHEW = cc.EvalSchemeSwitchingSetup(params)
    ccLWE = cc.GetBinCCForSchemeSwitch()

    cc.EvalSchemeSwitchingKeyGen(keys, privateKeyFHEW)

    print(f"FHEW scheme is using lattice parameter {ccLWE.Getn()},\n logQ {logQ_ccLWE},\n and modulus q {ccLWE.Getq()}\n")

    pLWE1 = ccLWE.GetMaxPlaintextSpace()  # Small precision
    modulus_LWE = 1 << logQ_ccLWE
    beta = ccLWE.GetBeta()
    pLWE2 = int(modulus_LWE / (2 * beta))  # Large precision

    scale1 = 1.0 / pLWE1
    scale2 = 1.0 / pLWE2

    # Generate keys for the CKKS intermediate computation
    cc.EvalMultKeyGen(keys.secretKey)
    cc.EvalRotateKeyGen(keys.secretKey, [1,2])

    # Step 4: Encoding and encryption of inputs
    # For correct CKKS decryption, the messages have to be much smaller than the FHEW plaintext modulus!
    # Inputs
    x1 = [1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0]
    x2 = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]

    x1Rot = RotateInt(x1,1)
    x1Rot = [x1Rot[i] + x1[i] for i in range(len(x1))]
    x1Int = [int(round(0.25 * elem * elem) % pLWE1) for elem in x1Rot]

    x2Rot = RotateInt(x2,2)
    x2Rot = [x2Rot[i] + x2[i] for i in range(len(x2))]
    x2Int = [int(round(0.25 * elem * elem) % pLWE2) for elem in x2Rot]

    # Encrypt
    # encrypted under small plantext modulus p = 4 and ciphertext modulus
    ctxtsLWE1 = [ccLWE.Encrypt(privateKeyFHEW, x1[i]) for i in range(slots)]  
    # encrypted under large plaintext modulus and large ciphertext modulus
    ctxtsLWE2 = [ccLWE.Encrypt(privateKeyFHEW, x2[i], FRESH, pLWE2, modulus_LWE) for i in range(slots)]  

    # Step 5. Perform the scheme switching
    cTemp = cc.EvalFHEWtoCKKS(ctxtsLWE1, slots, slots)

    print(f"\n---Input x1: {x1} encrypted under p = 4 and Q = {ctxtsLWE1[0].GetModulus()} ---\n")
    print(f"round( 0.5 * (x1 + rot(x1,1) )^2 ): {x1Int}\n")

    # Step 6. Perform the desired computation in CKKS
    cPoly = cc.EvalAdd(cTemp, cc.EvalRotate(cTemp, 1))
    cPoly = cc.EvalMult(cc.EvalMult(cPoly, cPoly), 0.25)

    # Perform the precomputation for switching back to CKKS
    cc.EvalCKKStoFHEWPrecompute(scale1)

    # Tranform the ciphertext from CKKS to FHEW
    cTemp1 = cc.EvalCKKStoFHEW(cPoly, slots)

    print(f"\nFHEW decryption with plaintext modulus {pLWE1}: ", end="")
    for i in range(len(cTemp1)):
        result = ccLWE.Decrypt(privateKeyFHEW, cTemp1[i], pLWE1)
        print(result, end=" ")
    print("\n")

    # Step 5'. Perform the scheme switching 
    cTemp = cc.EvalFHEWtoCKKS(ctxtsLWE2, slots, slots, pLWE2, 0, pLWE2)

    print(f"\n---Input x2: {x2} encrypted under p = {pLWE2} and Q = {ctxtsLWE2[0].GetModulus()} ---\n")
    print(f"round( 0.5 * (x2 + rot(x2,2) )^2 ): {x2Int}\n")

    # Step 6'. Perform the desired computation in CKKS
    cPoly = cc.EvalAdd(cTemp, cc.EvalRotate(cTemp, 2))
    cPoly = cc.EvalMult(cc.EvalMult(cPoly, cPoly), 0.25)

    # Perform the precomputation for switching back to CKKS
    cc.EvalCKKStoFHEWPrecompute(scale2)

    # Tranform the ciphertext from CKKS to FHEW
    cTemp2 = cc.EvalCKKStoFHEW(cPoly, slots)

    print(f"\nFHEW decryption with plaintext modulus {pLWE2}: ", end="")
    for i in range(len(cTemp2)):
        result = ccLWE.Decrypt(privateKeyFHEW, cTemp2[i], pLWE2)
        print(result, end=" ")
    print("\n")


def ComparisonViaSchemeSwitching():
    print("\n-----ComparisonViaSchemeSwitching-----\n")
    print("Output precision is only wrt the operations in CKKS after switching back.\n")

    # Step 1: Setup CryptoContext for CKKS
    scTech = FIXEDAUTO
    multDepth = 17
    if scTech == FLEXIBLEAUTOEXT:
        multDepth += 1

    scaleModSize = 50
    firstModSize = 60
    ringDim = 8192
    sl = HEStd_NotSet
    slBin = TOY
    logQ_ccLWE = 25
    slots = 16  # sparsely-packed
    batchSize = slots

    parameters = CCParamsCKKSRNS()
    parameters.SetMultiplicativeDepth(multDepth)
    parameters.SetScalingModSize(scaleModSize)
    parameters.SetFirstModSize(firstModSize)
    parameters.SetScalingTechnique(scTech)
    parameters.SetSecurityLevel(sl)
    parameters.SetRingDim(ringDim)
    parameters.SetBatchSize(batchSize)
    parameters.SetSecretKeyDist(UNIFORM_TERNARY)
    parameters.SetKeySwitchTechnique(HYBRID)
    parameters.SetNumLargeDigits(3)

    cc = GenCryptoContext(parameters)

    # Enable the features that you wish to use
    cc.Enable(PKE)
    cc.Enable(KEYSWITCH)
    cc.Enable(LEVELEDSHE)
    cc.Enable(ADVANCEDSHE)
    cc.Enable(SCHEMESWITCH)

    print(f"CKKS scheme is using ring dimension {cc.GetRingDimension()},\n and number of slots {slots}\n and supports a multiplicative depth of {multDepth}\n")

    # Generate encryption keys.
    keys = cc.KeyGen()

    # Step 2: Prepare the FHEW cryptocontext and keys for FHEW and scheme switching
    params = SchSwchParams()
    params.SetSecurityLevelCKKS(sl)
    params.SetSecurityLevelFHEW(slBin)
    params.SetCtxtModSizeFHEWLargePrec(logQ_ccLWE)
    params.SetNumSlotsCKKS(slots)
    params.SetNumValues(slots)
    
    privateKeyFHEW = cc.EvalSchemeSwitchingSetup(params)
    ccLWE = cc.GetBinCCForSchemeSwitch()

    cc.EvalSchemeSwitchingKeyGen(keys, privateKeyFHEW)

    print(f"FHEW scheme is using lattice parameter {ccLWE.Getn()},\n logQ {logQ_ccLWE},\n and modulus q {ccLWE.Getq()}\n")

    # Set the scaling factor to be able to decrypt; the LWE mod switch is performed on the ciphertext at the last level
    pLWE1 = ccLWE.GetMaxPlaintextSpace()  # Small precision
    modulus_LWE = 1 << logQ_ccLWE
    beta = ccLWE.GetBeta()
    pLWE2 = int(modulus_LWE / (2 * beta))  # Large precision

    scaleSignFHEW = 1.0
    cc.EvalCompareSwitchPrecompute(pLWE2, scaleSignFHEW)

    # Step 3: Encoding and encryption of inputs
    x1 = [0.0, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0, 11.0, 12.0, 13.0, 14.0, 15.0]
    x2 = [5.25] * slots

    ptxt1 = cc.MakeCKKSPackedPlaintext(x1, 1, 0, None, slots)
    ptxt2 = cc.MakeCKKSPackedPlaintext(x2, 1, 0, None, slots)

    c1 = cc.Encrypt(keys.publicKey, ptxt1)
    c2 = cc.Encrypt(keys.publicKey, ptxt2)

    cDiff = cc.EvalSub(c1, c2)

    # Step 4: CKKS to FHEW switching and sign evaluation to test correctness
    pDiff = cc.Decrypt(keys.secretKey, cDiff)
    pDiff.SetLength(slots)

    print("Difference of inputs: ", end="")
    for i in range(slots):
        print(pDiff.GetRealPackedValue()[i], end=" ")

    eps = 0.0001
    print("\nExpected sign result from CKKS: ", end="")
    for i in range(slots):
        print(int(round(pDiff.GetRealPackedValue()[i] / eps) * eps < 0), end=" ")
    print()

    LWECiphertexts = cc.EvalCKKStoFHEW(cDiff, slots)

    print("\nFHEW decryption with plaintext modulus ", pLWE2, ": ", end="")
    for i in range(len(LWECiphertexts)):
        plainLWE = ccLWE.Decrypt(privateKeyFHEW, LWECiphertexts[i], pLWE2)
        print(plainLWE, end=" ")

    print("\nExpected sign result in FHEW with plaintext modulus ", pLWE2, " and scale ", scaleSignFHEW, ": ", end="")
    for i in range(slots):
        print((int(round(pDiff.GetRealPackedValue()[i] * scaleSignFHEW)) % pLWE2 - pLWE2 / 2.0 >= 0), end=" ")
    print()

    print("Obtained sign result in FHEW with plaintext modulus ", pLWE2, " and scale ", scaleSignFHEW, ": ", end="")
    LWESign = [None] * len(LWECiphertexts)
    for i in range(len(LWECiphertexts)):
        LWESign[i] = ccLWE.EvalSign(LWECiphertexts[i])
        plainLWE = ccLWE.Decrypt(privateKeyFHEW, LWESign[i], 2)
        print(plainLWE, end=" ")
    print()

    # Step 5'': Direct comparison via CKKS->FHEW->CKKS
    cResult = cc.EvalCompareSchemeSwitching(c1, c2, slots, slots)
    plaintextDec3 = cc.Decrypt(keys.secretKey, cResult)
    plaintextDec3.SetLength(slots)
    print(f"Decrypted switched result: {plaintextDec3}\n")
   

def ArgminViaSchemeSwitching():
    print("\n-----ArgminViaSchemeSwitching-----\n")
    print("Output precision is only wrt the operations in CKKS after switching back\n")

    # Step 1: Setup CryptoContext for CKKS
    scaleModSize = 50
    firstModSize = 60
    ringDim = 8192
    sl = HEStd_NotSet
    slBin = TOY
    logQ_ccLWE = 25
    arbFunc = False
    oneHot = True  # Change to false if the output should not be one-hot encoded

    slots = 16  # sparsely-packed
    batchSize = slots
    numValues = 16
    scTech = FIXEDMANUAL
    multDepth = 9 + 3 + 1 + int(log2(numValues))  # 13 for FHEW to CKKS, log2(numValues) for argmin
    if scTech == FLEXIBLEAUTOEXT:
        multDepth += 1

    parameters = CCParamsCKKSRNS()
    parameters.SetMultiplicativeDepth(multDepth)
    parameters.SetScalingModSize(scaleModSize)
    parameters.SetFirstModSize(firstModSize)
    parameters.SetScalingTechnique(scTech)
    parameters.SetSecurityLevel(sl)
    parameters.SetRingDim(ringDim)
    parameters.SetBatchSize(batchSize)

    cc = GenCryptoContext(parameters)

    # Enable the features that you wish to use
    cc.Enable(PKE)
    cc.Enable(KEYSWITCH)
    cc.Enable(LEVELEDSHE)
    cc.Enable(ADVANCEDSHE)
    cc.Enable(SCHEMESWITCH)

    print("CKKS scheme is using ring dimension ", cc.GetRingDimension())
    print(", and number of slots ", slots, ", and supports a depth of ", multDepth, "\n")

    # Generate encryption keys
    keys = cc.KeyGen()

    # Step 2: Prepare the FHEW cryptocontext and keys for FHEW and scheme switching
    params = SchSwchParams()
    params.SetSecurityLevelCKKS(sl)
    params.SetSecurityLevelFHEW(slBin)
    params.SetCtxtModSizeFHEWLargePrec(logQ_ccLWE)
    params.SetNumSlotsCKKS(slots)
    params.SetNumValues(numValues)
    params.SetComputeArgmin(True)
    
    privateKeyFHEW = cc.EvalSchemeSwitchingSetup(params)
    ccLWE = cc.GetBinCCForSchemeSwitch()

    cc.EvalSchemeSwitchingKeyGen(keys, privateKeyFHEW)

    print(f"FHEW scheme is using lattice parameter {ccLWE.Getn()},\n logQ {logQ_ccLWE},\n and modulus q {ccLWE.Getq()}\n")

    # Scale the inputs to ensure their difference is correctly represented after switching to FHEW
    scaleSign = 512
    modulus_LWE = 1 << logQ_ccLWE
    beta = ccLWE.GetBeta()
    pLWE = int(modulus_LWE / (2 * beta))  # Large precision

    cc.EvalCompareSwitchPrecompute(pLWE, scaleSign)

    # Step 3: Encoding and encryption of inputs
    x1 = [-1.125, -1.12, 5.0, 6.0, -1.0, 2.0, 8.0, -1.0, 9.0, 10.0, 11.0, 12.0, 13.0, 14.0, 15.25, 15.30]

    print("Expected minimum value ", min(x1), " at location ", x1.index(min(x1)))
    print("Expected maximum value ", max(x1), " at location ", x1.index(max(x1)))

    ptxt1 = cc.MakeCKKSPackedPlaintext(x1)

    c1 = cc.Encrypt(keys.publicKey, ptxt1)

    # Step 4: Argmin evaluation
    result = cc.EvalMinSchemeSwitching(c1, keys.publicKey, numValues, slots)

    ptxtMin = cc.Decrypt(keys.secretKey, result[0])
    ptxtMin.SetLength(1)
    print("Minimum value: ", ptxtMin)

    ptxtMin = cc.Decrypt(keys.secretKey, result[1])
    if oneHot:
        ptxtMin.SetLength(numValues)
        print("Argmin indicator vector: ", ptxtMin)
    else:
        ptxtMin.SetLength(1)
        print("Argmin: ", ptxtMin)

    result = cc.EvalMaxSchemeSwitching(c1, keys.publicKey, numValues, slots)

    ptxtMax = cc.Decrypt(keys.secretKey, result[0])
    ptxtMax.SetLength(1)
    print("Maximum value: ", ptxtMax)

    ptxtMax = cc.Decrypt(keys.secretKey, result[1])
    if oneHot:
        ptxtMax.SetLength(numValues)
        print("Argmax indicator vector: ", ptxtMax)
    else:
        ptxtMax.SetLength(1)
        print("Argmax: ", ptxtMax)

def ArgminViaSchemeSwitchingAlt():
    print("\n-----ArgminViaSchemeSwitchingAlt-----\n")
    print("Output precision is only wrt the operations in CKKS after switching back\n")

    # Step 1: Setup CryptoContext for CKKS
    scaleModSize = 50
    firstModSize = 60
    ringDim = 8192
    sl = HEStd_NotSet
    slBin = TOY
    logQ_ccLWE = 25
    arbFunc = False
    oneHot = True
    alt = True

    slots = 16
    batchSize = slots
    numValues = 16
    scTech = FIXEDAUTO
    multDepth = 9 + 3 + 1 + int(log2(numValues))

    parameters = CCParamsCKKSRNS()
    parameters.SetMultiplicativeDepth(multDepth)
    parameters.SetScalingModSize(scaleModSize)
    parameters.SetFirstModSize(firstModSize)
    parameters.SetScalingTechnique(scTech)
    parameters.SetSecurityLevel(sl)
    parameters.SetRingDim(ringDim)
    parameters.SetBatchSize(batchSize)

    cc = GenCryptoContext(parameters)

    cc.Enable(PKE)
    cc.Enable(KEYSWITCH)
    cc.Enable(LEVELEDSHE)
    cc.Enable(ADVANCEDSHE)
    cc.Enable(SCHEMESWITCH)

    print(f"CKKS scheme is using ring dimension {cc.GetRingDimension()},")
    print(f"number of slots {slots}, and supports a multiplicative depth of {multDepth}\n")

    keys = cc.KeyGen()
    
    # Step 2: Prepare the FHEW cryptocontext and keys for FHEW and scheme switching
    params = SchSwchParams()
    params.SetSecurityLevelCKKS(sl)
    params.SetSecurityLevelFHEW(slBin)
    params.SetCtxtModSizeFHEWLargePrec(logQ_ccLWE)
    params.SetNumSlotsCKKS(slots)
    params.SetNumValues(numValues)
    params.SetComputeArgmin(True)
    params.SetUseAltArgmin(True)
    
    privateKeyFHEW = cc.EvalSchemeSwitchingSetup(params)
    ccLWE = cc.GetBinCCForSchemeSwitch()

    cc.EvalSchemeSwitchingKeyGen(keys, privateKeyFHEW)

    print(f"FHEW scheme is using lattice parameter {ccLWE.Getn()},\n logQ {logQ_ccLWE},\n and modulus q {ccLWE.Getq()}\n")

    scaleSign = 512
    modulus_LWE = 1 << logQ_ccLWE
    beta = ccLWE.GetBeta()
    pLWE = int(modulus_LWE / (2 * beta))

    cc.EvalCompareSwitchPrecompute(pLWE, scaleSign)

    # Step 3: Encoding and encryption of inputs

    # Inputs
    x1 = [-1.125, -1.12, 5.0, 6.0, -1.0, 2.0, 8.0, -1.0, 9.0, 10.0, 11.0, 12.0, 13.0, 14.0, 15.25, 15.30]

    print("Expected minimum value ", min(x1), " at location ", x1.index(min(x1)))
    print("Expected maximum value ", max(x1), " at location ", x1.index(max(x1)))

    # Encoding as plaintexts
    ptxt1 = cc.MakeCKKSPackedPlaintext(x1)  # Only if we set batchsize
    # ptxt1 = cc.MakeCKKSPackedPlaintext(x1, 1, 0, None, slots) # If batchsize is not set

    # Encrypt the encoded vectors
    c1 = cc.Encrypt(keys.publicKey, ptxt1)

    # Step 4: Argmin evaluation
    result = cc.EvalMinSchemeSwitchingAlt(c1, keys.publicKey, numValues, slots)

    ptxtMin = cc.Decrypt(keys.secretKey, result[0])
    ptxtMin.SetLength(1)
    print("Minimum value: ", ptxtMin)

    ptxtMin = cc.Decrypt(keys.secretKey, result[1])
    if oneHot:
        ptxtMin.SetLength(numValues)
        print("Argmin indicator vector: ", ptxtMin)
    else:
        ptxtMin.SetLength(1)
        print("Argmin: ", ptxtMin)

    result = cc.EvalMaxSchemeSwitchingAlt(c1, keys.publicKey, numValues, slots)

    ptxtMax = cc.Decrypt(keys.secretKey, result[0])
    ptxtMax.SetLength(1)
    print("Maximum value: ", ptxtMax)

    ptxtMax = cc.Decrypt(keys.secretKey, result[1])
    if oneHot:
        ptxtMax.SetLength(numValues)
        print("Argmax indicator vector: ", ptxtMax)
    else:
        ptxtMax.SetLength(1)
        print("Argmax: ", ptxtMax)

def ArgminViaSchemeSwitchingUnit():
    print("\n-----ArgminViaSchemeSwitchingUnit-----\n")
    print("Output precision is only wrt the operations in CKKS after switching back\n")

    # Step 1: Setup CryptoContext for CKKS
    scaleModSize = 50
    firstModSize = 60
    ringDim = 8192
    sl = HEStd_NotSet
    slBin = TOY
    logQ_ccLWE = 25
    arbFunc = False
    oneHot = True

    slots = 32  # sparsely-packed
    batchSize = slots
    numValues = 32
    multDepth = 9 + 3 + 1 + int(log2(numValues))  # 1 for CKKS to FHEW, 13 for FHEW to CKKS, log2(numValues) for argmin

    parameters = CCParamsCKKSRNS()
    if get_native_int()!=128:
        scTech = FLEXIBLEAUTOEXT
        multDepth += 1
        parameters.SetScalingTechnique(scTech)

    parameters.SetMultiplicativeDepth(multDepth)
    parameters.SetScalingModSize(scaleModSize)
    parameters.SetFirstModSize(firstModSize)
    parameters.SetSecurityLevel(sl)
    parameters.SetRingDim(ringDim)
    parameters.SetBatchSize(batchSize)

    cc = GenCryptoContext(parameters)

    # Enable the features that you wish to use
    cc.Enable(PKE)
    cc.Enable(KEYSWITCH)
    cc.Enable(LEVELEDSHE)
    cc.Enable(ADVANCEDSHE)
    cc.Enable(SCHEMESWITCH)
    cc.Enable(FHE)

    print(f"CKKS scheme is using ring dimension {cc.GetRingDimension()},")
    print(f"number of slots {slots}, and supports a multiplicative depth of {multDepth}\n")

    # Generate encryption keys.
    keys = cc.KeyGen()

    # Step 2: Prepare the FHEW cryptocontext and keys for FHEW and scheme switching
    params = SchSwchParams()
    params.SetSecurityLevelCKKS(sl)
    params.SetSecurityLevelFHEW(slBin)
    params.SetCtxtModSizeFHEWLargePrec(logQ_ccLWE)
    params.SetNumSlotsCKKS(slots)
    params.SetNumValues(numValues)
    params.SetComputeArgmin(True)
    
    privateKeyFHEW = cc.EvalSchemeSwitchingSetup(params)
    ccLWE = cc.GetBinCCForSchemeSwitch()

    cc.EvalSchemeSwitchingKeyGen(keys, privateKeyFHEW)

    print(f"FHEW scheme is using lattice parameter {ccLWE.Getn()},\n logQ {logQ_ccLWE},\n and modulus q {ccLWE.Getq()}\n")

    # Here we assume the message does not need scaling, as they are in the unit circle.
    cc.EvalCompareSwitchPrecompute(1, 1)

    # Step 3: Encoding and encryption of inputs

    # Inputs
    x1 = [-1.125, -1.12, 5.0, 6.0, -1.0, 2.0, 8.0, -1.0, 9.0, 10.0, 11.0, 12.0, 13.0, 14.0, 15.25, 15.30]
    if len(x1) < slots:
        x1.extend([0] * (slots - len(x1)))
    print("Input: ", x1)

    p = 1 << (firstModSize - scaleModSize - 1)
    x1 = [elem / (2 * p) for elem in x1]

    print("Input scaled: ", x1)
    print("Expected minimum value ", min(x1), " at location ", x1.index(min(x1)))
    print("Expected maximum value ", max(x1), " at location ", x1.index(max(x1)))

    # Encoding as plaintexts
    ptxt1 = cc.MakeCKKSPackedPlaintext(x1)

    # Encrypt the encoded vectors
    c1 = cc.Encrypt(keys.publicKey, ptxt1)

    # Step 4: Argmin evaluation
    result = cc.EvalMinSchemeSwitching(c1, keys.publicKey, numValues, slots)

    ptxtMin = cc.Decrypt(keys.secretKey, result[0])
    ptxtMin.SetLength(1)
    print("Minimum value: ", ptxtMin)

    ptxtMin = cc.Decrypt(keys.secretKey, result[1])
    if oneHot:
        ptxtMin.SetLength(numValues)
        print("Argmin indicator vector: ", ptxtMin)
    else:
        ptxtMin.SetLength(1)
        print("Argmin: ", ptxtMin)

    result = cc.EvalMaxSchemeSwitching(c1, keys.publicKey, numValues, slots)

    ptxtMax = cc.Decrypt(keys.secretKey, result[0])
    ptxtMax.SetLength(1)
    print("Maximum value: ", ptxtMax)

    ptxtMax = cc.Decrypt(keys.secretKey, result[1])
    if oneHot:
        ptxtMax.SetLength(numValues)
        print("Argmax indicator vector: ", ptxtMax)
    else:
        ptxtMax.SetLength(1)
        print("Argmax: ", ptxtMax)

def ArgminViaSchemeSwitchingAltUnit():
    print("\n-----ArgminViaSchemeSwitchingAltUnit-----\n")
    print("Output precision is only wrt the operations in CKKS after switching back\n")

    # Step 1: Setup CryptoContext for CKKS
    scaleModSize = 50
    firstModSize = 60
    ringDim = 8192
    sl = HEStd_NotSet
    slBin = TOY
    logQ_ccLWE = 25
    arbFunc = False
    oneHot = True
    alt = True  # alternative mode of argmin which has fewer rotation keys and does more operations in FHEW than in CKKS

    slots = 32  # sparsely-packed
    batchSize = slots
    numValues = 32
    multDepth = 9 + 3 + 1 + int(log2(numValues))  # 1 for CKKS to FHEW, 13 for FHEW to CKKS, log2(numValues) for argmin

    parameters = CCParamsCKKSRNS()
    if get_native_int()!=128:
        scTech = FLEXIBLEAUTOEXT
        multDepth += 1
        parameters.SetScalingTechnique(scTech)

    parameters.SetMultiplicativeDepth(multDepth)
    parameters.SetScalingModSize(scaleModSize)
    parameters.SetFirstModSize(firstModSize)
    parameters.SetSecurityLevel(sl)
    parameters.SetRingDim(ringDim)
    parameters.SetBatchSize(batchSize)

    cc = GenCryptoContext(parameters)

    # Enable the features that you wish to use
    cc.Enable(PKE)
    cc.Enable(KEYSWITCH)
    cc.Enable(LEVELEDSHE)
    cc.Enable(ADVANCEDSHE)
    cc.Enable(SCHEMESWITCH)
    cc.Enable(FHE)

    print(f"CKKS scheme is using ring dimension {cc.GetRingDimension()},")
    print(f"number of slots {slots}, and supports a multiplicative depth of {multDepth}\n")

    # Generate encryption keys.
    keys = cc.KeyGen()

    # Step 2: Prepare the FHEW cryptocontext and keys for FHEW and scheme switching
    params = SchSwchParams()
    params.SetSecurityLevelCKKS(sl)
    params.SetSecurityLevelFHEW(slBin)
    params.SetCtxtModSizeFHEWLargePrec(logQ_ccLWE)
    params.SetNumSlotsCKKS(slots)
    params.SetNumValues(numValues)
    params.SetComputeArgmin(True)
    params.SetUseAltArgmin(True)
    
    privateKeyFHEW = cc.EvalSchemeSwitchingSetup(params)
    ccLWE = cc.GetBinCCForSchemeSwitch()

    cc.EvalSchemeSwitchingKeyGen(keys, privateKeyFHEW)

    print(f"FHEW scheme is using lattice parameter {ccLWE.Getn()},\n logQ {logQ_ccLWE},\n and modulus q {ccLWE.Getq()}\n")

    # Here we assume the message does not need scaling, as they are in the unit circle.
    cc.EvalCompareSwitchPrecompute(1, 1)

    # Step 3: Encoding and encryption of inputs
    # Inputs
    x1 = [-1.125, -1.12, 5.0, 6.0, -1.0, 2.0, 8.0, -1.0, 9.0, 10.0, 11.0, 12.0, 13.0, 14.0, 15.25, 15.30]
    if len(x1) < slots:
        zeros = [0] * (slots - len(x1))
        x1.extend(zeros)
    print("Input: ", x1)

    p = 1 << (firstModSize - scaleModSize - 1)
    x1 = [elem / (2 * p) for elem in x1]

    print("Input scaled: ", x1)
    print("Expected minimum value ", min(x1), " at location ", x1.index(min(x1)))
    print("Expected maximum value ", max(x1), " at location ", x1.index(max(x1)))

    # Encoding as plaintexts
    ptxt1 = cc.MakeCKKSPackedPlaintext(x1)

    # Encrypt the encoded vectors
    c1 = cc.Encrypt(keys.publicKey, ptxt1)

    # Step 4: Argmin evaluation
    result = cc.EvalMinSchemeSwitchingAlt(c1, keys.publicKey, numValues, slots)

    ptxtMin = cc.Decrypt(keys.secretKey, result[0])
    ptxtMin.SetLength(1)
    print("Minimum value: ", ptxtMin)

    ptxtMin = cc.Decrypt(keys.secretKey, result[1])
    if oneHot:
        ptxtMin.SetLength(numValues)
        print("Argmin indicator vector: ", ptxtMin)
    else:
        ptxtMin.SetLength(1)
        print("Argmin: ", ptxtMin)

    result = cc.EvalMaxSchemeSwitchingAlt(c1, keys.publicKey, numValues, slots)

    ptxtMax = cc.Decrypt(keys.secretKey, result[0])
    ptxtMax.SetLength(1)
    print("Maximum value: ", ptxtMax)

    ptxtMax = cc.Decrypt(keys.secretKey, result[1])
    if oneHot:
        ptxtMax.SetLength(numValues)
        print("Argmax indicator vector: ", ptxtMax)
    else:
        ptxtMax.SetLength(1)
        print("Argmax: ", ptxtMax)

# Helper functions:
def ReduceRotation(index, slots):
    islots = int(slots)

    # if slots is a power of 2
    if (slots & (slots - 1)) == 0:
        n = int(log2(slots))
        if index >= 0:
            return index - ((index >> n) << n)
        return index + islots + ((int(abs(index)) >> n) << n)
    return (islots + index % islots) % islots

def RotateInt(a, index):
    slots = len(a)

    result = [0]*slots

    if index < 0 or index > slots:
        index = ReduceRotation(index, slots)

    if index == 0:
        result = a.copy()
    else:
        # two cases: i+index <= slots and i+index > slots
        for i in range(0, slots - index):
            result[i] = a[i + index]
        for i in range(slots - index, slots):
            result[i] = a[i + index - slots]

    return result

if __name__ == "__main__":
    main()
