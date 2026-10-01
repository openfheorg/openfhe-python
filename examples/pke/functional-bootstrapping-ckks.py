#
# Examples for functional bootstrapping for RLWE ciphertexts using CKKS.
#

from openfhe import *

QBFV_INIT = 1 << 60
QBFV_INIT_LARGE = 1 << 80


def fill(a, slots):
    # Clones the current vector up to the size indicated by the 'slots' variable
    return [a[i % len(a)] for i in range(slots)]


def rotate(a, index):
    # Rotates the vector by the index amount (positive - left, negative - right)
    slots = len(a)
    index = index % slots
    if index == 0:
        return list(a)
    return list(a[index:]) + list(a[:index])


def rotate_two_halves(a, index):
    # Rotates each half of the vector by the index amount, mimicking the BFV subring rotations
    slots = len(a)
    slots_half = slots >> 1
    index = index % slots_half
    if index == 0:
        return list(a)
    result = [0] * slots
    for i in range(slots_half - index):
        result[i] = a[i + index]
    for i in range(slots_half - index, slots_half):
        result[i] = a[i + index - slots_half]
    for i in range(slots_half, slots - index):
        result[i] = a[i + index]
    for i in range(slots - index, slots):
        result[i] = a[i + index - slots_half]
    return result


def arbitrary_lut(qbfv_init, p_input, p_output, Q, bigq, scale_thi, order, num_slots, ring_dim, func):
    # 1. Figure out whether sparse packing or full packing should be used.
    # numSlots represents the number of values to be encrypted in BFV.
    # If this number is the same as the ring dimension, then the CKKS slots is half.
    flag_sp = num_slots <= ring_dim // 2  # sparse packing
    num_slots_ckks = num_slots if flag_sp else num_slots // 2

    # 2. Input
    x = [p_input // 2, p_input // 2 + 1, 0, 3, 16, 33, 64, p_input - 1]
    print(f"First 8 elements of the input (repeated) up to size {num_slots}:")
    print(x)
    if len(x) < num_slots:
        x = fill(x, num_slots)

    # 3. The case of Boolean LUTs using the first order Trigonometric Hermite Interpolation
    # supports an optimized implementation.
    # In particular, it supports real coefficients as opposed to complex coefficients.
    # Therefore, we separate between this case and the general case.
    # There is no need to scale the coefficients in the Boolean case.
    # However, in the general case, it is recommended to scale down the Hermite
    # coefficients in order to bring their magnitude close to one. This scaling
    # is reverted later.
    binary_lut = (p_input == 2) and (order == 1)

    if binary_lut:
        # those are coefficients for [1, cos^2(pi x)], not [1, cos(2pi x)] as in the general case.
        coeff = [func(1), func(0) - func(1)]
    else:
        coeff = GetHermiteTrigCoefficients(func, p_input, order, scale_thi)  # divided by 2

    # 4. Set up the cryptoparameters.
    # The scaling factor in CKKS should have the same bit length as the RLWE ciphertext modulus.
    # The number of levels to be reserved before and after the LUT evaluation should be specified.
    # The secret key distribution for CKKS should be SPARSE_ENCAPSULATED (recommended), UNIFORM_TERNARY,
    # or SPARSE_TERNARY (discouraged).
    dcrt_bits = bigq.bit_length() - 1
    first_mod = bigq.bit_length() - 1
    levels_available_after_bootstrap = 0
    levels_available_before_bootstrap = 0
    dnum = 3
    secret_key_dist = SecretKeyDist.SPARSE_ENCAPSULATED
    scal_tech = ScalingTechnique.FLEXIBLEAUTO
    lvlb = [3, 3]

    parameters = CCParamsCKKSRNS()
    parameters.SetSecretKeyDist(secret_key_dist)
    parameters.SetSecurityLevel(SecurityLevel.HEStd_NotSet)
    parameters.SetScalingModSize(dcrt_bits)
    parameters.SetScalingTechnique(scal_tech)
    parameters.SetFirstModSize(first_mod)
    parameters.SetNumLargeDigits(dnum)
    parameters.SetBatchSize(num_slots_ckks)
    parameters.SetRingDim(ring_dim)

    depth = levels_available_after_bootstrap + FHECKKSRNS.GetFBTDepth(lvlb, coeff, p_input, order, secret_key_dist)
    parameters.SetMultiplicativeDepth(depth)

    cc = GenCryptoContext(parameters)
    cc.Enable(PKESchemeFeature.PKE)
    cc.Enable(PKESchemeFeature.KEYSWITCH)
    cc.Enable(PKESchemeFeature.LEVELEDSHE)
    cc.Enable(PKESchemeFeature.ADVANCEDSHE)
    cc.Enable(PKESchemeFeature.FHE)

    print(f"CKKS scheme is using ring dimension {cc.GetRingDimension()}, a multiplicative depth of {depth} "
          f"and the {scal_tech} rescaling technique\n")

    # 5. Compute various moduli and scaling sizes, used for scheme conversions.
    # Then generate the setup parameters and necessary keys.
    key_pair = cc.KeyGen()

    cc.EvalFBTSetup(coeff, num_slots_ckks, p_input, p_output, bigq, key_pair.publicKey, [0, 0], lvlb,
                    levels_available_after_bootstrap, 0, order)

    cc.EvalBootstrapKeyGen(key_pair.secretKey, num_slots_ckks)
    cc.EvalMultKeyGen(key_pair.secretKey)

    # 6. Perform encryption in the RLWE scheme, using a larger initial ciphertext modulus.
    # Switching the modulus to a smaller ciphertext modulus helps offset the encryption error.
    ep = SchemeletRLWEMP.GetElementParams(key_pair.secretKey, depth - (levels_available_before_bootstrap > 0))

    ctxt_bfv = SchemeletRLWEMP.EncryptCoeff(x, qbfv_init, p_input, key_pair.secretKey, ep)

    SchemeletRLWEMP.ModSwitch(ctxt_bfv, Q, qbfv_init)

    # 7. Convert from the RLWE ciphertext to a CKKS ciphertext (both use the same secret key).
    ctxt = SchemeletRLWEMP.ConvertRLWEToCKKS(cc, ctxt_bfv, key_pair.publicKey, bigq, num_slots_ckks,
                                             depth - (levels_available_before_bootstrap > 0))

    # 8. Apply the LUT over the ciphertext.
    ctxt_after_fbt = cc.EvalFBT(ctxt, coeff, p_input.bit_length() - 1, ep.GetModulus(), scale_thi, 0, order)

    # 9. Convert the result back to RLWE.
    polys = SchemeletRLWEMP.ConvertCKKSToRLWE(ctxt_after_fbt, Q)

    computed = SchemeletRLWEMP.DecryptCoeff(polys, Q, p_output, key_pair.secretKey, ep, num_slots_ckks, num_slots)

    print(f"First 8 elements of the obtained output % POutput: {computed[:8]}")

    exact = [func(elem) - p_output if func(elem) > p_output / 2.0 else func(elem) for elem in x]

    errors = [abs(e - c) % p_output for e, c in zip(exact, computed)]
    print(f"Max absolute error obtained: {max(errors)}\n")


def multi_value_bootstrapping(qbfv_init, p_input, p_output, Q, bigq, scale_thi, order, num_slots, ring_dim,
                              levels_computation):
    # 1. Figure out whether sparse packing or full packing should be used.
    flag_sp = num_slots <= ring_dim // 2  # sparse packing
    num_slots_ckks = num_slots if flag_sp else num_slots // 2

    # 2. Distinct functions to compute over the same input.
    a = p_input
    b = p_output

    def func1(x):
        return (x % a - a // 2) % b

    def func2(x):
        return (x % a) % b

    # 3. Input
    x = [p_input // 2, p_input // 2 + 1, 0, 3, 16, 33, 64, p_input - 1]
    print(f"First 8 elements of the input (repeated) up to size {num_slots}:")
    print(x)
    if len(x) < num_slots:
        x = fill(x, num_slots)

    # 4. Separate the optimized Boolean LUT case from the general case (see arbitrary_lut).
    binary_lut = (p_input == 2) and (order == 1)

    if binary_lut:
        coeff1 = [func1(1), func1(0) - func1(1)]
        coeff2 = [func2(1), func2(0) - func2(1)]
    else:
        coeff1 = GetHermiteTrigCoefficients(func1, p_input, order, scale_thi)
        coeff2 = GetHermiteTrigCoefficients(func2, p_input, order, scale_thi)

    # 5. Set up the cryptoparameters.
    dcrt_bits = bigq.bit_length() - 1
    first_mod = bigq.bit_length() - 1
    levels_available_after_bootstrap = 0
    levels_available_before_bootstrap = 0
    dnum = 3
    secret_key_dist = SecretKeyDist.SPARSE_ENCAPSULATED
    scal_tech = ScalingTechnique.FIXEDMANUAL
    lvlb = [3, 3]

    parameters = CCParamsCKKSRNS()
    parameters.SetSecretKeyDist(secret_key_dist)
    parameters.SetSecurityLevel(SecurityLevel.HEStd_NotSet)
    parameters.SetScalingModSize(dcrt_bits)
    parameters.SetScalingTechnique(scal_tech)
    parameters.SetFirstModSize(first_mod)
    parameters.SetNumLargeDigits(dnum)
    parameters.SetBatchSize(num_slots_ckks)
    parameters.SetRingDim(ring_dim)

    depth = levels_available_after_bootstrap + levels_computation + \
        FHECKKSRNS.GetFBTDepth(lvlb, coeff1, p_input, order, secret_key_dist)
    parameters.SetMultiplicativeDepth(depth)

    cc = GenCryptoContext(parameters)
    cc.Enable(PKESchemeFeature.PKE)
    cc.Enable(PKESchemeFeature.KEYSWITCH)
    cc.Enable(PKESchemeFeature.LEVELEDSHE)
    cc.Enable(PKESchemeFeature.ADVANCEDSHE)
    cc.Enable(PKESchemeFeature.FHE)

    print(f"CKKS scheme is using ring dimension {cc.GetRingDimension()}, a multiplicative depth of {depth} "
          f"and the {scal_tech} rescaling technique\n")

    # 6. Generate the setup parameters and necessary keys.
    key_pair = cc.KeyGen()

    cc.EvalFBTSetup(coeff1, num_slots_ckks, p_input, p_output, bigq, key_pair.publicKey, [0, 0], lvlb,
                    levels_available_after_bootstrap, levels_computation, order)

    cc.EvalBootstrapKeyGen(key_pair.secretKey, num_slots_ckks)
    cc.EvalMultKeyGen(key_pair.secretKey)
    cc.EvalAtIndexKeyGen(key_pair.secretKey, [-2])

    mask_real = fill([1, 1, 1, 1, 0, 0, 0, 0], num_slots)

    # The mask level is counted on the full modulus chain, which has an extra modulus for FLEXIBLEAUTOEXT
    ext_off = 1 if scal_tech == ScalingTechnique.FLEXIBLEAUTOEXT else 0

    # Note that the corresponding plaintext mask for full packing can be just real, as real times complex
    # multiplies both real and imaginary parts
    ptxt_mask = cc.MakeCKKSPackedPlaintext(
        fill([1, 1, 1, 1, 0, 0, 0, 0], num_slots_ckks), 1,
        depth + ext_off - lvlb[1] - levels_available_after_bootstrap - levels_computation, None, num_slots_ckks)

    # 7. When leveled computations (multiplications, rotations) are desired to be performed while in
    # slot-packed CKKS (before returning to RLWE coefficient packing), and the FFT method is used
    # for the homomorphic encoding and decoding during functional bootstrapping, the inputs in RLWE
    # should be encoded in a bit reversed order. This bit reverse order will be cancelled during
    # the homomorphic encoding, therefore the slots in CKKS will be in natural order.
    # Both the RLWE encryption and RLWE decryption should specify this flag.
    flag_br = lvlb[0] != 1 or lvlb[1] != 1

    # 8. Perform encryption in the RLWE scheme, using a larger initial ciphertext modulus.
    ep = SchemeletRLWEMP.GetElementParams(key_pair.secretKey, depth - (levels_available_before_bootstrap > 0))

    ctxt_bfv = SchemeletRLWEMP.EncryptCoeff(x, qbfv_init, p_input, key_pair.secretKey, ep, flag_br)

    SchemeletRLWEMP.ModSwitch(ctxt_bfv, Q, qbfv_init)

    # 9. Convert from the RLWE ciphertext to a CKKS ciphertext (both use the same secret key).
    ctxt = SchemeletRLWEMP.ConvertRLWEToCKKS(cc, ctxt_bfv, key_pair.publicKey, bigq, num_slots_ckks,
                                             depth - (levels_available_before_bootstrap > 0))

    # 10. Apply the LUTs over the ciphertext.
    # First, compute the complex exponential and its powers to reuse.
    # Second, apply multiple LUTs over these powers. All LUTs which reuse the precomputations must be
    # interpolated with the same shape (same PInput and order) as the coefficients used for the precomputation.
    exact = [func1(elem) - p_output if func1(elem) > p_output / 2.0 else func1(elem) for elem in x]
    exact2 = [func2(elem) - p_output if func2(elem) > p_output / 2.0 else func2(elem) for elem in x]

    complex_exp_powers = cc.EvalMVBPrecompute(ctxt, coeff1, p_input.bit_length() - 1, ep.GetModulus(), order)

    ctxt_after_fbt1 = cc.EvalMVB(complex_exp_powers, coeff1, p_input.bit_length() - 1, scale_thi,
                                 levels_computation, order)

    ctxt_after_fbt2 = cc.EvalMVBNoDecoding(complex_exp_powers, coeff2, p_input.bit_length() - 1, order)

    # Apply a rotation
    ctxt_after_fbt2 = cc.EvalRotate(ctxt_after_fbt2, -2)
    exact2 = rotate(exact2, -2) if flag_sp else rotate_two_halves(exact2, -2)

    # Apply a multiplicative mask
    ctxt_after_fbt2 = cc.EvalMult(ctxt_after_fbt2, ptxt_mask)
    cc.ModReduceInPlace(ctxt_after_fbt2)

    exact2 = [e * m for e, m in zip(exact2, mask_real)]

    # Back to coefficient encoding
    ctxt_after_fbt2 = cc.EvalHomDecoding(ctxt_after_fbt2, scale_thi, levels_computation - 1)

    # 11. Convert the results back to RLWE.
    polys = SchemeletRLWEMP.ConvertCKKSToRLWE(ctxt_after_fbt1, Q)

    computed = SchemeletRLWEMP.DecryptCoeff(polys, Q, p_output, key_pair.secretKey, ep, num_slots_ckks, num_slots,
                                            flag_br)

    print(f"First 8 elements of the obtained output = (input % PInput - POutput / 2) % POutput: {computed[:8]}")

    errors = [abs(e - c) % p_output for e, c in zip(exact, computed)]
    print(f"Max absolute error obtained in the first LUT: {max(errors)}\n")

    polys = SchemeletRLWEMP.ConvertCKKSToRLWE(ctxt_after_fbt2, Q)

    computed = SchemeletRLWEMP.DecryptCoeff(polys, Q, p_output, key_pair.secretKey, ep, num_slots_ckks, num_slots,
                                            flag_br)

    print(f"First 8 elements of the obtained output = (input % PInput) % POutput, rotated by -2 and masked: "
          f"{computed[:8]}")

    errors = [abs(int(e) - c) % p_output for e, c in zip(exact2, computed)]
    print(f"Max absolute error obtained in the second LUT: {max(errors)}\n")


def multi_precision_sign(qbfv_init, p_input, p_digit, Q, bigq, scale_thi, scale_step_thi, order, num_slots, ring_dim):
    # 1. Figure out whether sparse packing or full packing should be used.
    flag_sp = num_slots <= ring_dim // 2  # sparse packing
    num_slots_ckks = num_slots if flag_sp else num_slots // 2

    # 2. Functions necessary for the sign evaluation.
    a = p_input
    b = p_digit

    def func_mod(x):
        return x % b

    def func_step(x):
        return int((x % a) >= (b // 2))

    # 3. Input.
    x = [p_input // 2, p_input // 2 + 1, 0, 3, 16, 33, 64, p_input - 1]
    print(f"First 8 elements of the input (repeated) up to size {num_slots}:")
    print(x)
    if len(x) < num_slots:
        x = fill(x, num_slots)

    exact = [int(elem >= p_input / 2.0) for elem in x]

    # 4. Separate the optimized Boolean LUT case from the general case (see arbitrary_lut).
    binary_lut = (p_digit == 2) and (order == 1)

    coeffcomp_mod = []
    coeffcomp_step = []
    if binary_lut:
        coeffint_mod = [func_mod(1), func_mod(0) - func_mod(1)]
    else:
        coeffcomp_mod = GetHermiteTrigCoefficients(func_mod, p_digit, order, scale_thi)    # divided by 2
        coeffcomp_step = GetHermiteTrigCoefficients(func_step, p_digit, order, scale_step_thi)  # divided by 2

    # 5. Set up the cryptoparameters.
    # The scaling factor in CKKS should have the same bit length as the RLWE ciphertext modulus
    # corresponding to the digit.
    dcrt_bits = bigq.bit_length() - 1
    first_mod = bigq.bit_length() - 1
    levels_available_after_bootstrap = 0
    levels_available_before_bootstrap = 0
    dnum = 3
    secret_key_dist = SecretKeyDist.SPARSE_ENCAPSULATED
    scal_tech = ScalingTechnique.FIXEDMANUAL
    lvlb = [3, 3]

    parameters = CCParamsCKKSRNS()
    parameters.SetSecretKeyDist(secret_key_dist)
    parameters.SetSecurityLevel(SecurityLevel.HEStd_NotSet)
    parameters.SetScalingModSize(dcrt_bits)
    parameters.SetScalingTechnique(scal_tech)
    parameters.SetFirstModSize(first_mod)
    parameters.SetNumLargeDigits(dnum)
    parameters.SetBatchSize(num_slots_ckks)
    parameters.SetRingDim(ring_dim)

    if binary_lut:
        depth = levels_available_after_bootstrap + \
            FHECKKSRNS.GetFBTDepth(lvlb, coeffint_mod, p_digit, order, secret_key_dist)
    else:
        depth = levels_available_after_bootstrap + \
            FHECKKSRNS.GetFBTDepth(lvlb, coeffcomp_mod, p_digit, order, secret_key_dist)
    parameters.SetMultiplicativeDepth(depth)

    cc = GenCryptoContext(parameters)
    cc.Enable(PKESchemeFeature.PKE)
    cc.Enable(PKESchemeFeature.KEYSWITCH)
    cc.Enable(PKESchemeFeature.LEVELEDSHE)
    cc.Enable(PKESchemeFeature.ADVANCEDSHE)
    cc.Enable(PKESchemeFeature.FHE)

    key_pair = cc.KeyGen()

    print(f"CKKS scheme is using ring dimension {cc.GetRingDimension()}, a multiplicative depth of {depth} "
          f"and the {scal_tech} rescaling technique\n")

    # 6. Generate the setup parameters and necessary keys.
    cc.EvalMultKeyGen(key_pair.secretKey)

    if binary_lut:
        cc.EvalFBTSetup(coeffint_mod, num_slots_ckks, p_digit, p_input, bigq, key_pair.publicKey, [0, 0], lvlb,
                        levels_available_after_bootstrap, 0, order)
    else:
        cc.EvalFBTSetup(coeffcomp_mod, num_slots_ckks, p_digit, p_input, bigq, key_pair.publicKey, [0, 0], lvlb,
                        levels_available_after_bootstrap, 0, order)

    cc.EvalBootstrapKeyGen(key_pair.secretKey, num_slots_ckks)

    # 7. Perform encryption in the RLWE scheme, using a larger initial ciphertext modulus.
    ep = SchemeletRLWEMP.GetElementParams(key_pair.secretKey, depth - (levels_available_before_bootstrap > 0))

    ctxt_bfv = SchemeletRLWEMP.EncryptCoeff(x, qbfv_init, p_input, key_pair.secretKey, ep)

    SchemeletRLWEMP.ModSwitch(ctxt_bfv, Q, qbfv_init)
    qbfv_bits = Q.bit_length() - 1

    # 8. Set up the sign loop parameters.
    if binary_lut:
        coeff = coeffint_mod
    else:
        coeff = coeffcomp_mod

    checkeq2 = p_digit == 2
    checkgt2 = p_digit > 2
    p_digit_bits = p_digit.bit_length() - 1

    p_orig = p_input

    step = False
    go = qbfv_bits > dcrt_bits
    levels_to_drop = 0
    post_scaling_bits = 0

    # 9. Start the sign loop. For arbitrary digit size, pNew > 2, the last iteration needs
    # to evaluate step pNew not mod pNew.
    # Currently this only works when log(pNew) divides log(p).
    while go:
        # 9.1. Apply mod Bigq to extract the digit and convert it from RLWE to CKKS.
        encrypted_digit = ctxt_bfv.Clone()
        encrypted_digit.SwitchModulus(bigq)

        ctxt = SchemeletRLWEMP.ConvertRLWEToCKKS(cc, encrypted_digit, key_pair.publicKey, bigq, num_slots_ckks,
                                                 depth - (levels_available_before_bootstrap > 0))

        # 9.2 Bootstrap the digit.
        ctxt_after_fbt = cc.EvalFBT(ctxt, coeff, p_digit_bits, ep.GetModulus(),
                                    scale_thi * (1 << post_scaling_bits), levels_to_drop, order)

        # 9.3 Convert the result back to RLWE and update the
        # plaintext and ciphertext modulus of the ciphertext for the next iteration.
        polys = SchemeletRLWEMP.ConvertCKKSToRLWE(ctxt_after_fbt, Q)

        if not step:
            # 9.4 If not in the last iteration, subtract the digit from the ciphertext.
            ctxt_bfv = ctxt_bfv - polys

            # 9.5 Do modulus switching from Q to QNew for the RLWE ciphertext.
            q_new = Q >> p_digit_bits
            SchemeletRLWEMP.ModSwitch(ctxt_bfv, q_new, Q)
            Q >>= p_digit_bits
            p_input >>= p_digit_bits
            qbfv_bits -= p_digit_bits
            post_scaling_bits += p_digit_bits
        else:
            # 9.6 If in the last iteration, return the digit.
            ctxt_bfv = polys

        # 9.7 If in the last iteration, decrypt and assess correctness.
        go = qbfv_bits > dcrt_bits
        if step or (checkeq2 and not go):
            computed = SchemeletRLWEMP.DecryptCoeff(ctxt_bfv, Q, p_input, key_pair.secretKey, ep, num_slots_ckks,
                                                    num_slots)

            print(f"First 8 elements of the obtained sign: {computed[:8]}")

            errors = [abs(e - c) % p_orig for e, c in zip(exact, computed)]
            print(f"\nMax absolute error obtained: {max(errors)}\n")

        # 9.8 Determine whether it is the last iteration and if not, update the parameters for the next iteration.
        if checkgt2 and not go and not step:
            if not binary_lut:
                coeff = coeffcomp_step
            scale_thi = scale_step_thi
            step = True
            go = True
            if len(coeffcomp_mod) > 4 and GetMultiplicativeDepthByCoeffVector(coeffcomp_mod, True) > \
                    GetMultiplicativeDepthByCoeffVector(coeffcomp_step, True):
                levels_to_drop = GetMultiplicativeDepthByCoeffVector(coeffcomp_mod, True) - \
                    GetMultiplicativeDepthByCoeffVector(coeffcomp_step, True)


def main():
    print("\n*1.* Compute the function (x % PInput - POutput / 2) % POutput.\n")
    # Boolean LUT
    print("=====Boolean LUT order 1 sparsely packed=====\n")
    arbitrary_lut(QBFV_INIT, 2, 2, 1 << 33, 1 << 33, 1, 1, 8, 4096, lambda x: (x % 2 - 2 // 2) % 2)
    print("=====Boolean LUT order 2 sparsely packed=====\n")
    arbitrary_lut(QBFV_INIT, 2, 2, 1 << 33, 1 << 33, 1, 2, 8, 4096, lambda x: (x % 2 - 2 // 2) % 2)
    print("=====Boolean LUT order 1 fully packed=====\n")
    arbitrary_lut(QBFV_INIT, 2, 2, 1 << 33, 1 << 33, 1, 1, 1024, 4096, lambda x: (x % 2 - 2 // 2) % 2)
    # LUT with 8-bit input and 4-bit output
    print("=====8-to-4 bit LUT order 1 sparsely packed=====\n")
    arbitrary_lut(QBFV_INIT, 256, 16, 1 << 47, 1 << 47, 32, 1, 8, 4096, lambda x: (x % 256 - 16 // 2) % 16)

    print("\n\n*2.* Compute multiple functions over the same ciphertext.\n")
    # Two LUTs with 8-bit input and 8-bit output and intermediate leveled computations
    print("=====Multivalue bootstrapping for two 8-to-8 bit LUTs order 1 fully packed=====\n")
    multi_value_bootstrapping(QBFV_INIT, 256, 256, 1 << 47, 1 << 47, 32, 1, 256, 2048, 1)

    print("\n\n*3.* Homomorphically evaluate the sign.\n")
    # Compute the sign of a 12-bit input using 1-bit and 4-bit digits
    # The following needs to hold true: log2(PInput) - log2(PDigit) = log2(Q) - log2(Bigq)
    print("=====Sign evaluation of a 12-bit input using 1-bit digits order 1 sparsely packed=====\n")
    multi_precision_sign(QBFV_INIT, 4096, 2, 1 << 46, 1 << 35, 1, 1, 1, 32, 2048)
    print("=====Sign evaluation of a 12-bit input using 4-bit digits order 1 fully packed=====\n")
    multi_precision_sign(QBFV_INIT, 4096, 16, 1 << 48, 1 << 40, 32, 8, 1, 64, 2048)
    print("=====Sign evaluation of a 32-bit input using 8-bit digits order 1 fully packed=====\n")
    multi_precision_sign(QBFV_INIT_LARGE, 1 << 32, 256, 1 << 71, 1 << 47, 256, 32, 1, 64, 2048)


if __name__ == "__main__":
    main()
