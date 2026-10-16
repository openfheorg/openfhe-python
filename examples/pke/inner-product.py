#
# Simple example for BFV and CKKS for inner product.
#

from openfhe import *


def plain_inner_product(vec):
    return sum(el * el for el in vec)


def inner_product_bfv(incoming_vector):
    expected_result = plain_inner_product(incoming_vector)

    # Crypto CryptoParams
    parameters = CCParamsBFVRNS()
    parameters.SetPlaintextModulus(65537)
    parameters.SetMultiplicativeDepth(20)
    parameters.SetSecurityLevel(SecurityLevel.HEStd_NotSet)
    parameters.SetRingDim(1 << 7)
    batch_size = parameters.GetRingDim() // 2

    # Set crypto params and create context
    cc = GenCryptoContext(parameters)

    # Enable the features that you wish to use.
    cc.Enable(PKESchemeFeature.PKE)
    cc.Enable(PKESchemeFeature.LEVELEDSHE)
    cc.Enable(PKESchemeFeature.ADVANCEDSHE)

    keys = cc.KeyGen()
    cc.EvalMultKeyGen(keys.secretKey)
    cc.EvalSumKeyGen(keys.secretKey)

    plaintext1 = cc.MakePackedPlaintext(incoming_vector)
    ct1 = cc.Encrypt(keys.publicKey, plaintext1)
    final_result = cc.EvalInnerProduct(ct1, ct1, batch_size)
    res = cc.Decrypt(keys.secretKey, final_result)
    final = res.GetPackedValue()[0]

    print(f"Expected Result: {expected_result} Inner Product Result: {final}")
    return expected_result == final


def inner_product_ckks(incoming_vector):
    expected_result = plain_inner_product(incoming_vector)

    security_level = SecurityLevel.HEStd_NotSet
    dcrt_bits = 59
    ring_dim = 1 << 8
    batch_size = ring_dim // 2
    mult_depth = 10

    parameters = CCParamsCKKSRNS()
    parameters.SetMultiplicativeDepth(mult_depth)
    parameters.SetScalingModSize(dcrt_bits)
    parameters.SetBatchSize(batch_size)
    parameters.SetSecurityLevel(security_level)
    parameters.SetRingDim(ring_dim)

    cc = GenCryptoContext(parameters)

    cc.Enable(PKESchemeFeature.PKE)
    cc.Enable(PKESchemeFeature.LEVELEDSHE)
    cc.Enable(PKESchemeFeature.ADVANCEDSHE)

    keys = cc.KeyGen()
    cc.EvalMultKeyGen(keys.secretKey)
    cc.EvalSumKeyGen(keys.secretKey)

    plaintext1 = cc.MakeCKKSPackedPlaintext(incoming_vector)
    ct1 = cc.Encrypt(keys.publicKey, plaintext1)
    final_result = cc.EvalInnerProduct(ct1, ct1, batch_size)
    res = cc.Decrypt(keys.secretKey, final_result)
    res.SetLength(len(incoming_vector))
    final = res.GetCKKSPackedValue()[0].real

    print(f"Expected Result: {expected_result} Inner Product Result: {final}")
    return abs(expected_result - final) <= 0.0001


def main():
    vec = [1, 2, 3, 4, 5]
    bfv_res = inner_product_bfv(vec)
    print(f"BFV Inner Product Correct? {bfv_res}")

    print("********************************************************************")
    as_double = [el + el / 100.0 for el in vec]
    ckks_res = inner_product_ckks(as_double)
    print(f"CKKS Inner Product Correct? {ckks_res}")


if __name__ == "__main__":
    main()
