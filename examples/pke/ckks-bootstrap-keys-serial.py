#
# Example for serializing and deserializing CKKS bootstrap evaluation keys.
#

from openfhe import *
import os
import tempfile

datafolder = "demoData"
cc_location = "/bootstrap-cryptocontext.txt"
public_key_location = "/bootstrap-public-key.txt"
secret_key_location = "/bootstrap-secret-key.txt"
ciphertext_location = "/bootstrap-ciphertext.txt"
mult_key_location = "/bootstrap-eval-mult-keys.txt"
bootstrap_key_location = "/bootstrap-eval-keys.txt"


def error_check(condition, message):
    if not condition:
        raise Exception(message)


def main_action():
    parameters = CCParamsCKKSRNS()
    # SPARSE_ENCAPSULATED is recommended for CKKS bootstrapping (probability of failure below 2^-128). UNIFORM_TERNARY,
    # used here, is the distribution of the homomorphic encryption security guidelines; its probability of failure is
    # 2^-67 for N = 2^16 and 2^-27 for N = 2^17 with full packing.
    secret_key_dist = SecretKeyDist.UNIFORM_TERNARY
    parameters.SetSecretKeyDist(secret_key_dist)
    parameters.SetSecurityLevel(SecurityLevel.HEStd_NotSet)
    parameters.SetRingDim(1 << 12)

    if get_native_int() == 128:
        rescale_tech = ScalingTechnique.FIXEDAUTO
        dcrt_bits = 78
        first_mod = 89
    else:
        rescale_tech = ScalingTechnique.FLEXIBLEAUTO
        dcrt_bits = 59
        first_mod = 60

    parameters.SetScalingModSize(dcrt_bits)
    parameters.SetScalingTechnique(rescale_tech)
    parameters.SetFirstModSize(first_mod)

    level_budget = [4, 4]
    levels_available_after_bootstrap = 10
    depth = levels_available_after_bootstrap + CryptoContext.GetBootstrapDepth(level_budget, secret_key_dist)
    parameters.SetMultiplicativeDepth(depth)

    server_cc = GenCryptoContext(parameters)
    server_cc.Enable(PKESchemeFeature.PKE)
    server_cc.Enable(PKESchemeFeature.KEYSWITCH)
    server_cc.Enable(PKESchemeFeature.LEVELEDSHE)
    server_cc.Enable(PKESchemeFeature.ADVANCEDSHE)
    server_cc.Enable(PKESchemeFeature.FHE)

    num_slots = server_cc.GetRingDimension() // 2
    server_cc.EvalBootstrapSetup(level_budget, [0, 0], num_slots)

    key_pair = server_cc.KeyGen()
    server_cc.EvalMultKeyGen(key_pair.secretKey)
    server_cc.EvalBootstrapKeyGen(key_pair.secretKey, num_slots)

    x = [0.25, 0.5, 0.75, 1.0]
    plaintext = server_cc.MakeCKKSPackedPlaintext(x, 1, depth - 1)
    plaintext.SetLength(len(x))
    ciphertext = server_cc.Encrypt(key_pair.publicKey, plaintext)

    error_check(SerializeToFile(datafolder + cc_location, server_cc, BINARY),
                "Error serializing crypto context")
    error_check(SerializeToFile(datafolder + public_key_location, key_pair.publicKey, BINARY),
                "Error serializing public key")
    error_check(SerializeToFile(datafolder + secret_key_location, key_pair.secretKey, BINARY),
                "Error serializing secret key")
    error_check(SerializeToFile(datafolder + ciphertext_location, ciphertext, BINARY),
                "Error serializing ciphertext")

    error_check(server_cc.SerializeEvalMultKey(datafolder + mult_key_location, BINARY, ""),
                "Error serializing eval-mult keys")

    error_check(SerializeEvalBootstrapKey(datafolder + bootstrap_key_location, BINARY, server_cc,
                                          key_pair.secretKey.GetKeyTag(), num_slots),
                "Error serializing bootstrap eval keys")

    ClearEvalMultKeys()
    server_cc.ClearEvalAutomorphismKeys()
    ReleaseAllContexts()

    client_cc, res = DeserializeCryptoContext(datafolder + cc_location, BINARY)
    error_check(res, "Error deserializing crypto context")
    public_key, res = DeserializePublicKey(datafolder + public_key_location, BINARY)
    error_check(res, "Error deserializing public key")
    secret_key, res = DeserializePrivateKey(datafolder + secret_key_location, BINARY)
    error_check(res, "Error deserializing secret key")
    client_ciphertext, res = DeserializeCiphertext(datafolder + ciphertext_location, BINARY)
    error_check(res, "Error deserializing ciphertext")

    client_cc.EvalBootstrapSetup(level_budget, [0, 0], num_slots)

    error_check(client_cc.DeserializeEvalMultKey(datafolder + mult_key_location, BINARY),
                "Error deserializing eval-mult keys")

    error_check(DeserializeEvalBootstrapKey(datafolder + bootstrap_key_location, BINARY, client_cc,
                                            secret_key.GetKeyTag(), num_slots),
                "Error deserializing bootstrap eval keys")

    # The bootstrap keys can also be deserialized by an explicit list of automorphism indices.
    # Here we take the indices of the keys just loaded and load the same file again through the
    # by-index overload.
    bootstrap_key_indices = client_cc.GetExistingEvalAutomorphismKeyIndices(secret_key.GetKeyTag())
    error_check(DeserializeEvalBootstrapKey(datafolder + bootstrap_key_location, BINARY,
                                            secret_key.GetKeyTag(), bootstrap_key_indices),
                "Error deserializing bootstrap eval keys by index list")

    ciphertext_after = client_cc.EvalBootstrap(client_ciphertext)

    result = client_cc.Decrypt(secret_key, ciphertext_after)
    result.SetLength(len(x))

    print(f"Input: {plaintext}")
    print(f"Output after deserialized-key bootstrapping: {result}")

    client_cc.ClearStaticMapsAndVectors()


def main():
    global datafolder
    with tempfile.TemporaryDirectory() as td:
        datafolder = td + "/" + datafolder
        os.mkdir(datafolder)
        main_action()


if __name__ == "__main__":
    main()
