#
# Example for FE (Fourier extension) functional bootstrapping in CKKS: the ciphertext is
# refreshed and a function is evaluated on it in one pass, by evaluating the function's
# Fourier series over the bootstrapped message.
#

from openfhe import *
import math
import time

# Fourier coefficients for the function math.exp(x) in [-2, 2] of degree 29
COEFF_EXP_2_DOUBLE_29 = [
    complex(3.222093706013e+00, 0.000000000000e+00),
    complex(-3.847497325992e+00, -3.036911315182e+00),
    complex(1.613269565467e+00, 2.561562635536e+00),
    complex(-7.142688329459e-01, -1.718044084361e+00),
    complex(3.343375256712e-01, 1.087677253934e+00),
    complex(-1.590083748525e-01, -6.591856314553e-01),
    complex(7.444125399842e-02, 3.797240558554e-01),
    complex(-3.347789249240e-02, -2.057416664390e-01),
    complex(1.415639337190e-02, 1.036151378646e-01),
    complex(-5.504078824289e-03, -4.782261609566e-02),
    complex(1.912943397918e-03, 1.985252654576e-02),
    complex(-5.690043709362e-04, -7.207032810727e-03),
    complex(1.328669037822e-04, 2.177453328757e-03),
    complex(-1.854630094550e-05, -4.890711403220e-04),
    complex(-1.453596732859e-06, 5.053417952833e-05),
    complex(1.572743922262e-06, 1.548627313317e-05),
    complex(-2.838788709181e-07, -8.312159353832e-06),
    complex(-7.562004956940e-08, 8.274522508133e-07),
    complex(4.633880680387e-08, 6.598799631857e-07),
    complex(-5.869467412101e-10, -2.528773346321e-07),
    complex(-6.055031566421e-09, -3.204665662698e-08),
    complex(1.190783888161e-09, 4.385916878681e-08),
    complex(7.747582545133e-10, -3.358504294115e-09),
    complex(-3.348892690935e-10, -7.088429287982e-09),
    complex(-9.585399054352e-11, 1.863929871559e-09),
    complex(8.204146390023e-11, 1.136804343802e-09),
    complex(9.573941899682e-12, -5.803840255614e-10),
    complex(-2.013818972690e-11, -1.764939479287e-10),
    complex(1.533040187851e-13, 1.657178907988e-10),
    complex(5.134323521894e-12, 2.323787581630e-11)]

# Fourier coefficients for the function 1 / (1 + math.exp(-x)) in [-8, 8] of degree 34
COEFF_SIGMOID_8_DOUBLE_34 = [
    complex(2.500000000000e-01, 0.000000000000e+00),
    complex(1.276756478319e-15, -2.986114677117e-01),
    complex(-2.711798613355e-15, -1.305833657358e-03),
    complex(2.012279232133e-15, -6.069910606535e-02),
    complex(-3.874233833051e-17, -3.496972005070e-03),
    complex(-5.065392549852e-16, -1.436915534313e-02),
    complex(-4.025501720156e-16, -3.090757902275e-03),
    complex(6.661338147751e-16, -3.011048528323e-03),
    complex(9.549219054383e-17, -1.395169741000e-03),
    complex(-4.406197628981e-16, -7.358936474771e-04),
    complex(-2.137022113088e-16, -4.185575122752e-04),
    complex(4.614364446098e-16, -2.239585471946e-04),
    complex(4.897883314203e-19, -1.182545527493e-04),
    complex(-4.024558464266e-16, -6.447113701542e-05),
    complex(-1.695114860110e-16, -3.521198006050e-05),
    complex(3.903127820948e-16, -1.881494613389e-05),
    complex(1.909467050622e-16, -1.006822281208e-05),
    complex(-9.540979117872e-17, -5.490602888772e-06),
    complex(-6.585471100731e-17, -2.983401096265e-06),
    complex(1.040834085586e-16, -1.590510122180e-06),
    complex(1.641151407480e-16, -8.526983863427e-07),
    complex(-6.938893903907e-17, -4.673955051855e-07),
    complex(-1.931861246494e-16, -2.539297722240e-07),
    complex(3.035766082959e-16, -1.341034123884e-07),
    complex(7.532874064103e-17, -7.180768169489e-08),
    complex(-1.049507702966e-16, -4.002071006315e-08),
    complex(-8.495889538759e-17, -2.179193493192e-08),
    complex(1.587271980519e-16, -1.117364778916e-08),
    complex(5.298577332100e-17, -5.959189144748e-09),
    complex(-3.009745230820e-16, -3.501207830137e-09),
    complex(-9.186228167035e-17, -1.915294608676e-09),
    complex(2.055647319033e-16, -8.879601871852e-10),
    complex(4.123369939761e-16, -4.698662414010e-10),
    complex(-3.139849491518e-16, -3.309931637583e-10),
    complex(5.506066522859e-17, -1.816820400721e-10)]

# Fourier coefficients for the GELU approximation in [-8, 8] of degree 44
COEFF_GELU_8_DOUBLE_44 = [
    complex(1.970461314322e+00, 0.000000000000e+00),
    complex(-1.593875111273e+00, -2.423646025475e+00),
    complex(-5.332570094236e-02, 1.043627310063e+00),
    complex(-1.570391974449e-01, -5.402873054677e-01),
    complex(-3.940694771457e-02, 2.819289867863e-01),
    complex(-4.716127625363e-02, -1.391268773786e-01),
    complex(-2.418730432251e-02, 6.233923043025e-02),
    complex(-1.941167643365e-02, -2.432937320475e-02),
    complex(-1.260556521786e-02, 7.763676253796e-03),
    complex(-8.664960605021e-03, -1.754420766855e-03),
    complex(-5.704614002479e-03, 1.292565051534e-04),
    complex(-3.651093482904e-03, 8.792842531399e-05),
    complex(-2.270560959509e-03, -3.329062052015e-05),
    complex(-1.367226398367e-03, -2.302378982580e-06),
    complex(-7.979823621962e-04, 4.854603433774e-06),
    complex(-4.528446723700e-04, -5.500080713671e-07),
    complex(-2.508556888546e-04, -7.491453056646e-07),
    complex(-1.363438350097e-04, 2.239517241233e-07),
    complex(-7.312414261638e-05, 1.280298946860e-07),
    complex(-3.885704183314e-05, -6.935818435338e-08),
    complex(-2.045210744808e-05, -2.372215028579e-08),
    complex(-1.059289000752e-05, 2.148573735963e-08),
    complex(-5.323541994507e-06, 4.532466957308e-09),
    complex(-2.534606159357e-06, -7.005649868379e-09),
    complex(-1.095525020071e-06, -8.007947707722e-10),
    complex(-3.890401084408e-07, 2.430954434496e-09),
    complex(-7.123273537061e-08, 8.161443049159e-11),
    complex(5.044242802621e-08, -8.975149646921e-10),
    complex(8.120772961289e-08, 3.455961905541e-11),
    complex(7.542928368715e-08, 3.512492108152e-10),
    complex(5.884712616061e-08, -3.699939660207e-11),
    complex(4.212943410103e-08, -1.450199807245e-10),
    complex(2.870135674255e-08, 2.446543662105e-11),
    complex(1.893829504329e-08, 6.286847323116e-11),
    complex(1.220565836477e-08, -1.443831859627e-11),
    complex(7.712072154498e-09, -2.849185102259e-11),
    complex(4.784403550098e-09, 8.229923686986e-12),
    complex(2.915358732203e-09, 1.344066297062e-11),
    complex(1.744138401955e-09, -5.307266236734e-12),
    complex(1.034329697769e-09, -6.648169766598e-12),
    complex(6.098917724102e-10, 3.421664931631e-12),
    complex(3.589237189208e-10, 2.944192267787e-12),
    complex(2.213863333275e-10, -2.779015756058e-12),
    complex(1.478126284614e-10, -1.420742295235e-12),
    complex(1.014093012815e-10, 4.286355138519e-13)]


def build_normalized_input(slots):
    left = -0.5
    right = 0.5
    return [left + i * (right - left) / slots for i in range(slots)]


def compute_mean_precision_bits(expected, actual):
    count = min(len(expected), len(actual))
    if count == 0:
        return float("nan")
    min_expected = min(expected[:count])
    max_expected = max(expected[:count])
    sum_error = sum(abs(expected[i] - actual[i]) for i in range(count))
    range_expected = max_expected - min_expected
    if range_expected < 1e-15:
        range_expected = 1.0
    mean_error = sum_error / count
    return float("inf") if mean_error == 0.0 else -math.log2(mean_error / range_expected)


def print_values(values, count):
    print(" ".join(f"{v:.10f}" for v in values[:count]))


def main():
    ring_dim = 1 << 16
    num_slots = 1 << 15
    scaling_technique = ScalingTechnique.FLEXIBLEAUTO
    level_budget = [3, 2]
    bsgs_dim = [0, 0]
    dcrt_bits = 59
    first_mod = 60
    # SPARSE_ENCAPSULATED is recommended (probability of failure below 2^-128). UNIFORM_TERNARY (2^-79 for
    # N = 2^16, 2^-33 for N = 2^17) needs a larger depth; SPARSE_TERNARY (about 2^-23 for N = 2^16) is discouraged.
    skd = SecretKeyDist.SPARSE_ENCAPSULATED
    # GetFEFBTDepth covers the functional bootstrapping itself, for the longest of the three series; the
    # levels added on top of it are what is left to compute with on the refreshed ciphertext.
    levels_after_bootstrapping = 6
    depth = max(FHECKKSRNS.GetFEFBTDepth(level_budget, COEFF_EXP_2_DOUBLE_29, skd),
                FHECKKSRNS.GetFEFBTDepth(level_budget, COEFF_SIGMOID_8_DOUBLE_34, skd),
                FHECKKSRNS.GetFEFBTDepth(level_budget, COEFF_GELU_8_DOUBLE_44, skd)) + levels_after_bootstrapping

    parameters = CCParamsCKKSRNS()
    parameters.SetCKKSDataType(CKKSDataType.COMPLEX)
    parameters.SetSecretKeyDist(skd)
    parameters.SetSecurityLevel(SecurityLevel.HEStd_NotSet)
    parameters.SetRingDim(ring_dim)
    parameters.SetNumLargeDigits(3)
    parameters.SetKeySwitchTechnique(KeySwitchTechnique.HYBRID)
    parameters.SetScalingModSize(dcrt_bits)
    parameters.SetScalingTechnique(scaling_technique)
    parameters.SetFirstModSize(first_mod)
    parameters.SetBatchSize(num_slots)
    parameters.SetMultiplicativeDepth(depth)

    cc = GenCryptoContext(parameters)
    cc.Enable(PKESchemeFeature.PKE)
    cc.Enable(PKESchemeFeature.KEYSWITCH)
    cc.Enable(PKESchemeFeature.LEVELEDSHE)
    cc.Enable(PKESchemeFeature.ADVANCEDSHE)
    cc.Enable(PKESchemeFeature.FHE)
    cc.EvalFEFuncBootstrapSetup(level_budget, bsgs_dim, num_slots)

    key_pair = cc.KeyGen()
    cc.EvalMultKeyGen(key_pair.secretKey)
    cc.EvalBootstrapKeyGen(key_pair.secretKey, num_slots)

    normalized_input = build_normalized_input(num_slots)
    plaintext = cc.MakeCKKSPackedPlaintext(normalized_input, 1, depth - (level_budget[1] + 1), None, num_slots)
    input = cc.Encrypt(key_pair.publicKey, plaintext)
    # total modulus bits (computed from the full modulus of the chain, unlike the C++
    # example which sums the MSBs of the individual prime moduli)
    total_modulus_bits = SchemeletRLWEMP.GetElementParams(key_pair.secretKey, 0).GetModulus().bit_length()
    level_before_boot = plaintext.GetLevel()

    # The refresh itself - SlotsToCoeffs, modulus raise, CoeffsToSlots and the complex exponential - does not
    # depend on the target function, so it is run once here and shared by every function below. The powers
    # are precomputed for the longest series of the family (gelu, degree 44); the shorter ones are evaluated
    # against those same powers.
    t = time.time()
    shared_powers = cc.EvalFEFuncBootstrapPrecompute(input, COEFF_GELU_8_DOUBLE_44)
    precompute_ms = (time.time() - t) * 1000

    print(f"Shared bootstrapping and complex exponential: {round(precompute_ms)} ms "
          f"(paid once for all functions below)")

    def run_one(title, radius, coeffs, target):
        expected = [target(2.0 * radius * value) for value in normalized_input]

        t = time.time()
        output = cc.EvalFEFuncBootstrapWithPrecomp(shared_powers, coeffs)
        elapsed = (time.time() - t) * 1000

        decrypted = cc.Decrypt(key_pair.secretKey, output)
        decrypted.SetLength(len(expected))
        actual = decrypted.GetRealPackedValue()

        print(f"\n===== {title} =====")
        print(f"CKKS total modulus: {total_modulus_bits} bits")
        print(f"Level before bootstrapping: {level_before_boot}\n")
        print(f"Level after bootstrapping: {output.GetLevel()}")
        print(f"Series evaluation time: {round(elapsed)} ms")
        print(f"Slots amortize time: {elapsed / num_slots:.6f} ms\n")
        print("--- Sample Points Inspection (Total 10 points) ---")
        print_values(normalized_input, 10)
        print("----------- Expected Function Values: -----------")
        print_values(expected, 10)
        print("------- Functional Bootstrapping Results: -------")
        print_values(actual, 10)
        print("-------------------------------------------------")
        print(f"Precision: {compute_mean_precision_bits(expected, actual):.4f} bits")

    run_one("exp[-2,2]", 2.0, COEFF_EXP_2_DOUBLE_29, lambda x: math.exp(x))
    run_one("sigmoid[-8,8]", 8.0, COEFF_SIGMOID_8_DOUBLE_34, lambda x: 1.0 / (1.0 + math.exp(-x)))
    run_one("gelu_tanh[-8,8]", 8.0, COEFF_GELU_8_DOUBLE_44,
            lambda x: 0.5 * x * (1.0 + math.tanh(math.sqrt(2.0 / math.pi) * (x + 0.044715 * x**3))))


if __name__ == "__main__":
    main()
