#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <openfhe/pke/openfhe.h>
#include <vector>
#include <algorithm>
#include <complex> 
#include "cryptocontext_wrapper.h"

using namespace lbcrypto;
namespace py = pybind11;

Plaintext MakeCKKSPackedPlaintextWrapper(std::shared_ptr<CryptoContextImpl<DCRTPoly>> &self, 
            const std::vector<float> &value, 
            size_t depth, uint32_t level, 
            const std::shared_ptr<ParmType> params,
            usint slots)
            {
                if (!value.size())
                    OPENFHE_THROW(config_error, "Cannot encode an empty value vector");

                std::vector<std::complex<double>> complexValue(value.size());
                std::transform(value.begin(), value.end(), complexValue.begin(),
                       [](float da) { return std::complex<double>(da); });
                return self->MakeCKKSPackedPlaintext(complexValue, depth, level, params, slots); }