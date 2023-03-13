#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <openfhe/pke/openfhe.h>
#include "bindings.h"
#include "serialization.h"

using namespace lbcrypto;
namespace py = pybind11;

template <typename T>
bool SerializeToFileImpl(const std::string& filename, const T& obj, const std::string& sertype_str) {
    // call the appropriate serialization function based on the string
    if (sertype_str == "binary") {
        return Serial::SerializeToFile(filename, obj, SerType::BINARY);
    } else if (sertype_str == "json") {
        return Serial::SerializeToFile(filename, obj, SerType::JSON);
    }else {
        OPENFHE_THROW(serialize_error,"Serialization type not supported, use 'json' or 'binary'");
    }
    
    // switch (sertype_str)
    // {
    // case "json":
    //     return Serial::SerializeToFile(filename, obj, SerType::JSON);
    //     break;
    
    // case "binary":
    //     return Serial::SerializeToFile(filename, obj, SerType::BINARY);
    //     break;
    
    // default:
        
    // }
}

bool SerializeToFileInterface(const std::string& filename, const CryptoContext<DCRTPoly>& obj, const std::string& sertype_str) {
    return SerializeToFileImpl(filename, obj, sertype_str);
}

bool SerializeToFileInterface(const std::string& filename, const PublicKey<DCRTPoly>& obj, const std::string& sertype_str) {
    return SerializeToFileImpl(filename, obj, sertype_str);
}

bool SerializeToFileInterface(const std::string& filename, const PrivateKey<DCRTPoly>& obj, const std::string& sertype_str) {
    return SerializeToFileImpl(filename, obj, sertype_str);
}

void bind_serialization(pybind11::module &m) {
    m.def("SerializeToFile", static_cast<bool (*)(const std::string&, const CryptoContext<DCRTPoly>&, const std::string&)>(&SerializeToFileInterface), py::arg("filename"), py::arg("obj"), py::arg("sertype_str")="binary");
    
}


