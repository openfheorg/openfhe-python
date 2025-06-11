import os
import ctypes

def load_shared_library(lib_path):

    # Load a shared library ensuring its symbols are globally available. This is necessary as
    # the library provides symbols that your extension module (e.g., openfhe.so) depends on.
    return ctypes.CDLL(lib_path, mode=ctypes.RTLD_GLOBAL)

# The absolute path of the current package directory
package_dir = os.path.abspath(os.path.dirname(__file__))

# The directory where the shared libraries are located
libs_dir = os.path.join(package_dir, 'lib')

# List of all shared libraries to be loaded
shared_libs = ['libOPENFHEcore.so.1',
               'libOPENFHEbinfhe.so.1',
               'libOPENFHEpke.so.1',
               'libgomp.so']

# Load each shared library
for lib in shared_libs:
    lib_path = os.path.join(libs_dir, lib)
    if not os.path.exists(lib_path):
        raise FileNotFoundError(f"Required shared library not found: {lib_path}")
    load_shared_library(lib_path)

# Import the Python wrapper module (openfhe.so) from this package
from .openfhe import *
