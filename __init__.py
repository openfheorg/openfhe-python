import os
import ctypes

#######################################################################################################################
# Version #1
#######################################################################################################################
# def load_shared_library(lib_path):

#     # Load a shared library ensuring its symbols are globally available. This is necessary as
#     # the library provides symbols that your extension module (e.g., openfhe.so) depends on.
#     return ctypes.CDLL(lib_path, mode=ctypes.RTLD_GLOBAL)

# # The absolute path of the current package directory
# package_dir = os.path.abspath(os.path.dirname(__file__))

# # The directory where the shared libraries are located
# libs_dir = os.path.join(package_dir, 'lib')

# # List of all shared libraries to be loaded
# shared_libs = ['libOPENFHEcore.so.1',
#                'libOPENFHEbinfhe.so.1',
#                'libOPENFHEpke.so.1',
#                'libgomp.so']

# # Load each shared library
# for lib in shared_libs:
#     lib_path = os.path.join(libs_dir, lib)
#     if not os.path.exists(lib_path):
#         raise FileNotFoundError(f"Required shared library not found: {lib_path}")
#     load_shared_library(lib_path)

# # Import the Python wrapper module (openfhe.so) from this package
# from .openfhe import *

#######################################################################################################################
# Version #2
#######################################################################################################################
# Description:
# 1. check all directories in LD_LIBRARY_PATH for each .so.1.
# 2. fall back cleanly to the bundled wheel contents if the external .so is missing.
# 3. ensure RTLD_GLOBAL is used so Pybind11 bindings don’t hit undefined symbol errors.
def load_shared_library(libname, fallback_dir):
    # Search LD_LIBRARY_PATH
    ld_paths = os.environ.get("LD_LIBRARY_PATH", "").split(":")
    for path in ld_paths:
        # skip 'libgomp.so' if LD_LIBRARY_PATH is set as we should get it from the libgomp.so location
        if libname == 'libgomp.so':
            return
        lib_path = os.path.join(path, libname)
        if os.path.exists(lib_path):
            return ctypes.CDLL(lib_path, mode=ctypes.RTLD_GLOBAL)

    # Fallback to bundled wheel/lib directory
    fallback_path = os.path.join(fallback_dir, libname)
    if os.path.exists(fallback_path):
        return ctypes.CDLL(fallback_path, mode=ctypes.RTLD_GLOBAL)

    raise FileNotFoundError(
        f"Shared library {libname} not found in LD_LIBRARY_PATH or fallback path:\n"
        f"  - LD_LIBRARY_PATH: {ld_paths}\n"
        f"  - Fallback path: {fallback_path}"
    )

# Path to the bundled `lib/` directory inside site-packages
package_dir = os.path.abspath(os.path.dirname(__file__))
internal_lib_dir = os.path.join(package_dir, 'lib')

# Shared libraries required
shared_libs = [
    'libOPENFHEcore.so.1',
    'libOPENFHEpke.so.1',
    'libOPENFHEbinfhe.so.1',
    'libgomp.so', # should be excluded if LD_LIBRARY_PATH is set
]

# Load them from LD_LIBRARY_PATH or internal fallback
for lib in shared_libs:
    load_shared_library(lib, fallback_dir=internal_lib_dir)

# Import the Pybind11 extension after shared libraries are loaded
from .openfhe import *
