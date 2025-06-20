import os
import ctypes


def load_shared_library(libname, paths):
    for path in paths:
        lib_path = os.path.join(path, libname)
        if os.path.exists(lib_path):
            return ctypes.CDLL(lib_path, mode=ctypes.RTLD_GLOBAL)

    raise FileNotFoundError(
        f"Shared library {libname} not found in {paths}"
    )

# Search LD_LIBRARY_PATH
ld_paths = os.environ.get("LD_LIBRARY_PATH", "").split(":")

if not any(ld_paths):
    # Path to the bundled `lib/` directory inside site-packages
    package_dir = os.path.abspath(os.path.dirname(__file__))
    internal_lib_dir = [os.path.join(package_dir, 'lib')]

    # Shared libraries required
    shared_libs = [
        'libgomp.so',
        'libOPENFHEcore.so.1',
        'libOPENFHEbinfhe.so.1',
        'libOPENFHEpke.so.1',
    ]

    for libname in shared_libs:
        load_shared_library(libname, internal_lib_dir)

    from .openfhe import *

else:
    # Shared libraries required
    # skip 'libgomp.so' if LD_LIBRARY_PATH is set as we should get it from the libgomp.so location
    shared_libs = [
        'libOPENFHEcore.so.1',
        'libOPENFHEbinfhe.so.1',
        'libOPENFHEpke.so.1',
    ]

    for libname in shared_libs:
        load_shared_library(libname, ld_paths)

    # from .openfhe import *
