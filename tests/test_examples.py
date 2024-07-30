import os
import sys
from pathlib import Path
import importlib.util
import pytest
import tempfile
import shutil
import openfhe as fhe

pytestmark = pytest.mark.skipif(fhe.get_native_int() == 32, reason="Doesn't work for NATIVE_INT=32")

EXAMPLES_SCRIPTS_PATH = os.path.join(Path(__file__).parent.parent, "examples", "pke")


def importhelper(path, modulename):
    spec = importlib.util.spec_from_file_location(
        modulename, os.path.join(path, modulename + ".py")
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[modulename] = module
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    "raw_modulename",
    [
        "simple-ckks-bootstrapping.py",
        "simple-integers-serial-bgvrns.py",
        "function-evaluation.py",
        "advanced-real-numbers-128.py",
        "simple-integers-bgvrns.py",
        "simple-integers-serial.py",
        "polynomial-evaluation.py",
        "scheme-switching.py",
        "tckks-interactive-mp-bootstrapping.py",
        "advanced-real-numbers.py",
        "threshold-fhe-5p.py",
        "simple-integers.py",
        "simple-real-numbers-serial.py",
        "iterative-ckks-bootstrapping.py",
        "tckks-interactive-mp-bootstrapping-Chebyschev.py",
        "simple-real-numbers.py",
        "threshold-fhe.py",
        "pre-buffer.py",
    ],
)
def test_run_scripts(raw_modulename):
    with tempfile.TemporaryDirectory() as td:
        os.mkdir(td + "/demoData")
        modulename_py = raw_modulename.replace("-", "_")
        shutil.copyfile(
            os.path.join(EXAMPLES_SCRIPTS_PATH, raw_modulename),
            os.path.join(td, modulename_py),
        )
        sys.path.insert(0, td)
        modulename = modulename_py.split(".")[0]
        print(f"-*- running module {modulename} -*-")
        module = importhelper(td, modulename)
        module.main()
