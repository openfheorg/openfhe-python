import os
import subprocess
import sys
from pathlib import Path
import pytest
import tempfile
import shutil
import openfhe as fhe

pytestmark = pytest.mark.skipif(fhe.get_native_int() == 32, reason="Doesn't work for NATIVE_INT=32")

EXAMPLES_SCRIPTS_PATH = os.path.join(Path(__file__).parent.parent, "examples", "pke")


def run_example(scripts_path, raw_modulename, require_main):
    """
    Run one example in its own interpreter so the memory it allocates is
    returned to the OS when the example finishes. The binfhe examples keep
    their cryptocontexts and bootstrapping keys in module-level globals
    (~1-2.5 GB each); running every example inside the pytest process
    accumulates tens of GB and gets pytest OOM-killed on CI.
    """
    with tempfile.TemporaryDirectory() as td:
        os.mkdir(os.path.join(td, "demoData"))
        modulename_py = os.path.basename(raw_modulename).replace("-", "_")
        shutil.copyfile(
            os.path.join(scripts_path, raw_modulename),
            os.path.join(td, modulename_py),
        )
        modulename = modulename_py.split(".")[0]
        print(f"-*- running module {modulename} -*-")
        if require_main:
            # pke examples must define main() and must not run at import time
            code = f"import {modulename}; {modulename}.main()"
        else:
            # most binfhe examples run at import time; the serialization ones define main()
            code = f"import {modulename}; getattr({modulename}, 'main', lambda: None)()"
        env = dict(os.environ)
        env["PYTHONPATH"] = td + os.pathsep + env.get("PYTHONPATH", "")
        subprocess.run([sys.executable, "-c", code], cwd=td, env=env, check=True)


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
        "tckks-interactive-mp-bootstrapping-Chebyshev.py",
        "simple-real-numbers.py",
        "threshold-fhe.py",
        "pre-buffer.py",
        "advanced-ckks-bootstrapping.py",
        "ckks-noise-flooding.py",
        "depth-bfvrns.py",
        "depth-bfvrns-behz.py",
        "depth-bgvrns.py",
        "inner-product.py",
        "interactive-bootstrapping.py",
        "iterative-ckks-bootstrapping-composite-scaling.py",
        "linearwsum-evaluation.py",
        "pre-hra-secure.py",
        "rotation.py",
        "simple-ckks-bootstrapping-composite-scaling.py",
        "simple-complex-numbers.py",
        "simple-real-numbers-composite-scaling.py",
        "ckks-bootstrap-keys-serial.py",
        "ckks-release-memory.py",
        "scheme-switching-serial.py",
        "polynomial-evaluation-high-precision-composite-scaling.py",
        "simple-composite-scaling-manual.py",
    ],
)
def test_run_scripts(raw_modulename):
    run_example(EXAMPLES_SCRIPTS_PATH, raw_modulename, require_main=True)


# The functional bootstrapping examples take too long for the regular CI runs
# (FE-functional-bootstrapping-ckks uses ring dimension 2^16 with 2^15 slots),
# so they are run only when RUN_SLOW_EXAMPLES is set in the environment.
@pytest.mark.skipif(
    not os.environ.get("RUN_SLOW_EXAMPLES"),
    reason="set RUN_SLOW_EXAMPLES=1 to run the slow functional bootstrapping examples",
)
@pytest.mark.parametrize(
    "raw_modulename",
    [
        "functional-bootstrapping-ckks.py",
        "FE-functional-bootstrapping-ckks.py",
    ],
)
def test_run_slow_scripts(raw_modulename):
    run_example(EXAMPLES_SCRIPTS_PATH, raw_modulename, require_main=True)


BINFHE_EXAMPLES_SCRIPTS_PATH = os.path.join(Path(__file__).parent.parent, "examples", "binfhe")


@pytest.mark.parametrize(
    "raw_modulename",
    [
        "boolean.py",
        "boolean-ap.py",
        "boolean-lmkcdey.py",
        "boolean-multi-input.py",
        "boolean-serial-binary.py",
        "boolean-serial-binary-dynamic-large-precision.py",
        "boolean-serial-json.py",
        "boolean-serial-json-dynamic-large-precision.py",
        "boolean-truth-tables.py",
        "eval-decomp.py",
        "eval-flooring.py",
        "eval-function.py",
        "eval-sign.py",
        "pke/boolean-pke.py",
        "pke/boolean-ap-pke.py",
        "pke/boolean-serial-binary-pke.py",
        "pke/boolean-serial-json-pke.py",
        "pke/boolean-truth-tables-pke.py",
        "pke/eval-flooring-pke.py",
        "pke/eval-function-pke.py",
    ],
)
def test_run_binfhe_scripts(raw_modulename):
    run_example(BINFHE_EXAMPLES_SCRIPTS_PATH, raw_modulename, require_main=False)


def _parametrized_example_names(test_function):
    for mark in test_function.pytestmark:
        if mark.name == "parametrize" and mark.args[0] == "raw_modulename":
            return set(mark.args[1])
    raise AssertionError(f"{test_function.__name__} has no raw_modulename parametrization")


def test_example_inventory_is_complete():
    pke_examples = {
        path.relative_to(EXAMPLES_SCRIPTS_PATH).as_posix()
        for path in Path(EXAMPLES_SCRIPTS_PATH).rglob("*.py")
    }
    tested_pke_examples = _parametrized_example_names(test_run_scripts)
    tested_pke_examples |= _parametrized_example_names(test_run_slow_scripts)
    assert tested_pke_examples == pke_examples

    binfhe_examples = {
        path.relative_to(BINFHE_EXAMPLES_SCRIPTS_PATH).as_posix()
        for path in Path(BINFHE_EXAMPLES_SCRIPTS_PATH).rglob("*.py")
    }
    assert _parametrized_example_names(test_run_binfhe_scripts) == binfhe_examples
