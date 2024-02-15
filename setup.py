import os
import subprocess
import sys
from setuptools import setup, Extension
from setuptools.command.sdist import sdist as _sdist
from setuptools.command.build_ext import build_ext as _build_ext
from wheel.bdist_wheel import bdist_wheel as _bdist_wheel
import glob
import shutil

__version__ = '0.8.4'

class CMakeExtension(Extension):
    def __init__(self, name, sourcedir=''):
        super().__init__(name, sources=[])
        self.sourcedir = os.path.abspath(sourcedir)

class CMakeBuild(_build_ext):

    def run(self):
        for ext in self.extensions:
            self.build_cmake(ext)

    def build_cmake(self, ext):
        if os.path.exists('openfhe/openfhe.so'):
            return
        extdir = os.path.abspath(os.path.dirname(self.get_ext_fullpath(ext.name)))
        print(extdir)
        cmake_args = ['-DCMAKE_LIBRARY_OUTPUT_DIRECTORY=' + extdir,
                      '-DPYTHON_EXECUTABLE=' + sys.executable]

        cfg = 'Debug' if self.debug else 'Release'
        build_args = ['--config', cfg]

        build_temp = os.path.abspath(self.build_temp)
        os.makedirs(build_temp, exist_ok=True)

        num_cores = os.cpu_count() or 1
        build_args += ['--parallel', str(num_cores)]

        subprocess.check_call(['cmake', ext.sourcedir] + cmake_args, cwd=build_temp)
        subprocess.check_call(['cmake', '--build', '.', '--target', ext.name] + build_args, cwd=build_temp)

        so_files = glob.glob(os.path.join(extdir, '*.so'))
        if not so_files:
            raise RuntimeError("Cannot find any built .so file in " + extdir)

        src_file = so_files[0] 
        dst_file = os.path.join('openfhe', 'openfhe.so')
        shutil.move(src_file, dst_file)

# Run build_ext before sdist
class SDist(_sdist):
    def run(self):
        if os.path.exists('openfhe/openfhe.so'):
            os.remove('openfhe/openfhe.so')
        self.run_command('build_ext')
        super().run()

setup(
    name='openfhe',
    version=__version__,
    description='Python wrapper for OpenFHE C++ library.',
    author='OpenFHE Team',
    author_email='contact@openfhe.org',
    url='https://github.com/openfheorg/openfhe-python',
    license='BSD-2-Clause',
    packages=['openfhe'],
    package_data={'openfhe': ['*.so', '*.pyi']},
    ext_modules=[CMakeExtension('openfhe', sourcedir='')],
    cmdclass={
        'build_ext': CMakeBuild,
        'sdist': SDist
    },
    include_package_data=True,
    python_requires=">=3.6",
    install_requires=['pybind11', 'pybind11-global', 'pybind11-stubgen']
)
