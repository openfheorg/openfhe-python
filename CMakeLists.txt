cmake_minimum_required (VERSION 3.5.1)

project (OpenFHE-Python)

set(OPENFHE_PYTHON_VERSION_MAJOR 1)
set(OPENFHE_PYTHON_VERSION_MINOR 3)
set(OPENFHE_PYTHON_VERSION_PATCH 1)
set(OPENFHE_PYTHON_VERSION_TWEAK 0)
set(OPENFHE_PYTHON_VERSION ${OPENFHE_PYTHON_VERSION_MAJOR}.${OPENFHE_PYTHON_VERSION_MINOR}.${OPENFHE_PYTHON_VERSION_PATCH}.${OPENFHE_PYTHON_VERSION_TWEAK})

# OpenFHE version can be specified externally (-DOPENFHE_REQUIRED_VERSION=1.3.1)
if(NOT DEFINED OPENFHE_REQUIRED_VERSION)
    set(OPENFHE_REQUIRED_VERSION "1.3.1" CACHE STRING "Required OpenFHE version")
else()
    # User provided OPENFHE_REQUIRED_VERSION via -D
    message(STATUS "Using user-specified OpenFHE version: ${OPENFHE_REQUIRED_VERSION}")
endif()

set(CMAKE_CXX_STANDARD 17)
option( BUILD_STATIC "Set to ON to include static versions of the library" OFF)

if(APPLE)
    set(CMAKE_CXX_VISIBILITY_PRESET default)
endif()

find_package(OpenFHE ${OPENFHE_REQUIRED_VERSION} REQUIRED)
message(STATUS "Building with OpenFHE version: ${OPENFHE_REQUIRED_VERSION}")

set(PYBIND11_FINDPYTHON ON)
find_package(pybind11 REQUIRED)

# "CMAKE_INTERPROCEDURAL_OPTIMIZATION ON" (ON is the default value) causes link failure. see
# https://github.com/openfheorg/openfhe-python/actions/runs/11492843373/job/31987579944
set(CMAKE_INTERPROCEDURAL_OPTIMIZATION OFF)

set( OpenFHE_Py_SOURCES src/lib)
set( OpenFHE_Py_INCLUDES src/include)

include_directories( ${OPENMP_INCLUDES} )
include_directories( ${OpenFHE_INCLUDE} )
include_directories( ${OpenFHE_INCLUDE}/third-party/include )
include_directories( ${OpenFHE_INCLUDE}/core )
include_directories( ${OpenFHE_INCLUDE}/pke )
include_directories( ${OpenFHE_INCLUDE}/binfhe )
# include_directories( ${OpenFHE_Py_SOURCES} )
include_directories( ${OpenFHE_Py_INCLUDES}/pke )
include_directories( ${OpenFHE_Py_INCLUDES}/binfhe )
include_directories( ${OpenFHE_Py_INCLUDES}/docstrings )
include_directories( ${OpenFHE_Py_INCLUDES} )
### add directories for other OpenFHE modules as needed for your project

link_directories( ${OpenFHE_LIBDIR} )
link_directories( ${OPENMP_LIBRARIES} )
if(BUILD_STATIC)
    set( CMAKE_EXE_LINKER_FLAGS "${OpenFHE_EXE_LINKER_FLAGS} -static")
    link_libraries( ${OpenFHE_STATIC_LIBRARIES} )
else()
    set( CMAKE_EXE_LINKER_FLAGS ${OpenFHE_EXE_LINKER_FLAGS} )
    link_libraries( ${OpenFHE_SHARED_LIBRARIES} )
endif()

### ADD YOUR EXECUTABLE(s) HERE
### add_executable( EXECUTABLE-NAME SOURCES )
###
### EXAMPLE:
### add_executable( test demo-simple-example.cpp )

### Pybind Modules
pybind11_add_module(openfhe 
                    src/lib/bindings.cpp 
                    src/lib/binfhe_bindings.cpp
                    src/lib/binfhe/binfhecontext_wrapper.cpp
                    src/lib/pke/serialization.cpp 
                    src/lib/pke/cryptocontext_wrapper.cpp
                    )
### Python installation 
# Allow the user to specify the path to Python executable (if not provided, find it)
option(PYTHON_EXECUTABLE_PATH "Path to Python executable" "")
if(PYTHON_EXECUTABLE_PATH)
    set(Python_EXECUTABLE "${PYTHON_EXECUTABLE_PATH}")
endif()
find_package(Python REQUIRED COMPONENTS Interpreter Development)

# Check Python version
if(${Python_VERSION_MAJOR} EQUAL 3 AND ${Python_VERSION_MINOR} GREATER_EQUAL 10)
    execute_process(
        COMMAND "${Python_EXECUTABLE}" -c "from sys import exec_prefix; print(exec_prefix)"
        OUTPUT_VARIABLE PYTHON_SITE_PACKAGES
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
else()
    execute_process(
        COMMAND "${Python_EXECUTABLE}" -c "from distutils.sysconfig import get_python_lib; print(get_python_lib())"
        OUTPUT_VARIABLE PYTHON_SITE_PACKAGES
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
endif()

message(STATUS "Python site packages directory: ${PYTHON_SITE_PACKAGES}")
if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    set(Python_Install_Location "${PYTHON_SITE_PACKAGES}")
else()
    set(Python_Install_Location "${CMAKE_INSTALL_PREFIX}")
endif()
message("***** INSTALL IS AT ${Python_Install_Location}; to change, run cmake with -DCMAKE_INSTALL_PREFIX=/your/path")
install(TARGETS openfhe LIBRARY DESTINATION ${Python_Install_Location})
install(FILES ${CMAKE_SOURCE_DIR}/__init__.py DESTINATION ${Python_Install_Location})

