cmake_minimum_required (VERSION 3.5.1)

project (OpenFHE-Python)

set(OPENFHE_PYTHON_VERSION_MAJOR 0)
set(OPENFHE_PYTHON_VERSION_MINOR 8)
set(OPENFHE_PYTHON_VERSION_PATCH 6)
set(OPENFHE_PYTHON_VERSION ${OPENFHE_PYTHON_VERSION_MAJOR}.${OPENFHE_PYTHON_VERSION_MINOR}.${OPENFHE_PYTHON_VERSION_PATCH})

set(CMAKE_CXX_STANDARD 17)
option( BUILD_STATIC "Set to ON to include static versions of the library" OFF)

if(APPLE)
    set(CMAKE_CXX_VISIBILITY_PRESET default)
endif()

find_package(OpenFHE 1.1.3 REQUIRED)
find_package(pybind11 REQUIRED)

set( CMAKE_CXX_FLAGS ${OpenFHE_CXX_FLAGS} )
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

if(NOT PYTHON_EXECUTABLE_PATH)
    # Find Python and its development components
    find_package(Python REQUIRED COMPONENTS Interpreter Development)
else()
    # Set Python_EXECUTABLE to the specified path
    set(Python_EXECUTABLE "${PYTHON_EXECUTABLE_PATH}")
endif()
execute_process(
    COMMAND "${Python_EXECUTABLE}" -c "from distutils.sysconfig import get_python_lib; print(get_python_lib())"
    OUTPUT_VARIABLE PYTHON_SITE_PACKAGES
    OUTPUT_STRIP_TRAILING_WHITESPACE
)

message(STATUS "Python site packages directory: ${PYTHON_SITE_PACKAGES}")
install(TARGETS openfhe LIBRARY DESTINATION ${PYTHON_SITE_PACKAGES})
