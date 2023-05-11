cmake_minimum_required (VERSION 3.5.1)

project(openfhe)
set(CMAKE_CXX_STANDARD 17)
option( BUILD_STATIC "Set to ON to include static versions of the library" OFF)

find_package(OpenFHE)
find_package(pybind11 REQUIRED)

set( CMAKE_CXX_FLAGS ${OpenFHE_CXX_FLAGS} )
set( OpenFHE_Py_SOURCES src)
set( OpenFHE_Py_INCLUDES include)

include_directories( ${OPENMP_INCLUDES} )
include_directories( ${OpenFHE_INCLUDE} )
include_directories( ${OpenFHE_INCLUDE}/third-party/include )
include_directories( ${OpenFHE_INCLUDE}/core )
include_directories( ${OpenFHE_INCLUDE}/pke )
include_directories( ${OpenFHE_INCLUDE}/binfhe )
# include_directories( ${OpenFHE_Py_SOURCES} )
include_directories( ${OpenFHE_Py_INCLUDES}/pke )
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
                    src/bindings.cpp 
                    src/binfhe_bindings.cpp
                    src/pke/decryption.cpp 
                    src/pke/serialization.cpp 
                    src/pke/cryptocontext_wrapper.cpp
                    )
### Python installation 
find_package(Python REQUIRED COMPONENTS Interpreter Development)

execute_process(
    COMMAND "${Python_EXECUTABLE}" -c "from distutils.sysconfig import get_python_lib; print(get_python_lib())"
    OUTPUT_VARIABLE PYTHON_SITE_PACKAGES
    OUTPUT_STRIP_TRAILING_WHITESPACE
)

message(STATUS "Python site packages directory: ${PYTHON_SITE_PACKAGES}")
install(TARGETS openfhe LIBRARY DESTINATION ${PYTHON_SITE_PACKAGES})