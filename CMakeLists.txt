cmake_minimum_required (VERSION 3.16.3)

project (OpenFHE-Python)

set(OPENFHE_PYTHON_VERSION_MAJOR 1)
set(OPENFHE_PYTHON_VERSION_MINOR 6)
set(OPENFHE_PYTHON_VERSION_PATCH 1)
set(OPENFHE_PYTHON_VERSION_TWEAK 0)
set(OPENFHE_PYTHON_VERSION ${OPENFHE_PYTHON_VERSION_MAJOR}.${OPENFHE_PYTHON_VERSION_MINOR}.${OPENFHE_PYTHON_VERSION_PATCH}.${OPENFHE_PYTHON_VERSION_TWEAK})

# OpenFHE version can be specified externally (-DOPENFHE_REQUIRED_VERSION=1.6.1)
if(NOT DEFINED OPENFHE_REQUIRED_VERSION)
    set(OPENFHE_REQUIRED_VERSION "1.6.1" CACHE STRING "Required OpenFHE version")
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

# Allow the user to specify the path to the Python executable (if not provided, find it).
# Python must be selected before pybind11 is found: pybind11 locks in the first Python
# that CMake discovers, and a later find_package(Python) with a different interpreter fails.
set(PYTHON_EXECUTABLE_PATH "" CACHE FILEPATH "Path to Python executable")
if(PYTHON_EXECUTABLE_PATH)
    set(Python_EXECUTABLE "${PYTHON_EXECUTABLE_PATH}")
endif()
find_package(Python REQUIRED COMPONENTS Interpreter Development)

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
                    src/lib/pke/fbt.cpp
                    src/lib/pke/schemeswitching_data_serializer.cpp
                    )
# The next line ensures that the installed openfhe module can find its shared library dependencies
# in the 'lib/' subdirectory relative to itself without requiring LD_LIBRARY_PATH.
### target_link_options(openfhe PRIVATE "-Wl,-rpath=$ORIGIN/lib" "-Wl,--disable-new-dtags")
if(UNIX AND NOT APPLE)
    target_link_options(openfhe PRIVATE "-Wl,--enable-new-dtags" "-Wl,-rpath,\$ORIGIN/lib")
    # Also set target RPATH properties (survive install/copying)
    set_target_properties(openfhe PROPERTIES
        BUILD_RPATH   "\$ORIGIN/lib"
        INSTALL_RPATH "\$ORIGIN/lib"
    )
elseif(APPLE)
    # Enable RPATH use on macOS
    set(CMAKE_MACOSX_RPATH ON)
    # Set install-time rpath for all targets (unless overridden)
    set(CMAKE_INSTALL_RPATH "@loader_path/lib")

    target_link_options(openfhe PRIVATE "-Wl,-rpath,@loader_path/lib")
    # Also set target RPATH properties (survive install/copying)
    set_target_properties(openfhe PROPERTIES
        BUILD_RPATH   "@loader_path/lib"
        INSTALL_RPATH "@loader_path/lib"
       )
endif()


### Python installation
# sysconfig's platlib is the platform-specific site-packages directory (also inside venvs);
# sys.exec_prefix used here previously is the installation root, not site-packages.
execute_process(
    COMMAND "${Python_EXECUTABLE}" -c "import sysconfig; print(sysconfig.get_path('platlib'))"
    OUTPUT_VARIABLE PYTHON_SITE_PACKAGES
    OUTPUT_STRIP_TRAILING_WHITESPACE
)

message(STATUS "Python site packages directory: ${PYTHON_SITE_PACKAGES}")
if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    set(Python_Install_Location "${PYTHON_SITE_PACKAGES}")
else()
    set(Python_Install_Location "${CMAKE_INSTALL_PREFIX}")
endif()
message("***** INSTALL IS AT ${Python_Install_Location}; to change, run cmake with -DCMAKE_INSTALL_PREFIX=/your/path")
install(TARGETS openfhe LIBRARY DESTINATION ${Python_Install_Location})
install(FILES ${CMAKE_SOURCE_DIR}/src/__init__.py DESTINATION ${Python_Install_Location})

