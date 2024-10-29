import sys

def print_python_imported_modules():
    # print imported Python modules with their paths
    print("          ===== imported Python modules =====")
    for module_name, module in sorted(sys.modules.items()):
        try:
            module_file = module.__file__
            if module_file:
                print(f"{module_name}: {module_file}")
        except AttributeError:
            pass

def print_loaded_shared_libraries():
    # print loaded shared libraries from /proc/self/maps
    print("          ===== loaded shared C/C++ libraries =====")
    with open("/proc/self/maps", "r") as maps_file:
        lines = maps_file.readlines()
        for line in lines:
            if ".so" in line:
                parts = line.split()
                if len(parts) > 5:
                    print(parts[5])

if __name__ == "__main__":
    # import numpy
    # import pandas

    print("")
    print_python_imported_modules()
    print("")
    print_loaded_shared_libraries()
    print("")
