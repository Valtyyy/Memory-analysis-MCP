cmake_minimum_required(VERSION 3.26)
project(memory_mcp LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(Python 3.12 REQUIRED COMPONENTS Interpreter Development.Module Development.SABIModule)

execute_process(
  COMMAND "${Python_EXECUTABLE}" -m nanobind --cmake_dir
  OUTPUT_STRIP_TRAILING_WHITESPACE OUTPUT_VARIABLE nanobind_ROOT)
find_package(nanobind CONFIG REQUIRED)

nanobind_add_module(_memcore STABLE_ABI NB_STATIC
  cpp/src/types.cpp
  cpp/src/process.cpp
  cpp/src/reader.cpp
  cpp/src/scanner.cpp
  cpp/bindings/py_api.cpp
  cpp/bindings/module.cpp)

target_include_directories(_memcore PRIVATE cpp/include)
target_compile_features(_memcore PRIVATE cxx_std_20)
target_compile_definitions(_memcore PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX UNICODE _UNICODE)
if(MSVC)
  target_compile_options(_memcore PRIVATE /W4 /permissive- /utf-8)
endif()

install(TARGETS _memcore LIBRARY DESTINATION memory_mcp)
