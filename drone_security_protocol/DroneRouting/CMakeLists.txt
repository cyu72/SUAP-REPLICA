cmake_minimum_required(VERSION 3.14)
project(drone_routing)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Enable position independent code for all targets
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Enable parallel compilation
include(ProcessorCount)
ProcessorCount(N)
if(NOT N EQUAL 0)
  set(CMAKE_BUILD_PARALLEL_LEVEL ${N})
endif()

add_compile_options(-O3)

file(GLOB_RECURSE LIB_SOURCES "src/*.cpp")

include_directories(${PROJECT_SOURCE_DIR}/include)
include_directories(${PROJECT_SOURCE_DIR}/include/routing)
include(FetchContent)

# Fetch dependencies
FetchContent_Declare(
  nlohmann_json
  GIT_REPOSITORY https://github.com/nlohmann/json.git
  GIT_TAG        v3.7.3
)
set(JSON_BuildTests OFF CACHE INTERNAL "")
set(JSON_Install OFF CACHE INTERNAL "")

# Configure spdlog with PIC
FetchContent_Declare(
  spdlog
  GIT_REPOSITORY https://github.com/gabime/spdlog.git
  GIT_TAG v1.14.1
)
set(SPDLOG_BUILD_PIC ON CACHE INTERNAL "")

FetchContent_Declare(
  httplib
  GIT_REPOSITORY https://github.com/yhirose/cpp-httplib.git
  GIT_TAG v0.14.1
)
set(HTTPLIB_COMPILE ON CACHE INTERNAL "")

FetchContent_MakeAvailable(nlohmann_json spdlog httplib)

# OpenSSL configuration
set(OPENSSL_ROOT_DIR "" CACHE PATH "OpenSSL root directory")

find_package(OpenSSL REQUIRED)
if(NOT OpenSSL_FOUND)
  message(FATAL_ERROR "OpenSSL not found. Please install OpenSSL or specify OPENSSL_ROOT_DIR.")
endif()

# DroneRouting Library
add_library(DroneRouting SHARED ${LIB_SOURCES})
target_include_directories(DroneRouting 
  PUBLIC 
    ${PROJECT_SOURCE_DIR}/include/routing
    ${nlohmann_json_SOURCE_DIR}/include
    ${spdlog_SOURCE_DIR}/include
    ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(DroneRouting
    PUBLIC
    nlohmann_json::nlohmann_json
    spdlog::spdlog
    httplib::httplib
    ${OPENSSL_LIBRARIES}
)

set_target_properties(DroneRouting PROPERTIES 
  OUTPUT_NAME "drone_routing"
  UNITY_BUILD ON
)

# Use precompiled headers
target_precompile_headers(DroneRouting PUBLIC
  <vector>
  <string>
  <nlohmann/json.hpp>
  <spdlog/spdlog.h>
  PRIVATE
  <openssl/ssl.h>
  <openssl/crypto.h>
)