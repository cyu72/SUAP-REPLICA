cmake_minimum_required(VERSION 3.14)
project(rrt_search)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Enable parallel compilation
include(ProcessorCount)
ProcessorCount(N)
if(NOT N EQUAL 0)
  set(CMAKE_BUILD_PARALLEL_LEVEL ${N})
endif()

# Add compile options for release build
add_compile_options(-O3)

# Add the DroneRouting subdirectory
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../DroneRouting ${CMAKE_CURRENT_BINARY_DIR}/DroneRouting)

include(FetchContent)

# Fetch and configure dependencies
set(FETCHCONTENT_QUIET OFF)
set(FETCHCONTENT_UPDATES_DISCONNECTED ON)

FetchContent_Declare(
    asio
    GIT_REPOSITORY https://github.com/chriskohlhoff/asio.git
    GIT_TAG asio-1-28-0
)
FetchContent_MakeAvailable(asio)

# Set Asio variables for Crow
FetchContent_GetProperties(asio)
set(ASIO_INCLUDE_DIR ${asio_SOURCE_DIR}/asio/include CACHE INTERNAL "")
set(ASIO_FOUND TRUE CACHE INTERNAL "")

FetchContent_Declare(
    Crow
    GIT_REPOSITORY https://github.com/CrowCpp/Crow.git
    GIT_TAG v1.2.0
)
set(CROW_BUILD_EXAMPLES OFF CACHE INTERNAL "")
set(CROW_BUILD_TESTS OFF CACHE INTERNAL "")

FetchContent_Declare(
    httplib
    GIT_REPOSITORY https://github.com/yhirose/cpp-httplib.git
    GIT_TAG v0.11.2
)
set(HTTPLIB_COMPILE OFF CACHE INTERNAL "")

FetchContent_MakeAvailable(Crow httplib)

find_package(OpenSSL REQUIRED)

# rrt Executable
add_executable(rrt rrt.cpp)

# Enable unity build for rrt
set_target_properties(rrt PROPERTIES UNITY_BUILD ON)

# Add include directories
target_include_directories(rrt 
    PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${httplib_SOURCE_DIR}
    ${ASIO_INCLUDE_DIR}
)

target_link_libraries(rrt
    PRIVATE
    DroneRouting  # This will transitively provide spdlog
    Crow::Crow
    OpenSSL::SSL
    OpenSSL::Crypto
)

# Use precompiled headers
target_precompile_headers(rrt PRIVATE
    <vector>
    <string>
    <nlohmann/json.hpp>
    <spdlog/spdlog.h>
    <crow.h>
    <httplib.h>
    <openssl/ssl.h>
    <openssl/crypto.h>
)

set_target_properties(rrt PROPERTIES 
    OUTPUT_NAME "rrt"
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)