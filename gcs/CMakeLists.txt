cmake_minimum_required(VERSION 3.14)
project(gcs)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Include FetchContent module
include(FetchContent)

# Declare nlohmann_json
FetchContent_Declare(
  nlohmann_json
  GIT_REPOSITORY https://github.com/nlohmann/json.git
  GIT_TAG        v3.7.3
)
set(JSON_BuildTests OFF CACHE INTERNAL "")
FetchContent_MakeAvailable(nlohmann_json)

# Add your source file here
add_executable(gcs gcs.cpp)

# Link libraries to your target
target_link_libraries(gcs nlohmann_json::nlohmann_json)