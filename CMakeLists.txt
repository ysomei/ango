cmake_minimum_required(VERSION 3.16)
project(ango VERSION 0.3.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium>=1.0.18)

add_executable(ango
  src/main.cpp
  src/crypto.cpp
  src/gpg.cpp
  src/keystore.cpp
  src/process.cpp
  src/prompt.cpp
  src/session.cpp
)

target_compile_definitions(ango PRIVATE ANG_VERSION="${PROJECT_VERSION}")
target_compile_options(ango PRIVATE -Wall -Wextra -Wpedantic)
target_link_libraries(ango PRIVATE PkgConfig::SODIUM)

install(TARGETS ango RUNTIME DESTINATION bin)
