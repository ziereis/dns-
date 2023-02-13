cmake_minimum_required(VERSION 3.22)
project(dns_cpp)

set(CMAKE_CXX_STANDARD 23)

find_package(Boost REQUIRED)
find_package(fmt REQUIRED)
find_package(doctest REQUIRED)
find_package(range-v3 REQUIRED)

include(CTest)
enable_testing()

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
add_compile_options(-Wall -Wextra -Wconversion -pedantic -Wfatal-errors -fsanitize=undefined)
add_link_options(-fsanitize=undefined)

add_subdirectory(test EXCLUDE_FROM_ALL)
add_subdirectory(source)
