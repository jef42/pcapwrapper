cmake_minimum_required(VERSION 3.2.2)
option(GTEST_FOUND "Make build for gtest" OFF)

project(pcapwrapper CXX)
set(CMAKE_BUILD_TYPE Release)

if (GTEST_FOUND)
    set(CMAKE_CXX_FLAGS "-g -O0 --coverage")
endif()

file(GLOB_RECURSE SOURCES "src/*.cpp")
add_library(pcapwrapper SHARED ${SOURCES})

install(DIRECTORY "include/" DESTINATION /usr/include/pcapwrapper FILES_MATCHING PATTERN "*.h*")
install(TARGETS pcapwrapper DESTINATION /usr/lib)

