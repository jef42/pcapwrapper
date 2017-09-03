cmake_minimum_required(VERSION 3.5)
project(pcapwrapper CXX)
set(CMAKE_BUILD_TYPE Release)

file(GLOB_RECURSE SOURCES "src/PCAPLib/*.cpp")
add_library(pcapwrapper SHARED ${SOURCES})

install(DIRECTORY "src/PCAPLib/" DESTINATION /usr/include/pcapwrapper FILES_MATCHING PATTERN "*.h*")
install(TARGETS pcapwrapper DESTINATION /usr/lib)

