cmake_minimum_required(VERSION 3.5)
project(Log)

set(LOGDESIGN "Log_Design_Test")
set(LOGBASE "logbase")
message(STATUS "src this is source dir " ${CMAKE_SOURCE_DIR})


SET(CMAKE_BUILD_TYPE "Debug")
SET(CMAKE_CXX_FLAGS_DEBUG "$ENV{CXXFLAGS} -O0 -Wall -g -ggdb -Wunused ")
SET( CMAKE_EXPORT_COMPILE_COMMANDS ON )
SET(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
SET(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# 设置可执行文件名和源文件列表
set(SOURCES src/base_log.cpp)

file(GLOB_RECURSE Test "main.cpp")

# 添加头文件目录
include_directories(include)

# 生成可执行文件
add_library(${LOGBASE} SHARED ${SOURCES})
add_executable(${LOGDESIGN} ${Test})
target_link_libraries(${LOGDESIGN} PRIVATE ${LOGBASE} )
