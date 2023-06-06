cmake_minimum_required(VERSION 3.5)
project(basic)



SET(CMAKE_BUILD_TYPE "Debug")
SET(CMAKE_CXX_FLAGS_DEBUG "$ENV{CXXFLAGS} -O0 -Wall -g -ggdb")
set( CMAKE_EXPORT_COMPILE_COMMANDS ON )

# 设置可执行文件名和源文件列表
set(SOURCES
    main.cpp
    src/base_log.cpp
)

# 添加头文件目录
include_directories(include)

# 生成可执行文件
add_executable(${PROJECT_NAME} ${SOURCES})
