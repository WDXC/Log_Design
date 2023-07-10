cmake_minimum_required(VERSION 3.5)
project(Log)

message(STATUS "src this is source dir " ${CMAKE_SOURCE_DIR})


SET(CMAKE_BUILD_TYPE "Debug")
SET(CMAKE_CXX_FLAGS_DEBUG "$ENV{CXXFLAGS} -O0 -Wall -g -ggdb -Wunused")
SET( CMAKE_EXPORT_COMPILE_COMMANDS ON )
SET(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

LINK_DIRECTORIES(${CMAKE_SOURCE_DIR}/lib)

# 设置可执行文件名和源文件列表
set(SOURCES
    main.cpp
    src/base_log.cpp
)

# 添加头文件目录
include_directories(include
                    third_party/googletest/include
                    third_party/googlemock/include )

# 生成可执行文件
add_executable(${PROJECT_NAME} ${SOURCES})
add_library(${PROJECT_NAME}_base SHARED ${SOURCES})
add_executable(base_log_unittest test/base_log_test.cpp)
target_link_libraries(base_log_unittest libgmock.a libgtest.a libgtest_main.a
    libgmock_main.a pthread Log_base)
