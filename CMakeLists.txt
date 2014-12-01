project(avca)

cmake_minimum_required(VERSION 2.8.9)

project(avrouter)

if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
set(CMAKE_COMPILER_IS_CLANGXX 1)
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Intel")
if(UNIX)
set(CMAKE_COMPILER_IS_UNIX_ICC 1)
else()
# CMAKE_COMPILER_IS_WIN_ICC 的 c++11 模式命令行参数不一样
set(CMAKE_COMPILER_IS_WIN_ICC 1)
endif()
endif()

if(MSVC)
	set (Boost_USE_MULTITHREADED TRUE)
	set (Boost_USE_STATIC_LIBS TRUE)
endif()

find_package(Threads REQUIRED)
find_package(Boost 1.54 COMPONENTS thread system coroutine context regex date_time filesystem program_options REQUIRED)
find_package(OpenSSL REQUIRED)

link_directories(${Boost_LIBRARY_DIRS})
link_libraries(${Boost_LIBRARIES})
link_libraries(${OPENSSL_LIBRARIES})

include_directories(${Boost_INCLUDE_DIRS})
include_directories(${OPENSSL_INCLUDE_DIR})
include_directories(${CMAKE_THREAD_LIBS_INIT})

add_subdirectory(proto)
add_subdirectory(src)
