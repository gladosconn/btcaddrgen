cmake_minimum_required(VERSION 2.7.1)

project(btcaddrgen)

add_definitions(-std=c++11)

set(CMAKE_CXX_FLAGS_DEBUG "-g")

find_package(Boost REQUIRED program_options)

file(GLOB src "./src/*.cc")

add_executable(btcaddrgen ${src})

target_link_libraries(btcaddrgen ${Boost_LIBRARIES})
