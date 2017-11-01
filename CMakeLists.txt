cmake_minimum_required(VERSION 2.7.1)

project(btcaddrgen)

set(CMAKE_CXX_FLAGS_RELEASE "-std=c++11")
set(CMAKE_CXX_FLAGS_DEBUG "-g -std=c++11")

find_package(Boost REQUIRED program_options)
find_package(OpenSSL REQUIRED)

find_library(secp256k1 secp256k1)

include_directories(
    "./"
    ${OPENSSL_INCLUDE_DIR}
)

file(GLOB src "./src/*.cc")

add_executable(btcaddrgen ${src})

target_link_libraries(btcaddrgen ${Boost_LIBRARIES} ${OPENSSL_LIBRARIES} ${secp256k1})
