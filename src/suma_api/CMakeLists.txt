cmake_minimum_required(VERSION 3.10)
project(SUMA_API VERSION 1.0 LANGUAGES C)

set(CMAKE_BUILD_TYPE Release)



include_directories(
    ${CMAKE_SOURCE_DIR}/external/c/kubernetes
    ${CMAKE_SOURCE_DIR}/external/c/kubernetes
    ${CMAKE_SOURCE_DIR}/external/sqlite3
    ${CMAKE_SOURCE_DIR}/include
    /usr/include/openssl/
)


link_directories(${CMAKE_SOURCE_DIR}/c/kubernetes/build)

set(SOURCE_FILES
    src/ssl_test.c
    #src/main.c
    #src/ssl.c
    #src/sql3.c
    #external/sqlite3/sqlite3.c
)


add_executable(suma-api ${SOURCE_FILES})


target_link_libraries(suma-api
    ${CMAKE_SOURCE_DIR}/external/c/kubernetes/build/libkubernetes.so
    /usr/lib/x86_64-linux-gnu/libmicrohttpd.so
    /usr/lib/x86_64-linux-gnu/libssl.so
    /usr/lib/x86_64-linux-gnu/libcrypto.so

)

set_target_properties(suma-api PROPERTIES
    INSTALL_RPATH ${CMAKE_SOURCE_DIR}/external/c/kubernetes/build/ 
    BUILD_RPATH ${CMAKE_SOURCE_DIR}/external/c/kubernetes/build/
)

set_target_properties(suma-api PROPERTIES COMPILE_FLAGS "-g")

