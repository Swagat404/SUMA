cmake_minimum_required(VERSION 3.10)
project(SUMA_API VERSION 1.0 LANGUAGES C)

set(CMAKE_BUILD_TYPE Release)


include_directories(
    /home/ayush/c/kubernetes
    /home/ayush/c/kubernetes
    /usr/include
    ${CMAKE_SOURCE_DIR}/external/sqlite3
)


link_directories(/home/ayush/c/kubernetes/build)

set(SOURCE_FILES
    src/main.c
    external/sqlite3/sqlite3.c
)


add_executable(suma-api ${SOURCE_FILES})


target_link_libraries(suma-api
    /home/ayush/c/kubernetes/build/libkubernetes.so
    /usr/lib/x86_64-linux-gnu/libmicrohttpd.so
    /usr/lib
)

set_target_properties(suma-api PROPERTIES
    INSTALL_RPATH /home/ayush/c/kubernetes/build/ 
    BUILD_RPATH /home/ayush/c/kubernetes/build/
)

set_target_properties(suma-api PROPERTIES COMPILE_FLAGS "-g")

