cmake_minimum_required(VERSION 3.10)
project(bin2vex C)
# The version number.
set (Tutorial_VERSION_MAJOR 1)
set (Tutorial_VERSION_MINOR 0)
set(CMAKE_C_STANDARD 99)
add_compile_options("-g")

#4.27
include_directories(${PROJECT_SOURCE_DIR}/vex/pub)
include_directories(${PROJECT_SOURCE_DIR}/pyvex/pyvex_c)
link_directories(${PROJECT_SOURCE_DIR}/pyvex/pyvex_c)

set(pyvex_lib_PATH ${PROJECT_SOURCE_DIR}/pyvex/pyvex_c/libpyvex.a)
ADD_LIBRARY(pyvex_lib STATIC IMPORTED)
SET_TARGET_PROPERTIES(pyvex_lib PROPERTIES
    IMPORTED_LOCATION ${pyvex_lib_PATH})

set(vex_lib_PATH ${PROJECT_SOURCE_DIR}/vex/libvex.a)
ADD_LIBRARY(vex_lib STATIC IMPORTED)
SET_TARGET_PROPERTIES(vex_lib PROPERTIES
        IMPORTED_LOCATION ${vex_lib_PATH})

add_executable(bin2vex main.c utils.c)

#target_link_libraries (bin2vex ${CMAKE_DL_LIBS})
target_link_libraries (bin2vex pyvex)


# add the install targets
install (TARGETS bin2vex DESTINATION bin)
install (FILES "${PROJECT_BINARY_DIR}/mainconfig.h"
        DESTINATION include)
