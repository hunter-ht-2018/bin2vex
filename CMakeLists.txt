cmake_minimum_required(VERSION 3.10)
project(bin2vex C)
# The version number.
set (Tutorial_VERSION_MAJOR 1)
set (Tutorial_VERSION_MINOR 0)
#include_directories ("${PROJECT_SOURCE_DIR}/pyvex_c")
#add_subdirectory (pyvex_c)
set(CMAKE_C_STANDARD 99)


#4.27
include_directories(${PROJECT_SOURCE_DIR}/pyvex/pyvex_c)
link_directories(${PROJECT_SOURCE_DIR}/pyvex/pyvex_c)
link_libraries(${PROJECT_SOURCE_DIR}/pyvex/pyvex_c/libpyvex.so)


add_executable(bin2vex main.c)

target_link_libraries (bin2vex ${CMAKE_DL_LIBS})
target_link_libraries (bin2vex ${PROJECT_SOURCE_DIR}/pyvex/pyvex_c/libpyvex.so)


#target_link_libraries (untitled pyvex_c)
# add the install targets
install (TARGETS bin2vex DESTINATION bin)
install (FILES "${PROJECT_BINARY_DIR}/mainconfig.h"
        DESTINATION include)
