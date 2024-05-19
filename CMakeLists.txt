cmake_minimum_required(VERSION 3.16)

list(APPEND EXTRA_COMPONENT_DIRS "${CMAKE_SOURCE_DIR}/thirdparty" "${CMAKE_SOURCE_DIR}/libspookyaction/libspookyaction")

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(keycard-access)
