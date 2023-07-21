cmake_minimum_required(VERSION 3.16.0)
include($ENV{IDF_PATH}/tools/cmake/project.cmake)

if(EXISTS "${CMAKE_CURRENT_LIST_DIR}/project_name.txt")
    file(STRINGS "${CMAKE_CURRENT_LIST_DIR}/project_name.txt" PROJECT_NAME)
    project(${PROJECT_NAME})
else()
    project(keycard-access)
endif()