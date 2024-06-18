cmake_minimum_required(VERSION 3.16)

list(APPEND EXTRA_COMPONENT_DIRS "${CMAKE_SOURCE_DIR}/thirdparty")

find_package(Git)
if (Git_FOUND)
    execute_process(
            COMMAND ${GIT_EXECUTABLE} describe --tags --match 'v*.*.*' --dirty --always
            RESULT_VARIABLE SUCCESS
            OUTPUT_VARIABLE VERSION)
    if (SUCCESS)
        set(PROJECT_VER ${VERSION})
    else ()
        message("Unable to get the firmware version from git")
    endif ()
else ()
    message("Could not find git, version will not be set")
endif ()

include($ENV{IDF_PATH}/tools/cmake/project.cmake)

if (DEFINED ENV{KA_PROJECT_NAME})
    project("ka-$ENV{KA_PROJECT_NAME}")
else ()
    project("ka")
endif ()
