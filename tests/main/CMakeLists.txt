file(GLOB_RECURSE SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp")

idf_component_register(
        SRCS ${SOURCES}
        PRIV_INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/include
        PRIV_REQUIRES mittelib libspookyaction catchorg_catch2 libka
        WHOLE_ARCHIVE)
