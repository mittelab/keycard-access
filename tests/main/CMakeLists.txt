file(GLOB_RECURSE SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp")

idf_component_register(
        SRCS ${SOURCES}
        PRIV_REQUIRES mittelib libspookyaction catchorg_catch2 libka spooky_reporter
        WHOLE_ARCHIVE)
