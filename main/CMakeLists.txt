file(GLOB_RECURSE SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp")

idf_component_register(
        SRCS ${SOURCES}
        REQUIRES mittelib libspookyaction libka)

# TODO get this into a Kconfig
add_compile_definitions(PN532_SERIAL_TX=18 PN532_SERIAL_RX=17)
