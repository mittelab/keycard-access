file(GLOB_RECURSE SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp")

idf_component_register(
        SRCS ${SOURCES}
        INCLUDE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/include"
        REQUIRES
        mittelib
        libspookyaction
        libmodernjson
        libsemver
        libsodium
        esp_partition
        nvs_flash
        esp_wifi
        esp_http_client
        console
        esp_https_ota
        app_update
)
