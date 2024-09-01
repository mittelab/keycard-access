idf_component_register(
    SRCS "src/kaproto/tcp.cpp" "src/kaproto/secure.cpp"
    INCLUDE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/include"
    REQUIRES
        mittelib
        libsodium
        nlohmann_json
        libka
)
