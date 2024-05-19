set(JSON_VERSION 3.11.3)
set(JSON_FOLDER "${COMPONENT_DIR}/json")

idf_component_register(
     SRCS "${JSON_FOLDER}/json.hpp"
     INCLUDE_DIRS "${COMPONENT_DIR}")

add_compile_definitions(JSON_NO_IO JSON_NOEXCEPTION)

add_custom_command(
     OUTPUT "${JSON_FOLDER}/json.hpp"
     COMMAND curl -L https://github.com/nlohmann/json/releases/download/v${JSON_VERSION}/json.hpp -o ${JSON_FOLDER}/json.hpp
     VERBATIM)

add_custom_target(download_json
     DEPENDS "${JSON_FOLDER}/json.hpp")

add_dependencies("${COMPONENT_LIB}" download_json)

set_property(
     DIRECTORY "${COMPONENT_DIR}"
     APPEND PROPERTY ADDITIONAL_MAKE_CLEAN_FILES "${JSON_FOLDER}/json.hpp")
