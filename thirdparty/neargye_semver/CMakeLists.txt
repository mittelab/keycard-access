set(SEMVER_VERSION 0.3.1)
set(SEMVER_FOLDER "${COMPONENT_DIR}/semver")

idf_component_register(
     SRCS "${SEMVER_FOLDER}/semver.hpp"
     INCLUDE_DIRS "${COMPONENT_DIR}")

add_custom_command(
     OUTPUT "${SEMVER_FOLDER}/semver.hpp"
     COMMAND curl -L https://github.com/Neargye/semver/releases/download/v${SEMVER_VERSION}/semver.hpp -o ${SEMVER_FOLDER}/semver.hpp
     VERBATIM)

add_custom_target(download_semver
     DEPENDS "${SEMVER_FOLDER}/semver.hpp")

add_dependencies("${COMPONENT_LIB}" download_semver)

set_property(
     DIRECTORY "${COMPONENT_DIR}"
     APPEND PROPERTY ADDITIONAL_MAKE_CLEAN_FILES "${SEMVER_FOLDER}/semver.hpp")
