cmake_minimum_required(VERSION 3.24)

project(fhe_toolkit
    VERSION     0.6.0
    DESCRIPTION "JuLenny FHE Toolkit - customer-side client for the JuLenny FHE Platform"
    LANGUAGES   CXX
)

set(CMAKE_CXX_STANDARD          20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS        OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(FHE_TOOLKIT_BUILD_CLI          "Build the CLI executable"              ON)
option(FHE_TOOLKIT_BUILD_TESTS        "Build the test suite"                  OFF)
option(FHE_TOOLKIT_USE_OPENFHE        "Enable OpenFHE-backed crypto"          OFF)
option(FHE_TOOLKIT_WARNINGS_AS_ERRORS "Treat compiler warnings as errors"     OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

include(cmake/CompilerWarnings.cmake)
include(cmake/Dependencies.cmake)

add_subdirectory(core)

if(FHE_TOOLKIT_BUILD_CLI)
    add_subdirectory(cli)
endif()

if(FHE_TOOLKIT_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# ----------------------------------------------------------------------------
# Optionally bundle the self-contained MCP server in the package. It is built
# separately (linux/build-mcp-exe.sh -> mcp/sea/julenny-mcp, a Node SEA single
# executable; no Node needed at runtime). If present, it installs to
# /usr/bin/julenny-mcp so the .deb ships CLI + MCP together; if not built, the
# package is CLI-only. Built outside CMake because it's a Node/esbuild/postject
# toolchain, not a compile target.
# ----------------------------------------------------------------------------
option(FHE_TOOLKIT_BUNDLE_MCP "Bundle the SEA julenny-mcp server in the package" ON)
set(JULENNY_MCP_EXE "${CMAKE_CURRENT_SOURCE_DIR}/mcp/sea/julenny-mcp")
if(FHE_TOOLKIT_BUNDLE_MCP AND EXISTS "${JULENNY_MCP_EXE}")
    install(PROGRAMS "${JULENNY_MCP_EXE}" DESTINATION bin COMPONENT runtime)
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/linux/merge-claude-config.sh")
        install(PROGRAMS "${CMAKE_CURRENT_SOURCE_DIR}/linux/merge-claude-config.sh"
            DESTINATION share/julenny-fhe COMPONENT runtime)
    endif()
    message(STATUS "  Bundle MCP server:     ${JULENNY_MCP_EXE}")
    # NOTE: CPACK_STRIP_FILES is ON; verify the installed julenny-mcp still runs
    # after packaging (the SEA blob lives in an injected section). If strip breaks
    # it, switch CPACK_STRIP_FILES to an explicit list that excludes julenny-mcp.
elseif(FHE_TOOLKIT_BUNDLE_MCP)
    message(STATUS "  Bundle MCP server:     SKIPPED (mcp/sea/julenny-mcp not built; run linux/build-mcp-exe.sh)")
endif()

# ============================================================================
# Packaging (CPack) - component-restricted so deps' install rules don't leak
# ============================================================================

set(CPACK_PACKAGE_NAME           "julenny-fhe")
set(CPACK_PACKAGE_VENDOR         "JuLenny Ltd")
set(CPACK_PACKAGE_VERSION_MAJOR  ${PROJECT_VERSION_MAJOR})
set(CPACK_PACKAGE_VERSION_MINOR  ${PROJECT_VERSION_MINOR})
set(CPACK_PACKAGE_VERSION_PATCH  ${PROJECT_VERSION_PATCH})
set(CPACK_PACKAGE_CONTACT        "support@julenny.net")
set(CPACK_PACKAGE_HOMEPAGE_URL   "https://github.com/JuLenny-Ltd/julenny-toolkit")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY
    "Customer-side client for the JuLenny FHE Platform")
set(CPACK_PACKAGE_DESCRIPTION
    "Standalone CLI client for the JuLenny FHE Platform. Provides FHE key \
management, encryption, multi-party setup, and platform integration for \
customer-side privacy-preserving workflows. Built on OpenFHE.")
set(CPACK_RESOURCE_FILE_LICENSE  "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
set(CPACK_RESOURCE_FILE_README   "${CMAKE_CURRENT_SOURCE_DIR}/README.md")
set(CPACK_STRIP_FILES            ON)

# Build one .deb per component, but only ship 'runtime' (our CLI binary).
# This filters out any install rules from dependencies that don't tag with a
# component (they go into the unnamed/Unspecified component, which we exclude).
set(CPACK_DEB_COMPONENT_INSTALL ON)
set(CPACK_COMPONENTS_ALL        runtime)

set(CPACK_GENERATOR "DEB")
set(CPACK_DEBIAN_RUNTIME_PACKAGE_NAME         "julenny-fhe")
set(CPACK_DEBIAN_RUNTIME_FILE_NAME            "julenny-fhe-linux-amd64.deb")
set(CPACK_DEBIAN_RUNTIME_PACKAGE_MAINTAINER   "JuLenny Ltd <support@julenny.net>")
set(CPACK_DEBIAN_RUNTIME_PACKAGE_ARCHITECTURE "amd64")
set(CPACK_DEBIAN_RUNTIME_PACKAGE_SECTION      "utils")
set(CPACK_DEBIAN_RUNTIME_PACKAGE_PRIORITY     "optional")
set(CPACK_DEBIAN_RUNTIME_PACKAGE_HOMEPAGE     "https://github.com/JuLenny-Ltd/julenny-toolkit")
set(CPACK_DEBIAN_RUNTIME_PACKAGE_SHLIBDEPS    ON)

include(CPack)

message(STATUS "")
message(STATUS "JuLenny FHE Toolkit configuration:")
message(STATUS "  Version:               ${PROJECT_VERSION}")
message(STATUS "  Build type:            ${CMAKE_BUILD_TYPE}")
message(STATUS "  C++ standard:          C++${CMAKE_CXX_STANDARD}")
message(STATUS "  Build CLI:             ${FHE_TOOLKIT_BUILD_CLI}")
message(STATUS "  Build tests:           ${FHE_TOOLKIT_BUILD_TESTS}")
message(STATUS "  Use OpenFHE:           ${FHE_TOOLKIT_USE_OPENFHE}")
message(STATUS "  Warnings as errors:    ${FHE_TOOLKIT_WARNINGS_AS_ERRORS}")
message(STATUS "  OpenSSL version:       ${OPENSSL_VERSION}")
message(STATUS "")
