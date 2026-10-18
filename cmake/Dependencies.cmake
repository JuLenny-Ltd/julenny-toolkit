# Fetch header-only and small compiled dependencies via CMake FetchContent.
# Versions are pinned to specific tags for reproducible builds.

include(FetchContent)

# Disable fmt's consteval format-string checking.
# Required: clang-cl 20+ fails fmt's consteval as not-a-constant-expression.
# Tradeoff: format string typos become runtime errors instead of compile-time.
add_compile_definitions(FMT_USE_CONSTEVAL=0)

# OpenFHE headers use M_PI/M_E math constants which are non-standard.
# MSVC requires _USE_MATH_DEFINES to expose them via <cmath>.
# Required for any translation unit that #includes openfhe headers on Windows.
if(MSVC)
    add_compile_definitions(_USE_MATH_DEFINES)
endif()

# CMP0077 NEW: make option() honor pre-existing normal variables.
# Without this, our overrides for HTTPLIB_INSTALL etc. get ignored.
if(POLICY CMP0077)
    cmake_policy(SET CMP0077 NEW)
endif()

find_package(OpenSSL 3.0 REQUIRED)

# Disable each dependency's own install rules so their files don't leak
# into our .deb. CACHE BOOL + FORCE is required to override the
# option(...) calls in the dependencies' CMakeLists.txt.
set(JSON_Install             OFF CACHE BOOL "" FORCE)
set(JSON_BuildTests          OFF CACHE BOOL "" FORCE)
set(SPDLOG_INSTALL           OFF CACHE BOOL "" FORCE)
set(SPDLOG_BUILD_EXAMPLE     OFF CACHE BOOL "" FORCE)
set(SPDLOG_BUILD_TESTS       OFF CACHE BOOL "" FORCE)
set(CLI11_INSTALL            OFF CACHE BOOL "" FORCE)
set(CLI11_BUILD_TESTS        OFF CACHE BOOL "" FORCE)
set(CLI11_BUILD_EXAMPLES     OFF CACHE BOOL "" FORCE)
set(CATCH_INSTALL_DOCS       OFF CACHE BOOL "" FORCE)
set(CATCH_INSTALL_EXTRAS     OFF CACHE BOOL "" FORCE)

FetchContent_Declare(cli11
    GIT_REPOSITORY https://github.com/CLIUtils/CLI11.git
    GIT_TAG        v2.7.2
    GIT_SHALLOW    TRUE
)
FetchContent_Declare(json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG        v3.12.0
    GIT_SHALLOW    TRUE
)
FetchContent_Declare(spdlog
    GIT_REPOSITORY https://github.com/gabime/spdlog.git
    GIT_TAG        v1.17.0  # bumped from v1.14.1: fixes fmt consteval issue with clang-cl 20+
    GIT_SHALLOW    TRUE
)

FetchContent_MakeAvailable(cli11 json spdlog)

# Treat the fetched libraries' headers as system headers, so our warning set never reports their
# code. FetchContent_Declare(... SYSTEM) would do this but needs CMake 3.25; we support 3.24.
function(fhe_toolkit_mark_system_headers)
    foreach(tgt IN LISTS ARGN)
        get_target_property(real ${tgt} ALIASED_TARGET)
        if(real)
            set(tgt ${real})
        endif()
        get_target_property(dirs ${tgt} INTERFACE_INCLUDE_DIRECTORIES)
        if(dirs)
            set_property(TARGET ${tgt} APPEND PROPERTY INTERFACE_SYSTEM_INCLUDE_DIRECTORIES ${dirs})
        endif()
    endforeach()
endfunction()

fhe_toolkit_mark_system_headers(CLI11::CLI11 nlohmann_json::nlohmann_json spdlog::spdlog)

if(FHE_TOOLKIT_BUILD_TESTS)
    FetchContent_Declare(catch2
        GIT_REPOSITORY https://github.com/catchorg/Catch2.git
        GIT_TAG        v3.16.0
        GIT_SHALLOW    TRUE
    )
    FetchContent_MakeAvailable(catch2)
    fhe_toolkit_mark_system_headers(Catch2::Catch2 Catch2::Catch2WithMain)
    list(APPEND CMAKE_MODULE_PATH ${catch2_SOURCE_DIR}/extras)
endif()

if(FHE_TOOLKIT_USE_OPENFHE)
    # OpenFHE version is pinned across all platforms (Linux .deb, Windows app,
    # and the platform). Bumping it is a coordinated change: rebuild and re-test
    # every consumer, and reissue any downstream releases on the new version.
    # Never let this drift.
    find_package(OpenFHE 1.5.1 EXACT REQUIRED CONFIG)
    find_package(OpenMP)  # Optional: OpenFHE may be built without OpenMP on Windows
    message(STATUS "OpenFHE: ${BASE_OPENFHE_VERSION} (include: ${OpenFHE_INCLUDE})")
endif()
