set(FHE_TOOLKIT_CORE_SOURCES
    src/ffi/fhe_toolkit.cpp
    src/storage/base64url.cpp
    src/storage/filesystem_store.cpp
    src/registry/canonical_json.cpp
    src/registry/envelope.cpp
    src/registry/hex.cpp
    src/registry/signature.cpp
    src/registry/trust_root.cpp
    src/crypto/signing.cpp
)

if(FHE_TOOLKIT_USE_OPENFHE)
    list(APPEND FHE_TOOLKIT_CORE_SOURCES
        src/crypto/context.cpp
        src/crypto/keys.cpp
        src/crypto/ciphertext.cpp
        src/crypto/eval_keys.cpp
    )
endif()

add_library(fhe_toolkit_core STATIC ${FHE_TOOLKIT_CORE_SOURCES})

target_include_directories(fhe_toolkit_core
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(fhe_toolkit_core
    PRIVATE
        fhe_toolkit_warnings
        OpenSSL::SSL
        OpenSSL::Crypto
        spdlog::spdlog
)

target_link_libraries(fhe_toolkit_core
    PUBLIC
        nlohmann_json::nlohmann_json
)

target_compile_definitions(fhe_toolkit_core
    PRIVATE
        FHE_TOOLKIT_VERSION_STRING="${PROJECT_VERSION}"
        FHE_TOOLKIT_VERSION_MAJOR=${PROJECT_VERSION_MAJOR}
        FHE_TOOLKIT_VERSION_MINOR=${PROJECT_VERSION_MINOR}
        FHE_TOOLKIT_VERSION_PATCH=${PROJECT_VERSION_PATCH}
)

if(FHE_TOOLKIT_USE_OPENFHE)
    target_link_libraries(fhe_toolkit_core
        PRIVATE
            OPENFHEpke_static
            OPENFHEbinfhe_static
            OPENFHEcore_static
            OpenMP::OpenMP_CXX
    )
    target_include_directories(fhe_toolkit_core SYSTEM PRIVATE
        ${OpenFHE_INCLUDE}
        ${OpenFHE_INCLUDE}/core
        ${OpenFHE_INCLUDE}/pke
        ${OpenFHE_INCLUDE}/binfhe
    )
    target_compile_definitions(fhe_toolkit_core PRIVATE
        FHE_TOOLKIT_HAS_OPENFHE=1
        MATHBACKEND=4
    )
endif()

set_target_properties(fhe_toolkit_core PROPERTIES
    CXX_VISIBILITY_PRESET     hidden
    VISIBILITY_INLINES_HIDDEN ON
)
