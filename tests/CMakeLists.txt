include(Catch)

set(FHE_TOOLKIT_TEST_SOURCES
    storage/filesystem_store_test.cpp
    registry/canonical_json_test.cpp
    registry/envelope_test.cpp
    registry/signature_test.cpp
)

if(FHE_TOOLKIT_USE_OPENFHE)
    list(APPEND FHE_TOOLKIT_TEST_SOURCES
        crypto/keys_test.cpp
        crypto/ciphertext_test.cpp
        crypto/multiparty_test.cpp
    )
endif()

add_executable(fhe_toolkit_tests ${FHE_TOOLKIT_TEST_SOURCES})

target_link_libraries(fhe_toolkit_tests
    PRIVATE
        fhe_toolkit_core
        fhe_toolkit_warnings
        Catch2::Catch2WithMain
)

target_include_directories(fhe_toolkit_tests
    PRIVATE
        ${CMAKE_SOURCE_DIR}/core/src
)

target_compile_definitions(fhe_toolkit_tests PRIVATE
    FHE_TOOLKIT_SCHEMAS_DIR="${CMAKE_SOURCE_DIR}/third_party/schemas"
)

if(FHE_TOOLKIT_USE_OPENFHE)
    target_include_directories(fhe_toolkit_tests SYSTEM PRIVATE
        ${OpenFHE_INCLUDE}
        ${OpenFHE_INCLUDE}/core
        ${OpenFHE_INCLUDE}/pke
        ${OpenFHE_INCLUDE}/binfhe
    )
    target_compile_definitions(fhe_toolkit_tests PRIVATE MATHBACKEND=4)
endif()

catch_discover_tests(fhe_toolkit_tests)
