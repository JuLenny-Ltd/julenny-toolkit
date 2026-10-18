include(Catch)

set(FHE_TOOLKIT_TEST_SOURCES
    storage/filesystem_store_test.cpp
    registry/canonical_json_test.cpp
    registry/envelope_test.cpp
    registry/signature_test.cpp
    registry/psi_definition_test.cpp
    psi/digest_test.cpp
    psi/table_test.cpp
    psi/reference_test.cpp
    psi/solver_test.cpp
    psi/bundle_test.cpp
    psi/shard_test.cpp
    psi/advice_test.cpp
    psi/count_test.cpp
    psi/size_class_test.cpp
)

if(FHE_TOOLKIT_USE_OPENFHE)
    list(APPEND FHE_TOOLKIT_TEST_SOURCES
        crypto/keys_test.cpp
        crypto/ciphertext_test.cpp
        crypto/multiparty_test.cpp
        crypto/context_spec_test.cpp
        psi/itemized_result_test.cpp
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

# Windows/clang-cl: the same compiler-rt builtins and OpenMP link inputs as the CLI
# (see cli/CMakeLists.txt); without them OpenFHE's 128-bit helpers stay unresolved.
if(WIN32)
    target_link_directories(fhe_toolkit_tests PRIVATE
        "C:/Program Files/Microsoft Visual Studio/18/Community/VC/Tools/Llvm/x64/lib/clang/20/lib/windows"
        "C:/Program Files/Microsoft Visual Studio/18/Community/VC/Tools/Llvm/x64/lib"
    )
    target_link_libraries(fhe_toolkit_tests PRIVATE
        clang_rt.builtins-x86_64.lib
        libomp.lib
    )
endif()

catch_discover_tests(fhe_toolkit_tests)
