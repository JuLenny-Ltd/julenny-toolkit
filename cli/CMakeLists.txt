add_executable(julenny-fhe
    src/main.cpp
    src/prompts.cpp
    src/commands/keys.cpp
    src/commands/crypto.cpp
)

target_include_directories(julenny-fhe
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/core/src
)

target_link_libraries(julenny-fhe
    PRIVATE
        fhe_toolkit_core
        fhe_toolkit_warnings
        CLI11::CLI11
        nlohmann_json::nlohmann_json
        spdlog::spdlog
)

set_target_properties(julenny-fhe PROPERTIES
    OUTPUT_NAME "julenny-fhe"
)

# Windows/clang-cl: OpenFHE's static libs reference compiler-rt builtins
# (128-bit integer helpers like __fixdfti / __modti3) and OpenMP, which the
# MSVC-style linker does not pull in automatically. Mirror the WinUI app's
# link inputs (windows/JuLennyFHE/JuLennyFHE.vcxproj AdditionalDependencies
# + AdditionalLibraryDirectories).
if(WIN32)
    target_link_directories(julenny-fhe PRIVATE
        "C:/Program Files/Microsoft Visual Studio/18/Community/VC/Tools/Llvm/x64/lib/clang/20/lib/windows"
        "C:/Program Files/Microsoft Visual Studio/18/Community/VC/Tools/Llvm/x64/lib"
    )
    target_link_libraries(julenny-fhe PRIVATE
        clang_rt.builtins-x86_64.lib
        libomp.lib
    )
endif()

# Wire the OpenFHE version that we linked against into the CLI so commands
# like `crypto dump-sample` write accurate metadata. Never hardcode the
# version in source: it drifts.
if(FHE_TOOLKIT_USE_OPENFHE)
    target_compile_definitions(julenny-fhe PRIVATE
        FHE_TOOLKIT_OPENFHE_VERSION="${BASE_OPENFHE_VERSION}")
endif()

# Install rules - puts the binary in /usr/bin when the .deb is installed
install(TARGETS julenny-fhe
    RUNTIME DESTINATION bin
    COMPONENT runtime
)
