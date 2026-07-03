# Shared compiler warning flags.
# Link this INTERFACE library to first-party targets to inherit our warning set.
# Third-party dependencies fetched via FetchContent are NOT linked to this and
# keep their own (typically more permissive) warning settings.

add_library(fhe_toolkit_warnings INTERFACE)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(fhe_toolkit_warnings INTERFACE
        -Wall
        -Wextra
        -Wpedantic
        -Wshadow
        -Wnon-virtual-dtor
        -Wold-style-cast
        -Wcast-align
        -Wunused
        -Woverloaded-virtual
        -Wnull-dereference
        -Wdouble-promotion
        -Wformat=2
    )
    if(FHE_TOOLKIT_WARNINGS_AS_ERRORS)
        target_compile_options(fhe_toolkit_warnings INTERFACE -Werror)
    endif()
endif()

# Clang-only: suppress noise categories that fire on every C++20 feature.
# We target C++20 by design; "incompatible with C++98" is not actionable
# feedback. Same for the pre-C++17 and pedantic unsafe-buffer warnings.
# Done as a separate block (not in the elseif chain) so it applies to
# both clang and clang-cl on top of the GNU|Clang flags above.
if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    target_compile_options(fhe_toolkit_warnings INTERFACE
        -Wno-c++98-compat
        -Wno-c++98-compat-pedantic
        -Wno-pre-c++17-compat
        -Wno-unsafe-buffer-usage
        -Wno-unsafe-buffer-usage-in-libc-call
    )
endif()

if(MSVC AND NOT CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    target_compile_options(fhe_toolkit_warnings INTERFACE
        /W4
        /permissive-
    )
    if(FHE_TOOLKIT_WARNINGS_AS_ERRORS)
        target_compile_options(fhe_toolkit_warnings INTERFACE /WX)
    endif()
endif()
