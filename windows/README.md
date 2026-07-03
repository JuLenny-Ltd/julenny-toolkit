# JuLenny FHE Toolkit - Windows app (C++/WinRT, WinUI 3)

Native Windows app using C++/WinRT and WinUI 3. Statically links the
toolkit's core library to call directly into the FHE plumbing - no
.NET runtime, no shim DLL.

## Status

Scaffolding only. First deliverable is a window that displays
"Toolkit core version: 0.0.1" - proving the C++/WinRT then ToolkitClient
then core library pipeline works. Real UI screens (grants, access
requests, keys, executions) come on top of this scaffolding.

## Toolchain pinning

**Split toolchain**:

- `core` static library + OpenFHE: built with **clang-cl** (Clang in
  MSVC-compatibility mode). Mandatory - OpenFHE's source uses
  GCC-extension features (`__int128`, math constants, `<cxxabi.h>`) that
  MSVC rejects but clang-cl handles correctly.
- WinUI 3 app: built with **MSVC** (default toolset, v145 in VS 2026).
  Mandatory - the WinUI 3 XAML compiler step silently skips when toolset
  is ClangCL, so `.xaml.g.h` files never get generated. Trying to use
  ClangCL for a WinUI 3 packaged app is a dead end on the current MS
  tooling.

The two toolsets link cleanly because clang-cl produces MSVC-ABI-compatible
objects by design (same name mangling, calling conventions, exception
handling).

## Prerequisites

- Windows 11 (Windows 10 19041+ also works)
- Visual Studio 2026 (or 2022 17.10+); Community edition is fine.
  Required workloads / components:
    - Workload: Desktop development with C++
    - Workload: Universal Windows Platform development (for WinUI 3 templates)
    - Individual component: C++ WinUI app development tools
    - Individual component: C++ Clang Compiler for Windows (clang-cl)
    - Individual component: MSBuild support for LLVM (clang-cl) toolset
    - Individual component: C++ CMake tools for Windows
    - Individual component: Windows 11 SDK 10.0.22621.0 or newer
- CMake 3.24+ (bundled with the C++ CMake tools above)
- Git for Windows
- OpenSSL 3.0+ for Windows. Easiest source:
  https://slproweb.com/products/Win32OpenSSL.html - install the
  full (~244 MB) Win64 installer to `C:\Program Files\OpenSSL-Win64\`.
  Then add `C:\Program Files\OpenSSL-Win64\bin` to PATH.

## Build OpenFHE for Windows (one-time)

OpenFHE upstream does not officially support Windows/MSVC builds.
We patch it locally to work with clang-cl. From a fresh
**"Developer PowerShell for VS"** (open from Start menu, then
switch to x64 mode):

    Import-Module "$env:VSINSTALLDIR\Common7\Tools\Microsoft.VisualStudio.DevShell.dll"
    Enter-VsDevShell -VsInstallPath $env:VSINSTALLDIR -SkipAutomaticLocation `
        -DevCmdArguments "-arch=x64 -host_arch=x64"

Clone and check out the pinned tag:

    cd C:\Users\David
    git clone https://github.com/openfheorg/openfhe-development.git openfhe
    cd openfhe
    git checkout v1.5.1

Apply six patches (see `windows/openfhe-patches.md` in this repo for
the full PowerShell scripts; each is a small surgical edit):

    1. CMakeLists.txt: wrap `-Wall -Werror` (lines 162-163) in `if(NOT MSVC)`
    2. CMakeLists.txt: wrap `-O3` (lines 193-194) in `if(NOT MSVC)`
    3. CMakeLists.txt: add `-D_USE_MATH_DEFINES` to MSVC compile flags
    4. CMakeLists.txt: replace bash `cp -R` (line 740) with `${CMAKE_COMMAND} -E copy_directory`
    5. src/core/include/math/math-hal.h: change `#ifdef _MSC_VER`
       to `#if defined(_MSC_VER) && !defined(__clang__)`
    6. src/core/lib/utils/demangle.cpp: change
       `#if defined(__clang__) || defined(__GNUC__)` to
       `#if (defined(__clang__) || defined(__GNUC__)) && !defined(_MSC_VER)`

Configure with the ClangCL toolset and explicit x86_64 compiler target:

    cd C:\Users\David\openfhe
    mkdir build
    cd build
    cmake .. -G "Visual Studio 18 2026" -A x64 -T ClangCL `
        -DCMAKE_C_COMPILER_TARGET=x86_64-pc-windows-msvc `
        -DCMAKE_CXX_COMPILER_TARGET=x86_64-pc-windows-msvc `
        -DCMAKE_INSTALL_PREFIX="C:/Users/David/openfhe-install" `
        -DBUILD_STATIC=ON `
        -DBUILD_SHARED=OFF `
        -DBUILD_UNITTESTS=OFF `
        -DBUILD_EXAMPLES=OFF `
        -DBUILD_BENCHMARKS=OFF `
        -DBUILD_EXTRAS=OFF `
        -DWITH_OPENMP=OFF

Build (20-30 min) and install:

    cmake --build . --config Release --parallel 2>&1 | Tee-Object -FilePath build.log
    cmake --install . --config Release

Result: `C:\Users\David\openfhe-install\` contains
`include\openfhe\` (headers), `lib\` (the three static libs:
`OPENFHEcore_static.lib`, `OPENFHEpke_static.lib`,
`OPENFHEbinfhe_static.lib`), and `CMake\` (CMake config files).

## Build our core library for Windows (one-time)

In a fresh Developer PowerShell (with x64 mode set as above):

    cd C:\Users\David\fhe-toolkit
    Remove-Item -Recurse -Force build -ErrorAction SilentlyContinue
    mkdir build
    cd build
    cmake .. -G "Visual Studio 18 2026" -A x64 -T ClangCL `
        -DCMAKE_C_COMPILER_TARGET=x86_64-pc-windows-msvc `
        -DCMAKE_CXX_COMPILER_TARGET=x86_64-pc-windows-msvc `
        -DCMAKE_PREFIX_PATH="C:/Users/David/openfhe-install" `
        -DOPENSSL_ROOT_DIR="C:/Program Files/OpenSSL-Win64" `
        -DFHE_TOOLKIT_USE_OPENFHE=ON `
        -DFHE_TOOLKIT_BUILD_CLI=OFF `
        -DFHE_TOOLKIT_BUILD_TESTS=OFF
    cmake --build . --config Release --parallel 2>&1 | Tee-Object -FilePath build.log

Result: `build\core\Release\fhe_toolkit_core.lib` (~22 MB).

The toolkit's `cmake/Dependencies.cmake` already includes the
necessary Windows-specific patches (FMT_USE_CONSTEVAL=0,
_USE_MATH_DEFINES on MSVC, optional OpenMP, spdlog v1.17.0+).

## Set up the Visual Studio project

The .sln and .vcxproj are intentionally not committed - best
generated by VS's New Project wizard for the exact VS version.

1. Visual Studio 2026 then File then New then Project.
2. Search for "Blank App, Packaged (WinUI in Desktop)", pick the C++ version.
3. Project name: `JuLennyFHE`. Location: `C:\Users\David\fhe-toolkit\windows\`.
   Solution name: `JuLennyFHE`. Check "Place solution and project in
   the same directory."
4. Create. Close VS.

## Drop in the toolkit's committed source files

The fresh VS project has its own placeholder App.xaml, MainWindow.xaml,
pch.h etc. Our committed scaffold sits in the same `JuLennyFHE\` folder
the wizard wants to create the project in, which means you need to move
the scaffold aside before running the wizard, then merge it back. From
PowerShell in `windows\`:

    Move-Item JuLennyFHE JuLennyFHE_scaffold_temp

Now run the New Project wizard (above). Once VS finishes and closes:

    Copy-Item -Recurse -Force JuLennyFHE_scaffold_temp\* JuLennyFHE\
    Remove-Item -Recurse -Force JuLennyFHE_scaffold_temp

Reopen the solution. Right-click project then Add then Existing Item then
add `Services\ToolkitClient.h` and `Services\ToolkitClient.cpp` (these
are new files VS doesn't know about). The App/MainWindow/pch files were
replaced in place; VS already references those by name.

## Configure project properties

Right-click project then Properties. Set Configuration to "All
Configurations", Platform to "x64".

Leave **Platform Toolset** at the default MSVC (e.g. v145 in VS 2026).
Do **not** switch to LLVM (clang-cl): the WinUI 3 XAML compiler silently
skips when toolset is ClangCL, so `.xaml.g.h` files never get generated
and the build fails. The `core` lib's clang-cl objects link cleanly into
the MSVC-built app because clang-cl emits MSVC-ABI-compatible objects.

**C/C++** then **General** then **Additional Include Directories**:

    $(GeneratedFilesDir)
    $(SolutionDir)..\..\core\include
    C:\Users\David\openfhe-install\include\openfhe
    C:\Users\David\openfhe-install\include\openfhe\core
    C:\Users\David\openfhe-install\include\openfhe\pke
    C:\Users\David\openfhe-install\include\openfhe\binfhe
    C:\Program Files\OpenSSL-Win64\include

**C/C++** then **Preprocessor** then **Preprocessor Definitions**
(prepend to existing `%(PreprocessorDefinitions)` macro):

    MATHBACKEND=4
    _USE_MATH_DEFINES
    FMT_USE_CONSTEVAL=0

**C/C++** then **Command Line** then **Additional Options**, append:

    /utf-8

Ensures source files with non-ASCII characters (em-dashes, etc.) are
interpreted correctly by MSVC for wide-string literals.

**Linker** then **General** then **Additional Library Directories**:

    $(SolutionDir)..\..\build\core\Release
    C:\Users\David\openfhe-install\lib
    C:\Program Files\OpenSSL-Win64\lib\VC\x64\MD

**Linker** then **Input** then **Additional Dependencies** (append):

    fhe_toolkit_core.lib
    OPENFHEpke_static.lib
    OPENFHEcore_static.lib
    OPENFHEbinfhe_static.lib
    libssl.lib
    libcrypto.lib

Order of OpenFHE libs matters slightly: pke depends on core; binfhe
is independent. Listing pke before core lets the linker resolve
forward references in one pass.

## Build and run

Configuration: Release, Platform: x64. F5.

**Developer Mode** must be enabled on the dev machine to F5 a packaged
WinUI 3 app (Settings → Privacy & Security → For developers).

Splash screen briefly, then a window opens titled "JuLenny FHE Toolkit"
with the wordmark, an "FHE Toolkit" heading, status text ("Not
configured..."), and Poll/Health Check buttons. Clicking Health Check
appends the stub status line to the log pane - proves the
C++/WinRT → ToolkitClient → core lib pipeline is live.

## Troubleshooting

**"cannot find fhe_toolkit/..." or OpenFHE headers**: include paths
wrong; verify `$(SolutionDir)..\..\core\include` resolves correctly
in Project Properties. The exact resolution depends on where you
created the .sln; check by hovering over the include path in the
property page.

**Linker errors about OpenFHE or fhe_toolkit_core symbols
(`unresolved external symbol`)**: typically means a library directory
isn't on the linker search path, or the library file isn't named
exactly as expected. Re-check Linker then General then Additional
Library Directories. (The earlier version of this doc warned about
toolset mismatch - that turned out not to be the issue. clang-cl and
MSVC are ABI-compatible on Windows; mixing them within one project
is supported by Microsoft.)

**`'MainWindow.xaml.g.h' file not found` / `'App.xaml.g.h' file not
found`**: the XAML compiler didn't run, so the `.g.h` files don't
exist. Most common cause is that Platform Toolset is set to
`LLVM (clang-cl)`. Switch back to MSVC. Clean + Rebuild.

**`'MainWindow_base' is not a member of winrt::JuLennyFHE::implementation`**:
`MainWindow.xaml.h` is including `MainWindow.xaml.g.h` directly. As of
CppWinRT v2.0.250303, the correct include is `MainWindow.g.h` - that
header defines `MainWindow_base` and transitively includes
`MainWindow.xaml.g.h`. The committed scaffold uses the correct include.

**`'Services': the symbol to the left of a '::' must be a type`** when
referencing `ToolkitClient` from inside `winrt::JuLennyFHE::implementation`:
name lookup picks up the WinRT-projected `winrt::JuLennyFHE` parent
namespace and fails. Use the leading-`::` form
`::JuLennyFHE::Services::ToolkitClient` to refer to our root namespace.

**Linker errors about OpenSSL (`libssl.lib not found` or
`unresolved external symbol _SSL_*`)**: confirm OpenSSL is installed
and the lib directory matches your install. The slproweb installer
places libs at `C:\Program Files\OpenSSL-Win64\lib\VC\x64\MD\` for
the dynamic-CRT build. If you used vcpkg with static CRT, use
`C:\vcpkg\installed\x64-windows-static\lib\` instead and switch
project properties C/C++ then Code Generation then Runtime Library
to **Multi-threaded (/MT)**.

**XAML compile errors after replacing files**: right-click the .xaml
in VS then Properties then confirm "Item Type" is "XAML Compiler"
and "Generator" is "MSBuild:Compile".

**`error : MSVC COMPILER IS NOT SUPPORTED`** when building OpenFHE:
you missed patch 5 (math-hal.h). Re-apply it.

**`Cannot support NATIVE_SIZE == 64`** when configuring OpenFHE:
the Compiler Target wasn't set; add
`-DCMAKE_C_COMPILER_TARGET=x86_64-pc-windows-msvc` and
`-DCMAKE_CXX_COMPILER_TARGET=x86_64-pc-windows-msvc` to the cmake
configure.
