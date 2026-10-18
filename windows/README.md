# JuLenny Toolkit - Windows app (C++/WinRT, WinUI 3)

Native Windows app using C++/WinRT and WinUI 3. Statically links the
toolkit's core library to call directly into the FHE plumbing - no
.NET runtime, no shim DLL.

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

    cd $env:USERPROFILE
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

    cd $env:USERPROFILE\openfhe
    mkdir build
    cd build
    cmake .. -G "Visual Studio 18 2026" -A x64 -T ClangCL `
        -DCMAKE_C_COMPILER_TARGET=x86_64-pc-windows-msvc `
        -DCMAKE_CXX_COMPILER_TARGET=x86_64-pc-windows-msvc `
        -DCMAKE_INSTALL_PREFIX="$env:USERPROFILE/openfhe-install" `
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

Result: `%USERPROFILE%\openfhe-install\` contains
`include\openfhe\` (headers), `lib\` (the three static libs:
`OPENFHEcore_static.lib`, `OPENFHEpke_static.lib`,
`OPENFHEbinfhe_static.lib`), and `CMake\` (CMake config files).

## Build our core library for Windows (one-time)

In a fresh Developer PowerShell (with x64 mode set as above):

    cd $env:USERPROFILE\fhe-toolkit
    Remove-Item -Recurse -Force build -ErrorAction SilentlyContinue
    mkdir build
    cd build
    cmake .. -G "Visual Studio 18 2026" -A x64 -T ClangCL `
        -DCMAKE_C_COMPILER_TARGET=x86_64-pc-windows-msvc `
        -DCMAKE_CXX_COMPILER_TARGET=x86_64-pc-windows-msvc `
        -DCMAKE_PREFIX_PATH="$env:USERPROFILE/openfhe-install" `
        -DOPENSSL_ROOT_DIR="C:/Program Files/OpenSSL-Win64" `
        -DFHE_TOOLKIT_USE_OPENFHE=ON `
        -DFHE_TOOLKIT_BUILD_CLI=OFF `
        -DFHE_TOOLKIT_BUILD_TESTS=OFF
    cmake --build . --config Release --parallel 2>&1 | Tee-Object -FilePath build.log

Result: `build\core\Release\fhe_toolkit_core.lib` (~22 MB).

The toolkit's `cmake/Dependencies.cmake` already includes the
necessary Windows-specific patches (FMT_USE_CONSTEVAL=0,
_USE_MATH_DEFINES on MSVC, optional OpenMP, spdlog v1.17.0+).

## Build the app, the CLI, the MCP server and the installer

The Visual Studio project is in the repository (`windows/JuLennyToolkit/JuLennyToolkit.vcxproj`).
It expects OpenFHE in `%USERPROFILE%\openfhe-install` and OpenSSL in
`C:\Program Files\OpenSSL-Win64`. From PowerShell, at the root of the repository:

    windows\build-core.ps1          # the core library (clang-cl)
    windows\build-cli.ps1           # julenny-toolkit.exe
    windows\build-release.ps1       # the desktop app, unpackaged and self-contained
    windows\build-mcp-exe.ps1       # julenny-mcp.exe (needs Node.js)
    windows\build-folderpicker.ps1  # the installer's folder-picker helper
    iscc windows\installer\julenny-toolkit.iss   # the installer (Inno Setup 6)

Put the Windows SDK's `signtool` on `PATH` before building `julenny-mcp.exe`, or the file
keeps a damaged signature.

The desktop app's build needs plenty of free memory. With about 2 GB free, the WinUI
precompiled-header step fails with `C3859` or `C1076`; close other programs and run it again.
