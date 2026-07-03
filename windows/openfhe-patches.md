# OpenFHE source patches required for Windows / clang-cl build

OpenFHE upstream does not officially support Windows/MSVC. Six surgical
patches make `v1.5.1` build with **clang-cl** (the only supported Windows
path). Apply these to a fresh OpenFHE clone before configuring with CMake.

These patches are deliberately **not** committed inside OpenFHE - they
live here so any developer setting up a Windows build can re-apply them.
If OpenFHE upstream eventually supports clang-cl natively, these can be
deleted.

## Where OpenFHE lives in our setup

The reference build uses `C:\Users\David\openfhe\` for source and
`C:\Users\David\openfhe-install\` for the install prefix. Adjust paths in
the scripts below if your layout differs.

## How to apply

Run each PowerShell block from a Developer PowerShell for VS (any arch).
Each script makes a `.bak` of the file before editing, so you can restore
if needed.

### Patch 1+2+3 - CMakeLists.txt: conditional compile flags

GCC-style `-Wall -Werror -O3` flags break MSVC. Wrap them in `if(NOT MSVC)`
blocks. Also add `-D_USE_MATH_DEFINES` for MSVC so `<cmath>` exposes
`M_PI`, `M_E`, etc.

```powershell
$file = "C:\Users\David\openfhe\CMakeLists.txt"
Copy-Item $file "$file.bak" -Force
$content = Get-Content $file -Raw

# 1. C compile flags
$content = $content.Replace(
    'set(C_COMPILE_FLAGS "-Wall -Werror -DOPENFHE_VERSION=${OPENFHE_VERSION}")',
    @'
if(MSVC)
    set(C_COMPILE_FLAGS "-DOPENFHE_VERSION=${OPENFHE_VERSION} -D_USE_MATH_DEFINES")
else()
    set(C_COMPILE_FLAGS "-Wall -Werror -DOPENFHE_VERSION=${OPENFHE_VERSION}")
endif()
'@)

# 2. CXX compile flags
$content = $content.Replace(
    'set(CXX_COMPILE_FLAGS "-Wall -Werror -DOPENFHE_VERSION=${OPENFHE_VERSION}")',
    @'
if(MSVC)
    set(CXX_COMPILE_FLAGS "-DOPENFHE_VERSION=${OPENFHE_VERSION} -D_USE_MATH_DEFINES")
else()
    set(CXX_COMPILE_FLAGS "-Wall -Werror -DOPENFHE_VERSION=${OPENFHE_VERSION}")
endif()
'@)

# 3. Wrap -O3 in non-MSVC conditional
$content = $content.Replace(
    '    set(C_COMPILE_FLAGS "${C_COMPILE_FLAGS} -O3")',
    @'
    if(NOT MSVC)
        set(C_COMPILE_FLAGS "${C_COMPILE_FLAGS} -O3")
    endif()
'@)
$content = $content.Replace(
    '    set(CXX_COMPILE_FLAGS "${CXX_COMPILE_FLAGS} -O3")',
    @'
    if(NOT MSVC)
        set(CXX_COMPILE_FLAGS "${CXX_COMPILE_FLAGS} -O3")
    endif()
'@)

Set-Content $file -Value $content -NoNewline
```

### Patch 4 - CMakeLists.txt: portable demoData copy

Replace bash `cp -R` with `cmake -E copy_directory` (cross-platform).

```powershell
$file = "C:\Users\David\openfhe\CMakeLists.txt"
$content = Get-Content $file -Raw
$old = '    COMMAND [ ! -d ${BINDEMODATAPATH} ] && cp -R ${DEMODATAPATH} ${BINDEMODATAPATH} && echo "-- Copied demoData files" || echo "-- demoData folder already exists")'
$new = '    COMMAND ${CMAKE_COMMAND} -E copy_directory ${DEMODATAPATH} ${BINDEMODATAPATH})'
$content = $content.Replace($old, $new)
Set-Content $file -Value $content -NoNewline
```

### Patch 5 - math-hal.h: let clang-cl through MSVC block

OpenFHE explicitly blocks MSVC compilation. clang-cl defines `_MSC_VER`
(MSVC-compat) AND `__clang__`. Refine the check to allow clang-cl.

```powershell
$file = "C:\Users\David\openfhe\src\core\include\math\math-hal.h"
Copy-Item $file "$file.bak" -Force
$lines = Get-Content $file
$output = New-Object System.Collections.Generic.List[string]
for ($i = 0; $i -lt $lines.Length; $i++) {
    if ($lines[$i] -eq '#ifdef _MSC_VER' -and $i+1 -lt $lines.Length -and $lines[$i+1] -match 'MSVC COMPILER IS NOT SUPPORTED') {
        $output.Add('#if defined(_MSC_VER) && !defined(__clang__)')
    } else {
        $output.Add($lines[$i])
    }
}
$output | Set-Content $file
```

### Patch 6 - demangle.cpp: exclude clang-cl from GCC/Clang block

`<cxxabi.h>` exists on libstdc++/libc++ but not on MSVC's STL. clang-cl uses
MSVC's STL, so exclude it from the include path.

```powershell
$file = "C:\Users\David\openfhe\src\core\lib\utils\demangle.cpp"
Copy-Item $file "$file.bak" -Force
$lines = Get-Content $file
$output = New-Object System.Collections.Generic.List[string]
foreach ($line in $lines) {
    if ($line -eq '#if defined(__clang__) || defined(__GNUC__)') {
        $output.Add('#if (defined(__clang__) || defined(__GNUC__)) && !defined(_MSC_VER)')
    } else {
        $output.Add($line)
    }
}
$output | Set-Content $file
```

## Verification

After all 6 patches, configure should succeed without errors:

```powershell
cd C:\Users\David\openfhe
mkdir build
cd build
cmake .. -G "Visual Studio 18 2026" -A x64 -T ClangCL `
    -DCMAKE_C_COMPILER_TARGET=x86_64-pc-windows-msvc `
    -DCMAKE_CXX_COMPILER_TARGET=x86_64-pc-windows-msvc `
    -DCMAKE_INSTALL_PREFIX="C:/Users/David/openfhe-install" `
    -DBUILD_STATIC=ON -DBUILD_SHARED=OFF `
    -DBUILD_UNITTESTS=OFF -DBUILD_EXAMPLES=OFF `
    -DBUILD_BENCHMARKS=OFF -DBUILD_EXTRAS=OFF `
    -DWITH_OPENMP=OFF
```

Expected end of output: `Configuring done` / `Generating done`. No
`Cannot support NATIVE_SIZE == 64`, no `MSVC COMPILER IS NOT SUPPORTED`.
