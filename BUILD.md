# Building the JuLenny FHE Toolkit

This document covers building the toolkit from source on Linux. macOS
builds use the same instructions; Windows builds are documented
separately when the Windows path is implemented.

## Prerequisites

System packages (Debian / Ubuntu names; equivalents on other distros):

```bash
apt install -y \
  build-essential \
  cmake \
  git \
  libssl-dev \
  pkg-config
```

Minimum versions:

| Tool        | Version |
|-------------|---------|
| CMake       | 3.24    |
| GCC         | 11      |
| Clang       | 14      |
| OpenSSL     | 3.0     |

Verify:

```bash
cmake --version
gcc --version
openssl version
```

If your distribution ships an older CMake, install a current one from
Kitware's repository or via `pip install cmake`.

## Dependencies

The build fetches the following header-only libraries via CMake's
`FetchContent` automatically. You do not need to install them
yourself.

- **CLI11** - argument parsing
- **nlohmann/json** - JSON serialization
- **spdlog** - logging
- **Catch2** - testing framework

These are pinned to specific tags in the top-level `CMakeLists.txt`.

System dependencies that must be present:

- **OpenSSL** - used for TLS in the HTTP client and for ed25519
  signature verification of function definitions.

A later phase will add **OpenFHE** as a system dependency. Build
instructions for OpenFHE itself will be documented when that phase
lands. The current skeleton does not require OpenFHE.

## Building

From the repository root:

```bash
cmake -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build -j
```

Build artifacts land in `build/`:

- `build/cli/julenny-toolkit` - the CLI executable
- `build/core/libfhe_toolkit_core.a` - the core static library

Run the CLI:

```bash
./build/cli/julenny-toolkit --help
```

## Running tests

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Debug -DFHE_TOOLKIT_BUILD_TESTS=ON
cmake --build build -j
ctest --test-dir build --output-on-failure
```

## Build options

| Option                       | Default | Purpose                                       |
|------------------------------|---------|-----------------------------------------------|
| `FHE_TOOLKIT_BUILD_CLI`      | ON      | Build the CLI executable                      |
| `FHE_TOOLKIT_BUILD_TESTS`    | OFF     | Build the test suite                          |
| `FHE_TOOLKIT_USE_OPENFHE`    | OFF     | Enable OpenFHE-backed crypto (not yet)        |
| `CMAKE_BUILD_TYPE`           | Release | `Debug` / `Release` / `RelWithDebInfo`        |

## Reproducible builds

Production releases use a pinned toolchain (specific compiler version,
specific CMake version, specific dependency tags) so that the
distributed binaries are bit-identical to those built from source by a
third party. Reproducible-build verification instructions ship with
each release. This is not yet implemented in the skeleton.

## Cross-platform notes

The `core/` library is portable C++20 and is intended to build on
Linux, macOS, Windows, Android (via NDK), and iOS. The skeleton has
been validated only on Linux x86_64 at this stage. As we add platform
support, this section will grow.

## Troubleshooting

**`Could not find OpenSSL`** - install `libssl-dev` and ensure
`pkg-config --modversion openssl` returns a version >= 3.0. If you
have a custom OpenSSL install, pass `-DOPENSSL_ROOT_DIR=/your/path`
to the CMake configure step.

**`Could not find CMake >= 3.24`** - your distribution's CMake is too
old. Install a current version via Kitware's apt repository or
`pip install cmake`.

**`FetchContent` is slow on first build** - the first configure
downloads ~5-10 MB of header-only dependency sources. They are cached
in `build/_deps/` and not redownloaded on subsequent builds.
