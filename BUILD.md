# Building the JuLenny Toolkit

This document covers building from source on Linux. For Windows, see
[`windows/README.md`](windows/README.md). Most users should install a release instead:
the `.deb` or the Windows installer from the releases page.

## Prerequisites

```bash
apt install -y build-essential cmake git libssl-dev pkg-config
```

Minimum versions: CMake 3.24, GCC 11 or Clang 14, OpenSSL 3.0. Building the MCP server
also needs Node.js.

## OpenFHE

All homomorphic encryption goes through OpenFHE, pinned to exactly version 1.5.1. Build it
once as static libraries:

```bash
git clone https://github.com/openfheorg/openfhe-development.git
cd openfhe-development && git checkout v1.5.1
cmake -B build -DBUILD_STATIC=ON -DBUILD_SHARED=OFF -DBUILD_UNITTESTS=OFF \
  -DBUILD_EXAMPLES=OFF -DBUILD_BENCHMARKS=OFF -DCMAKE_INSTALL_PREFIX=$HOME/openfhe-install
cmake --build build -j
cmake --install build
```

The other dependencies (CLI11, nlohmann/json, spdlog, and Catch2 for tests) are fetched by
CMake automatically, pinned in `cmake/Dependencies.cmake`. OpenSSL is used for the Ed25519
signatures on function definitions and key-exchange messages.

## Building

From the repository root:

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release -DFHE_TOOLKIT_USE_OPENFHE=ON \
  -DCMAKE_PREFIX_PATH=$HOME/openfhe-install
cmake --build build -j
./build/cli/julenny-toolkit --version
```

Without `-DFHE_TOOLKIT_USE_OPENFHE=ON` the build contains no cryptography.

To run the tests, add `-DFHE_TOOLKIT_BUILD_TESTS=ON` to the configure step, build, then:

```bash
ctest --test-dir build --output-on-failure
```

## The MCP server and the .deb

`linux/build-mcp-exe.sh` builds the MCP server as a single executable, `mcp/sea/julenny-mcp`.
Then `cpack` in the build folder produces the `.deb`, which includes the MCP server when it
has been built.

## Build options

| Option | Default | Purpose |
|---|---|---|
| `FHE_TOOLKIT_USE_OPENFHE` | OFF | The cryptography. Required for a working toolkit |
| `FHE_TOOLKIT_BUILD_CLI` | ON | Build the CLI |
| `FHE_TOOLKIT_BUILD_TESTS` | OFF | Build the test suite |
| `FHE_TOOLKIT_BUNDLE_MCP` | ON | Include the MCP server in the `.deb` when built |
| `FHE_TOOLKIT_WARNINGS_AS_ERRORS` | OFF | Treat compiler warnings as errors |

## Troubleshooting

**`Could not find OpenFHE`**: pass the folder OpenFHE was installed to with
`-DCMAKE_PREFIX_PATH`, and check it is version 1.5.1 exactly.

**`Could not find OpenSSL`**: install `libssl-dev`, or pass `-DOPENSSL_ROOT_DIR=/your/path`.

**CMake too old**: install a current one from Kitware's apt repository or with
`pip install cmake`.
