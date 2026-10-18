#ifndef FHE_TOOLKIT_STORAGE_SECRET_STORE_H
#define FHE_TOOLKIT_STORAGE_SECRET_STORE_H

// Internal C++ interface for secret-key persistence.
//
// SecretStore is the abstraction over WHERE a customer's secret material
// lives - encrypted file, AWS KMS, HSM, etc. The core library uses this
// interface; specific adapters implement it.
//
// This header is INTERNAL to the core library. The customer-facing C API
// for configuring which store is in use lives in
// include/fhe_toolkit/fhe_toolkit.h (added in a later chunk).

#include <cstddef>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace fhe_toolkit::storage {

using Bytes = std::vector<std::byte>;

// Abstract base class for secret-storage adapters.
//
// Thread safety: implementations are not required to be thread-safe unless
// they document otherwise. Callers must synchronize externally.
//
// Concurrency between processes: multiple processes accessing the same
// store may race. v1 implementations do not provide cross-process locking.
class SecretStore {
public:
    virtual ~SecretStore() = default;

    // Stores `value` under `key`. Overwrites any existing value.
    // Throws on I/O or crypto failures.
    virtual void put(std::string_view key, std::span<const std::byte> value) = 0;

    // Returns the stored value for `key`, or nullopt if the key doesn't exist.
    // Throws only on I/O or crypto failures (e.g. corrupted file, wrong passphrase).
    virtual std::optional<Bytes> get(std::string_view key) = 0;

    // Removes the value at `key`. Returns true if the key existed.
    virtual bool remove(std::string_view key) = 0;

    // Returns true if `key` has a stored value.
    virtual bool exists(std::string_view key) = 0;

    // Returns all stored keys with the given prefix.
    // Order is implementation-defined.
    virtual std::vector<std::string> list(std::string_view prefix) = 0;
};

}  // namespace fhe_toolkit::storage

#endif
