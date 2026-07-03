// Implementation of the public C API.
// This file is the surface that all UI shells call into.

#include "fhe_toolkit/fhe_toolkit.h"

extern "C" {

const char* fhe_toolkit_version(void) {
    return FHE_TOOLKIT_VERSION_STRING;
}

const char* fhe_toolkit_status_string(fhe_toolkit_status_t status) {
    switch (status) {
        case FHE_TOOLKIT_OK:              return "ok";
        case FHE_TOOLKIT_ERR_INVALID_ARG: return "invalid argument";
        case FHE_TOOLKIT_ERR_NOT_FOUND:   return "not found";
        case FHE_TOOLKIT_ERR_IO:          return "i/o error";
        case FHE_TOOLKIT_ERR_CRYPTO:      return "cryptographic error";
        case FHE_TOOLKIT_ERR_PROTOCOL:    return "protocol error";
        case FHE_TOOLKIT_ERR_INTERNAL:    return "internal error";
    }
    return "unknown status";
}

}  // extern "C"
