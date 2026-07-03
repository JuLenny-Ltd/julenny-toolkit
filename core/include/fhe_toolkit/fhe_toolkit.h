#ifndef FHE_TOOLKIT_H
#define FHE_TOOLKIT_H

/**
 * @file fhe_toolkit.h
 * @brief Public C API for the JuLenny FHE Toolkit core library.
 *
 * This header is the stable boundary between the core library and
 * every UI shell that wraps it (CLI, desktop GUI, mobile apps). It
 * uses only C-compatible types so any language with a C FFI can
 * bind the core.
 *
 * Memory ownership rule: pointers returned by this API are owned by
 * the library and must NOT be freed by the caller, unless the
 * function's documentation explicitly states otherwise.
 *
 * Thread safety: functions are thread-safe unless documented
 * otherwise. Handles are NOT safe to share across threads without
 * external synchronization.
 */

#ifdef __cplusplus
extern "C" {
#endif

typedef enum fhe_toolkit_status {
    FHE_TOOLKIT_OK              = 0,
    FHE_TOOLKIT_ERR_INVALID_ARG = 1,
    FHE_TOOLKIT_ERR_NOT_FOUND   = 2,
    FHE_TOOLKIT_ERR_IO          = 3,
    FHE_TOOLKIT_ERR_CRYPTO      = 6,
    FHE_TOOLKIT_ERR_PROTOCOL    = 7,
    FHE_TOOLKIT_ERR_INTERNAL    = 99
} fhe_toolkit_status_t;

typedef struct fhe_toolkit_handle fhe_toolkit_handle_t;

const char* fhe_toolkit_version(void);
const char* fhe_toolkit_status_string(fhe_toolkit_status_t status);

#ifdef __cplusplus
}
#endif

#endif
