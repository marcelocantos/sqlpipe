// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0
//
// Emscripten wrapper for sqldeep. Re-exports the C API with
// EMSCRIPTEN_KEEPALIVE so symbols survive dead-code elimination.

#include <emscripten/emscripten.h>

// Include sqldeep's implementation directly (single-TU build).
// sqldeep header — path set via -I flag during compilation.
#include <sqldeep.h>

extern "C" {

EMSCRIPTEN_KEEPALIVE
char* wasm_sqldeep_transpile(const char* input,
                             char** err_msg, int* err_line, int* err_col) {
    return sqldeep_transpile(input, err_msg, err_line, err_col);
}

EMSCRIPTEN_KEEPALIVE
char* wasm_sqldeep_transpile_fk(const char* input,
                                const sqldeep_foreign_key* fks, int fk_count,
                                char** err_msg, int* err_line, int* err_col) {
    return sqldeep_transpile_fk(input, fks, fk_count, err_msg, err_line, err_col);
}

EMSCRIPTEN_KEEPALIVE
char* wasm_sqldeep_transpile_backend(const char* input,
                                     sqldeep_backend backend,
                                     char** err_msg, int* err_line, int* err_col) {
    return sqldeep_transpile_backend(input, backend, err_msg, err_line, err_col);
}

EMSCRIPTEN_KEEPALIVE
const char* wasm_sqldeep_version(void) {
    return sqldeep_version();
}

EMSCRIPTEN_KEEPALIVE
void wasm_sqldeep_free(void* ptr) {
    sqldeep_free(ptr);
}

} // extern "C"
