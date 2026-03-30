// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

// Compile liteparser C sources as part of the Go package.
// These must be compiled as C (not C++) because liteparser uses
// C-specific constructs (void* implicit conversion, etc.).
#include "internal/c/liteparser/arena.c"
#include "internal/c/liteparser/liteparser.c"
#include "internal/c/liteparser/lp_tokenize.c"
#include "internal/c/liteparser/lp_unparse.c"
#include "internal/c/liteparser/parse.c"
