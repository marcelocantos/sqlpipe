// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

// Compile deepparser C sources as part of the Go package.
// These must be compiled as C (not C++) because deepparser uses
// C-specific constructs (void* implicit conversion, etc.).
#include "internal/c/deepparser/arena.c"
#include "internal/c/deepparser/liteparser.c"
#include "internal/c/deepparser/lp_tokenize.c"
#include "internal/c/deepparser/lp_unparse.c"
#include "internal/c/deepparser/parse.c"
