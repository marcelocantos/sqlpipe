// swift-tools-version: 6.0
// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

import PackageDescription

let package = Package(
    name: "Sqlpipe",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [
        .library(name: "Sqlpipe", targets: ["Sqlpipe"]),
        .library(name: "CSqlpipe", targets: ["CSqlpipe"]),
    ],
    targets: [
        .target(
            name: "CSqlpipe",
            // sqldeep and sqlift are bundled into sqlpipe.cpp; the standalone
            // copies would duplicate their symbols. lp_lempar.c is a lemon
            // template #included by parse.c, not compiled on its own.
            exclude: [
                "sqldeep.cpp",
                "sqlift.cpp",
                "deepparser/lp_lempar.c",
            ],
            publicHeadersPath: "include",
            cSettings: [
                .define("SQLITE_ENABLE_SESSION"),
                .define("SQLITE_ENABLE_PREUPDATE_HOOK"),
                .define("SQLITE_ENABLE_DESERIALIZE"),
                // Resolve <liteparser.h> from the vendored deepparser sources.
                .headerSearchPath("deepparser"),
                .unsafeFlags(["-w"]),
            ],
            cxxSettings: [
                .define("SQLITE_ENABLE_SESSION"),
                .define("SQLITE_ENABLE_PREUPDATE_HOOK"),
                .define("SQLITE_ENABLE_DESERIALIZE"),
                .headerSearchPath("deepparser"),
                .unsafeFlags(["-w"]),
            ]
        ),
        .target(
            name: "Sqlpipe",
            dependencies: ["CSqlpipe"]
        ),
    ],
    cxxLanguageStandard: .cxx2b
)
