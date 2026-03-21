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
            publicHeadersPath: "include",
            cSettings: [
                .define("SQLITE_ENABLE_SESSION"),
                .define("SQLITE_ENABLE_PREUPDATE_HOOK"),
                .define("SQLITE_ENABLE_DESERIALIZE"),
                .unsafeFlags(["-w"]),
            ],
            cxxSettings: [
                .define("SQLITE_ENABLE_SESSION"),
                .define("SQLITE_ENABLE_PREUPDATE_HOOK"),
                .define("SQLITE_ENABLE_DESERIALIZE"),
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
