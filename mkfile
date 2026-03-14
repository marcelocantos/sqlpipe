# ── Toolchain ────────────────────────────────────────────────────────
cc  = cc
cxx = c++ -std=c++23
ar  = ar

sqlite_flags = -DSQLITE_ENABLE_SESSION -DSQLITE_ENABLE_PREUPDATE_HOOK -DSQLITE_ENABLE_DESERIALIZE
cflags   = -w $sqlite_flags
cxxflags = -Wall -Wextra -Wpedantic $sqlite_flags

vendor   = vendor
sqldeep  = ../sqldeep
incflags = -Idist -I$vendor/include

# ── Sources ──────────────────────────────────────────────────────────
test_srcs = tests/doctest_main.cpp $[wildcard tests/test_*.cpp]
test_objs = $[patsubst %.cpp,build/%.o,$test_srcs]

# ── Default target ───────────────────────────────────────────────────
build/libsqlpipe.a: build/sqlite3.o build/lz4.o build/sqlift.o build/sqlpipe.o
    $ar rcs $target $inputs

# ── Tasks ────────────────────────────────────────────────────────────
!test: build/sqlpipe_tests
    ./$input

!example: build/loopback
    ./$input

!fuzz: build/fuzz_deserialize
    mkdir -p corpus/deserialize
    ./$input corpus/deserialize -max_total_time=60

!wasm: build/wasm/sqlpipe.js

!clean:
    rm -rf build/ .mk/

# ── Binaries ─────────────────────────────────────────────────────────
build/sqlpipe_tests: $test_objs build/libsqlpipe.a
    $cxx $cxxflags -o $target $inputs

build/loopback: build/examples/loopback.o build/libsqlpipe.a
    $cxx $cxxflags -o $target $inputs

build/fuzz_deserialize: build/tests/fuzz_deserialize.o build/libsqlpipe.a
    $cxx $cxxflags -fsanitize=fuzzer,address -o $target $inputs

build/tests/fuzz_deserialize.o: tests/fuzz_deserialize.cpp
    $cxx $cxxflags $incflags -fsanitize=fuzzer,address -c $input -o $target

# ── Wasm (Emscripten) ──────────────────────────────────────────
wasm_emflags = -sMODULARIZE=1 -sEXPORT_NAME=createSqlpipeModule \
    -sEXPORTED_RUNTIME_METHODS='["cwrap","ccall","getValue","setValue","UTF8ToString","stringToUTF8","stringToUTF8OnStack","lengthBytesUTF8","stackAlloc","stackSave","stackRestore","addFunction","removeFunction","HEAPU8"]' \
    -sEXPORTED_FUNCTIONS='["_malloc","_free"]' \
    -sALLOW_TABLE_GROWTH -sINITIAL_MEMORY=16777216 -sALLOW_MEMORY_GROWTH=1 \
    -sSTACK_SIZE=1048576 -sDISABLE_EXCEPTION_CATCHING=0

build/wasm/sqlpipe.js: build/wasm/sqlpipe_wapi.o build/wasm/sqldeep_wapi.o build/wasm/sqldeep.o build/wasm/sqlpipe.o build/wasm/sqlift.o build/wasm/sqlite3.o build/wasm/lz4.o
    em++ -std=c++23 $wasm_emflags -o $target $inputs

build/wasm/sqlpipe_wapi.o: web/sqlpipe_wapi.cpp
    em++ -std=c++23 $cxxflags $incflags -c $input -o $target

build/wasm/sqldeep_wapi.o: web/sqldeep_wapi.cpp
    em++ -std=c++20 -I$sqldeep/dist -c $input -o $target

build/wasm/sqldeep.o: $sqldeep/dist/sqldeep.cpp
    em++ -std=c++20 -I$sqldeep/dist -Wall -Wextra -Wpedantic -c $input -o $target

build/wasm/sqlpipe.o: dist/sqlpipe.cpp
    em++ -std=c++23 $cxxflags $incflags -c $input -o $target

build/wasm/sqlift.o: $vendor/src/sqlift.cpp
    em++ -std=c++23 $cxxflags $incflags -c $input -o $target

build/wasm/sqlite3.o: $vendor/src/sqlite3.c
    emcc $cflags -c $input -o $target

build/wasm/lz4.o: $vendor/src/lz4.c
    emcc $cflags -I$vendor/include -c $input -o $target

# ── Compilation rules ────────────────────────────────────────────────
build/sqlite3.o: $vendor/src/sqlite3.c
    $cc $cflags -c $input -o $target

build/lz4.o: $vendor/src/lz4.c
    $cc $cflags -I$vendor/include -c $input -o $target

build/sqlift.o: $vendor/src/sqlift.cpp
    $cxx $cxxflags $incflags -c $input -o $target

build/sqlpipe.o: dist/sqlpipe.cpp
    $cxx $cxxflags $incflags -c $input -o $target

build/tests/{name}.o: tests/{name}.cpp
    $cxx $cxxflags $incflags -c $input -o $target

build/examples/{name}.o: examples/{name}.cpp
    $cxx $cxxflags $incflags -c $input -o $target
