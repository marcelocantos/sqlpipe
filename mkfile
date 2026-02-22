# ── Toolchain ────────────────────────────────────────────────────────
cc  = cc
cxx = c++ -std=c++20
ar  = ar

sqlite_flags = -DSQLITE_ENABLE_SESSION -DSQLITE_ENABLE_PREUPDATE_HOOK
cflags   = -w $sqlite_flags
cxxflags = -Wall -Wextra -Wpedantic $sqlite_flags

vendor   = vendor
incflags = -I. -I$vendor/include -I$vendor/github.com/gabime/spdlog/include

# ── Sources ──────────────────────────────────────────────────────────
test_srcs = $[wildcard tests/*.cpp]
test_objs = $[patsubst %.cpp,build/%.o,$test_srcs]

# ── Default target ───────────────────────────────────────────────────
build/libsqlpipe.a: build/sqlite3.o build/sqlpipe.o
    $ar rcs $target $inputs

# ── Tasks ────────────────────────────────────────────────────────────
!test: build/sqlpipe_tests
    ./$input

!example: build/loopback
    ./$input

!clean:
    rm -rf build/ .mk/

# ── Binaries ─────────────────────────────────────────────────────────
build/sqlpipe_tests: $test_objs build/libsqlpipe.a
    $cxx $cxxflags -o $target $inputs

build/loopback: build/examples/loopback.o build/libsqlpipe.a
    $cxx $cxxflags -o $target $inputs

# ── Compilation rules ────────────────────────────────────────────────
build/sqlite3.o: $vendor/src/sqlite3.c
    $cc $cflags -c $input -o $target

build/sqlpipe.o: sqlpipe.cpp
    $cxx $cxxflags $incflags -c $input -o $target

build/tests/{name}.o: tests/{name}.cpp
    $cxx $cxxflags $incflags -c $input -o $target

build/examples/{name}.o: examples/{name}.cpp
    $cxx $cxxflags $incflags -c $input -o $target
