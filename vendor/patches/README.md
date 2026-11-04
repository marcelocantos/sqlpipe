# Local dependency patches

None. Postgres extract, parse-on, diff, and apply live in the sqlift
submodule (`sqlift_db_wrap_exec`). `scripts/bundle-deps.sh` copies
`dist/sqlift.h` and `dist/sqlift.cpp` directly. Do not reintroduce a
patch that forks that API.
