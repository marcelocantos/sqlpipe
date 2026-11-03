# Local dependency patches

`sqlift-postgres.patch` preserves the sqlift Postgres executor and borrowed
SQLite handle implementation already distributed in sqlpipe commit
`dda1ae8`. Its baseline is the pinned sqlift commit
`8c5e15760fe350e96532a90d3aa3c68bf0c7b6d5` (v0.18.0).

`scripts/bundle-deps.sh` applies this patch after copying upstream sources,
then generates the distribution and wrapper copies. Updating the sqlift
submodule requires rebasing or removing this patch explicitly; do not drop
the bundled implementation by regenerating from unpatched upstream.
