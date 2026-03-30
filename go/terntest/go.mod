module github.com/marcelocantos/sqlpipe/go/terntest

go 1.25.7

require (
	github.com/marcelocantos/sqlpipe/go/sqlpipe v0.15.0
	github.com/marcelocantos/tern v0.0.0
)

require (
	github.com/dunglas/httpsfv v1.1.0 // indirect
	github.com/pierrec/lz4/v4 v4.1.25 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/quic-go/quic-go v0.59.0 // indirect
	github.com/quic-go/webtransport-go v0.10.0 // indirect
	golang.org/x/crypto v0.49.0 // indirect
	golang.org/x/net v0.51.0 // indirect
	golang.org/x/sys v0.42.0 // indirect
	golang.org/x/text v0.35.0 // indirect
)

replace (
	github.com/marcelocantos/sqlpipe/go/sqlpipe => ../sqlpipe
	github.com/marcelocantos/tern => ../../../tern
)
