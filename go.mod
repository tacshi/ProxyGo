module proxygo

go 1.27.3

tool github.com/egoist/mygo/cmd/mygo

require (
	github.com/andybalholm/brotli v1.2.6
	github.com/bufbuild/protocompile v0.14.1
	github.com/dop251/goja v0.0.0-20261020172427-7b1a02208696
	github.com/ebitengine/purego v0.11.1
	github.com/egoist/mygo v0.6.2
	github.com/egoist/mygo/proxygoui v0.0.0
	github.com/itchyny/gojq v0.12.19
	github.com/klauspost/compress v1.20.3
	github.com/modelcontextprotocol/go-sdk v1.8.0
	github.com/theory/jsonpath v0.12.2
	go.yaml.in/yaml/v3 v3.0.5
	golang.org/x/net v0.60.0
	golang.org/x/sys v0.49.0
	google.golang.org/protobuf v1.36.12
	software.sslmate.com/src/go-pkcs12 v0.7.4
)

require (
	github.com/dlclark/regexp2/v2 v2.8.1 // indirect
	github.com/go-sourcemap/sourcemap v2.1.3+incompatible // indirect
	github.com/go-text/typesetting v0.3.5 // indirect
	github.com/google/jsonschema-go v0.4.3 // indirect
	github.com/google/pprof v0.0.0-20230207041349-798e818bf904 // indirect
	github.com/itchyny/timefmt-go v0.1.8 // indirect
	github.com/segmentio/asm v1.1.3 // indirect
	github.com/segmentio/encoding v0.5.4 // indirect
	github.com/yosida95/uritemplate/v3 v3.0.2 // indirect
	golang.org/x/crypto v0.58.0 // indirect
	golang.org/x/image v0.46.0 // indirect
	golang.org/x/oauth2 v0.35.0 // indirect
	golang.org/x/sync v0.24.0 // indirect
	golang.org/x/text v0.43.0 // indirect
	golang.org/x/time v0.15.0 // indirect
)

// MyGo's ui package, with ProxyGo's patches: see third_party/mygo-ui/UPSTREAM.md.
replace github.com/egoist/mygo/proxygoui => ./third_party/mygo-ui
