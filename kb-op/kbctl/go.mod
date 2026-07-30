module github.com/pardhuvarmax/kernel-borderlands/kb-op/kbctl

go 1.25.0

require (
	github.com/pardhuvarmax/kernel-borderlands/kb-control-plane v0.0.0
	github.com/spf13/cobra v1.10.2
	google.golang.org/grpc v1.82.0
)

require (
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/spf13/pflag v1.0.9 // indirect
	golang.org/x/net v0.53.0 // indirect
	golang.org/x/sys v0.43.0 // indirect
	golang.org/x/text v0.36.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260414002931-afd174a4e478 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)

replace github.com/pardhuvarmax/kernel-borderlands/kb-control-plane => ../../kb-control-plane
