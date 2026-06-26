PROTO_DIR := proto
BIN_DIR   := bin

.PHONY: proto build run test tidy clean

## proto: regenerate Go bindings from proto/kb.proto.
## Requires: protoc, protoc-gen-go, protoc-gen-go-grpc on $PATH.
##   go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
##   go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
##
## NOTE: --go_out is the repo root (.), NOT $(PROTO_DIR). With
## paths=source_relative, protoc re-applies the input file's path
## (proto/kb.proto) on top of --go_out, so --go_out=proto would produce
## proto/proto/kb.pb.go instead of proto/kb.pb.go.
proto:
	protoc --go_out=. --go_opt=paths=source_relative \
	       --go-grpc_out=. --go-grpc_opt=paths=source_relative \
	       $(PROTO_DIR)/kb.proto

build:
	go build -o $(BIN_DIR)/kbd ./cmd/kbd

run:
	go run ./cmd/kbd

test:
	go test ./... -v

## tidy: pulls in google.golang.org/grpc (not yet in go.mod) and refreshes go.sum.
tidy:
	go mod tidy

clean:
	rm -rf $(BIN_DIR)