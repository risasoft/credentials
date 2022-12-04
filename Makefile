
PROTO_IN := proto
PROTO_OUT := pb
PROTO_DEPS := $(wildcard $(PROTO_IN)/*.proto)

.PHONY: all
all: protos
	go build .

.PHONY: protos
protos: $(PROTO_DEPS)
	protoc -I=./$(PROTO_IN) --go_out=paths=source_relative:$(PROTO_OUT) $(PROTO_DEPS)

.PHONY: test
test: protos
	go test

./cred-cli: cli/main.go
	go build -o cred-cli cli/main.go 
