
PROTO_IN := proto
PROTO_OUT := pb
PROTO_DEPS := $(wildcard $(PROTO_IN)/*.proto)
protos: $(PROTO_DEPS)
	protoc -I=./$(PROTO_IN) --go_out=paths=source_relative:$(PROTO_OUT) $(PROTO_DEPS)

test: protos
	go test

