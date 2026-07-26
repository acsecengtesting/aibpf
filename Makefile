.PHONY: all clean bpf cli proxy test

CLANG ?= clang
CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_x86
GO := go

BPF_SRC := $(wildcard bpf/*.c)
BPF_OBJ := $(BPF_SRC:.c=.o)

all: bpf cli proxy

bpf: $(BPF_OBJ)

bpf/%.o: bpf/%.c
	$(CLANG) $(CFLAGS) -c $< -o $@

cli:
	$(GO) build -o bin/aibpf ./cmd/aibpf

proxy:
	$(GO) build -o bin/aibpf-proxy ./cmd/proxy

test:
	$(GO) test ./...

clean:
	rm -f bpf/*.o bin/*

install: all
	cp bin/aibpf /usr/local/bin/
	cp bin/aibpf-proxy /usr/local/bin/
