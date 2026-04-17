BPF_CLANG=clang
BPF_CFLAGS=-O2 -g -target bpf -I/usr/include/$(shell uname -m)-linux-gnu

all: build

build: ebpf/program.o go-build

ebpf/program.o: ebpf/program.c
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@

go-build:
	go mod tidy
	go build -o observer main.go

run: build
	sudo ./observer

clean:
	rm -f ebpf/*.o observer