package bpf

//go:generate go tool bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -I./headers" Firewall firewall.c -- -D__TARGET_ARCH_x86
