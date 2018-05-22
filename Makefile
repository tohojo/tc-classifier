CC := clang
LD := llc
KERNEL_DIR := $(HOME)/build/linux-cake
CFLAGS := -O2 -g -Wall -target bpf -c

tc-classifier.o: tc-classifier.c

clean: tc-classifier.o
	rm -f tc-classifier.o
