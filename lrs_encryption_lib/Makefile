# Makefile for LRS Encryption

CC = gcc
CFLAGS = -O2 -Wall -Wextra
LDFLAGS = -lsodium

all: lrs_encryption lrs_wrapper_test

lrs_encryption: lrs_encryption.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

lrs_encryption_lib.o: lrs_encryption_lib.c
	$(CC) $(CFLAGS) -c $< -o $@

lrs_wrapper.o: lrs_wrapper.c
	$(CC) $(CFLAGS) -c $< -o $@

lrs_wrapper_test: lrs_wrapper_test.c lrs_wrapper.o lrs_encryption_lib.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f lrs_encryption lrs_wrapper_test *.o

test: lrs_encryption
	./lrs_encryption test

test-wrapper: lrs_wrapper_test
	./lrs_wrapper_test

.PHONY: all clean test test-wrapper