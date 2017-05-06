CFLAGS=-fPIC -g -std=c99 -Werror

all: libsmkex.so

libsmkex.so: libsmkex.o pkt.o crypto.o
	$(CC) -shared -o $@ $^ -ldl -lcrypto -lssl

.PHONY: clean
clean:
	rm -vf libsmkex.so *.o
