CFLAGS=-g

all: client server

client: client.o
	$(CC) -o $@ $<

server: server.o
	$(CC) -o $@ $<

clean:
	rm -vf *.o client server

