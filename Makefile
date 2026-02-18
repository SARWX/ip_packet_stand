CC = gcc
CFLAGS = -Wall -g
LDFLAGS = -lparsec

all: sender receiver

sender: sender.c
	$(CC) $(CFLAGS) -o sender sender.c $(LDFLAGS)

receiver: receiver.c
	$(CC) $(CFLAGS) -o receiver receiver.c $(LDFLAGS)

clean:
	rm -f sender receiver *.o

.PHONY: all clean