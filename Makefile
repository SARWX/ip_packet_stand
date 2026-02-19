# Простой Makefile
CC = gcc
CFLAGS = -Wall -g
LDFLAGS = -lparsec-base -lparsec-mac

all: server client simple_client

server: server.c
	$(CC) $(CFLAGS) -o server server.c $(LDFLAGS)

client: client.c
	$(CC) $(CFLAGS) -o client client.c $(LDFLAGS)

simple_client: simple_client.c
	$(CC) $(CFLAGS) -o simple_client simple_client.c

clean:
	rm -f server client simple_client

# Попытка установить метки (если есть pdpl-file)
labels:
	-sudo pdpl-file 0:0 server 2>/dev/null
	-sudo pdpl-file 0:0 client 2>/dev/null
	@echo "Попытка установки меток завершена"

.PHONY: all clean labels