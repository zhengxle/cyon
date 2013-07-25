# Cyon Makefile

CC=gcc
BIN=cyon-server
C_BIN=cyon-client

S_SRC=	src/cyon.c src/connection.c src/net.c src/mem.c \
	src/store.c src/utils.c src/linux.c
S_OBJS=	$(S_SRC:.c=.o)

C_SRC=	src/client.c
C_OBJS=	$(C_SRC:.c=.o)

CFLAGS+=-Wall -Wstrict-prototypes -Wmissing-prototypes
CFLAGS+=-Wmissing-declarations -Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+=-Wsign-compare -Iincludes -g
LDFLAGS=-lssl -lcrypto

all:
	make clean
	make cyon-server
	make cyon-client

cyon-server: $(S_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(S_OBJS) -o $(BIN)

cyon-client: $(C_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(C_OBJS) -o $(C_BIN)

.c.o: $<
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f src/*.o $(BIN) $(C_BIN)
