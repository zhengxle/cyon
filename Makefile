# Cyon Makefile

CC=gcc

S_SRC=	src/cyon.c src/cluster.c src/connection.c src/net.c src/mem.c \
	src/shared.c src/store.c src/utils.c src/linux.c
S_OBJS=	$(S_SRC:.c=.o)

C_SRC=	src/cli.c src/shared.c
C_OBJS=	$(C_SRC:.c=.o)

CFLAGS+=-Wall -Wstrict-prototypes -Wmissing-prototypes
CFLAGS+=-Wmissing-declarations -Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+=-Wsign-compare -Iincludes -g
LDFLAGS+=-lssl -lcrypto

all:
	make cyon-server
	make cyon-cli

cyon-server: $(S_SRC)
	@CFLAGS="-DCYON_SERVER=1" OBJS="$(S_OBJS)" BIN=cyon-server make generic

cyon-cli: $(C_SRC)
	@BIN="cyon-cli" OBJS="$(C_OBJS)" make generic

generic: $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJS) -o $(BIN)

.c.o: $<
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f src/*.o cyon-server cyon-cli
