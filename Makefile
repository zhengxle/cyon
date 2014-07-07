# Cyon Makefile

CC=gcc
INSTALL_DIR=/usr/local/bin
INCLUDE_DIR=/usr/local/include/cyon

S_SRC=	src/cyon.c src/connection.c src/net.c src/mem.c \
	src/shared.c src/store.c src/utils.c src/linux.c src/pool.c \
	src/threads.c
S_OBJS=	$(S_SRC:.c=.o)

C_SRC=	src/cmd.c src/shared.c
C_OBJS=	$(C_SRC:.c=.o)

CFLAGS+=-Wall -Wstrict-prototypes -Wmissing-prototypes
CFLAGS+=-Wmissing-declarations -Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+=-Wsign-compare -Iincludes -g
LDFLAGS+=-lpthread -lssl -lcrypto

all:
	make cyon-server
	rm -f src/shared.o
	make cyon-cmd

cyon-server: $(S_SRC)
	@CFLAGS="-DCYON_SERVER=1" OBJS="$(S_OBJS)" BIN=cyon-server make generic

cyon-cmd: $(C_SRC)
	@BIN="cyon-cmd" OBJS="$(C_OBJS)" make generic

generic: $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $(BIN) $(LDFLAGS)

.c.o: $<
	$(CC) $(CFLAGS) -c $< -o $@

install: cyon-server cyon-cmd
	mkdir -p $(INCLUDE_DIR)
	install -m 555 cyon-server $(INSTALL_DIR)/cyon-server
	install -m 555 cyon-cmd $(INSTALL_DIR)/cyon-cmd
	install -m 644 includes/*.h $(INCLUDE_DIR)

uninstall:
	rm -f $(INSTALL_DIR)/cyon-server
	rm -f $(INSTALL_DIR)/cyon-cmd
	rm -rf $(INCLUDE_DIR)

clean:
	rm -f src/*.o cyon-server cyon-cmd
