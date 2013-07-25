/*
 * Copyright (c) 2013 Joris Vink <joris@coders.se>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <fcntl.h>

#include "cyon.h"

struct member {
	u_int64_t		offset;
	u_int32_t		length;
	u_int8_t		*cksum;
	struct member		**next;
} __attribute__((__packed__));

volatile sig_atomic_t	sig_recv;

struct listener		server;
SSL_CTX			*ssl_ctx = NULL;
u_int64_t		last_store_write;

static void		cyon_signal(int);
static void		cyon_ssl_init(void);
static void		cyon_server_bind(struct listener *, char *, u_int16_t);

int
main(int argc, char *argv[])
{
	u_int64_t	now;

	cyon_mem_init();
	cyon_ssl_init();
	cyon_connection_init();
	cyon_server_bind(&server, "127.0.0.1", 3331);
	cyon_platform_event_init();
	cyon_store_init();

	sig_recv = 0;
	signal(SIGQUIT, cyon_signal);

	last_store_write = cyon_time_ms();
	cyon_debug("cyond: ready");
	for (;;) {
		if (sig_recv == SIGQUIT)
			break;

		now = cyon_time_ms();
		if ((now - last_store_write) >= CYON_STORE_WRITE_INTERVAL) {
			last_store_write = now;
			if (!cyon_store_write())
				cyon_debug("could not write store");
			else
				cyon_debug("store saved to disk");
		}

		cyon_platform_event_wait();
		cyon_connection_prune();
	}

	return (0);
}

static void
cyon_ssl_init(void)
{
	SSL_library_init();
	SSL_load_error_strings();

	ssl_ctx = SSL_CTX_new(SSLv23_server_method());
	if (ssl_ctx == NULL)
		fatal("cyon_ssl_init(): SSL_CTX_new(): %s", ssl_errno_s);

	if (!SSL_CTX_use_certificate_chain_file(ssl_ctx, "cert/server.crt"))
		fatal("SSL_CTX_use_certificate_chain_file(): %s", ssl_errno_s);

	if (!SSL_CTX_use_PrivateKey_file(ssl_ctx,
	    "cert/server.key", SSL_FILETYPE_PEM))
		fatal("SSL_CTX_use_PrivateKey_file(): %s", ssl_errno_s);

	if (!SSL_CTX_check_private_key(ssl_ctx))
		fatal("Public/Private key mismatch");

	SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_SSLv2);
	SSL_CTX_set_mode(ssl_ctx, SSL_MODE_RELEASE_BUFFERS);
	SSL_CTX_set_mode(ssl_ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);

	cyon_debug("ssl initialized");
}

static void
cyon_server_bind(struct listener *l, char *ip, u_int16_t port)
{
	int	on;

	if ((l->fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
		fatal("socket(): %s", errno_s);
	if (!cyon_connection_nonblock(l->fd))
		fatal("cyon_connection_nonblock(): %s", errno_s);

	on = 1;
	if (setsockopt(l->fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&on,
	    sizeof(on)) == -1)
		fatal("setsockopt(): %s", errno_s);

	memset(&(l->sin), 0, sizeof(l->sin));
	l->sin.sin_family = AF_INET;
	l->sin.sin_port = htons(port);
	l->sin.sin_addr.s_addr = inet_addr(ip);

	if (bind(l->fd, (struct sockaddr *)&(l->sin), sizeof(l->sin)) == -1)
		fatal("bind(): %s", errno_s);
	if (listen(l->fd, 10) == -1)
		fatal("listen(): %s", errno_s);
}

static void
cyon_signal(int sig)
{
	sig_recv = sig;
}
