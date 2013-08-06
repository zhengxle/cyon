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
#include <signal.h>
#include <unistd.h>

#include "cyon.h"

volatile sig_atomic_t	sig_recv;

struct listener		server;
char			*join_node;
extern const char	*__progname;
SSL_CTX			*ssl_ctx = NULL;
u_int64_t		last_store_write;

static void		usage(void);
static void		cyon_signal(int);
static void		cyon_ssl_init(void);
static void		cyon_server_bind(struct listener *, char *, u_int16_t);

static void
usage(void)
{
	fprintf(stderr, "Usage: %s [-b ip] [-p port]\n", __progname);
	exit(1);
}

int
main(int argc, char *argv[])
{
	char		*ip;
	u_int64_t	now;
	u_int16_t	port;
	int		ch, err;
	u_int8_t	foreground;

	port = 3331;
	foreground = 0;
	ip = "127.0.0.1";
	join_node = NULL;

	while ((ch = getopt(argc, argv, "b:fj:m:p:")) != -1) {
		switch (ch) {
		case 'b':
			ip = optarg;
			break;
		case 'f':
			foreground = 1;
			break;
		case 'j':
			join_node = optarg;
			break;
		case 'm':
			break;
		case 'p':
			port = cyon_strtonum(optarg, 1, 65535, &err);
			if (err != CYON_RESULT_OK)
				fatal("invalid port: %s", optarg);
			break;
		case '?':
		default:
			usage();
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

	cyon_log_init();
	cyon_mem_init();
	cyon_ssl_init();
	cyon_connection_init();
	cyon_server_bind(&server, ip, port);
	cyon_platform_event_init();

	if (foreground == 0 && daemon(1, 1) == -1)
		fatal("could not forkify(): %s", errno_s);

	cyon_store_init();

	sig_recv = 0;
	signal(SIGQUIT, cyon_signal);
	signal(SIGINT, cyon_signal);
	signal(SIGHUP, cyon_signal);
	signal(SIGPIPE, SIG_IGN);

	if (join_node != NULL) {
		if (!cyon_cluster_join(join_node))
			fatal("could not join cluster node %s", join_node);
	}

	last_store_write = cyon_time_ms();
	cyon_log(LOG_NOTICE, "server ready on %s:%d", ip, port);
	for (;;) {
		if (sig_recv == SIGQUIT) {
			sig_recv = 0;
			if (!cyon_store_write()) {
				cyon_log(LOG_ALERT,
				    "store error, continuing server");
				continue;
			}

			break;
		}

		now = cyon_time_ms();
		if ((now - last_store_write) >= CYON_STORE_WRITE_INTERVAL) {
			last_store_write = now;
			if (!cyon_store_write())
				cyon_log(LOG_WARNING, "could not write store");
			else
				cyon_log(LOG_NOTICE, "store saved to disk");
		}

		cyon_platform_event_wait();
		cyon_connection_prune();
	}

	cyon_connection_disconnect_all();
	cyon_log(LOG_NOTICE, "server stopped");

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
