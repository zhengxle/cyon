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

#include <sys/socket.h>
#include <sys/epoll.h>

#include <netdb.h>
#include <unistd.h>

#include "cyon.h"

static int		cyon_cluster_recv_op(struct netbuf *);

static TAILQ_HEAD(, connection)		nodes;
static SSL_CTX				*cluster_ctx;

void
cyon_cluster_init(void)
{
	TAILQ_INIT(&nodes);
}

void
cyon_cluster_join(const char *host)
{
	int			r;
	u_int8_t		*p;
	struct connection	*c;
	struct cyon_op		*op;
	SHA256_CTX		ctx;
	size_t			len, off;
	char			*pass, *port;
	struct addrinfo		*results, *res;
	u_char			hash[SHA256_DIGEST_LENGTH];

	if ((port = strchr(host, ':')) != NULL)
		*(port)++ = '\0';
	else
		port = "3331";

	r = getaddrinfo(host, port, NULL, &results);
	if (r != 0)
		fatal("%s: %s", host, gai_strerror(r));

	for (res = results; res->ai_next != NULL; res = res->ai_next) {
		if (res->ai_family == AF_INET &&
		    res->ai_socktype == SOCK_STREAM)
			break;
	}

	if (res == NULL)
		fatal("no usuable IP found for %s", host);

	c = cyon_malloc(sizeof(struct connection));
	c->sin = *(struct sockaddr_in *)res->ai_addr;
	if ((c->fd = socket(res->ai_family, res->ai_socktype, 0)) == -1)
		fatal("socket(): %s", errno_s);
	if (connect(c->fd, res->ai_addr, res->ai_addrlen) == -1)
		fatal("connect(): %s", errno_s);

	freeaddrinfo(results);

	cluster_ctx = SSL_CTX_new(SSLv3_method());
	if (cluster_ctx == NULL)
		fatal("SSL_CTX_new(): %s", ssl_errno_s);

	if ((c->ssl = SSL_new(cluster_ctx)) == NULL)
		fatal("SSL_new(): %s", ssl_errno_s);

	SSL_set_fd(c->ssl, c->fd);
	if (!SSL_connect(c->ssl))
		fatal("SSL_connect(): %s", ssl_errno_s);

	if ((pass = getpass("passphrase: ")) == NULL)
		fatal("could not read passphrase");

	SHA256_Init(&ctx);
	SHA256_Update(&ctx, pass, strlen(pass));
	SHA256_Final(hash, &ctx);
	memset(pass, '\0', strlen(pass));

	len = sizeof(struct cyon_op) + SHA256_DIGEST_LENGTH;
	p = cyon_malloc(len);

	op = (struct cyon_op *)p;
	op->op = CYON_OP_AUTH;
	net_write32((u_int8_t *)&(op->length), SHA256_DIGEST_LENGTH);
	memcpy(p + sizeof(struct cyon_op), hash, SHA256_DIGEST_LENGTH);

	if (SSL_write(c->ssl, p, len) <= 0)
		fatal("SSL_write(): %s", ssl_errno_s);

	off = 0;
	memset(p, 0, len);
	len = sizeof(struct cyon_op);
	while (off != len) {
		r = SSL_read(c->ssl, p + off, len - off);
		if (r <= 0)
			fatal("SSL_read(): %s", ssl_errno_s);
		off += r;
	}

	op = (struct cyon_op *)p;
	if (op->op != CYON_OP_RESULT_OK)
		fatal("Node %s denied access to join cluster", host);

	memset(op, 0, sizeof(struct cyon_op));
	op->op = CYON_OP_IMANODE;
	if (SSL_write(c->ssl, op, sizeof(struct cyon_op)) <= 0)
		fatal("SSL_write(): %s", ssl_errno_s);

	cyon_mem_free(p);

	if (!cyon_connection_nonblock(c->fd))
		fatal("cyon_connection_nonblock(): %s", errno_s);

	c->flags = 0;
	c->owner = NULL;
	c->state = CONN_STATE_ESTABLISHED;
	TAILQ_INIT(&(c->send_queue));
	TAILQ_INIT(&(c->recv_queue));

	cyon_cluster_node_register(c);
	cyon_platform_event_schedule(c->fd, EPOLLIN | EPOLLOUT | EPOLLET, 0, c);
}

void
cyon_cluster_node_register(struct connection *c)
{
	if (c->flags & CONN_IS_NODE)
		return;

	cyon_debug("new node arrived: %s", inet_ntoa(c->sin.sin_addr));

	c->flags |= CONN_IS_NODE;
	TAILQ_INSERT_TAIL(&nodes, c, list);

	net_recv_queue(c, sizeof(struct cyon_op), 0,
	    NULL, cyon_cluster_recv_op);
}

static int
cyon_cluster_recv_op(struct netbuf *nb)
{
	struct connection	*c = (struct connection *)nb->owner;

	cyon_debug("new node op arrived");

	net_recv_queue(c, sizeof(struct cyon_op), 0,
	    NULL, cyon_cluster_recv_op);

	return (CYON_RESULT_OK);
}
