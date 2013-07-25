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
#include <sys/socket.h>

#include <endian.h>
#include <fcntl.h>
#include <unistd.h>

#include "cyon.h"

static int		cyon_connection_recv_op(struct netbuf *);
static int		cyon_connection_recv_put(struct netbuf *);
static int		cyon_connection_recv_get(struct netbuf *);
static void		cyon_connection_recv_stats(struct connection *);
static void		cyon_connection_recv_write(struct connection *);

static TAILQ_HEAD(, connection)		disconnected;
static TAILQ_HEAD(, connection)		clients;

void
cyon_connection_init(void)
{
	TAILQ_INIT(&disconnected);
	TAILQ_INIT(&clients);
}

int
cyon_connection_accept(struct listener *l, struct connection **out)
{
	socklen_t		len;
	struct connection	*c;

	cyon_debug("cyon_connection_accept(%p)", l);

	*out = NULL;
	len = sizeof(struct sockaddr_in);
	c = (struct connection *)cyon_malloc(sizeof(*c));
	if ((c->fd = accept(l->fd, (struct sockaddr *)&(c->sin), &len)) == -1) {
		cyon_mem_free(c);
		cyon_debug("accept(): %s", errno_s);
		return (CYON_RESULT_ERROR);
	}

	if (!cyon_connection_nonblock(c->fd)) {
		close(c->fd);
		cyon_mem_free(c);
		return (CYON_RESULT_ERROR);
	}

	c->owner = l;
	c->ssl = NULL;
	c->flags = 0;
	c->state = CONN_STATE_SSL_SHAKE;

	TAILQ_INIT(&(c->send_queue));
	TAILQ_INIT(&(c->recv_queue));
	TAILQ_INSERT_TAIL(&clients, c, list);

	*out = c;
	return (CYON_RESULT_OK);
}

void
cyon_connection_disconnect(struct connection *c)
{
	if (c->state != CONN_STATE_DISCONNECTING) {
		cyon_debug("preparing %p for disconnection", c);
		c->state = CONN_STATE_DISCONNECTING;

		TAILQ_REMOVE(&clients, c, list);
		TAILQ_INSERT_TAIL(&disconnected, c, list);
	}
}

int
cyon_connection_handle(struct connection *c)
{
	int			r;

	cyon_debug("cyon_connection_handle(%p)", c);

	switch (c->state) {
	case CONN_STATE_SSL_SHAKE:
		if (c->ssl == NULL) {
			c->ssl = SSL_new(ssl_ctx);
			if (c->ssl == NULL) {
				cyon_debug("SSL_new(): %s", ssl_errno_s);
				return (CYON_RESULT_ERROR);
			}

			SSL_set_fd(c->ssl, c->fd);
			SSL_set_accept_state(c->ssl);
		}

		r = SSL_accept(c->ssl);
		if (r <= 0) {
			r = SSL_get_error(c->ssl, r);
			switch (r) {
			case SSL_ERROR_WANT_READ:
			case SSL_ERROR_WANT_WRITE:
				return (CYON_RESULT_OK);
			default:
				cyon_debug("SSL_accept(): %s", ssl_errno_s);
				return (CYON_RESULT_ERROR);
			}
		}

		r = SSL_get_verify_result(c->ssl);
		if (r != X509_V_OK) {
			cyon_debug("SSL_get_verify_result(): %s", ssl_errno_s);
			return (CYON_RESULT_ERROR);
		}

		net_recv_queue(c, sizeof(struct cyon_op), 0,
		    NULL, cyon_connection_recv_op);

		c->state = CONN_STATE_ESTABLISHED;
		/* FALLTHROUGH */
	case CONN_STATE_ESTABLISHED:
		if (c->flags & CONN_READ_POSSIBLE) {
			if (!net_recv_flush(c))
				return (CYON_RESULT_ERROR);
		}

		if (c->flags & CONN_WRITE_POSSIBLE) {
			if (!net_send_flush(c))
				return (CYON_RESULT_ERROR);
		}
		break;
	case CONN_STATE_DISCONNECTING:
		break;
	default:
		cyon_debug("unknown state on %d (%d)", c->fd, c->state);
		break;
	}

	return (CYON_RESULT_OK);
}

void
cyon_connection_remove(struct connection *c)
{
	struct netbuf		*nb, *next;

	cyon_debug("cyon_connection_remove(%p)", c);

	if (c->ssl != NULL)
		SSL_free(c->ssl);
	close(c->fd);

	for (nb = TAILQ_FIRST(&(c->send_queue)); nb != NULL; nb = next) {
		next = TAILQ_NEXT(nb, list);
		TAILQ_REMOVE(&(c->send_queue), nb, list);
		if (nb->buf != NULL)
			cyon_mem_free(nb->buf);
		cyon_mem_free(nb);
	}

	for (nb = TAILQ_FIRST(&(c->recv_queue)); nb != NULL; nb = next) {
		next = TAILQ_NEXT(nb, list);
		TAILQ_REMOVE(&(c->recv_queue), nb, list);
		cyon_mem_free(nb->buf);
		cyon_mem_free(nb);
	}

	cyon_mem_free(c);
}

void
cyon_connection_prune(void)
{
	struct connection	*c, *next;

	for (c = TAILQ_FIRST(&disconnected); c != NULL; c = next) {
		next = TAILQ_NEXT(c, list);
		TAILQ_REMOVE(&disconnected, c, list);
		cyon_connection_remove(c);
	}
}

int
cyon_connection_nonblock(int fd)
{
	int		flags;

	if ((flags = fcntl(fd, F_GETFL, 0)) == -1) {
		cyon_debug("fcntl(): F_GETFL %s", errno_s);
		return (CYON_RESULT_ERROR);
	}

	flags |= O_NONBLOCK;
	if (fcntl(fd, F_SETFL, flags) == -1) {
		cyon_debug("fcntl(): F_SETFL %s", errno_s);
		return (CYON_RESULT_ERROR);
	}

	return (CYON_RESULT_OK);
}

static int
cyon_connection_recv_op(struct netbuf *nb)
{
	int			r;
	u_int32_t		len;
	struct cyon_op		*op = (struct cyon_op *)nb->buf;
	struct connection	*c = (struct connection *)nb->owner;

	r = CYON_RESULT_ERROR;
	len = net_read32((u_int8_t *)&(op->length));
	cyon_debug("cyon_connection_recv_op(): %d (len: %d)", op->op, len);

	switch (op->op) {
	case CYON_OP_PUT:
		r = net_recv_expand(c, nb, len, cyon_connection_recv_put);
		break;
	case CYON_OP_GET:
		r = net_recv_expand(c, nb, len, cyon_connection_recv_get);
		break;
	case CYON_OP_WRITE:
		r = CYON_RESULT_OK;
		cyon_connection_recv_write(c);
		break;
	case CYON_OP_STATS:
		r = CYON_RESULT_OK;
		cyon_connection_recv_stats(c);
		break;
	default:
		cyon_debug("unknown cyon_op %d", op->op);
		break;
	}

	net_recv_queue(c, sizeof(struct cyon_op), 0,
	    NULL, cyon_connection_recv_op);

	return (r);
}

static int
cyon_connection_recv_put(struct netbuf *nb)
{
	struct cyon_op		ret;
	u_int32_t		dlen, klen;
	u_int8_t		*key, *data;
	struct connection	*c = (struct connection *)nb->owner;

	klen = net_read32(nb->buf + sizeof(struct cyon_op));
	dlen = net_read32(nb->buf + sizeof(struct cyon_op) + sizeof(u_int32_t));

	key = nb->buf + sizeof(struct cyon_op) + (sizeof(u_int32_t) * 2);
	data = key + klen;

	if (cyon_store_put(key, klen, data, dlen))
		ret.op = CYON_OP_RESULT_OK;
	else
		ret.op = CYON_OP_RESULT_ERROR;

	ret.length = 0;
	net_send_queue(c, (u_int8_t *)&ret, sizeof(ret), 0, NULL, NULL);

	return (CYON_RESULT_OK);
}

static int
cyon_connection_recv_get(struct netbuf *nb)
{
	struct cyon_op		ret, *op;
	u_int32_t		klen, dlen;
	u_int8_t		*key, *data;
	struct connection	*c = (struct connection *)nb->owner;

	op = (struct cyon_op *)nb->buf;
	klen = net_read32((u_int8_t *)&(op->length));
	key = nb->buf + sizeof(struct cyon_op);

	if (cyon_store_get(key, klen, &data, &dlen)) {
		ret.op = CYON_OP_RESULT_OK;
		net_write32((u_int8_t *)&(ret.length), dlen);

		net_send_queue(c, (u_int8_t *)&ret, sizeof(ret), 0, NULL, NULL);
		net_send_queue(c, data, dlen,
		    NETBUF_USE_DATA_DIRECT, NULL, NULL);
	} else {
		ret.op = CYON_OP_RESULT_ERROR;
		net_write32((u_int8_t *)&(ret.length), 0);
		net_send_queue(c, (u_int8_t *)&ret, sizeof(ret), 0, NULL, NULL);
	}

	return (CYON_RESULT_OK);
}

static void
cyon_connection_recv_write(struct connection *c)
{
	struct cyon_op		ret;

	last_store_write = cyon_time_ms();
	net_write32((u_int8_t *)&(ret.length), 0);

	if (cyon_store_write())
		ret.op = CYON_OP_RESULT_OK;
	else
		ret.op = CYON_OP_RESULT_ERROR;

	net_send_queue(c, (u_int8_t *)&ret, sizeof(ret), 0, NULL, NULL);
}

static void
cyon_connection_recv_stats(struct connection *c)
{
	struct cyon_op		ret;
	struct cyon_stats	stats;

	ret.op = CYON_OP_RESULT_OK;
	net_write32((u_int8_t *)&(ret.length), sizeof(struct cyon_stats));

	stats.keycount = htobe64(key_count);
	net_write32((u_int8_t *)&(stats.meminuse), meminuse);

	net_send_queue(c, (u_int8_t *)&ret, sizeof(ret), 0, NULL, NULL);
	net_send_queue(c, (u_int8_t *)&stats, sizeof(stats), 0, NULL, NULL);
}