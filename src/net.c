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

#include "cyon.h"

void
net_send_queue(struct connection *c, u_int8_t *data, size_t len, int flags,
    struct netbuf **out, int (*cb)(struct netbuf *))
{
	struct netbuf		*nb;

	nb = (struct netbuf *)cyon_malloc(sizeof(*nb));
	nb->cb = cb;
	nb->len = len;
	nb->owner = c;
	nb->offset = 0;
	nb->flags = flags;
	nb->type = NETBUF_SEND;

	if (len > 0) {
		if (flags & NETBUF_USE_DATA_DIRECT) {
			nb->buf = data;
		} else {
			nb->buf = (u_int8_t *)cyon_malloc(nb->len);
			memcpy(nb->buf, data, nb->len);
		}
	} else {
		nb->buf = NULL;
	}

	TAILQ_INSERT_TAIL(&(c->send_queue), nb, list);
	if (out != NULL)
		*out = nb;
}

void
net_recv_queue(struct connection *c, size_t len, int flags,
    struct netbuf **out, int (*cb)(struct netbuf *))
{
	struct netbuf		*nb;

	nb = (struct netbuf *)cyon_malloc(sizeof(*nb));
	nb->cb = cb;
	nb->len = len;
	nb->owner = c;
	nb->offset = 0;
	nb->flags = flags;
	nb->type = NETBUF_RECV;
	nb->buf = (u_int8_t *)cyon_malloc(nb->len);

	TAILQ_INSERT_TAIL(&(c->recv_queue), nb, list);
	if (out != NULL)
		*out = nb;
}

int
net_recv_expand(struct connection *c, struct netbuf *nb, size_t len,
    int (*cb)(struct netbuf *))
{
	if (nb->type != NETBUF_RECV) {
		cyon_debug("net_recv_expand(): wrong netbuf type");
		return (CYON_RESULT_ERROR);
	}

	nb->cb = cb;
	nb->len += len;
	nb->buf = (u_int8_t *)cyon_realloc(nb->buf, nb->len);

	TAILQ_REMOVE(&(c->recv_queue), nb, list);
	TAILQ_INSERT_HEAD(&(c->recv_queue), nb, list);

	return (CYON_RESULT_OK);
}

int
net_send(struct connection *c)
{
	int			r;
	struct netbuf		*nb;

	while (!TAILQ_EMPTY(&(c->send_queue))) {
		nb = TAILQ_FIRST(&(c->send_queue));
		if (nb->len == 0) {
			cyon_debug("net_send(): len is 0");
			return (CYON_RESULT_ERROR);
		}

		r = SSL_write(c->ssl,
		    (nb->buf + nb->offset), (nb->len - nb->offset));

		cyon_debug("net_send(%ld/%ld bytes), progress with %d",
		    nb->offset, nb->len, r);

		if (r <= 0) {
			r = SSL_get_error(c->ssl, r);
			switch (r) {
			case SSL_ERROR_WANT_READ:
			case SSL_ERROR_WANT_WRITE:
				c->flags &= ~CONN_WRITE_POSSIBLE;
				return (CYON_RESULT_OK);
			default:
				cyon_debug("SSL_write(): %s", ssl_errno_s);
				return (CYON_RESULT_ERROR);
			}
		}

		nb->offset += (size_t)r;
		if (nb->offset == nb->len) {
			TAILQ_REMOVE(&(c->send_queue), nb, list);

			if (nb->cb != NULL)
				r = nb->cb(nb);
			else
				r = CYON_RESULT_OK;

			if (nb->offset == nb->len) {
				if (nb->buf != NULL &&
				    !(nb->flags & NETBUF_USE_DATA_DIRECT))
					cyon_mem_free(nb->buf);
				cyon_mem_free(nb);
			}

			if (r != CYON_RESULT_OK)
				return (r);
		}
	}

	return (CYON_RESULT_OK);
}

int
net_send_flush(struct connection *c)
{
	cyon_debug("net_send_flush(%p)", c);

	while (!TAILQ_EMPTY(&(c->send_queue)) &&
	    (c->flags & CONN_WRITE_POSSIBLE)) {
		if (!net_send(c))
			return (CYON_RESULT_ERROR);
	}

	return (CYON_RESULT_OK);
}

int
net_recv(struct connection *c)
{
	int			r;
	struct netbuf		*nb;

	while (!TAILQ_EMPTY(&(c->recv_queue))) {
		nb = TAILQ_FIRST(&(c->recv_queue));
		if (nb->cb == NULL) {
			cyon_debug("cyon_read_client(): nb->cb == NULL");
			return (CYON_RESULT_ERROR);
		}

		r = SSL_read(c->ssl,
		    (nb->buf + nb->offset), (nb->len - nb->offset));

		cyon_debug("net_recv(%ld/%ld bytes), progress with %d",
		    nb->offset, nb->len, r);

		if (r <= 0) {
			r = SSL_get_error(c->ssl, r);
			switch (r) {
			case SSL_ERROR_WANT_READ:
			case SSL_ERROR_WANT_WRITE:
				c->flags &= ~CONN_READ_POSSIBLE;
				return (CYON_RESULT_OK);
			default:
				cyon_debug("SSL_read(): %s", ssl_errno_s);
				return (CYON_RESULT_ERROR);
			}
		}

		nb->offset += (size_t)r;
		if (nb->offset == nb->len) {
			r = nb->cb(nb);
			if (nb->offset == nb->len) {
				TAILQ_REMOVE(&(c->recv_queue), nb, list);

				cyon_mem_free(nb->buf);
				cyon_mem_free(nb);
			}

			if (r != CYON_RESULT_OK)
				return (r);
		}
	}

	return (CYON_RESULT_OK);
}

int
net_recv_flush(struct connection *c)
{
	cyon_debug("net_recv_flush(%p)", c);

	while (!TAILQ_EMPTY(&(c->recv_queue)) &&
	    (c->flags & CONN_READ_POSSIBLE)) {
		if (!net_recv(c))
			return (CYON_RESULT_ERROR);
	}

	return (CYON_RESULT_OK);
}
