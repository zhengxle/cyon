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

#include "cyon.h"

void
net_send_queue(struct connection *c, u_int8_t *data, u_int32_t len)
{
	struct netbuf		*nb;
	u_int32_t		avail;

	nb = TAILQ_LAST(&(c->send_queue), netbuf_head);
	if (nb != NULL && nb->b_len < nb->m_len) {
		avail = nb->m_len - nb->b_len;
		if (len < avail) {
			memcpy(nb->buf + nb->b_len, data, len);
			nb->b_len += len;
			return;
		} else if (len > avail) {
			memcpy(nb->buf + nb->b_len, data, avail);
			nb->b_len += avail;

			len -= avail;
			data += avail;
			if (len == 0)
				return;
		}
	}

	nb = cyon_malloc(sizeof(struct netbuf));
	nb->flags = 0;
	nb->cb = NULL;
	nb->owner = c;
	nb->s_off = 0;
	nb->b_len = len;
	nb->type = NETBUF_SEND;

	if (nb->b_len < NETBUF_SEND_PAYLOAD_MAX)
		nb->m_len = NETBUF_SEND_PAYLOAD_MAX;
	else
		nb->m_len = nb->b_len;

	nb->buf = cyon_malloc(nb->m_len);
	if (len > 0)
		memcpy(nb->buf, data, nb->b_len);

	TAILQ_INSERT_TAIL(&(c->send_queue), nb, list);
}

void
net_recv_queue(struct connection *c, size_t len, int flags,
    struct netbuf **out, int (*cb)(struct netbuf *))
{
	struct netbuf		*nb;

	nb = cyon_malloc(sizeof(struct netbuf));
	nb->cb = cb;
	nb->b_len = len;
	nb->m_len = len;
	nb->owner = c;
	nb->s_off = 0;
	nb->flags = flags;
	nb->type = NETBUF_RECV;
	nb->buf = cyon_malloc(nb->b_len);

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
	nb->b_len += len;
	nb->m_len = nb->b_len;
	nb->buf = cyon_realloc(nb->buf, nb->b_len);

	TAILQ_REMOVE(&(c->recv_queue), nb, list);
	TAILQ_INSERT_HEAD(&(c->recv_queue), nb, list);

	return (CYON_RESULT_OK);
}

int
net_send(struct connection *c)
{
	int			r;
	struct netbuf		*nb;
	u_int32_t		len;

	while (!TAILQ_EMPTY(&(c->send_queue))) {
		nb = TAILQ_FIRST(&(c->send_queue));
		if (nb->b_len != 0) {
			len = MIN(NETBUF_SEND_PAYLOAD_MAX,
			    nb->b_len - nb->s_off);
			r = SSL_write(c->ssl, (nb->buf + nb->s_off), len);

			cyon_debug("net_send(%d/%d bytes), progress with %d",
			    nb->s_off, nb->b_len, r);

			if (r <= 0) {
				r = SSL_get_error(c->ssl, r);
				switch (r) {
				case SSL_ERROR_WANT_READ:
				case SSL_ERROR_WANT_WRITE:
					c->flags &= ~CONN_WRITE_POSSIBLE;
					return (CYON_RESULT_OK);
				default:
					cyon_debug("SSL_write(): %s",
					    ssl_errno_s);
					return (CYON_RESULT_ERROR);
				}
			}

			nb->s_off += (size_t)r;
		}

		if (nb->s_off == nb->b_len) {
			TAILQ_REMOVE(&(c->send_queue), nb, list);

			cyon_mem_free(nb->buf);
			cyon_mem_free(nb);
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
		    (nb->buf + nb->s_off), (nb->b_len - nb->s_off));

		cyon_debug("net_recv(%ld/%ld bytes), progress with %d",
		    nb->s_off, nb->b_len, r);

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

		nb->s_off += (size_t)r;
		if (nb->s_off == nb->b_len) {
			r = nb->cb(nb);
			if (nb->s_off == nb->b_len) {
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
