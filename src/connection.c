/*
 * Copyright (c) 2013-2014 Joris Vink <joris@coders.se>
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

#include <netinet/tcp.h>

#include <endian.h>
#include <fcntl.h>
#include <pthread.h>
#include <unistd.h>

#include "cyon.h"
#include "shared.h"

static int		cyon_connection_recv_op(struct netbuf *);
static int		cyon_connection_recv_put(struct netbuf *);
static int		cyon_connection_recv_get(struct netbuf *);
static int		cyon_connection_recv_del(struct netbuf *);
static int		cyon_connection_recv_aput(struct netbuf *);
static int		cyon_connection_recv_aget(struct netbuf *);
static int		cyon_connection_recv_adel(struct netbuf *);
static int		cyon_connection_recv_acreate(struct netbuf *);

static int		cyon_connection_recv_replay(struct netbuf *);
static int		cyon_connection_recv_replace(struct netbuf *);
static int		cyon_connection_recv_auth(struct netbuf *);
static int		cyon_connection_recv_setauth(struct netbuf *);

static void		cyon_connection_recv_stats(struct connection *);
static void		cyon_connection_recv_write(struct connection *);

static int		connection_extract_data(struct netbuf *,
			    u_int32_t *, u_int32_t *,
			    u_int8_t **, u_int8_t **);

static pthread_mutex_t			dc_lock;
static TAILQ_HEAD(, connection)		disconnected;

#define CYON_OP_READ(f, nb, off)				\
	f((nb->buf + sizeof(struct cyon_op)) + off)

void
cyon_connection_init(void)
{
	TAILQ_INIT(&disconnected);
	pthread_mutex_init(&dc_lock, NULL);
}

int
cyon_connection_accept(struct listener *l)
{
	struct thread		*t;
	struct connection	*c;
	void			*s;
	socklen_t		len;

	cyon_debug("cyon_connection_accept(%p)", l);

	c = (struct connection *)cyon_malloc(sizeof(*c));

	if (l->type == EVENT_TYPE_INET_SOCKET) {
		s = &(c->a_sin);
		len = sizeof(struct sockaddr_in);
	} else {
		s = &(c->a_sun);
		len = sizeof(struct sockaddr_un);
	}

	if ((c->fd = accept(l->fd, (struct sockaddr *)s, &len)) == -1) {
		cyon_mem_free(c);
		cyon_debug("accept(): %s", errno_s);
		return (CYON_RESULT_ERROR);
	}

	if (!cyon_connection_nonblock(c->fd,
	    (l->type == EVENT_TYPE_INET_SOCKET))) {
		close(c->fd);
		cyon_mem_free(c);
		return (CYON_RESULT_ERROR);
	}

	t = cyon_thread_getnext();

	c->l = l;
	c->ssl = NULL;
	c->flags = 0;
	c->owner = t;
	c->nctx = &(t->nctx);
	c->idle_timer.start = 0;
	c->type = EVENT_TYPE_CONNECTION;
	c->idle_timer.length = idle_timeout;

	TAILQ_INIT(&(c->send_queue));
	TAILQ_INIT(&(c->recv_queue));

	pthread_mutex_lock(&(t->lock));
	TAILQ_INSERT_TAIL(&(t->nctx.clients), c, list);
	pthread_mutex_unlock(&(t->lock));

	if (l->type == EVENT_TYPE_INET_SOCKET) {
		c->state = CONN_STATE_SSL_SHAKE;
	} else {
		c->state = CONN_STATE_ESTABLISHED;
		net_recv_queue(c, sizeof(struct cyon_op), NETBUF_USE_OPPOOL,
		    NULL, cyon_connection_recv_op);
	}

	if (store_passphrase == NULL)
		c->flags |= CONN_AUTHENTICATED;

	cyon_connection_start_idletimer(c);
	cyon_platform_event_schedule(&(t->nctx), c->fd,
	    EPOLLIN | EPOLLOUT | EPOLLET, 0, c);

	return (CYON_RESULT_OK);
}

void
cyon_connection_disconnect(struct connection *c)
{
	struct thread	*t = (struct thread *)c->owner;

	if (c->state != CONN_STATE_DISCONNECTING) {
		cyon_debug("preparing %p for disconnection", c);
		c->state = CONN_STATE_DISCONNECTING;

		TAILQ_REMOVE(&(t->nctx.clients), c, list);

		pthread_mutex_lock(&dc_lock);
		TAILQ_INSERT_TAIL(&disconnected, c, list);
		pthread_mutex_unlock(&dc_lock);
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

		net_recv_queue(c, sizeof(struct cyon_op), NETBUF_USE_OPPOOL,
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

	cyon_connection_start_idletimer(c);

	return (CYON_RESULT_OK);
}

void
cyon_connection_remove(struct connection *c)
{
	struct netbuf		*nb, *next;
	struct netcontext	*nctx = (struct netcontext *)c->nctx;

	cyon_debug("cyon_connection_remove(%p)", c);

	if (c->ssl != NULL)
		SSL_free(c->ssl);
	close(c->fd);

	for (nb = TAILQ_FIRST(&(c->send_queue)); nb != NULL; nb = next) {
		next = TAILQ_NEXT(nb, list);
		TAILQ_REMOVE(&(c->send_queue), nb, list);
		if (nb->buf != NULL)
			cyon_mem_free(nb->buf);
		pool_put(&(nctx->nb_pool), nb);
	}

	for (nb = TAILQ_FIRST(&(c->recv_queue)); nb != NULL; nb = next) {
		next = TAILQ_NEXT(nb, list);
		TAILQ_REMOVE(&(c->recv_queue), nb, list);
		if (nb->flags & NETBUF_USE_OPPOOL)
			pool_put(&(nctx->op_pool), nb->buf);
		else
			cyon_mem_free(nb->buf);
		pool_put(&(nctx->nb_pool), nb);
	}

	cyon_mem_free(c);
}

void
cyon_connection_check_idletimer(u_int64_t now)
{
	u_int64_t		d;
	struct connection	*c;
	struct thread		*t = THREAD_VAR(thread);

	pthread_mutex_lock(&(t->lock));
	TAILQ_FOREACH(c, &(t->nctx.clients), list) {
		d = now - c->idle_timer.start;
		if (d >= c->idle_timer.length) {
			cyon_debug("%p idle for %d ms, expiring", c, d);
			cyon_connection_disconnect(c);
		}
	}
	pthread_mutex_unlock(&(t->lock));
}

void
cyon_connection_start_idletimer(struct connection *c)
{
	if (idle_timeout == 0)
		return;

	c->flags |= CONN_IDLE_TIMER_ACT;
	c->idle_timer.start = cyon_time_ms();
}

void
cyon_connection_stop_idletimer(struct connection *c)
{
	if (idle_timeout == 0)
		return;

	c->flags &= ~CONN_IDLE_TIMER_ACT;
	c->idle_timer.start = 0;
}

void
cyon_connection_disconnect_all(struct thread *t)
{
	struct connection	*c, *next;

	for (c = TAILQ_FIRST(&(t->nctx.clients)); c != NULL; c = next) {
		next = TAILQ_NEXT(c, list);
		TAILQ_REMOVE(&(t->nctx.clients), c, list);

		pthread_mutex_lock(&dc_lock);
		TAILQ_INSERT_TAIL(&disconnected, c, list);
		pthread_mutex_unlock(&dc_lock);
	}
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
cyon_connection_nonblock(int fd, int nodelay)
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

	if (nodelay != 1)
		return (CYON_RESULT_OK);

	if (setsockopt(fd, IPPROTO_TCP,
	    TCP_NODELAY, (char *)&nodelay, sizeof(nodelay)) == -1)
		cyon_log(LOG_NOTICE, "failed to set TCP_NODELAY on %d", fd);

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
	cyon_connection_stop_idletimer(c);

	if (!(c->flags & CONN_AUTHENTICATED) && op->op != CYON_OP_AUTH)
		return (CYON_RESULT_ERROR);

	switch (op->op) {
	case CYON_OP_PUT:
		r = net_recv_expand(c, nb, len, cyon_connection_recv_put);
		break;
	case CYON_OP_GET:
		r = net_recv_expand(c, nb, len, cyon_connection_recv_get);
		break;
	case CYON_OP_DEL:
		r = net_recv_expand(c, nb, len, cyon_connection_recv_del);
		break;
	case CYON_OP_REPLACE:
		r = net_recv_expand(c, nb, len, cyon_connection_recv_replace);
		break;
	case CYON_OP_APUT:
		r = net_recv_expand(c, nb, len, cyon_connection_recv_aput);
		break;
	case CYON_OP_AGET:
		r = net_recv_expand(c, nb, len, cyon_connection_recv_aget);
		break;
	case CYON_OP_ADEL:
		r = net_recv_expand(c, nb, len, cyon_connection_recv_adel);
		break;
	case CYON_OP_ACREATE:
		r = net_recv_expand(c, nb, len, cyon_connection_recv_acreate);
		break;
	case CYON_OP_SETAUTH:
		r = net_recv_expand(c, nb, len, cyon_connection_recv_setauth);
		break;
	case CYON_OP_REPLAY:
		r = net_recv_expand(c, nb, len, cyon_connection_recv_replay);
		break;
	case CYON_OP_AUTH:
		if (len == 0) {
			r = cyon_connection_recv_auth(nb);
		} else {
			r = net_recv_expand(c, nb, len,
			    cyon_connection_recv_auth);
		}
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

	net_recv_queue(c, sizeof(struct cyon_op), NETBUF_USE_OPPOOL,
	    NULL, cyon_connection_recv_op);

	return (r);
}

static int
cyon_connection_recv_acreate(struct netbuf *nb)
{
	struct cyon_op		ret;
	struct store_array	*ar;
	u_int8_t		*data, *key;
	u_int32_t		klen, elm, elen, dlen;
	struct connection	*c = (struct connection *)nb->owner;

	klen = CYON_OP_READ(net_read32, nb, 0);
	elm = CYON_OP_READ(net_read32, nb, sizeof(u_int32_t));
	elen = CYON_OP_READ(net_read32, nb, (sizeof(u_int32_t) * 2));

	if ((int)klen <= 0 || (int)elm <= 0 || (int)elen <= 0)
		return (CYON_RESULT_ERROR);

	if (elm > CYON_ARRAY_ELM_MAX) {
		ret.length = 0;
		ret.op = CYON_OP_RESULT_ERROR;
		ret.error = CYON_ERROR_ARRAY_ELM_TOO_BIG;
		net_send_queue(c, (u_int8_t *)&ret, sizeof(ret), 0);
		return (net_send_flush(c));
	}

	if (elen > CYON_ARRAY_ELEN_MAX) {
		ret.length = 0;
		ret.op = CYON_OP_RESULT_ERROR;
		ret.error = CYON_ERROR_ARRAY_ELEN_TOO_BIG;
		net_send_queue(c, (u_int8_t *)&ret, sizeof(ret), 0);
		return (net_send_flush(c));
	}

	key = nb->buf + sizeof(struct cyon_op) + (sizeof(u_int32_t) * 3);
	dlen = sizeof(struct store_array) + (elm * elen);
	data = cyon_malloc(dlen);
	memset(data, 0, dlen);

	ar = (struct store_array *)data;
	ar->elm = elm;
	ar->count = 0;
	ar->elen = elen;

	cyon_store_lock(1);
	if (cyon_store_put(key, klen, data, dlen, 0, &(ret.error)))
		ret.op = CYON_OP_RESULT_OK;
	else
		ret.op = CYON_OP_RESULT_ERROR;

	cyon_store_unlock();
	cyon_mem_free(data);

	ret.length = 0;
	net_send_queue(c, (u_int8_t *)&ret, sizeof(ret), 0);

	return (net_send_flush(c));
}

static int
cyon_connection_recv_aput(struct netbuf *nb)
{
	struct cyon_op		ret;
	u_int32_t		klen, dlen;
	u_int8_t		*key, *data;
	struct connection	*c = (struct connection *)nb->owner;

	if (!connection_extract_data(nb, &klen, &dlen, &key, &data))
		return (CYON_RESULT_ERROR);

	cyon_store_lock(1);
	if (cyon_store_aput(key, klen, data, dlen, &(ret.error))) {
		ret.op = CYON_OP_RESULT_OK;
	} else {
		ret.op = CYON_OP_RESULT_ERROR;
	}

	cyon_store_unlock();

	ret.length = 0;
	net_send_queue(c, (u_int8_t *)&ret, sizeof(ret), 0);
	return (net_send_flush(c));
}

static int
cyon_connection_recv_adel(struct netbuf *nb)
{
	struct cyon_op		ret;
	u_int8_t		*key, *data;
	u_int32_t		klen, dlen, offset;
	struct connection	*c = (struct connection *)nb->owner;

	if (!connection_extract_data(nb, &klen, &dlen, &key, &data))
		return (CYON_RESULT_ERROR);

	if (dlen != sizeof(u_int32_t))
		return (CYON_RESULT_ERROR);

	offset = net_read32(data);

	cyon_store_lock(1);
	if (cyon_store_adel(key, klen, offset, &(ret.error))) {
		ret.op = CYON_OP_RESULT_OK;
	} else {
		ret.op = CYON_OP_RESULT_ERROR;
	}

	cyon_store_unlock();

	ret.length = 0;
	net_send_queue(c, (u_int8_t *)&ret, sizeof(ret), 0);
	return (net_send_flush(c));
}

static int
cyon_connection_recv_aget(struct netbuf *nb)
{
	struct store_array	*ar;
	struct cyon_op		ret;
	u_int8_t		*key, *p, *data;
	u_int32_t		klen, start, end, plen, dlen;
	struct connection	*c = (struct connection *)nb->owner;

	klen = CYON_OP_READ(net_read32, nb, 0);
	start = CYON_OP_READ(net_read32, nb, sizeof(u_int32_t));
	end = CYON_OP_READ(net_read32, nb, (sizeof(u_int32_t) * 2));

	if ((int)klen <= 0 || (int)start < 0 || (int)end < 0) {
		cyon_debug("klen: %d - start: %d - end: %d", klen, start, end);
		return (CYON_RESULT_ERROR);
	}

	key = nb->buf + sizeof(struct cyon_op) + (sizeof(u_int32_t) * 3);
	cyon_debug("fetching %d-%d from %.*s", start, end, klen, key);

	cyon_store_lock(0);
	if (cyon_store_get(key, klen, &p, &plen, &(ret.error))) {
		dlen = 0;
		data = NULL;

		ar = (struct store_array *)p;
		p += sizeof(struct store_array);
		plen -= sizeof(struct store_array);

		if (end > ar->count || start >= ar->count) {
			ret.op = CYON_OP_RESULT_ERROR;
			ret.error = CYON_ERROR_INVALID_OFFSET;
		} else if (start == 0 && end == 0) {
			data = p;
			dlen = ar->count * ar->elen;
		} else if (start > 0 && end == 0) {
			data = p + (start * ar->elen);
			dlen = (ar->count * ar->elen) - (start * ar->elen);
		} else if (start == 0 && end > 0) {
			data = p;
			dlen = end * ar->elen;
		} else if (start < end) {
			data = p + (start * ar->elen);
			dlen = (end * ar->elen) - (start * ar->elen);
		} else if (start == end) {
			data = p + (start * ar->elen);
			dlen = ar->elen;
		} else {
			ret.op = CYON_OP_RESULT_ERROR;
			ret.error = CYON_ERROR_INVALID_OFFSET;
		}

		if (data != NULL)
			ret.op = CYON_OP_RESULT_OK;

		net_write32((u_int8_t *)&(ret.length), dlen);
		net_send_queue(c, (u_int8_t *)&ret, sizeof(ret), 0);
		if (data != NULL)
			net_send_queue(c, data, dlen, 0);
	} else {
		ret.length = 0;
		ret.op = CYON_OP_RESULT_ERROR;
		net_send_queue(c, (u_int8_t *)&ret, sizeof(ret), 0);
	}

	cyon_store_unlock();

	return (net_send_flush(c));
}

static int
cyon_connection_recv_put(struct netbuf *nb)
{
	struct cyon_op		ret;
	u_int32_t		dlen, klen;
	u_int8_t		*key, *data;
	struct connection	*c = (struct connection *)nb->owner;

	if (!connection_extract_data(nb, &klen, &dlen, &key, &data))
		return (CYON_RESULT_ERROR);

	cyon_store_lock(1);
	if (cyon_store_put(key, klen, data, dlen, 0, &(ret.error)))
		ret.op = CYON_OP_RESULT_OK;
	else
		ret.op = CYON_OP_RESULT_ERROR;
	cyon_store_unlock();

	ret.length = 0;
	net_send_queue(c, (u_int8_t *)&ret, sizeof(ret), 0);
	return (net_send_flush(c));
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

	if ((int)klen <= 0) {
		return (CYON_RESULT_ERROR);
	}

	cyon_store_lock(0);

	if (cyon_store_get(key, klen, &data, &dlen, &(ret.error))) {
		ret.op = CYON_OP_RESULT_OK;
		net_write32((u_int8_t *)&(ret.length), dlen);

		net_send_queue(c, (u_int8_t *)&ret, sizeof(ret), 0);
		net_send_queue(c, data, dlen, 0);
	} else {
		ret.op = CYON_OP_RESULT_ERROR;
		net_write32((u_int8_t *)&(ret.length), 0);
		net_send_queue(c, (u_int8_t *)&ret, sizeof(ret), 0);
	}

	cyon_store_unlock();

	return (net_send_flush(c));
}

static int
cyon_connection_recv_del(struct netbuf *nb)
{
	u_int32_t		klen;
	u_int8_t		*key;
	struct cyon_op		ret, *op;
	struct connection	*c = (struct connection *)nb->owner;

	op = (struct cyon_op *)nb->buf;
	klen = net_read32((u_int8_t *)&(op->length));
	key = nb->buf + sizeof(struct cyon_op);

	if ((int)klen <= 0)
		return (CYON_RESULT_ERROR);

	cyon_store_lock(1);

	if (cyon_store_del(key, klen, &(ret.error)))
		ret.op = CYON_OP_RESULT_OK;
	else
		ret.op = CYON_OP_RESULT_ERROR;

	cyon_store_unlock();

	net_write32((u_int8_t *)&(ret.length), 0);
	net_send_queue(c, (u_int8_t *)&ret, sizeof(ret), 0);
	return (net_send_flush(c));
}

static int
cyon_connection_recv_replace(struct netbuf *nb)
{
	struct cyon_op		ret;
	u_int32_t		dlen, klen;
	u_int8_t		*key, *data;
	struct connection	*c = (struct connection *)nb->owner;

	if (!connection_extract_data(nb, &klen, &dlen, &key, &data))
		return (CYON_RESULT_ERROR);

	cyon_store_lock(1);
	if (cyon_store_replace(key, klen, data, dlen, &(ret.error)))
		ret.op = CYON_OP_RESULT_OK;
	else
		ret.op = CYON_OP_RESULT_ERROR;
	cyon_store_unlock();

	ret.length = 0;
	net_send_queue(c, (u_int8_t *)&ret, sizeof(ret), 0);
	return (net_send_flush(c));
}

static int
cyon_connection_recv_auth(struct netbuf *nb)
{
	struct thread		*t;
	u_int32_t		klen;
	struct cyon_op		*op, ret;
	SHA256_CTX		sha256ctx;
	u_int8_t		*passphrase;
	u_char			hash[SHA256_DIGEST_LENGTH];
	struct connection	*c = (struct connection *)nb->owner;

	op = (struct cyon_op *)nb->buf;
	klen = net_read32((u_int8_t *)&(op->length));
	passphrase = nb->buf + sizeof(struct cyon_op);

	if ((store_passphrase == NULL && klen != 0) ||
	    (store_passphrase != NULL && klen == 0))
		return (CYON_RESULT_ERROR);

	net_write32((u_int8_t *)&(ret.length), 0);

	if (klen > 0) {
		SHA256_Init(&sha256ctx);
		SHA256_Update(&sha256ctx, passphrase, klen);
		SHA256_Final(hash, &sha256ctx);
	}

	cyon_store_lock(0);

	if ((store_passphrase != NULL &&
	    !memcmp(store_passphrase, hash, SHA256_DIGEST_LENGTH)) ||
	    (store_passphrase == NULL && klen == 0)) {
		ret.op = CYON_OP_RESULT_OK;
		c->flags |= CONN_AUTHENTICATED;
	} else {
		ret.op = CYON_OP_RESULT_ERROR;
	}

	cyon_store_unlock();

	net_send_queue(c, (u_int8_t *)&ret, sizeof(ret), 0);
	if (ret.op != CYON_OP_RESULT_OK) {
		net_send_flush(c);

		t = (struct thread *)c->owner;
		pthread_mutex_lock(&(t->lock));
		cyon_connection_disconnect(c);
		pthread_mutex_unlock(&(t->lock));
	}

	return (net_send_flush(c));
}

static int
cyon_connection_recv_setauth(struct netbuf *nb)
{
	u_int32_t		klen;
	u_int8_t		*hash;
	struct cyon_op		*op, ret;
	struct connection	*c = (struct connection *)nb->owner;

	op = (struct cyon_op *)nb->buf;
	klen = net_read32((u_int8_t *)&(op->length));
	hash = nb->buf + sizeof(struct cyon_op);

	if (klen != SHA256_DIGEST_LENGTH)
		return (CYON_RESULT_ERROR);

	cyon_store_lock(1);

	if (store_passphrase != NULL)
		cyon_mem_free(store_passphrase);
	store_passphrase = cyon_malloc(SHA256_DIGEST_LENGTH);
	memcpy(store_passphrase, hash, SHA256_DIGEST_LENGTH);

	cyon_store_unlock();

	ret.op = CYON_OP_RESULT_OK;
	net_write32((u_int8_t *)&(ret.length), 0);

	net_send_queue(c, (u_int8_t *)&ret, sizeof(ret), 0);
	cyon_storelog_write(CYON_OP_SETAUTH,
	    store_passphrase, SHA256_DIGEST_LENGTH, NULL, 0, 0);

	return (net_send_flush(c));
}

static void
cyon_connection_recv_write(struct connection *c)
{
	struct cyon_op		ret;

	last_store_write = cyon_time_ms();
	net_write32((u_int8_t *)&(ret.length), 0);

	if (pthread_mutex_lock(&store_write_lock))
		fatal("failed to grab store write lock");

	signaled_store_write = 1;
	pthread_mutex_unlock(&store_write_lock);

	ret.op = CYON_OP_RESULT_OK;
	net_send_queue(c, (u_int8_t *)&ret, sizeof(ret), 0);
	net_send_flush(c);
}

static void
cyon_connection_recv_stats(struct connection *c)
{
	struct cyon_op		ret;
	char			*hex;
	struct cyon_stats	stats;

	ret.op = CYON_OP_RESULT_OK;
	net_write32((u_int8_t *)&(ret.length), sizeof(struct cyon_stats));

	cyon_store_lock(0);
	cyon_sha_hex(store_state, &hex);
	stats.modified = store_modified;
	stats.meminuse = htobe64(meminuse);
	stats.keycount = htobe64(key_count);
	memcpy(stats.state, hex, sizeof(stats.state));
	cyon_mem_free(hex);
	cyon_store_unlock();

	net_send_queue(c, (u_int8_t *)&ret, sizeof(ret), 0);
	net_send_queue(c, (u_int8_t *)&stats, sizeof(stats), 0);
	net_send_flush(c);
}

static int
cyon_connection_recv_replay(struct netbuf *nb)
{
	u_int32_t		slen;
	char			*state;
	struct cyon_op		ret, *op;
	struct connection	*c = (struct connection *)nb->owner;

	op = (struct cyon_op *)nb->buf;
	slen = net_read32((u_int8_t *)&(op->length));
	if (slen != SHA_DIGEST_STRING_LEN)
		return (CYON_RESULT_ERROR);

	state = (char *)(nb->buf + sizeof(struct cyon_op));

	memset(&ret, 0, sizeof(ret));
	net_write32((u_int8_t *)&(ret.length), 0);

	if (!cyon_storelog_replay(state, CYON_REPLAY_REQUEST))
		ret.op = CYON_OP_RESULT_ERROR;
	else
		ret.op = CYON_OP_RESULT_OK;

	net_send_queue(c, (u_int8_t *)&ret, sizeof(ret), 0);
	return (net_send_flush(c));
}

static int
connection_extract_data(struct netbuf *nb, u_int32_t *klen, u_int32_t *dlen,
    u_int8_t **key, u_int8_t **data)
{
	*klen = CYON_OP_READ(net_read32, nb, 0);
	*dlen = CYON_OP_READ(net_read32, nb, sizeof(u_int32_t));

	if (*(int *)klen <= 0 || *(int *)dlen <= 0)
		return (CYON_RESULT_ERROR);

	*key = nb->buf + sizeof(struct cyon_op) + (sizeof(u_int32_t) * 2);
	*data = *key + *klen;

	return (CYON_RESULT_OK);
}
