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

#include <netinet/tcp.h>

#include <endian.h>
#include <fcntl.h>
#include <pthread.h>
#include <unistd.h>

#include "cyon.h"

static int		cyon_connection_recv_op(struct netbuf *);
static int		cyon_connection_recv_put(struct netbuf *);
static int		cyon_connection_recv_get(struct netbuf *);
static int		cyon_connection_recv_del(struct netbuf *);
static int		cyon_connection_recv_replace(struct netbuf *);
static int		cyon_connection_recv_auth(struct netbuf *);
static int		cyon_connection_recv_setauth(struct netbuf *);
static int		cyon_connection_recv_getkeys(struct netbuf *);
static void		cyon_connection_recv_stats(struct connection *);
static void		cyon_connection_recv_write(struct connection *);

static pthread_mutex_t			dc_lock;
static TAILQ_HEAD(, connection)		disconnected;

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
	socklen_t		len;

	cyon_debug("cyon_connection_accept(%p)", l);

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

	t = cyon_thread_getnext();

	c->ssl = NULL;
	c->flags = 0;
	c->owner = t;
	c->nctx = &(t->nctx);
	c->idle_timer.start = 0;
	c->state = CONN_STATE_SSL_SHAKE;
	c->idle_timer.length = idle_timeout;

	TAILQ_INIT(&(c->send_queue));
	TAILQ_INIT(&(c->recv_queue));
	TAILQ_INSERT_TAIL(&(t->nctx.clients), c, list);

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

	TAILQ_FOREACH(c, &(t->nctx.clients), list) {
		d = now - c->idle_timer.start;
		if (d >= c->idle_timer.length) {
			cyon_debug("%p idle for %d ms, expiring", c, d);
			cyon_connection_disconnect(c);
		}
	}
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

	flags = 1;
	if (setsockopt(fd, IPPROTO_TCP,
	    TCP_NODELAY, (char *)&flags, sizeof(flags)) == -1)
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
	case CYON_OP_MAKELINK:
		r = net_recv_expand(c, nb, len, cyon_connection_recv_put);
		break;
	case CYON_OP_GET:
		r = net_recv_expand(c, nb, len, cyon_connection_recv_get);
		break;
	case CYON_OP_GETKEYS:
		r = net_recv_expand(c, nb, len, cyon_connection_recv_getkeys);
		break;
	case CYON_OP_SETAUTH:
		r = net_recv_expand(c, nb, len, cyon_connection_recv_setauth);
		break;
	case CYON_OP_DEL:
		r = net_recv_expand(c, nb, len, cyon_connection_recv_del);
		break;
	case CYON_OP_REPLACE:
		r = net_recv_expand(c, nb, len, cyon_connection_recv_replace);
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
cyon_connection_recv_put(struct netbuf *nb)
{
	struct cyon_op		ret;
	u_int8_t		*key, *data;
	u_int32_t		dlen, klen, flags;
	struct cyon_op		*op = (struct cyon_op *)nb->buf;
	struct connection	*c = (struct connection *)nb->owner;

	klen = net_read32(nb->buf + sizeof(struct cyon_op));
	dlen = net_read32(nb->buf + sizeof(struct cyon_op) + sizeof(u_int32_t));

	if (klen == 0 || dlen == 0) {
		cyon_debug("klen: %d - dlen: %d", klen, dlen);
		return (CYON_RESULT_ERROR);
	}

	key = nb->buf + sizeof(struct cyon_op) + (sizeof(u_int32_t) * 2);
	data = key + klen;

	if (op->op == CYON_OP_MAKELINK)
		flags = NODE_FLAG_ISLINK;
	else
		flags = 0;

	cyon_store_lock(1);

	if (cyon_store_put(key, klen, data, dlen, flags))
		ret.op = CYON_OP_RESULT_OK;
	else
		ret.op = CYON_OP_RESULT_ERROR;

	cyon_store_unlock();

	ret.length = 0;
	net_send_queue(c, (u_int8_t *)&ret, sizeof(ret));
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

	if (klen == 0) {
		cyon_debug("klen: %d", klen);
		return (CYON_RESULT_ERROR);
	}

	cyon_store_lock(0);

	if (cyon_store_get(key, klen, &data, &dlen)) {
		ret.op = CYON_OP_RESULT_OK;
		net_write32((u_int8_t *)&(ret.length), dlen);

		net_send_queue(c, (u_int8_t *)&ret, sizeof(ret));
		net_send_queue(c, data, dlen);
	} else {
		ret.op = CYON_OP_RESULT_ERROR;
		net_write32((u_int8_t *)&(ret.length), 0);
		net_send_queue(c, (u_int8_t *)&ret, sizeof(ret));
	}

	cyon_store_unlock();

	return (net_send_flush(c));
}

static int
cyon_connection_recv_getkeys(struct netbuf *nb)
{
	struct cyon_op		ret, *op;
	u_int32_t		klen, olen;
	u_int8_t		*key, *out;
	struct connection	*c = (struct connection *)nb->owner;

	op = (struct cyon_op *)nb->buf;
	klen = net_read32((u_int8_t *)&(op->length));
	key = nb->buf + sizeof(struct cyon_op);

	if (klen == 0)
		return (CYON_RESULT_ERROR);

	/* Lock as write, as it uses some globals */
	cyon_store_lock(1);

	if (cyon_store_getkeys(key, klen, &out, &olen)) {
		ret.op = CYON_OP_RESULT_OK;
		net_write32((u_int8_t *)&(ret.length), olen);

		net_send_queue(c, (u_int8_t *)&ret, sizeof(ret));

		if (olen > 0)
			net_send_queue(c, out, olen);
	} else {
		ret.op = CYON_OP_RESULT_ERROR;
		net_write32((u_int8_t *)&(ret.length), 0);
		net_send_queue(c, (u_int8_t *)&ret, sizeof(ret));
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

	if (klen == 0) {
		cyon_debug("klen: %d", klen);
		return (CYON_RESULT_ERROR);
	}

	cyon_store_lock(1);

	if (cyon_store_del(key, klen))
		ret.op = CYON_OP_RESULT_OK;
	else
		ret.op = CYON_OP_RESULT_ERROR;

	cyon_store_unlock();

	net_write32((u_int8_t *)&(ret.length), 0);
	net_send_queue(c, (u_int8_t *)&ret, sizeof(ret));
	return (net_send_flush(c));
}

static int
cyon_connection_recv_replace(struct netbuf *nb)
{
	struct cyon_op		ret;
	u_int32_t		dlen, klen;
	u_int8_t		*key, *data;
	struct connection	*c = (struct connection *)nb->owner;

	klen = net_read32(nb->buf + sizeof(struct cyon_op));
	dlen = net_read32(nb->buf + sizeof(struct cyon_op) + sizeof(u_int32_t));

	if (klen == 0 || dlen == 0) {
		cyon_debug("klen: %d - dlen: %d", klen, dlen);
		return (CYON_RESULT_ERROR);
	}

	key = nb->buf + sizeof(struct cyon_op) + (sizeof(u_int32_t) * 2);
	data = key + klen;

	cyon_store_lock(1);

	if (cyon_store_replace(key, klen, data, dlen))
		ret.op = CYON_OP_RESULT_OK;
	else
		ret.op = CYON_OP_RESULT_ERROR;

	cyon_store_unlock();

	ret.length = 0;
	net_send_queue(c, (u_int8_t *)&ret, sizeof(ret));
	return (net_send_flush(c));
}

static int
cyon_connection_recv_auth(struct netbuf *nb)
{
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
	    (store_passphrase != NULL && klen == 0)) {
		cyon_log(LOG_NOTICE, "botched authentication request from %s",
		    inet_ntoa(c->sin.sin_addr));
		return (CYON_RESULT_ERROR);
	}

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
		cyon_log(LOG_NOTICE, "connection from %s is now authenticated",
		    inet_ntoa(c->sin.sin_addr));
	} else {
		ret.op = CYON_OP_RESULT_ERROR;
		cyon_log(LOG_NOTICE, "failed authentication from %s",
		    inet_ntoa(c->sin.sin_addr));
	}

	cyon_store_unlock();

	net_send_queue(c, (u_int8_t *)&ret, sizeof(ret));
	if (ret.op != CYON_OP_RESULT_OK) {
		net_send_flush(c);
		cyon_connection_disconnect(c);
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

	if (klen != SHA256_DIGEST_LENGTH) {
		cyon_log(LOG_NOTICE, "botched setauth packet from %s",
		    inet_ntoa(c->sin.sin_addr));
		return (CYON_RESULT_ERROR);
	}

	cyon_store_lock(1);

	if (store_passphrase != NULL)
		cyon_mem_free(store_passphrase);
	store_passphrase = cyon_malloc(SHA256_DIGEST_LENGTH);
	memcpy(store_passphrase, hash, SHA256_DIGEST_LENGTH);

	cyon_store_unlock();

	ret.op = CYON_OP_RESULT_OK;
	net_write32((u_int8_t *)&(ret.length), 0);

	net_send_queue(c, (u_int8_t *)&ret, sizeof(ret));
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

	/* XXX - signal parent to start one instead. */
	//cyon_storewrite_start();

	ret.op = CYON_OP_RESULT_ERROR;
	net_send_queue(c, (u_int8_t *)&ret, sizeof(ret));
	net_send_flush(c);
}

static void
cyon_connection_recv_stats(struct connection *c)
{
	struct cyon_op		ret;
	struct cyon_stats	stats;

	ret.op = CYON_OP_RESULT_OK;
	net_write32((u_int8_t *)&(ret.length), sizeof(struct cyon_stats));

	cyon_store_lock(0);
	stats.keycount = htobe64(key_count);
	stats.meminuse = htobe64(meminuse);
	cyon_store_unlock();

	net_send_queue(c, (u_int8_t *)&ret, sizeof(ret));
	net_send_queue(c, (u_int8_t *)&stats, sizeof(stats));
	net_send_flush(c);
}
