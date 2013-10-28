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

#ifndef _H_CYON_H
#define _H_CYON_H

#include <sys/types.h>
#include <sys/queue.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <errno.h>
#include <syslog.h>

/* Shared server & cli stuff. */
#define CYON_OP_PUT		1
#define CYON_OP_GET		2
#define CYON_OP_WRITE		3
#define CYON_OP_STATS		4
#define CYON_OP_AUTH		5
#define CYON_OP_SETAUTH		6
#define CYON_OP_DEL		7
#define CYON_OP_REPLACE		8
#define CYON_OP_GETKEYS		9
#define CYON_OP_MAKELINK	10
#define CYON_OP_RESULT_OK	200
#define CYON_OP_RESULT_ERROR	201

struct cyon_op {
	u_int8_t		op;
	u_int32_t		length;
} __attribute__((__packed__));

struct cyon_stats {
	u_int64_t		meminuse;
	u_int64_t		keycount;
} __attribute__((__packed__));

#define CYON_RESULT_ERROR	0
#define CYON_RESULT_OK		1
#define errno_s			strerror(errno)
#define ssl_errno_s		ERR_error_string(ERR_get_error(), NULL)

u_int16_t	net_read16(u_int8_t *);
u_int32_t	net_read32(u_int8_t *);
void		net_write16(u_int8_t *, u_int16_t);
void		net_write32(u_int8_t *, u_int32_t);
void		fatal(const char *, ...);

/* Server stuff only. */
#if defined(CYON_SERVER)

#if defined(DEBUG)
#define cyon_debug(fmt, ...)		\
	cyon_debug_internal(__FILE__, __LINE__, fmt, ##__VA_ARGS__)
#else
#define cyon_debug(fmt, ...)
#endif

#define STORE_KLEN_OFFSET(b)		((b + sizeof(struct cyon_op)))
#define STORE_DLEN_OFFSET(b)		((b + sizeof(struct cyon_op) + 4))
#define STORE_KEY_OFFSET(b)		((b + sizeof(struct cyon_op) + 8))
#define STORE_DATA_OFFSET(b, s)		((STORE_KEY_OFFSET(b) + s))

#define CYON_STORE_WRITE_NOFORK		0
#define CYON_STORE_WRITE_FORK		1
#define CYON_STORE_WRITE_INTERVAL	60000
#define CYON_IDLE_TIMER_MAX		20000

#define NODE_FLAG_HASDATA		0x01
#define NODE_FLAG_ISLINK		0x02
#define NODE_FLAG_ISCOLLECTION		0x04

#define NETBUF_RECV		0
#define NETBUF_SEND		1

#define NETBUF_CALL_CB_ALWAYS		0x01
#define NETBUF_FORCE_REMOVE		0x02
#define NETBUF_USE_DATA_DIRECT		0x04

struct netbuf {
	u_int8_t		*buf;
	u_int32_t		offset;
	u_int32_t		len;
	u_int8_t		type;
	u_int8_t		flags;

	void			*owner;
	void			*extra;
	int			(*cb)(struct netbuf *);

	TAILQ_ENTRY(netbuf)	list;
};

#define CONN_STATE_UNKNOWN		0
#define CONN_STATE_SSL_SHAKE		1
#define CONN_STATE_ESTABLISHED		2
#define CONN_STATE_DISCONNECTING	3

#define CONN_READ_POSSIBLE		0x01
#define CONN_WRITE_POSSIBLE		0x02
#define CONN_AUTHENTICATED		0x10
#define CONN_IS_NODE			0x20
#define CONN_IDLE_TIMER_ACT		0x40

struct listener {
	int			fd;
	struct sockaddr_in	sin;
};

struct connection {
	int			fd;
	u_int8_t		state;
	struct sockaddr_in	sin;
	void			*owner;
	SSL			*ssl;
	u_int8_t		flags;

	struct {
		u_int64_t	length;
		u_int64_t	start;
	} idle_timer;

	TAILQ_HEAD(, netbuf)	send_queue;
	TAILQ_HEAD(, netbuf)	recv_queue;

	TAILQ_ENTRY(connection)	list;
};

extern struct listener		server;
extern SSL_CTX			*ssl_ctx;
extern u_int64_t		meminuse;
extern u_int64_t		key_count;
extern char			*storepath;
extern u_int32_t		idle_timeout;
extern u_int64_t		last_store_write;
extern u_char			*store_passphrase;
extern u_int8_t			store_nowrite;
extern u_int8_t			server_started;

u_int64_t	cyon_time_ms(void);
u_int64_t	cyon_time_us(void);
void		cyon_log_init(void);
void		cyon_storelog_flush(void);
void		cyon_storewrite_start(void);
void		cyon_log(int, const char *, ...);
void		cyon_strlcpy(char *, const char *, size_t);
void		cyon_debug_internal(char *, int, const char *, ...);
long long	cyon_strtonum(const char *, long long, long long, int *);
void		cyon_storelog_write(u_int8_t, u_int8_t *, u_int32_t,
		    u_int8_t *, u_int32_t, u_int32_t);

void		*cyon_malloc(size_t);
void		*cyon_calloc(size_t, size_t);
void		*cyon_realloc(void *, size_t);
char		*cyon_strdup(const char *);
void		cyon_mem_free(void *);
void		cyon_mem_init(void);

void		cyon_connection_init(void);
void		cyon_connection_prune(void);
int		cyon_connection_nonblock(int);
void		cyon_connection_disconnect_all(void);
int		cyon_connection_handle(struct connection *);
void		cyon_connection_remove(struct connection *);
void		cyon_connection_disconnect(struct connection *);
void		cyon_connection_start_idletimer(struct connection *);
void		cyon_connection_stop_idletimer(struct connection *);
void		cyon_connection_check_idletimer(u_int64_t);
int		cyon_connection_accept(struct listener *,
		    struct connection **);

void		cyon_platform_event_init(void);
void		cyon_platform_event_wait(void);
void		cyon_platform_event_schedule(int, int, int, void *);

void		net_send_queue(struct connection *, u_int8_t *,
		    size_t, int, struct netbuf **, int (*cb)(struct netbuf *));
void		net_recv_queue(struct connection *, size_t, int,
		    struct netbuf **, int (*cb)(struct netbuf *));
int		net_recv_expand(struct connection *, struct netbuf *,
		    size_t, int (*cb)(struct netbuf *));

int		net_send(struct connection *);
int		net_recv(struct connection *);
int		net_send_flush(struct connection *);
int		net_recv_flush(struct connection *);

void		cyon_store_init(void);
pid_t		cyon_store_write(void);
int		cyon_store_del(u_int8_t *, u_int32_t);
int		cyon_store_put(u_int8_t *, u_int32_t, u_int8_t *,
		    u_int32_t, u_int32_t);
int		cyon_store_get(u_int8_t *, u_int32_t, u_int8_t **, u_int32_t *);
int		cyon_store_getkeys(u_int8_t *, u_int32_t,
		    u_int8_t **, u_int32_t *);
int		cyon_store_replace(u_int8_t *, u_int32_t,
		    u_int8_t *, u_int32_t);

void		cyon_cluster_init(void);
void		cyon_cluster_join(const char *);
void		cyon_cluster_node_register(struct connection *, int);

#endif /* CYON_SERVER */

#endif /* !_H_CYON_H */
