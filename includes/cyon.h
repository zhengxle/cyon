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
#include <sys/epoll.h>
#include <sys/un.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <errno.h>
#include <signal.h>
#include <syslog.h>

#define SHA_DIGEST_STRING_LEN	((SHA_DIGEST_LENGTH * 2) + 1)

/* Shared server & cli stuff. */
#define CYON_OP_PUT		1
#define CYON_OP_GET		2
#define CYON_OP_WRITE		3
#define CYON_OP_STATS		4
#define CYON_OP_AUTH		5
#define CYON_OP_SETAUTH		6
#define CYON_OP_DEL		7
#define CYON_OP_REPLACE		8
#define CYON_OP_REPLAY		9
#define CYON_OP_APUT		10
#define CYON_OP_AGET		11
#define CYON_OP_ADEL		12
#define CYON_OP_ACREATE		13

#define CYON_OP_RESULT_OK	200
#define CYON_OP_RESULT_ERROR	201

/* Error codes. */
#define CYON_ERROR_UNKNOWN		0
#define CYON_ERROR_EEXIST		1
#define CYON_ERROR_ENOENT		2
#define CYON_ERROR_READONLY_MODE	3
#define CYON_ERROR_KEYLEN_INVALID	4
#define CYON_ERROR_INVALID_ARRAY_LEN	5
#define CYON_ERROR_INVALID_OFFSET	6

struct cyon_op {
	u_int8_t		op;
	u_int8_t		error;
	u_int32_t		length;
};

struct cyon_stats {
	u_int64_t		meminuse;
	u_int64_t		keycount;
	u_int8_t		state[SHA_DIGEST_STRING_LEN];
	u_int8_t		modified;
};

#define CYON_RESULT_ERROR	0
#define CYON_RESULT_OK		1

/* Server stuff only. */
#if defined(CYON_SERVER)

#define CYON_DEFAULT_PID	"/tmp/cyon.pid"

#define DEBUG		1

#if defined(DEBUG)
#define cyon_debug(fmt, ...)		\
	cyon_debug_internal(__FILE__, __LINE__, fmt, ##__VA_ARGS__)
#else
#define cyon_debug(fmt, ...)
#endif

#define CYON_OP_DISK_DATA	150	/* Not an actual network op */

#define CYON_KEY_MAX			(USHRT_MAX - 1)

#define CYON_MEM_STORE			0
#define CYON_DISK_STORE			1

#define CYON_STOREFLUSH_LOG		0
#define CYON_STOREFLUSH_DISK		1

#define CYON_NO_CHECKSUM		0
#define CYON_ADD_CHECKSUM		1

#define CYON_REPLAY_STARTUP		0
#define CYON_REPLAY_REQUEST		1

#define CYON_STORE_WRITE_NOFORK		0
#define CYON_STORE_WRITE_FORK		1
#define CYON_STORE_WRITE_INTERVAL	60000
#define CYON_IDLE_TIMER_MAX		20000

#define NODE_FLAG_HASDATA		0x01
#define NODE_FLAG_ISLINK		0x02

#define NETBUF_RECV			0
#define NETBUF_SEND			1
#define NETBUF_SEND_PAYLOAD_MAX		4000

#define NETBUF_NO_FRAGMENT		0x01
#define NETBUF_USE_OPPOOL		0x04

#define CYON_LOG_FILE			"%s/%s.%s"
#define CYON_WRITELOG_FILE		"%s/%s.write"
#define CYON_STORE_FILE			"%s/%s.store"
#define CYON_STORE_TMPFILE		"%s/%s.store.new"
#define CYON_STORE_DSFILE		"%s/%s.data"

#define THREAD_VAR(x)			pthread_getspecific(x)

struct netbuf {
	u_int8_t		*buf;
	u_int32_t		s_off;
	u_int32_t		b_len;
	u_int32_t		m_len;
	u_int8_t		type;
	u_int8_t		flags;

	void			*owner;
	void			*extra;
	int			(*cb)(struct netbuf *);

	TAILQ_ENTRY(netbuf)	list;
};

TAILQ_HEAD(netbuf_head, netbuf);

struct pool_region {
	void			*start;

	LIST_ENTRY(pool_region)	list;
};

struct pool_entry {
	u_int8_t			state;
	struct pool_region		*region;
	LIST_ENTRY(pool_entry)		list;
};

struct pool {
	u_int32_t		elen;
	u_int32_t		slen;
	u_int32_t		elms;
	u_int32_t		inuse;
	char			*name;
	pthread_mutex_t		lock;

	LIST_HEAD(, pool_region)	regions;
	LIST_HEAD(, pool_entry)		freelist;
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

#define EVENT_TYPE_INET_SOCKET		1
#define EVENT_TYPE_UNIX_SOCKET		2
#define EVENT_TYPE_CONNECTION		3

struct listener {
	int			type;
	int			fd;

	union {
		struct sockaddr_in	sin;
		struct sockaddr_un	sun;
	} addr;

};

#define a_sin		addr.sin
#define a_sun		addr.sun

struct connection {
	int			type;
	int			fd;
	u_int8_t		state;
	union {
		struct sockaddr_in	sin;
		struct sockaddr_un	sun;
	} addr;
	struct listener		*l;
	SSL			*ssl;
	u_int8_t		flags;
	void			*owner;
	void			*nctx;

	struct {
		u_int64_t	length;
		u_int64_t	start;
	} idle_timer;

	TAILQ_HEAD(, netbuf)	send_queue;
	TAILQ_HEAD(, netbuf)	recv_queue;

	TAILQ_ENTRY(connection)	list;
};

TAILQ_HEAD(connection_list, connection);

struct netcontext {
	u_int8_t			flags;
	int				efd;
	struct epoll_event		*events;
	struct pool			nb_pool;
	struct pool			op_pool;
	struct connection_list		clients;
};

struct thread {
	u_int16_t			id;
	pthread_t			tid;
	u_int8_t			quit;
	struct netcontext		nctx;
	pthread_mutex_t			lock;
};

struct store_array {
	u_int32_t			elm;
	u_int32_t			elen;
	u_int32_t			count;
};

extern struct listener		server;
extern pthread_key_t		thread;
extern struct pool		nb_pool;
extern struct pool		op_pool;
extern SSL_CTX			*ssl_ctx;
extern u_int64_t		meminuse;
extern u_int64_t		key_count;
extern char			*storepath;
extern char			*storename;
extern u_int32_t		idle_timeout;
extern u_int16_t		thread_count;
extern pthread_mutex_t		store_write_lock;
extern u_int64_t		last_store_write;
extern u_char			*store_passphrase;
extern u_int8_t			store_mode;
extern u_int8_t			store_retain_logs;
extern u_int8_t			store_nopersist;
extern u_int8_t			server_started;
extern u_int8_t			store_modified;
extern u_int8_t			store_always_sync;
extern u_int8_t			cyon_readonly_mode;
extern u_int8_t			signaled_store_write;
extern u_int8_t			store_state[SHA_DIGEST_LENGTH];

u_int64_t	cyon_time_ms(void);
u_int64_t	cyon_time_us(void);
void		cyon_log_init(void);
void		cyon_store_flush(int);
void		cyon_storelog_reopen(int);
void		cyon_storewrite_start(void);
int		cyon_storelog_replay(char *, int);
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

void		cyon_sha_hex(u_int8_t *, char **);
void		cyon_atomic_write(int, void *, u_int32_t, SHA_CTX *);
int		cyon_atomic_read(int, void *, u_int32_t, SHA_CTX *, int);

void		cyon_connection_init(void);
void		cyon_connection_prune(void);
int		cyon_connection_nonblock(int, int);
int		cyon_connection_accept(struct listener *);
int		cyon_connection_handle(struct connection *);
void		cyon_connection_remove(struct connection *);
void		cyon_connection_disconnect(struct connection *);
void		cyon_connection_disconnect_all(struct thread *);
void		cyon_connection_start_idletimer(struct connection *);
void		cyon_connection_stop_idletimer(struct connection *);
void		cyon_connection_check_idletimer(u_int64_t);

void		cyon_threads_init(void);
void		cyon_threads_start(void);
void		cyon_threads_stop(void);
void		*cyon_thread_entry(void *);
struct thread	*cyon_thread_getnext(void);

void		cyon_platform_event_init(struct netcontext *);
void		cyon_platform_event_wait(struct netcontext *);
void		cyon_platform_event_schedule(struct netcontext *,
		    int, int, int, void *);

void		net_init(struct netcontext *);
void		net_send_queue(struct connection *, u_int8_t *, u_int32_t, int);
void		net_recv_queue(struct connection *, size_t, int,
		    struct netbuf **, int (*cb)(struct netbuf *));
int		net_recv_expand(struct connection *, struct netbuf *,
		    size_t, int (*cb)(struct netbuf *));

int		net_send_flush(struct connection *);
int		net_recv_flush(struct connection *);

void		cyon_store_lock(int);
void		cyon_store_init(void);
pid_t		cyon_store_write(void);
void		cyon_store_unlock(void);
void		cyon_store_current_state(u_int8_t *);
int		cyon_store_del(u_int8_t *, u_int32_t, u_int8_t *);
int		cyon_store_put(u_int8_t *, u_int32_t, u_int8_t *,
		    u_int32_t, u_int32_t, u_int8_t *);
int		cyon_store_get(u_int8_t *, u_int32_t, u_int8_t **,
		    u_int32_t *, u_int8_t *);
int		cyon_store_replace(u_int8_t *, u_int32_t,
		    u_int8_t *, u_int32_t, u_int8_t *);

void		*pool_get(struct pool *);
void		pool_put(struct pool *, void *);
void		pool_init(struct pool *, char *, u_int32_t, u_int32_t);

#endif /* CYON_SERVER */

#endif /* !_H_CYON_H */
