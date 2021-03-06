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
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/un.h>

#include <fcntl.h>
#include <signal.h>
#include <pthread.h>
#include <unistd.h>

#include "cyon.h"
#include "shared.h"

static void		usage(void);
static void		cyon_signal(int);
static void		cyon_write_pid(void);
static void		cyon_unlink_pid(void);
static void		cyon_storewrite_wait(int);
static void		cyon_ssl_init(char *, char *);
static void		cyon_bind_socket(struct listener *, int);
static void		cyon_bind_unix(struct listener *, char *);
static void		cyon_bind_ip(struct listener *, char *, u_int16_t);
static void		cyon_bind_finish(struct listener *, void *, size_t);

static struct {
	int	opt;
	char	*label;
	char	*descr;
} use_options[] = {
	{ 'a',	NULL,		"Sync to disk after each write op (slow)" },
	{ 'b',	"ip",		"Bind to the given IP address" },
	{ 'f',	NULL,		"Runs cyon in foreground mode" },
	{ 'i',	NULL,		"Idle timeout for connections" },
	{ 'l',	NULL,		"Retain store log files" },
	{ 'n',	NULL,		"No data persistence" },
	{ 'p',	"port",		"Use given port to listen for connections" },
	{ 'r',	"storedir",	"Directory where all data is stored" },
	{ 's',	"storename",	"Name of the cyon store" },
	{ 't',	"threads",	"Number of threads to run with" },
	{ 'u',	"path",		"Unix socket to bind to" },
	{ 'w',	"interval",	"Time in minutes in between store writes" },
	{ 'x',	NULL,		"Read-only mode" },
	{ 0,	NULL,		NULL },
};

volatile sig_atomic_t	sig_recv;

struct netcontext	nctx;
extern const char	*__progname;
SSL_CTX			*ssl_ctx = NULL;
u_int16_t		thread_count = 1;
pthread_mutex_t		store_write_lock;
u_int64_t		last_store_write;
u_int8_t		server_started = 0;
u_int8_t		signaled_store_write;
u_int8_t		store_always_sync = 0;
u_int8_t		cyon_readonly_mode = 0;
u_int32_t		idle_timeout = CYON_IDLE_TIMER_MAX;

static struct listener	server_inet;
static struct listener	server_unix;
static pid_t		writepid = -1;
static u_int32_t	store_write_int = CYON_STORE_WRITE_INTERVAL;

int
main(int argc, char *argv[])
{
	struct stat	st;
	u_int64_t	now;
	u_int16_t	port;
	int		ch, err;
	u_int8_t	foreground;
	char		fpath[MAXPATHLEN];
	char		*ip, *unix_sockpath;
	u_int64_t	last_store_flush, last_signaled_write_check;

	ip = NULL;
	port = 3331;
	foreground = 0;
	storepath = NULL;
	unix_sockpath = NULL;
	store_retain_logs = 0;

	while ((ch = getopt(argc, argv, "ab:fi:lnp:r:s:t:u:w:xz")) != -1) {
		switch (ch) {
		case 'a':
			store_always_sync = 1;
			break;
		case 'b':
			ip = optarg;
			break;
		case 'f':
			foreground = 1;
			break;
		case 'i':
			idle_timeout = cyon_strtonum(optarg, 0,
			    UINT_MAX / 1000, &err);
			if (err != CYON_RESULT_OK)
				fatal("Invalid timeout value: %s", optarg);
			idle_timeout = idle_timeout * 1000;
			break;
		case 'l':
			store_retain_logs = 1;
			break;
		case 'n':
			store_nopersist = 1;
			break;
		case 'p':
			port = cyon_strtonum(optarg, 1, 65535, &err);
			if (err != CYON_RESULT_OK)
				fatal("Invalid port: %s", optarg);
			break;
		case 'r':
			storepath = optarg;
			break;
		case 's':
			storename = optarg;
			break;
		case 't':
			thread_count = cyon_strtonum(optarg, 1, 65535, &err);
			if (err != CYON_RESULT_OK)
				fatal("Invalid number of threads: %s", optarg);
			break;
		case 'u':
			unix_sockpath = optarg;
			break;
		case 'w':
			store_write_int = cyon_strtonum(optarg, 0, 254, &err);
			if (err != CYON_RESULT_OK)
				fatal("Invalid write interval: %s", optarg);
			store_write_int = (store_write_int * 60) * 1000;
			break;
		case 'x':
			cyon_readonly_mode = 1;
			break;
		case '?':
		default:
			usage();
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

	if (store_nopersist == 0 && (storepath == NULL || storename == NULL)) {
		fprintf(stderr,
		    "Please set storepath (-r) and storename (-s)\n");
		usage();
	}

	if (ip != NULL && argc != 2)
		usage();

	snprintf(fpath, sizeof(fpath), CYON_WRITELOG_FILE,
	    storepath, storename);
	if (stat(fpath, &st) != -1) {
		printf("cyon-server: %s is in the way\n", fpath);
		fatal("please append it to the current log");
	}

	cyon_log_init();
	cyon_mem_init();
	cyon_threads_init();

	if (ip != NULL)
		cyon_ssl_init(argv[0], argv[1]);

	cyon_connection_init();

	if (ip != NULL)
		cyon_bind_ip(&server_inet, ip, port);
	if (unix_sockpath != NULL)
		cyon_bind_unix(&server_unix, unix_sockpath);

	if (foreground == 0)
		printf("cyon daemonizing, check system log for details\n");

	if (foreground == 0 && daemon(1, 1) == -1)
		fatal("could not forkify(): %s", errno_s);

	cyon_write_pid();
	cyon_store_init();

	signaled_store_write = 0;
	pthread_mutex_init(&store_write_lock, NULL);

	sig_recv = 0;
	signal(SIGQUIT, cyon_signal);
	signal(SIGINT, cyon_signal);
	signal(SIGHUP, cyon_signal);
	signal(SIGPIPE, SIG_IGN);

	cyon_threads_start();

	server_started = 1;
	last_signaled_write_check = last_store_write = cyon_time_ms();
	cyon_log(LOG_NOTICE, "server ready - running %d threads", thread_count);

	cyon_platform_event_init(&nctx);

	if (ip != NULL) {
		cyon_platform_event_schedule(&nctx, server_inet.fd,
		    EPOLLIN, 0, &server_inet);
	}

	if (unix_sockpath != NULL) {
		cyon_platform_event_schedule(&nctx, server_unix.fd,
		    EPOLLIN, 0, &server_unix);
	}

	for (;;) {
		if (sig_recv == SIGQUIT)
			break;

		cyon_platform_event_wait(&nctx);
		cyon_connection_prune();

		now = cyon_time_ms();
		if ((now - last_signaled_write_check) >= 1000) {
			last_signaled_write_check = now;

			if (pthread_mutex_lock(&store_write_lock))
				fatal("failed to lock on store write lock");

			if (signaled_store_write) {
				signaled_store_write = 0;
				cyon_storewrite_start();
			}

			pthread_mutex_unlock(&store_write_lock);
		}

		if (writepid == -1 && store_write_int != 0 &&
		    (now - last_store_write) >= store_write_int) {
			last_store_write = now;
			cyon_storewrite_start();
		}

		if (store_always_sync == 0 &&
		    ((now - last_store_flush) >= 1)) {

			cyon_store_lock(1);
			last_store_flush = now;
			cyon_store_flush();
			cyon_store_unlock();
		}

		if (writepid != -1)
			cyon_storewrite_wait(0);
	}

	if (writepid != -1)
		cyon_storewrite_wait(1);

	cyon_threads_stop();

	cyon_storewrite_start();
	cyon_storewrite_wait(1);
	cyon_unlink_pid();

	if (unix_sockpath != NULL) {
		if (unlink(unix_sockpath) == -1) {
			cyon_log(LOG_NOTICE, "unlink(%s): %s",
			    unix_sockpath, errno_s);
		}
	}

	cyon_log(LOG_NOTICE, "server stopped");

	return (0);
}

void
cyon_storewrite_start(void)
{
	if (writepid != -1) {
		cyon_log(LOG_NOTICE,
		    "store write still in progress (%d)", writepid);
		return;
	}

	writepid = cyon_store_write();
	if (writepid == CYON_RESULT_OK)
		writepid = -1;
}

static void
cyon_ssl_init(char *cert, char *key)
{
	SSL_library_init();
	SSL_load_error_strings();

	ssl_ctx = SSL_CTX_new(SSLv23_server_method());
	if (ssl_ctx == NULL)
		fatal("cyon_ssl_init(): SSL_CTX_new(): %s", ssl_errno_s);

	if (!SSL_CTX_use_certificate_chain_file(ssl_ctx, cert))
		fatal("SSL_CTX_use_certificate_chain_file(): %s", ssl_errno_s);

	if (!SSL_CTX_use_PrivateKey_file(ssl_ctx, key, SSL_FILETYPE_PEM))
		fatal("SSL_CTX_use_PrivateKey_file(): %s", ssl_errno_s);

	if (!SSL_CTX_check_private_key(ssl_ctx))
		fatal("Public/Private key mismatch");

	SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_SSLv2);
#if defined(SSL_MODE_RELEASE_BUFFERS)
	SSL_CTX_set_mode(ssl_ctx, SSL_MODE_RELEASE_BUFFERS);
#endif
	SSL_CTX_set_mode(ssl_ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);
}

static void
cyon_bind_ip(struct listener *l, char *ip, u_int16_t port)
{
	int	on;

	cyon_bind_socket(l, AF_INET);
	l->type = EVENT_TYPE_INET_SOCKET;

	on = 1;
	if (setsockopt(l->fd, SOL_SOCKET, SO_REUSEADDR,
	    (const char *)&on, sizeof(on)) == -1)
		fatal("setsockopt(): %s", errno_s);

	memset(&(l->a_sin), 0, sizeof(l->a_sin));
	l->a_sin.sin_family = AF_INET;
	l->a_sin.sin_port = htons(port);
	l->a_sin.sin_addr.s_addr = inet_addr(ip);

	cyon_bind_finish(l, &(l->a_sin), sizeof(l->a_sin));
}

static void
cyon_bind_unix(struct listener *l, char *path)
{
	cyon_bind_socket(l, AF_UNIX);
	l->type = EVENT_TYPE_UNIX_SOCKET;

	memset(&(l->a_sun), 0, sizeof(l->a_sun));
	l->a_sun.sun_family = AF_UNIX;
	cyon_strlcpy(l->a_sun.sun_path, path, sizeof(l->a_sun.sun_path));

	cyon_bind_finish(l, &(l->a_sun), sizeof(l->a_sun));
}

static void
cyon_bind_socket(struct listener *l, int type)
{
	if ((l->fd = socket(type, SOCK_STREAM, 0)) == -1)
		fatal("socket(): %s", errno_s);
	if (!cyon_connection_nonblock(l->fd, (type == AF_INET)))
		fatal("cyon_connection_nonblock(): %s", errno_s);
}

static void
cyon_bind_finish(struct listener *l, void *s, size_t len)
{
	if (bind(l->fd, (struct sockaddr *)s, len) == -1)
		fatal("bind(): %s", errno_s);
	if (listen(l->fd, 10) == -1)
		fatal("listen(): %s", errno_s);
}

static void
cyon_storewrite_wait(int final)
{
	int		fd;
	struct stat	st;
	pid_t		pid;
	int		status;
	u_int8_t	hash[SHA_DIGEST_LENGTH];
	char		fpath[MAXPATHLEN], tpath[MAXPATHLEN], *hex, *old;

	if (writepid == -1)
		return;

	if (final)
		pid = waitpid(writepid, &status, 0);
	else
		pid = waitpid(writepid, &status, WNOHANG);

	if (pid == -1) {
		cyon_log(LOG_NOTICE, "waitpid(): %s", errno_s);
		return;
	}

	if (pid == 0)
		return;

	if (pid != writepid) {
		cyon_log(LOG_NOTICE,
		    "waitpid() returned %d, expected %d", pid, writepid);
		return;
	}

	if (WEXITSTATUS(status) != 0 ||
	    WTERMSIG(status) || WCOREDUMP(status)) {
		cyon_log(LOG_NOTICE,
		    "store write failed, see log messages (%d)", writepid);
		writepid = -1;
		return;
	}

	snprintf(fpath, sizeof(fpath), CYON_STORE_FILE, storepath, storename);
	if ((fd = open(fpath, O_RDONLY)) == -1) {
		cyon_log(LOG_NOTICE, "cannot verify store: %s", errno_s);
		return;
	}

	if (fstat(fd, &st) == -1) {
		close(fd);
		cyon_log(LOG_NOTICE, "cannot stat store: %s", errno_s);
		return;
	}

	if (lseek(fd, st.st_size - SHA_DIGEST_LENGTH, SEEK_SET) == -1) {
		close(fd);
		cyon_log(LOG_NOTICE, "cannot seek to SHA: %s", errno_s);
		return;
	}

	cyon_atomic_read(fd, hash, SHA_DIGEST_LENGTH, CYON_NO_CHECKSUM, 0);
	close(fd);

	cyon_sha_hex(hash, &hex);
	cyon_sha_hex(store_state, &old);

	if (store_retain_logs) {
		if (memcmp(hash, store_state, SHA_DIGEST_LENGTH)) {
			cyon_log(LOG_NOTICE,
			    "state transition %s -> %s", old, hex);
		} else {
			cyon_log(LOG_NOTICE, "no store state changes");
		}
	} else {
		snprintf(fpath, sizeof(fpath),
		    CYON_LOG_FILE, storepath, storename, old);
		if (unlink(fpath) == -1) {
			cyon_log(LOG_NOTICE,
			    "cannot unlink old log: %s (%s)", fpath, errno_s);
		}
	}

	if (!cyon_readonly_mode) {
		snprintf(fpath, sizeof(fpath),
		    CYON_LOG_FILE, storepath, storename, hex);
		snprintf(tpath, sizeof(tpath),
		    CYON_WRITELOG_FILE, storepath, storename);

		if (rename(tpath, fpath) == -1)
			fatal("cannot move tmp log into place: %s", errno_s);
	}

	cyon_mem_free(hex);
	cyon_mem_free(old);
	memcpy(store_state, hash, SHA_DIGEST_LENGTH);

	cyon_log(LOG_NOTICE, "store write completed (%d)", writepid);
	writepid = -1;
}

static void
cyon_signal(int sig)
{
	sig_recv = sig;
}

static void
usage(void)
{
	u_int8_t	i;

	printf("Usage: cyon-server [options] ([certfile] [keyfile])\n");
	printf("Available options for cyon:\n");
	for (i = 0; use_options[i].descr != NULL; i++) {
		printf("   -%c %s\t\t%s\n", use_options[i].opt,
		    (use_options[i].label != NULL) ? use_options[i].label :
		    "  ", use_options[i].descr);
	}

	exit(1);
}

static void
cyon_write_pid(void)
{
	FILE		*fp;
	char		fpath[MAXPATHLEN];

	if (store_nopersist) {
		cyon_strlcpy(fpath, CYON_DEFAULT_PID, sizeof(fpath));
	} else {
		snprintf(fpath, sizeof(fpath), "%s/cyon.pid", storepath);
	}

	if ((fp = fopen(fpath, "w")) == NULL) {
		cyon_log(LOG_NOTICE, "failed to write pidfile: %s", errno_s);
	} else {
		fprintf(fp, "%d\n", getpid());
		fclose(fp);
	}
}

static void
cyon_unlink_pid(void)
{
	char		fpath[MAXPATHLEN];

	if (store_nopersist) {
		cyon_strlcpy(fpath, CYON_DEFAULT_PID, sizeof(fpath));
	} else {
		snprintf(fpath, sizeof(fpath), "%s/cyon.pid", storepath);
	}

	if (unlink(fpath) == -1)
		cyon_log(LOG_NOTICE, "pid file lingers: %s", errno_s);
}
