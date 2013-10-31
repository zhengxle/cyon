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

#include <fcntl.h>
#include <signal.h>
#include <unistd.h>

#include "cyon.h"

static void		usage(void);
static void		cyon_signal(int);
static void		cyon_ssl_init(void);
static void		cyon_storewrite_wait(int);
static void		cyon_server_bind(struct listener *, char *, u_int16_t);

static struct {
	int	opt;
	char	*label;
	char	*descr;
} use_options[] = {
	{ 'b',	"ip",		"Bind to the given IP address" },
	{ 'd',	"storedir",	"Directory where all data is stored" },
	{ 'f',	NULL,		"Runs cyon in foreground mode" },
	{ 'n',	NULL,		"No data persistence" },
	{ 'p',	"port",		"Use given port to listen for connections" },
	{ 's',	"storename",	"Name of the cyon store" },
	{ 'w',	"interval",	"Time in minutes in between store writes" },
	{ 0,	NULL,		NULL },
};

volatile sig_atomic_t	sig_recv;

struct listener		server;
extern const char	*__progname;
SSL_CTX			*ssl_ctx = NULL;
u_int64_t		last_store_write;
u_int8_t		server_started = 0;
u_int32_t		idle_timeout = CYON_IDLE_TIMER_MAX;

static pid_t		writepid = -1;
static u_int32_t	store_write_int = CYON_STORE_WRITE_INTERVAL;

int
main(int argc, char *argv[])
{
	struct stat	st;
	char		*ip;
	u_int64_t	now;
	u_int16_t	port;
	int		ch, err;
	u_int8_t	foreground;
	char		fpath[MAXPATHLEN];
	u_int64_t	last_storelog_flush, idle_check;

	port = 3331;
	foreground = 0;
	storepath = NULL;
	ip = "127.0.0.1";

	while ((ch = getopt(argc, argv, "b:d:fi:np:s:w:")) != -1) {
		switch (ch) {
		case 'b':
			ip = optarg;
			break;
		case 'd':
			storepath = optarg;
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
		case 'n':
			store_nowrite = 1;
			break;
		case 'p':
			port = cyon_strtonum(optarg, 1, 65535, &err);
			if (err != CYON_RESULT_OK)
				fatal("Invalid port: %s", optarg);
			break;
		case 's':
			storename = optarg;
			break;
		case 'w':
			store_write_int = cyon_strtonum(optarg, 0, 254, &err);
			if (err != CYON_RESULT_OK)
				fatal("Invalid write interval: %s", optarg);
			store_write_int = (store_write_int * 60) * 1000;
			break;
		case '?':
		default:
			usage();
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

	if (storepath == NULL || storename == NULL) {
		fprintf(stderr,
		    "Please set storepath (-d) and storename (-s)\n");
		usage();
	}

	snprintf(fpath, sizeof(fpath), CYON_WRITELOG_FILE,
	    storepath, storename);
	if (stat(fpath, &st) != -1) {
		printf("cyon-server: %s is in the way\n", fpath);
		fatal("please append it to the current log");
	}

	cyon_log_init();
	cyon_mem_init();
	cyon_ssl_init();
	cyon_connection_init();
	cyon_server_bind(&server, ip, port);
	cyon_platform_event_init();

	if (foreground == 0)
		printf("cyon daemonizing, check system log for details\n");

	if (foreground == 0 && daemon(1, 1) == -1)
		fatal("could not forkify(): %s", errno_s);

	cyon_store_init();

	sig_recv = 0;
	signal(SIGQUIT, cyon_signal);
	signal(SIGINT, cyon_signal);
	signal(SIGHUP, cyon_signal);
	signal(SIGPIPE, SIG_IGN);

	server_started = 1;
	idle_check = last_store_write = cyon_time_ms();
	cyon_log(LOG_NOTICE, "server ready on %s:%d", ip, port);

	for (;;) {
		if (sig_recv == SIGQUIT)
			break;

		now = cyon_time_ms();
		if (writepid == -1 && store_write_int != 0 &&
		    (now - last_store_write) >= store_write_int) {
			last_store_write = now;
			cyon_storewrite_start();
		}

		if ((now - last_storelog_flush) >= 1) {
			last_storelog_flush = now;
			cyon_storelog_flush();
		}

		cyon_storewrite_wait(0);
		cyon_platform_event_wait();

		if (idle_timeout > 0 && (now - idle_check) >= 10000) {
			idle_check = now;
			cyon_connection_check_idletimer(now);
		}

		cyon_connection_prune();
	}

	if (writepid != -1)
		cyon_storewrite_wait(1);

	cyon_storewrite_start();
	cyon_storewrite_wait(1);
	cyon_connection_disconnect_all();

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
cyon_storewrite_wait(int final)
{
	pid_t		pid;
	int		status;

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
	} else {
		cyon_log(LOG_NOTICE,
		    "store write completed (%d)", writepid);
	}

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

	printf("Available options for cyon:\n");
	for (i = 0; use_options[i].descr != NULL; i++) {
		printf("   -%c %s\t\t%s\n", use_options[i].opt,
		    (use_options[i].label != NULL) ? use_options[i].label :
		    "  ", use_options[i].descr);
	}

	exit(1);
}
